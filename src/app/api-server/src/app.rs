// Copyright Kamu Data, Inc. and contributors. All rights reserved.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0.

use std::future::{Future, IntoFuture};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use arrow_flight::sql::SqlInfo;
use chrono::Duration;
use dill::{CatalogBuilder, Component};
use internal_error::*;
use kamu::domain::{DidGeneratorDefault, TenancyConfig};
use kamu::{DatasetStorageUnitLocalFs, DatasetStorageUnitS3, DatasetStorageUnitWriter};
use s3_utils::S3Context;
use tracing::{error, info, warn};
use url::Url;

use crate::config::{
    ApiServerConfig,
    AuthProviderConfig,
    RepoConfig,
    UploadRepoStorageConfig,
    ACCOUNT_KAMU,
};
use crate::ui_configuration::{UIConfiguration, UIFeatureFlags};
use crate::{
    cli,
    configure_database_components,
    configure_in_memory_components,
    connect_database_initially,
    spawn_password_refreshing_job,
    try_build_db_connection_settings,
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub const BINARY_NAME: &str = env!("CARGO_PKG_NAME");
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_RUST_LOG: &str = "debug,";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub async fn run(args: cli::Cli, config: ApiServerConfig) -> Result<(), InternalError> {
    let repo_url = if let Some(repo_url) = config.repo.repo_url.as_ref().cloned() {
        repo_url
    } else {
        let workspace_dir = find_workspace();
        if !workspace_dir.exists() {
            panic!(
                "Directory is not a kamu workspace: {}",
                workspace_dir.display()
            );
        }
        Url::from_directory_path(workspace_dir.join("datasets")).unwrap()
    };

    let tenancy_config = if args.multi_tenant || repo_url.scheme() != "file" {
        TenancyConfig::MultiTenant
    } else {
        TenancyConfig::SingleTenant
    };

    let local_dir = tempfile::tempdir().unwrap();

    info!(
        version = VERSION,
        args = ?std::env::args().collect::<Vec<_>>(),
        repo_url = %repo_url,
        local_dir = %local_dir.path().display(),
        config = ?config,
        "Initializing Kamu API Server",
    );

    let kamu_account_name = odf::AccountName::new_unchecked(ACCOUNT_KAMU);
    let server_account_subject = kamu_accounts::CurrentAccountSubject::logged(
        odf::AccountID::new_seeded_ed25519(kamu_account_name.as_bytes()),
        kamu_account_name,
        true,
    );

    let db_config = config.database.clone();

    let ui_config = UIConfiguration {
        ingest_upload_file_limit_mb: config.upload_repo.max_file_size_mb,
        feature_flags: UIFeatureFlags {
            enable_dataset_env_vars_management: config.dataset_env_vars.is_enabled(),
            ..UIFeatureFlags::default()
        },
    };

    let catalog = init_dependencies(config, &repo_url, tenancy_config, local_dir.path())
        .await
        .build();

    // Register metrics
    let metrics_registry = observability::metrics::register_all(&catalog);

    // Database requires extra actions:
    let final_catalog = if db_config.needs_database() {
        // Connect database and obtain a connection pool
        let catalog_with_pool = connect_database_initially(&catalog).await?;

        // Periodically refresh password in the connection pool, if configured
        spawn_password_refreshing_job(&db_config, &catalog_with_pool).await;

        catalog_with_pool
    } else {
        catalog
    };

    initialize_components(&final_catalog, server_account_subject.clone()).await?;

    match args.command {
        cli::Command::Gql(c) => match c.subcommand {
            cli::Gql::Schema(_) => {
                println!("{}", kamu_adapter_graphql::schema().sdl());
                Ok(())
            }
            cli::Gql::Query(sc) => {
                let result = crate::gql_server::gql_query(&sc.query, sc.full, final_catalog).await;
                print!("{}", result);
                Ok(())
            }
        },
        cli::Command::Metrics(_) => {
            // TODO: Proper implementation is blocked by https://github.com/tikv/rust-prometheus/issues/526
            let metric_families = metrics_registry.gather();
            println!("{metric_families:#?}");
            Ok(())
        }
        cli::Command::Run(c) => {
            let shutdown_requested = graceful_shutdown::trap_signals();

            let address = c
                .address
                .unwrap_or(std::net::Ipv4Addr::new(127, 0, 0, 1).into());

            // API servers are built from the regular catalog
            // that does not contain any auth subject, thus they will rely on
            // their own middlewares to authenticate per request / session and execute
            // all processing in the user context.
            let (http_server, local_addr, maybe_shutdown_notify) =
                crate::http_server::build_server(
                    address,
                    c.http_port,
                    final_catalog.clone(),
                    tenancy_config,
                    ui_config,
                    args.e2e_output_data_path.as_ref(),
                )
                .await?;

            let flightsql_server = crate::flightsql_server::FlightSqlServer::new(
                address,
                c.flightsql_port,
                final_catalog.clone(),
            )
            .await;

            // System services are built from the special catalog that contains the admin
            // subject. Thus all services that require authorization are granted full access
            // to all resources.
            //
            // TODO: Granting admin access to all system services is a security threat. We
            // should consider to instead propagate the auth info of the user who triggered
            // some system flow alongside all actions to enforce proper authorization.
            let system_catalog = CatalogBuilder::new_chained(&final_catalog)
                .add_value(server_account_subject)
                .build();

            let task_agent = system_catalog
                .get_one::<dyn kamu_task_system::TaskAgent>()
                .unwrap();

            let flow_agent = system_catalog
                .get_one::<dyn kamu_flow_system::FlowAgent>()
                .unwrap();

            let outbox_agent = system_catalog
                .get_one::<messaging_outbox::OutboxAgent>()
                .unwrap();

            info!(
                http_endpoint = format!("http://{}", local_addr),
                flightsql_endpoint = format!("flightsql://{}", flightsql_server.local_addr()),
                "Serving traffic"
            );

            let server_run_fut: Pin<Box<dyn Future<Output = _>>> =
                if let Some(shutdown_notify) = maybe_shutdown_notify {
                    Box::pin(async move {
                        let server_with_graceful_shutdown =
                            http_server.with_graceful_shutdown(async move {
                                tokio::select! {
                                    _ = shutdown_requested => {}
                                    _ = shutdown_notify.notified() => {}
                                }
                            });

                        server_with_graceful_shutdown.await
                    })
                } else {
                    Box::pin(http_server.into_future())
                };

            // Run phase
            // TODO: PERF: Do we need to spawn these into separate tasks?
            tokio::select! {
                res = server_run_fut => { res.int_err() },
                res = flightsql_server.run() => { res.int_err() },
                res = task_agent.run() => { res.int_err() },
                res = flow_agent.run() => { res.int_err() },
                res = outbox_agent.run() => { res.int_err() },
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub fn init_observability() -> observability::init::Guard {
    observability::init::auto(
        observability::config::Config::from_env_with_prefix("KAMU_OTEL_")
            .with_service_name(BINARY_NAME)
            .with_service_version(VERSION)
            .with_default_log_levels(DEFAULT_RUST_LOG),
    )
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub fn load_config(path: Option<&PathBuf>) -> Result<ApiServerConfig, InternalError> {
    use figment::providers::Format;

    let mut figment = figment::Figment::from(figment::providers::Serialized::defaults(
        ApiServerConfig::default(),
    ));

    if let Some(path) = path {
        if !path.is_file() {
            return InternalError::bail(format!("Config file '{}' not found", path.display()));
        }

        figment = figment.merge(figment::providers::Yaml::file(path));
    };

    figment
        .merge(
            figment::providers::Env::prefixed("KAMU_API_SERVER_CONFIG_")
                .split("__")
                .lowercase(false),
        )
        .extract()
        .int_err()
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub async fn init_dependencies(
    config: ApiServerConfig,
    repo_url: &Url,
    tenancy_config: TenancyConfig,
    local_dir: &Path,
) -> CatalogBuilder {
    let mut b = CatalogBuilder::new();

    // TODO: Improve output multiplexing and cache interface
    let run_info_dir = local_dir.join("run");
    let cache_dir = local_dir.join("cache");
    let remote_repos_dir = local_dir.join("repos");
    std::fs::create_dir_all(&run_info_dir).unwrap();
    std::fs::create_dir_all(&cache_dir).unwrap();
    std::fs::create_dir_all(&remote_repos_dir).unwrap();

    b.add_value(tenancy_config);

    b.add_value(kamu::domain::RunInfoDir::new(run_info_dir));
    b.add_value(kamu::domain::CacheDir::new(cache_dir));
    b.add_value(kamu::RemoteReposDir::new(remote_repos_dir));

    b.add::<time_source::SystemTimeSourceDefault>();

    b.add::<DidGeneratorDefault>();

    b.add_value(prometheus::Registry::new_custom(Some("kamu_api_server".into()), None).unwrap());

    b.add::<container_runtime::ContainerRuntime>();
    b.add_value(container_runtime::ContainerRuntimeConfig {
        runtime: config.engine.runtime,
        network_ns: config.engine.network_ns,
    });

    b.add::<kamu::EngineProvisionerLocal>();
    b.add_value(kamu::EngineProvisionerLocalConfig {
        max_concurrency: config.engine.max_concurrency,
        start_timeout: config.engine.start_timeout.into(),
        shutdown_timeout: config.engine.shutdown_timeout.into(),
        spark_image: config.engine.images.spark,
        flink_image: config.engine.images.flink,
        datafusion_image: config.engine.images.datafusion,
        risingwave_image: config.engine.images.risingwave,
    });

    b.add_value(config.protocol.ipfs.into_gateway_config());
    b.add_value(kamu::utils::ipfs_wrapper::IpfsClient::default());

    // FlightSQL
    let mut sql_info = kamu_adapter_flight_sql::sql_info::default_sql_info();
    sql_info.append(SqlInfo::FlightSqlServerName, crate::BINARY_NAME);
    sql_info.append(SqlInfo::FlightSqlServerVersion, crate::VERSION);
    b.add_value(sql_info.build().unwrap());

    b.add_value(config.protocol.flight_sql.to_session_auth_config());
    b.add_value(config.protocol.flight_sql.to_session_caching_config());

    b.add::<kamu_adapter_flight_sql::SessionAuthAnonymous>();
    b.add::<kamu_adapter_flight_sql::SessionManagerCaching>();
    b.add::<kamu_adapter_flight_sql::SessionManagerCachingState>();
    b.add::<kamu_adapter_flight_sql::KamuFlightSqlService>();
    //

    b.add::<kamu::FetchService>();
    b.add_value(config.source.to_infra_cfg());
    b.add_value(config.source.mqtt.to_infra_cfg());
    b.add_value(config.source.ethereum.to_infra_cfg());

    if let Some(identity_config) = config
        .identity
        .as_ref()
        .and_then(|identity| identity.to_infra_cfg())
    {
        b.add_value(identity_config);
    }

    b.add::<odf::dataset::DatasetFactoryImpl>();
    b.add::<kamu::ObjectStoreRegistryImpl>();
    b.add::<kamu::RemoteAliasesRegistryImpl>();
    b.add::<kamu::RemoteAliasResolverImpl>();

    b.add::<kamu::DatasetChangesServiceImpl>();

    b.add::<kamu::RemoteRepositoryRegistryImpl>();

    b.add::<kamu::utils::simple_transfer_protocol::SimpleTransferProtocol>();
    b.add::<kamu_adapter_http::SmartTransferProtocolClientWs>();

    b.add::<kamu::DataFormatRegistryImpl>();

    b.add::<kamu::PollingIngestServiceImpl>();
    b.add::<kamu::PushIngestPlannerImpl>();
    b.add::<kamu::PushIngestExecutorImpl>();
    b.add::<kamu::TransformRequestPlannerImpl>();
    b.add::<kamu::TransformElaborationServiceImpl>();
    b.add::<kamu::TransformExecutorImpl>();
    b.add::<kamu::SyncServiceImpl>();
    b.add::<kamu::SyncRequestBuilder>();
    b.add::<kamu::CompactionPlannerImpl>();
    b.add::<kamu::CompactionExecutorImpl>();
    b.add::<kamu::VerificationServiceImpl>();
    b.add::<kamu::PullRequestPlannerImpl>();
    b.add::<kamu::PushRequestPlannerImpl>();
    b.add::<kamu::SetWatermarkPlannerImpl>();
    b.add::<kamu::SetWatermarkExecutorImpl>();
    b.add::<kamu::MetadataQueryServiceImpl>();
    b.add::<kamu::QueryServiceImpl>();
    b.add::<kamu::ResetPlannerImpl>();
    b.add::<kamu::ResetExecutorImpl>();
    b.add::<kamu::RemoteStatusServiceImpl>();

    b.add::<kamu::AppendDatasetMetadataBatchUseCaseImpl>();
    b.add::<kamu::CommitDatasetEventUseCaseImpl>();
    b.add::<kamu::CompactDatasetUseCaseImpl>();
    b.add::<kamu::CreateDatasetFromSnapshotUseCaseImpl>();
    b.add::<kamu::CreateDatasetUseCaseImpl>();
    b.add::<kamu::DeleteDatasetUseCaseImpl>();
    b.add::<kamu::GetDatasetDownstreamDependenciesUseCaseImpl>();
    b.add::<kamu::GetDatasetUpstreamDependenciesUseCaseImpl>();
    b.add::<kamu::PullDatasetUseCaseImpl>();
    b.add::<kamu::PushDatasetUseCaseImpl>();
    b.add::<kamu::RenameDatasetUseCaseImpl>();
    b.add::<kamu::ResetDatasetUseCaseImpl>();
    b.add::<kamu::SetWatermarkUseCaseImpl>();
    b.add::<kamu::VerifyDatasetUseCaseImpl>();

    b.add_builder(
        messaging_outbox::OutboxImmediateImpl::builder()
            .with_consumer_filter(messaging_outbox::ConsumerFilter::ImmediateConsumers),
    );
    b.add::<messaging_outbox::OutboxTransactionalImpl>();
    b.add::<messaging_outbox::OutboxDispatchingImpl>();
    b.bind::<dyn messaging_outbox::Outbox, messaging_outbox::OutboxDispatchingImpl>();
    b.add::<messaging_outbox::OutboxAgent>();
    b.add::<messaging_outbox::OutboxAgentMetrics>();

    b.add::<kamu_datasets_services::DatasetEntryServiceImpl>();
    b.add::<kamu_datasets_services::DependencyGraphServiceImpl>();
    b.add::<kamu_datasets_services::DatasetEntryIndexer>();
    b.add::<kamu_datasets_services::DependencyGraphIndexer>();

    messaging_outbox::register_message_dispatcher::<kamu::domain::DatasetLifecycleMessage>(
        &mut b,
        kamu::domain::MESSAGE_PRODUCER_KAMU_CORE_DATASET_SERVICE,
    );
    messaging_outbox::register_message_dispatcher::<kamu_task_system::TaskProgressMessage>(
        &mut b,
        kamu_task_system::MESSAGE_PRODUCER_KAMU_TASK_AGENT,
    );
    messaging_outbox::register_message_dispatcher::<
        kamu_flow_system::FlowConfigurationUpdatedMessage,
    >(
        &mut b,
        kamu_flow_system_services::MESSAGE_PRODUCER_KAMU_FLOW_CONFIGURATION_SERVICE,
    );
    messaging_outbox::register_message_dispatcher::<kamu_flow_system::FlowTriggerUpdatedMessage>(
        &mut b,
        kamu_flow_system_services::MESSAGE_PRODUCER_KAMU_FLOW_TRIGGER_SERVICE,
    );
    messaging_outbox::register_message_dispatcher::<kamu_flow_system::FlowProgressMessage>(
        &mut b,
        kamu_flow_system_services::MESSAGE_PRODUCER_KAMU_FLOW_PROGRESS_SERVICE,
    );

    b.add_value(messaging_outbox::OutboxConfig::new(
        Duration::seconds(config.outbox.awaiting_step_secs.unwrap()),
        config.outbox.batch_size.unwrap(),
    ));

    kamu_task_system_services::register_dependencies(&mut b);

    b.add_value(kamu_flow_system::FlowAgentConfig::new(
        chrono::Duration::try_seconds(1).unwrap(),
        chrono::Duration::try_minutes(1).unwrap(),
    ));
    kamu_flow_system_services::register_dependencies(&mut b);

    b.add::<kamu_accounts_services::AuthenticationServiceImpl>();
    b.add::<kamu_accounts_services::AccessTokenServiceImpl>();
    b.add::<kamu_accounts_services::PredefinedAccountsRegistrator>();

    kamu_adapter_auth_oso_rebac::register_dependencies(&mut b);

    b.add::<kamu_auth_rebac_services::RebacIndexer>();

    b.add::<odf::dataset::DummyOdfServerAccessTokenResolver>();

    configure_repository(&mut b, repo_url, &config.repo).await;

    b.add::<kamu_accounts_services::LoginPasswordAuthProvider>();
    b.add::<kamu_accounts_services::AccountServiceImpl>();

    let mut need_to_add_default_predefined_accounts_config = true;

    match tenancy_config {
        TenancyConfig::SingleTenant => {
            b.add_value(kamu_accounts::PredefinedAccountsConfig::single_tenant());
            need_to_add_default_predefined_accounts_config = false;
        }
        TenancyConfig::MultiTenant => {
            b.add::<kamu_auth_rebac_services::MultiTenantRebacDatasetLifecycleMessageConsumer>();

            for provider in config.auth.providers {
                match provider {
                    AuthProviderConfig::Github(github_config) => {
                        b.add::<kamu_adapter_oauth::OAuthGithub>();

                        b.add_value(kamu_adapter_oauth::GithubAuthenticationConfig::new(
                            github_config.client_id,
                            github_config.client_secret,
                        ));
                    }
                    AuthProviderConfig::Password(prov) => {
                        b.add_value(kamu_accounts::PredefinedAccountsConfig {
                            predefined: prov.accounts,
                        });
                        need_to_add_default_predefined_accounts_config = false
                    }
                }
            }
        }
    }

    if need_to_add_default_predefined_accounts_config {
        b.add_value(kamu_accounts::PredefinedAccountsConfig::default());
    }

    b.add_value(kamu::domain::ServerUrlConfig::new(
        kamu::domain::Protocols {
            base_url_platform: config.url.base_url_platform,
            base_url_rest: config.url.base_url_rest,
            base_url_flightsql: config.url.base_url_flightsql,
        },
    ));

    let maybe_jwt_secret = if !config.auth.jwt_secret.is_empty() {
        Some(config.auth.jwt_secret)
    } else {
        None
    };

    b.add_value(kamu_accounts::JwtAuthenticationConfig::new(
        maybe_jwt_secret,
    ));

    b.add_value(kamu_adapter_http::FileUploadLimitConfig::new_in_mb(
        config.upload_repo.max_file_size_mb,
    ));

    match config.upload_repo.storage {
        UploadRepoStorageConfig::Local => {
            b.add::<kamu_adapter_http::UploadServiceLocal>();
        }
        UploadRepoStorageConfig::S3(s3_config) => {
            let s3_upload_direct_url = Url::parse(&s3_config.bucket_s3_url).unwrap();
            b.add_builder(
                kamu_adapter_http::UploadServiceS3::builder()
                    .with_s3_upload_context(S3Context::from_url(&s3_upload_direct_url).await),
            );
            b.bind::<dyn kamu_adapter_http::UploadService, kamu_adapter_http::UploadServiceS3>();
        }
    }

    let dataset_env_vars_config = &config.dataset_env_vars;
    match dataset_env_vars_config.encryption_key.as_ref() {
        None => {
            match dataset_env_vars_config.enabled.as_ref() {
                None => {
                    error!("Dataset env vars configuration is missing. Feature will be disabled");
                }
                Some(true) => panic!("Dataset env vars encryption key is required"),
                _ => {}
            }
            b.add::<kamu_datasets_services::DatasetKeyValueServiceSysEnv>();
            b.add::<kamu_datasets_services::DatasetEnvVarServiceNull>();
        }
        Some(encryption_key) => {
            if let Some(enabled) = &dataset_env_vars_config.enabled
                && !enabled
            {
                warn!("Dataset env vars feature will be disabled");
                b.add::<kamu_datasets_services::DatasetKeyValueServiceSysEnv>();
                b.add::<kamu_datasets_services::DatasetEnvVarServiceNull>();
            } else {
                assert!(
                    kamu_datasets::DatasetEnvVar::try_asm_256_gcm_from_str(encryption_key).is_ok(),
                    "Invalid dataset env var encryption key. Key must be a 32-character \
                     alphanumeric string",
                );
                b.add::<kamu_datasets_services::DatasetKeyValueServiceImpl>();
                b.add::<kamu_datasets_services::DatasetEnvVarServiceImpl>();
            }
        }
    }
    b.add_value(config.dataset_env_vars);

    b.add::<database_common::DatabaseTransactionRunner>();

    b.add::<kamu_auth_rebac_services::RebacServiceImpl>();
    b.add_value(kamu_auth_rebac_services::DefaultAccountProperties { is_admin: false });
    b.add_value(kamu_auth_rebac_services::DefaultDatasetProperties {
        allows_anonymous_read: false,
        allows_public_read: false,
    });

    let maybe_db_connection_settings = try_build_db_connection_settings(&config.database);
    if let Some(db_connection_settings) = maybe_db_connection_settings {
        configure_database_components(&mut b, &config.database, db_connection_settings);
    } else {
        configure_in_memory_components(&mut b);
    };

    b
}

async fn configure_repository(b: &mut CatalogBuilder, repo_url: &Url, config: &RepoConfig) {
    match repo_url.scheme() {
        "file" => {
            let datasets_dir = repo_url.to_file_path().unwrap();

            b.add_builder(DatasetStorageUnitLocalFs::builder().with_root(datasets_dir.clone()));
            b.bind::<dyn odf::DatasetStorageUnit, DatasetStorageUnitLocalFs>();
            b.bind::<dyn DatasetStorageUnitWriter, DatasetStorageUnitLocalFs>();

            b.add::<kamu::ObjectStoreBuilderLocalFs>();
        }
        "s3" | "s3+http" | "s3+https" => {
            let s3_context = S3Context::from_url(repo_url).await;

            if config.caching.registry_cache_enabled {
                b.add::<kamu::S3RegistryCache>();
            }

            let metadata_cache_local_fs_path = config
                .caching
                .metadata_local_fs_cache_path
                .clone()
                .map(Arc::new);

            b.add_builder(
                DatasetStorageUnitS3::builder()
                    .with_s3_context(s3_context.clone())
                    .with_metadata_cache_local_fs_path(metadata_cache_local_fs_path),
            );
            b.bind::<dyn odf::DatasetStorageUnit, DatasetStorageUnitS3>();
            b.bind::<dyn DatasetStorageUnitWriter, DatasetStorageUnitS3>();

            let allow_http = repo_url.scheme() == "s3+http";
            b.add_value(kamu::ObjectStoreBuilderS3::new(s3_context, allow_http))
                .bind::<dyn kamu::domain::ObjectStoreBuilder, kamu::ObjectStoreBuilderS3>();

            // LFS object store is still needed for Datafusion operations that create
            // temporary file, such as push ingest
            b.add::<kamu::ObjectStoreBuilderLocalFs>();
        }
        _ => panic!("Unsupported repository scheme: {}", repo_url.scheme()),
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Workspace
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub fn find_workspace() -> PathBuf {
    let cwd = Path::new(".").canonicalize().unwrap();
    if let Some(ws) = find_workspace_rec(&cwd) {
        ws
    } else {
        cwd.join(".kamu")
    }
}

fn find_workspace_rec(p: &Path) -> Option<PathBuf> {
    let root_dir = p.join(".kamu");
    if root_dir.exists() {
        Some(root_dir)
    } else if let Some(parent) = p.parent() {
        find_workspace_rec(parent)
    } else {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

async fn initialize_components(
    catalog: &dill::Catalog,
    server_account_subject: kamu_accounts::CurrentAccountSubject,
) -> Result<(), InternalError> {
    let logged_catalog = dill::CatalogBuilder::new_chained(catalog)
        .add_value(server_account_subject)
        .build();

    init_on_startup::run_startup_jobs(&logged_catalog)
        .await
        .int_err()
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
