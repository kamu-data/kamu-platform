// Copyright Kamu Data, Inc. and contributors. All rights reserved.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0.

use kamu::domain::TenancyConfig;
use kamu_api_server::ui_configuration::UIConfiguration;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[test_group::group(resourcegen)]
#[tokio::test]
async fn update_api_schemas() {
    let mut schemas_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    schemas_path.push("../../../resources");

    // GraphQL
    let gql_schema = kamu_adapter_graphql::schema().sdl();
    std::fs::write(schemas_path.join("schema.gql"), gql_schema).unwrap();

    // OpenAPI
    let openapi_schema = get_openapi_schema(TenancyConfig::SingleTenant).await;
    std::fs::write(schemas_path.join("openapi.json"), openapi_schema).unwrap();

    let openapi_schema = get_openapi_schema(TenancyConfig::MultiTenant).await;
    std::fs::write(schemas_path.join("openapi-mt.json"), openapi_schema).unwrap();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

async fn get_openapi_schema(tenancy_config: TenancyConfig) -> String {
    // Starts the HTTP server and fetches schema from the endpoint
    let (server, addr, _) = kamu_api_server::http_server::build_server(
        "127.0.0.1".parse().unwrap(),
        None,
        dill::Catalog::builder().build(),
        tenancy_config,
        UIConfiguration::default(),
        None,
    )
    .await
    .unwrap();

    let notify_shutdown = std::sync::Arc::new(tokio::sync::Notify::new());
    let shutdown = notify_shutdown.clone();

    let server = server.with_graceful_shutdown(async move { shutdown.notified().await });
    let server = tokio::spawn(async move { server.await.unwrap() });

    let openapi_schema: serde_json::Value = reqwest::get(format!("http://{addr}/openapi.json"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    notify_shutdown.notify_waiters();
    server.await.unwrap();

    serde_json::to_string_pretty(&openapi_schema).unwrap()
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
