// Copyright Kamu Data, Inc. and contributors. All rights reserved.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0.

/////////////////////////////////////////////////////////////////////////////////////////

use kamu::domain::{AnonymousAccountReason, CurrentAccountSubject};

pub(crate) fn build_server(
    address: Option<std::net::IpAddr>,
    http_port: Option<u16>,
    catalog: dill::Catalog,
    multi_tenant_workspace: bool,
) -> axum::Server<hyper::server::conn::AddrIncoming, axum::routing::IntoMakeService<axum::Router>> {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let gql_schema = kamu_adapter_graphql::schema();

    let app = axum::Router::new()
        .route("/", axum::routing::get(root_handler))
        .route(
            "/graphql",
            axum::routing::get(graphql_playground_handler).post(graphql_handler),
        )
        .route(
            "/platform/token/validate",
            axum::routing::get(platform_token_validate_handler),
        )
        .nest(
            if multi_tenant_workspace {
                "/:account_name/:dataset_name"
            } else {
                "/:dataset_name"
            },
            kamu_adapter_http::add_dataset_resolver_layer(
                kamu_adapter_http::smart_transfer_protocol_router(),
                multi_tenant_workspace,
            ),
        )
        .layer(
            tower::ServiceBuilder::new()
                .layer(tower_http::trace::TraceLayer::new_for_http())
                .layer(
                    tower_http::cors::CorsLayer::new()
                        .allow_origin(tower_http::cors::Any)
                        .allow_methods(vec![http::Method::GET, http::Method::POST])
                        .allow_headers(tower_http::cors::Any),
                )
                .layer(axum::extract::Extension(catalog))
                .layer(axum::extract::Extension(gql_schema))
                .layer(kamu_adapter_http::AuthenticationLayer::new()),
        );

    let addr = SocketAddr::from((
        address.unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        http_port.unwrap_or(0),
    ));

    axum::Server::bind(&addr).serve(app.into_make_service())
}

/////////////////////////////////////////////////////////////////////////////////////////
// Routes
/////////////////////////////////////////////////////////////////////////////////////////

async fn root_handler() -> impl axum::response::IntoResponse {
    axum::response::Html(
        r#"
        <h1>Kamu API Server</h1>
        <ul>
            <li><a href="/graphql">GraphQL Endpoint</a></li>
            <li><a href="/graphql">GraphQL Playground</a></li>
        </ul>
        "#,
    )
}

/////////////////////////////////////////////////////////////////////////////////////////

async fn graphql_handler(
    schema: axum::extract::Extension<kamu_adapter_graphql::Schema>,
    req: async_graphql_axum::GraphQLRequest,
) -> async_graphql_axum::GraphQLResponse {
    schema.execute(req.into_inner()).await.into()
}

/////////////////////////////////////////////////////////////////////////////////////////

async fn graphql_playground_handler() -> impl axum::response::IntoResponse {
    axum::response::Html(async_graphql::http::playground_source(
        async_graphql::http::GraphQLPlaygroundConfig::new("/graphql"),
    ))
}

/////////////////////////////////////////////////////////////////////////////////////////

// TODO: move this logic to `kamu_adapter_http` crate
async fn platform_token_validate_handler(
    catalog: axum::extract::Extension<dill::Catalog>,
) -> axum::response::Response {
    let current_account_subject = catalog.get_one::<CurrentAccountSubject>().unwrap();

    match current_account_subject.as_ref() {
        CurrentAccountSubject::Logged(_) => {
            return axum::response::Response::builder()
                .status(http::StatusCode::OK)
                .body(Default::default())
                .unwrap()
        }
        CurrentAccountSubject::Anonymous(reason) => {
            return axum::response::Response::builder()
                .status(match reason {
                    AnonymousAccountReason::AuthenticationExpired => http::StatusCode::UNAUTHORIZED,
                    AnonymousAccountReason::AuthenticationInvalid => http::StatusCode::BAD_REQUEST,
                    AnonymousAccountReason::NoAuthenticationProvided => {
                        http::StatusCode::BAD_REQUEST
                    }
                })
                .body(Default::default())
                .unwrap();
        }
    }
}

/////////////////////////////////////////////////////////////////////////////////////////
