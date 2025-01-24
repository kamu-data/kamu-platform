// Copyright Kamu Data, Inc. and contributors. All rights reserved.
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0.

use async_trait::async_trait;
use internal_error::{ErrorIntoInternal, InternalError, ResultIntoInternal};
use kamu_adapter_http::general::AccountResponse;
use kamu_adapter_http::LoginRequestBody;
use reqwest::{Method, StatusCode};
use thiserror::Error;

use crate::{AccessToken, KamuApiServerClient, RequestBody};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[async_trait]
pub trait KamuApiServerClientExt {
    fn account(&self) -> AccountApi<'_>;

    fn auth(&mut self) -> AuthApi<'_>;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[async_trait]
impl KamuApiServerClientExt for KamuApiServerClient {
    fn account(&self) -> AccountApi<'_> {
        AccountApi { client: self }
    }

    fn auth(&mut self) -> AuthApi<'_> {
        AuthApi { client: self }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// API: Auth
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct AccountApi<'a> {
    client: &'a KamuApiServerClient,
}

impl AccountApi<'_> {
    pub async fn me(&mut self) -> Result<AccountResponse, AccountMeError> {
        let response = self
            .client
            .rest_api_call(Method::GET, "/accounts/me", None)
            .await;

        match response.status() {
            StatusCode::OK => Ok(response.json().await.int_err()?),
            StatusCode::UNAUTHORIZED => Err(AccountMeError::Unauthorized),
            unexpected_status => Err(format!("Unexpected status: {unexpected_status}")
                .int_err()
                .into()),
        }
    }
}

#[derive(Error, Debug)]
pub enum AccountMeError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error(transparent)]
    Internal(#[from] InternalError),
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// API: Auth
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct AuthApi<'a> {
    client: &'a mut KamuApiServerClient,
}

impl AuthApi<'_> {
    pub async fn login_as_kamu(&mut self) -> AccessToken {
        self.login(
            indoc::indoc!(
                r#"
                mutation {
                  auth {
                    login(loginMethod: "password", loginCredentialsJson: "{\"login\":\"kamu\",\"password\":\"kamu\"}") {
                      accessToken
                    }
                  }
                }
                "#,
            )
        ).await
    }

    pub async fn login_as_e2e_user(&mut self) -> AccessToken {
        // We are using DummyOAuthGithub, so the loginCredentialsJson can be arbitrary
        self.login(indoc::indoc!(
            r#"
            mutation {
              auth {
                login(loginMethod: "oauth_github", loginCredentialsJson: "") {
                  accessToken
                }
              }
            }
            "#,
        ))
        .await
    }

    pub async fn login_via_rest(
        &mut self,
        login_method: impl ToString,
        login_credentials_json: serde_json::Value,
    ) -> Result<(), LoginError> {
        let request_body = LoginRequestBody {
            login_method: login_method.to_string(),
            login_credentials_json: serde_json::to_string(&login_credentials_json).int_err()?,
        };
        let request_body_json = serde_json::to_value(request_body).int_err()?;
        let response = self
            .client
            .rest_api_call(
                Method::POST,
                "/platform/login",
                Some(RequestBody::Json(request_body_json)),
            )
            .await;

        match response.status() {
            StatusCode::OK => Ok(()),
            StatusCode::UNAUTHORIZED => Err(LoginError::Unauthorized),
            unexpected_status => Err(format!("Unexpected status: {unexpected_status}")
                .int_err()
                .into()),
        }
    }

    pub async fn token_validate(&self) -> Result<(), TokenValidateError> {
        let response = self
            .client
            .rest_api_call(Method::GET, "/platform/token/validate", None)
            .await;

        match response.status() {
            StatusCode::OK => Ok(()),
            StatusCode::UNAUTHORIZED => Err(TokenValidateError::Unauthorized),
            unexpected_status => Err(format!("Unexpected status: {unexpected_status}")
                .int_err()
                .into()),
        }
    }

    async fn login(&mut self, login_request: &str) -> AccessToken {
        let login_response = self.client.graphql_api_call(login_request).await;
        let access_token = login_response["auth"]["login"]["accessToken"]
            .as_str()
            .map(ToOwned::to_owned)
            .unwrap();

        self.client.set_token(Some(access_token.clone()));

        access_token
    }
}

#[derive(Error, Debug)]
pub enum LoginError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error(transparent)]
    Internal(#[from] InternalError),
}

#[derive(Error, Debug)]
pub enum TokenValidateError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error(transparent)]
    Internal(#[from] InternalError),
}
