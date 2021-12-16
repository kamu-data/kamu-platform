use async_graphql::*;
use serde::Deserialize;

pub(crate) struct Auth;

#[Object]
impl Auth {
    // TODO: PERF: Cache instance?
    #[graphql(skip)]
    fn get_client(&self) -> Result<reqwest::Client, reqwest::Error> {
        reqwest::Client::builder()
            .user_agent(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION"),
            ))
            .build()
    }

    async fn github_login(&self, code: String) -> Result<LoginResponse> {
        let client_id = std::env::var("KAMU_AUTH_GITHUB_CLIENT_ID")
            .expect("KAMU_AUTH_GITHUB_CLIENT_ID env var is not set");
        let client_secret = std::env::var("KAMU_AUTH_GITHUB_CLIENT_SECRET")
            .expect("KAMU_AUTH_GITHUB_CLIENT_SECRET env var is not set");

        let params = [
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code", code),
        ];

        let client = self.get_client()?;

        let body = client
            .post("https://github.com/login/oauth/access_token")
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&params)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

        let token = serde_json::from_str::<AccessToken>(&body).map_err(|_| {
            Error::new("Failed to process auth response")
                .extend_with(|_, e| e.set("github_response", body))
        })?;

        let account_info = client
            .get("https://api.github.com/user")
            .bearer_auth(&token.access_token)
            .header(reqwest::header::ACCEPT, "application/vnd.github.v3+json")
            .send()
            .await?
            .error_for_status()?
            .json::<AccountInfo>()
            .await?;

        Ok(LoginResponse {
            token,
            account_info,
        })
    }

    async fn account_info(&self, access_token: String) -> Result<AccountInfo> {
        let client = self.get_client()?;

        let account_info = client
            .get("https://api.github.com/user")
            .bearer_auth(access_token)
            .header(reqwest::header::ACCEPT, "application/vnd.github.v3+json")
            .send()
            .await?
            .error_for_status()?
            .json::<AccountInfo>()
            .await?;

        Ok(account_info)
    }
}

#[derive(SimpleObject, Debug, Clone, Deserialize)]
pub(crate) struct LoginResponse {
    token: AccessToken,
    account_info: AccountInfo,
}

#[derive(SimpleObject, Debug, Clone, Deserialize)]
pub(crate) struct AccessToken {
    access_token: String,
    scope: String,
    token_type: String,
}

#[derive(Deserialize)]
pub struct AccessTokenError {
    error: String,
    error_description: Option<String>,
    error_uri: Option<String>,
}

#[derive(SimpleObject, Debug, Clone, Deserialize)]
pub(crate) struct AccountInfo {
    login: String,
    name: String,
    email: Option<String>,
    avatar_url: Option<String>,
    gravatar_id: Option<String>,
}
