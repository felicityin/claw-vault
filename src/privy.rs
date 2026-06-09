use anyhow::{Result, anyhow};
use base64::Engine;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde_json::Value;
use std::env;

#[derive(Clone)]
pub struct PrivyClient {
    http: reqwest::Client,
    base_url: String,
    app_id: String,
    app_secret: String,
}

impl PrivyClient {
    pub fn from_env() -> Result<Self> {
        let app_id = env::var("PRIVY_APP_ID").map_err(|_| anyhow!("PRIVY_APP_ID is required"))?;
        let app_secret =
            env::var("PRIVY_APP_SECRET").map_err(|_| anyhow!("PRIVY_APP_SECRET is required"))?;
        let base_url =
            env::var("PRIVY_API_BASE_URL").unwrap_or_else(|_| "https://api.privy.io/v1".into());

        Ok(Self {
            http: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            app_id,
            app_secret,
        })
    }

    pub async fn create_policy(&self, body: Value) -> Result<Value> {
        self.request(reqwest::Method::POST, "/policies", Some(body))
            .await
    }

    pub async fn create_wallet(&self, chain_type: &str, policy_ids: &[String]) -> Result<Value> {
        self.request(
            reqwest::Method::POST,
            "/wallets",
            Some(serde_json::json!({
                "chain_type": chain_type,
                "policy_ids": policy_ids
            })),
        )
        .await
    }

    pub async fn get_wallet(&self, wallet_id: &str) -> Result<Value> {
        self.request(reqwest::Method::GET, &format!("/wallets/{wallet_id}"), None)
            .await
    }

    pub async fn get_balance(&self, wallet_id: &str, asset: &str, chain: &str) -> Result<Value> {
        self.request(
            reqwest::Method::GET,
            &format!(
                "/wallets/{wallet_id}/balance?asset={asset}&chain={chain}&include_currency=usd"
            ),
            None,
        )
        .await
    }

    pub async fn wallet_rpc(&self, wallet_id: &str, body: Value) -> Result<Value> {
        self.request(
            reqwest::Method::POST,
            &format!("/wallets/{wallet_id}/rpc"),
            Some(body),
        )
        .await
    }

    pub async fn get_transaction(&self, transaction_id: &str) -> Result<Value> {
        self.request(
            reqwest::Method::GET,
            &format!("/transactions/{transaction_id}"),
            None,
        )
        .await
    }

    async fn request(
        &self,
        method: reqwest::Method,
        endpoint: &str,
        body: Option<Value>,
    ) -> Result<Value> {
        let url = format!("{}{}", self.base_url, endpoint);
        let mut request = self.http.request(method, url).headers(self.headers()?);
        if let Some(body) = body {
            request = request.json(&body);
        }

        let response = request.send().await?;
        let status = response.status();
        let text = response.text().await?;
        if !status.is_success() {
            return Err(anyhow!("Privy API error {status}: {text}"));
        }

        if text.trim().is_empty() {
            Ok(serde_json::json!({}))
        } else {
            Ok(serde_json::from_str(&text)?)
        }
    }

    fn headers(&self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        let auth = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", self.app_id, self.app_secret));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {auth}"))?,
        );
        headers.insert("privy-app-id", HeaderValue::from_str(&self.app_id)?);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        Ok(headers)
    }
}
