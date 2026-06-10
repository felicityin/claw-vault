mod auth;
mod http;
mod mcp;
mod privy;
mod store;
mod tools;
mod validation;

use std::env;

use anyhow::Result;
use http::serve_http;
use mcp::McpServer;
use privy::PrivyClient;
use store::WalletStore;
use tools::ToolService;

#[tokio::main]
async fn main() -> Result<()> {
    let privy = PrivyClient::from_env()?;
    let database_url = env::var("VAULT_DATABASE_URL")?;
    let store = WalletStore::connect(&database_url).await?;

    let service = ToolService::new(privy, store);

    match env::var("VAULT_TRANSPORT").as_deref() {
        Ok("http") => serve_http(service).await,
        _ => McpServer::new(service).serve_stdio().await,
    }
}
