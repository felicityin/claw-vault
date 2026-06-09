mod http;
mod mcp;
mod privy;
mod store;
mod tools;
mod validation;

use anyhow::Result;
use http::serve_http;
use mcp::McpServer;
use privy::PrivyClient;
use std::env;
use std::path::PathBuf;
use store::WalletStore;
use tools::ToolService;

#[tokio::main]
async fn main() -> Result<()> {
    let privy = PrivyClient::from_env()?;
    let store_path = env::var("VAULT_WALLET_STORE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("data/agent-wallets.json"));
    let store = WalletStore::load(store_path).await?;

    let service = ToolService::new(privy, store);

    match env::var("VAULT_TRANSPORT").as_deref() {
        Ok("http") => serve_http(service).await,
        _ => McpServer::new(service).serve_stdio().await,
    }
}
