use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentWallet {
    pub agent_id: String,
    pub wallet_id: String,
    pub address: String,
    pub chain_type: String,
    pub policy_ids: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoreData {
    wallets: BTreeMap<String, AgentWallet>,
}

pub struct WalletStore {
    path: PathBuf,
    data: Mutex<StoreData>,
}

impl WalletStore {
    pub async fn load(path: PathBuf) -> Result<Self> {
        let data = if tokio::fs::try_exists(&path).await? {
            let bytes = tokio::fs::read(&path).await?;
            serde_json::from_slice(&bytes)?
        } else {
            StoreData::default()
        };

        Ok(Self {
            path,
            data: Mutex::new(data),
        })
    }

    pub async fn get(&self, agent_id: &str) -> Option<AgentWallet> {
        self.data.lock().await.wallets.get(agent_id).cloned()
    }

    pub async fn list(&self) -> Vec<AgentWallet> {
        self.data.lock().await.wallets.values().cloned().collect()
    }

    pub async fn insert(&self, wallet: AgentWallet) -> Result<()> {
        let snapshot = {
            let mut data = self.data.lock().await;
            data.wallets.insert(wallet.agent_id.clone(), wallet);
            serde_json::to_vec_pretty(&*data)?
        };
        write_atomic(&self.path, &snapshot).await
    }
}

async fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let tmp = path.with_extension("tmp");
    tokio::fs::write(&tmp, bytes).await?;
    tokio::fs::rename(tmp, path).await?;
    Ok(())
}
