use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use sqlx::mysql::{MySqlPool, MySqlPoolOptions};

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

#[derive(Clone)]
pub struct WalletStore {
    pool: MySqlPool,
}

impl WalletStore {
    pub async fn connect(database_url: &str) -> Result<Self> {
        let max_connections = std::env::var("VAULT_DB_MAX_CONNECTIONS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(5);

        let pool = MySqlPoolOptions::new()
            .max_connections(max_connections)
            .connect(database_url)
            .await?;
        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    async fn migrate(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS agent_wallets (
                agent_id VARCHAR(128) NOT NULL PRIMARY KEY,
                wallet_id VARCHAR(191) NOT NULL,
                address VARCHAR(191) NOT NULL,
                chain_type VARCHAR(64) NOT NULL,
                policy_ids JSON NOT NULL,
                metadata JSON NOT NULL,
                created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                UNIQUE KEY uniq_wallet_id (wallet_id),
                KEY idx_chain_type (chain_type)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            "#,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get(&self, agent_id: &str) -> Result<Option<AgentWallet>> {
        let row = sqlx::query(
            r#"
            SELECT agent_id, wallet_id, address, chain_type, policy_ids, metadata, created_at
            FROM agent_wallets
            WHERE agent_id = ?
            "#,
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(row_to_wallet).transpose()
    }

    pub async fn list(&self) -> Result<Vec<AgentWallet>> {
        let rows = sqlx::query(
            r#"
            SELECT agent_id, wallet_id, address, chain_type, policy_ids, metadata, created_at
            FROM agent_wallets
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_wallet).collect()
    }

    pub async fn insert(&self, wallet: AgentWallet) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO agent_wallets (
                agent_id, wallet_id, address, chain_type, policy_ids, metadata, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&wallet.agent_id)
        .bind(&wallet.wallet_id)
        .bind(&wallet.address)
        .bind(&wallet.chain_type)
        .bind(serde_json::to_string(&wallet.policy_ids)?)
        .bind(serde_json::to_string(&wallet.metadata)?)
        .bind(wallet.created_at.naive_utc())
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

fn row_to_wallet(row: sqlx::mysql::MySqlRow) -> Result<AgentWallet> {
    let policy_ids: String = row.try_get("policy_ids")?;
    let metadata: String = row.try_get("metadata")?;
    let created_at: chrono::NaiveDateTime = row.try_get("created_at")?;

    Ok(AgentWallet {
        agent_id: row.try_get("agent_id")?,
        wallet_id: row.try_get("wallet_id")?,
        address: row.try_get("address")?,
        chain_type: row.try_get("chain_type")?,
        policy_ids: serde_json::from_str(&policy_ids)?,
        metadata: serde_json::from_str(&metadata)?,
        created_at: DateTime::<Utc>::from_naive_utc_and_offset(created_at, Utc),
    })
}
