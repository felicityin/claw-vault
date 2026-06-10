use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use sqlx::mysql::{MySqlPool, MySqlPoolOptions, MySqlRow};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wallet {
    pub id: i64,
    pub user_id: String,
    pub agent_id: String,
    pub provider: String,
    pub provider_wallet_id: String,
    pub address: String,
    pub chain_type: String,
    pub policy_ids: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct NewWallet {
    pub user_id: String,
    pub agent_id: String,
    pub provider: String,
    pub provider_wallet_id: String,
    pub address: String,
    pub chain_type: String,
    pub policy_ids: Vec<String>,
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
            CREATE TABLE IF NOT EXISTS wallets (
                id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                user_id VARCHAR(128) NOT NULL,
                agent_id VARCHAR(128) NOT NULL,
                provider VARCHAR(64) NOT NULL,
                provider_wallet_id VARCHAR(191) NOT NULL,
                address VARCHAR(191) NOT NULL,
                chain_type VARCHAR(64) NOT NULL,
                policy_ids JSON NOT NULL,
                metadata JSON NOT NULL,
                created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                UNIQUE KEY uniq_provider_wallet (provider, provider_wallet_id),
                KEY idx_owner (user_id, agent_id),
                KEY idx_owner_provider_wallet (user_id, agent_id, provider, provider_wallet_id),
                KEY idx_chain_type (chain_type)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS wallet_audit_logs (
                id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                user_id VARCHAR(128) NOT NULL,
                agent_id VARCHAR(128) NOT NULL,
                wallet_id BIGINT NULL,
                provider VARCHAR(64) NULL,
                provider_wallet_id VARCHAR(191) NULL,
                action VARCHAR(64) NOT NULL,
                request_id VARCHAR(128) NULL,
                params_hash VARCHAR(128) NULL,
                transaction_id VARCHAR(191) NULL,
                status VARCHAR(32) NOT NULL,
                error_message TEXT NULL,
                created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                KEY idx_user_agent_created (user_id, agent_id, created_at),
                KEY idx_wallet_created (wallet_id, created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            "#,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn insert(&self, wallet: NewWallet) -> Result<Wallet> {
        let created_at = Utc::now();
        let result = sqlx::query(
            r#"
            INSERT INTO wallets (
                user_id, agent_id, provider, provider_wallet_id, address, chain_type,
                policy_ids, metadata, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&wallet.user_id)
        .bind(&wallet.agent_id)
        .bind(&wallet.provider)
        .bind(&wallet.provider_wallet_id)
        .bind(&wallet.address)
        .bind(&wallet.chain_type)
        .bind(serde_json::to_string(&wallet.policy_ids)?)
        .bind(serde_json::to_string(&wallet.metadata)?)
        .bind(created_at.naive_utc())
        .execute(&self.pool)
        .await?;

        let id = i64::try_from(result.last_insert_id())
            .map_err(|_| anyhow!("wallet id exceeds i64 range"))?;
        Ok(Wallet {
            id,
            user_id: wallet.user_id,
            agent_id: wallet.agent_id,
            provider: wallet.provider,
            provider_wallet_id: wallet.provider_wallet_id,
            address: wallet.address,
            chain_type: wallet.chain_type,
            policy_ids: wallet.policy_ids,
            created_at,
            metadata: wallet.metadata,
        })
    }

    pub async fn get_by_id_for_agent(
        &self,
        wallet_id: i64,
        user_id: &str,
        agent_id: &str,
    ) -> Result<Option<Wallet>> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, agent_id, provider, provider_wallet_id, address, chain_type,
                   policy_ids, metadata, created_at
            FROM wallets
            WHERE id = ? AND user_id = ? AND agent_id = ?
            "#,
        )
        .bind(wallet_id)
        .bind(user_id)
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(row_to_wallet).transpose()
    }

    #[allow(dead_code)]
    pub async fn get_by_provider_wallet_for_agent(
        &self,
        user_id: &str,
        agent_id: &str,
        provider: &str,
        provider_wallet_id: &str,
    ) -> Result<Option<Wallet>> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, agent_id, provider, provider_wallet_id, address, chain_type,
                   policy_ids, metadata, created_at
            FROM wallets
            WHERE user_id = ? AND agent_id = ? AND provider = ? AND provider_wallet_id = ?
            "#,
        )
        .bind(user_id)
        .bind(agent_id)
        .bind(provider)
        .bind(provider_wallet_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(row_to_wallet).transpose()
    }

    pub async fn list_for_agent(&self, user_id: &str, agent_id: &str) -> Result<Vec<Wallet>> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, agent_id, provider, provider_wallet_id, address, chain_type,
                   policy_ids, metadata, created_at
            FROM wallets
            WHERE user_id = ? AND agent_id = ?
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_wallet).collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record_audit(
        &self,
        user_id: &str,
        agent_id: &str,
        wallet: Option<&Wallet>,
        action: &str,
        request_id: Option<&str>,
        status: &str,
        error_message: Option<&str>,
        transaction_id: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO wallet_audit_logs (
                user_id, agent_id, wallet_id, provider, provider_wallet_id, action,
                request_id, params_hash, transaction_id, status, error_message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)
            "#,
        )
        .bind(user_id)
        .bind(agent_id)
        .bind(wallet.map(|wallet| wallet.id))
        .bind(wallet.map(|wallet| wallet.provider.as_str()))
        .bind(wallet.map(|wallet| wallet.provider_wallet_id.as_str()))
        .bind(action)
        .bind(request_id)
        .bind(transaction_id)
        .bind(status)
        .bind(error_message)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

fn row_to_wallet(row: MySqlRow) -> Result<Wallet> {
    let policy_ids: String = row.try_get("policy_ids")?;
    let metadata: String = row.try_get("metadata")?;
    let created_at: chrono::NaiveDateTime = row.try_get("created_at")?;

    Ok(Wallet {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        agent_id: row.try_get("agent_id")?,
        provider: row.try_get("provider")?,
        provider_wallet_id: row.try_get("provider_wallet_id")?,
        address: row.try_get("address")?,
        chain_type: row.try_get("chain_type")?,
        policy_ids: serde_json::from_str(&policy_ids)?,
        metadata: serde_json::from_str(&metadata)?,
        created_at: DateTime::<Utc>::from_naive_utc_and_offset(created_at, Utc),
    })
}
