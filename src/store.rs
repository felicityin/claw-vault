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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletPolicy {
    pub id: i64,
    pub user_id: String,
    pub agent_id: String,
    pub provider: String,
    pub provider_policy_id: String,
    pub name: String,
    pub chain_type: String,
    pub policy_json: serde_json::Value,
    pub status: String,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewWalletPolicy {
    pub user_id: String,
    pub agent_id: String,
    pub provider: String,
    pub provider_policy_id: String,
    pub name: String,
    pub chain_type: String,
    pub policy_json: serde_json::Value,
    pub status: String,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletPolicyRule {
    pub id: i64,
    pub policy_id: i64,
    pub user_id: String,
    pub agent_id: String,
    pub provider: String,
    pub provider_policy_id: String,
    pub provider_rule_id: Option<String>,
    pub rule_json: serde_json::Value,
    pub status: String,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewWalletPolicyRule {
    pub policy_id: i64,
    pub user_id: String,
    pub agent_id: String,
    pub provider: String,
    pub provider_policy_id: String,
    pub provider_rule_id: Option<String>,
    pub rule_json: serde_json::Value,
    pub status: String,
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

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS wallet_policies (
                id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                user_id VARCHAR(128) NOT NULL,
                agent_id VARCHAR(128) NOT NULL,
                provider VARCHAR(64) NOT NULL,
                provider_policy_id VARCHAR(191) NOT NULL,
                name VARCHAR(128) NOT NULL,
                chain_type VARCHAR(64) NOT NULL,
                policy_json JSON NOT NULL,
                status VARCHAR(32) NOT NULL,
                metadata JSON NOT NULL,
                created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                UNIQUE KEY uniq_provider_policy (provider, provider_policy_id),
                KEY idx_owner_agent (user_id, agent_id),
                KEY idx_status (status)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS wallet_policy_rules (
                id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                policy_id BIGINT NOT NULL,
                user_id VARCHAR(128) NOT NULL,
                agent_id VARCHAR(128) NOT NULL,
                provider VARCHAR(64) NOT NULL,
                provider_policy_id VARCHAR(191) NOT NULL,
                provider_rule_id VARCHAR(191) NULL,
                rule_json JSON NOT NULL,
                status VARCHAR(32) NOT NULL,
                metadata JSON NOT NULL,
                created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                KEY idx_policy (policy_id),
                KEY idx_owner_agent (user_id, agent_id),
                KEY idx_provider_rule (provider, provider_policy_id, provider_rule_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS wallet_policy_links (
                wallet_id BIGINT NOT NULL,
                policy_id BIGINT NOT NULL,
                user_id VARCHAR(128) NOT NULL,
                agent_id VARCHAR(128) NOT NULL,
                created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                PRIMARY KEY (wallet_id, policy_id),
                KEY idx_policy_id (policy_id),
                KEY idx_owner_agent (user_id, agent_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS policy_audit_logs (
                id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                user_id VARCHAR(128) NOT NULL,
                agent_id VARCHAR(128) NOT NULL,
                policy_id BIGINT NULL,
                rule_id BIGINT NULL,
                provider VARCHAR(64) NULL,
                provider_policy_id VARCHAR(191) NULL,
                provider_rule_id VARCHAR(191) NULL,
                action VARCHAR(64) NOT NULL,
                request_id VARCHAR(128) NULL,
                status VARCHAR(32) NOT NULL,
                error_message TEXT NULL,
                created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                KEY idx_user_agent_created (user_id, agent_id, created_at),
                KEY idx_policy_created (policy_id, created_at),
                KEY idx_rule_created (rule_id, created_at)
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

    pub async fn update_wallet_policy_ids(
        &self,
        wallet_id: i64,
        user_id: &str,
        agent_id: &str,
        policy_ids: &[String],
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE wallets
            SET policy_ids = ?
            WHERE id = ? AND user_id = ? AND agent_id = ?
            "#,
        )
        .bind(serde_json::to_string(policy_ids)?)
        .bind(wallet_id)
        .bind(user_id)
        .bind(agent_id)
        .execute(&self.pool)
        .await?;
        Ok(())
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

    pub async fn create_policy(&self, policy: NewWalletPolicy) -> Result<WalletPolicy> {
        let created_at = Utc::now();
        let result = sqlx::query(
            r#"
            INSERT INTO wallet_policies (
                user_id, agent_id, provider, provider_policy_id, name, chain_type,
                policy_json, status, metadata, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&policy.user_id)
        .bind(&policy.agent_id)
        .bind(&policy.provider)
        .bind(&policy.provider_policy_id)
        .bind(&policy.name)
        .bind(&policy.chain_type)
        .bind(serde_json::to_string(&policy.policy_json)?)
        .bind(&policy.status)
        .bind(serde_json::to_string(&policy.metadata)?)
        .bind(created_at.naive_utc())
        .execute(&self.pool)
        .await?;
        let id = i64::try_from(result.last_insert_id())
            .map_err(|_| anyhow!("policy id exceeds i64 range"))?;
        Ok(WalletPolicy {
            id,
            user_id: policy.user_id,
            agent_id: policy.agent_id,
            provider: policy.provider,
            provider_policy_id: policy.provider_policy_id,
            name: policy.name,
            chain_type: policy.chain_type,
            policy_json: policy.policy_json,
            status: policy.status,
            metadata: policy.metadata,
            created_at,
        })
    }

    pub async fn get_policy_for_agent(
        &self,
        policy_id: i64,
        user_id: &str,
        agent_id: &str,
    ) -> Result<Option<WalletPolicy>> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, agent_id, provider, provider_policy_id, name, chain_type,
                   policy_json, status, metadata, created_at
            FROM wallet_policies
            WHERE id = ? AND user_id = ? AND agent_id = ?
            "#,
        )
        .bind(policy_id)
        .bind(user_id)
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_policy).transpose()
    }

    pub async fn list_policies_for_agent(
        &self,
        user_id: &str,
        agent_id: &str,
    ) -> Result<Vec<WalletPolicy>> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, agent_id, provider, provider_policy_id, name, chain_type,
                   policy_json, status, metadata, created_at
            FROM wallet_policies
            WHERE user_id = ? AND agent_id = ?
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_policy).collect()
    }

    pub async fn update_policy_for_agent(
        &self,
        policy_id: i64,
        user_id: &str,
        agent_id: &str,
        name: &str,
        chain_type: &str,
        policy_json: &serde_json::Value,
        status: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE wallet_policies
            SET name = ?, chain_type = ?, policy_json = ?, status = ?
            WHERE id = ? AND user_id = ? AND agent_id = ?
            "#,
        )
        .bind(name)
        .bind(chain_type)
        .bind(serde_json::to_string(policy_json)?)
        .bind(status)
        .bind(policy_id)
        .bind(user_id)
        .bind(agent_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_policy_for_agent(
        &self,
        policy_id: i64,
        user_id: &str,
        agent_id: &str,
    ) -> Result<()> {
        sqlx::query(
            "DELETE FROM wallet_policy_links WHERE policy_id = ? AND user_id = ? AND agent_id = ?",
        )
        .bind(policy_id)
        .bind(user_id)
        .bind(agent_id)
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "DELETE FROM wallet_policy_rules WHERE policy_id = ? AND user_id = ? AND agent_id = ?",
        )
        .bind(policy_id)
        .bind(user_id)
        .bind(agent_id)
        .execute(&self.pool)
        .await?;
        sqlx::query("DELETE FROM wallet_policies WHERE id = ? AND user_id = ? AND agent_id = ?")
            .bind(policy_id)
            .bind(user_id)
            .bind(agent_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn create_policy_rule(&self, rule: NewWalletPolicyRule) -> Result<WalletPolicyRule> {
        let created_at = Utc::now();
        let result = sqlx::query(
            r#"
            INSERT INTO wallet_policy_rules (
                policy_id, user_id, agent_id, provider, provider_policy_id, provider_rule_id,
                rule_json, status, metadata, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(rule.policy_id)
        .bind(&rule.user_id)
        .bind(&rule.agent_id)
        .bind(&rule.provider)
        .bind(&rule.provider_policy_id)
        .bind(&rule.provider_rule_id)
        .bind(serde_json::to_string(&rule.rule_json)?)
        .bind(&rule.status)
        .bind(serde_json::to_string(&rule.metadata)?)
        .bind(created_at.naive_utc())
        .execute(&self.pool)
        .await?;
        let id = i64::try_from(result.last_insert_id())
            .map_err(|_| anyhow!("rule id exceeds i64 range"))?;
        Ok(WalletPolicyRule {
            id,
            policy_id: rule.policy_id,
            user_id: rule.user_id,
            agent_id: rule.agent_id,
            provider: rule.provider,
            provider_policy_id: rule.provider_policy_id,
            provider_rule_id: rule.provider_rule_id,
            rule_json: rule.rule_json,
            status: rule.status,
            metadata: rule.metadata,
            created_at,
        })
    }

    pub async fn get_policy_rule_for_agent(
        &self,
        rule_id: i64,
        policy_id: i64,
        user_id: &str,
        agent_id: &str,
    ) -> Result<Option<WalletPolicyRule>> {
        let row = sqlx::query(
            r#"
            SELECT id, policy_id, user_id, agent_id, provider, provider_policy_id,
                   provider_rule_id, rule_json, status, metadata, created_at
            FROM wallet_policy_rules
            WHERE id = ? AND policy_id = ? AND user_id = ? AND agent_id = ?
            "#,
        )
        .bind(rule_id)
        .bind(policy_id)
        .bind(user_id)
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_policy_rule).transpose()
    }

    pub async fn list_policy_rules_for_agent(
        &self,
        policy_id: i64,
        user_id: &str,
        agent_id: &str,
    ) -> Result<Vec<WalletPolicyRule>> {
        let rows = sqlx::query(
            r#"
            SELECT id, policy_id, user_id, agent_id, provider, provider_policy_id,
                   provider_rule_id, rule_json, status, metadata, created_at
            FROM wallet_policy_rules
            WHERE policy_id = ? AND user_id = ? AND agent_id = ?
            ORDER BY created_at DESC
            "#,
        )
        .bind(policy_id)
        .bind(user_id)
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_policy_rule).collect()
    }

    pub async fn update_policy_rule_for_agent(
        &self,
        rule_id: i64,
        policy_id: i64,
        user_id: &str,
        agent_id: &str,
        provider_rule_id: Option<&str>,
        rule_json: &serde_json::Value,
        status: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE wallet_policy_rules
            SET provider_rule_id = ?, rule_json = ?, status = ?
            WHERE id = ? AND policy_id = ? AND user_id = ? AND agent_id = ?
            "#,
        )
        .bind(provider_rule_id)
        .bind(serde_json::to_string(rule_json)?)
        .bind(status)
        .bind(rule_id)
        .bind(policy_id)
        .bind(user_id)
        .bind(agent_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_policy_rule_for_agent(
        &self,
        rule_id: i64,
        policy_id: i64,
        user_id: &str,
        agent_id: &str,
    ) -> Result<()> {
        sqlx::query(
            "DELETE FROM wallet_policy_rules WHERE id = ? AND policy_id = ? AND user_id = ? AND agent_id = ?",
        )
        .bind(rule_id)
        .bind(policy_id)
        .bind(user_id)
        .bind(agent_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn attach_policy_to_wallet(
        &self,
        wallet_id: i64,
        policy_id: i64,
        user_id: &str,
        agent_id: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT IGNORE INTO wallet_policy_links (wallet_id, policy_id, user_id, agent_id)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(wallet_id)
        .bind(policy_id)
        .bind(user_id)
        .bind(agent_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn detach_policy_from_wallet(
        &self,
        wallet_id: i64,
        policy_id: i64,
        user_id: &str,
        agent_id: &str,
    ) -> Result<()> {
        sqlx::query(
            "DELETE FROM wallet_policy_links WHERE wallet_id = ? AND policy_id = ? AND user_id = ? AND agent_id = ?",
        )
        .bind(wallet_id)
        .bind(policy_id)
        .bind(user_id)
        .bind(agent_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_wallet_policies(
        &self,
        wallet_id: i64,
        user_id: &str,
        agent_id: &str,
    ) -> Result<Vec<WalletPolicy>> {
        let rows = sqlx::query(
            r#"
            SELECT p.id, p.user_id, p.agent_id, p.provider, p.provider_policy_id, p.name,
                   p.chain_type, p.policy_json, p.status, p.metadata, p.created_at
            FROM wallet_policy_links l
            JOIN wallet_policies p ON p.id = l.policy_id
            WHERE l.wallet_id = ? AND l.user_id = ? AND l.agent_id = ?
            ORDER BY l.created_at DESC
            "#,
        )
        .bind(wallet_id)
        .bind(user_id)
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_policy).collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record_policy_audit(
        &self,
        user_id: &str,
        agent_id: &str,
        policy: Option<&WalletPolicy>,
        rule: Option<&WalletPolicyRule>,
        action: &str,
        request_id: Option<&str>,
        status: &str,
        error_message: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO policy_audit_logs (
                user_id, agent_id, policy_id, rule_id, provider, provider_policy_id,
                provider_rule_id, action, request_id, status, error_message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(user_id)
        .bind(agent_id)
        .bind(
            policy
                .map(|policy| policy.id)
                .or_else(|| rule.map(|rule| rule.policy_id)),
        )
        .bind(rule.map(|rule| rule.id))
        .bind(
            policy
                .map(|policy| policy.provider.as_str())
                .or_else(|| rule.map(|rule| rule.provider.as_str())),
        )
        .bind(
            policy
                .map(|policy| policy.provider_policy_id.as_str())
                .or_else(|| rule.map(|rule| rule.provider_policy_id.as_str())),
        )
        .bind(rule.and_then(|rule| rule.provider_rule_id.as_deref()))
        .bind(action)
        .bind(request_id)
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

fn row_to_policy(row: MySqlRow) -> Result<WalletPolicy> {
    let policy_json: String = row.try_get("policy_json")?;
    let metadata: String = row.try_get("metadata")?;
    let created_at: chrono::NaiveDateTime = row.try_get("created_at")?;

    Ok(WalletPolicy {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        agent_id: row.try_get("agent_id")?,
        provider: row.try_get("provider")?,
        provider_policy_id: row.try_get("provider_policy_id")?,
        name: row.try_get("name")?,
        chain_type: row.try_get("chain_type")?,
        policy_json: serde_json::from_str(&policy_json)?,
        status: row.try_get("status")?,
        metadata: serde_json::from_str(&metadata)?,
        created_at: DateTime::<Utc>::from_naive_utc_and_offset(created_at, Utc),
    })
}

fn row_to_policy_rule(row: MySqlRow) -> Result<WalletPolicyRule> {
    let rule_json: String = row.try_get("rule_json")?;
    let metadata: String = row.try_get("metadata")?;
    let created_at: chrono::NaiveDateTime = row.try_get("created_at")?;

    Ok(WalletPolicyRule {
        id: row.try_get("id")?,
        policy_id: row.try_get("policy_id")?,
        user_id: row.try_get("user_id")?,
        agent_id: row.try_get("agent_id")?,
        provider: row.try_get("provider")?,
        provider_policy_id: row.try_get("provider_policy_id")?,
        provider_rule_id: row.try_get("provider_rule_id")?,
        rule_json: serde_json::from_str(&rule_json)?,
        status: row.try_get("status")?,
        metadata: serde_json::from_str(&metadata)?,
        created_at: DateTime::<Utc>::from_naive_utc_and_offset(created_at, Utc),
    })
}
