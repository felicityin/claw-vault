use crate::privy::PrivyClient;
use crate::store::{AgentWallet, WalletStore};
use crate::validation::{
    chain_id_from_caip2, validate_agent_id, validate_allowed_caip2, validate_evm_address,
    validate_hex_data, validate_wei_decimal, wei_decimal_to_hex,
};
use anyhow::{Result, anyhow};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use std::env;

pub struct ToolService {
    privy: PrivyClient,
    store: WalletStore,
}

impl ToolService {
    pub fn new(privy: PrivyClient, store: WalletStore) -> Self {
        Self { privy, store }
    }

    pub fn tool_definitions(&self) -> Vec<Value> {
        vec![
            json!({
                "name": "create_agent_wallet",
                "description": "Create a policy-bound Privy wallet for a Clawup agent. A wallet is never created without an attached policy.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "agent_id": {"type": "string"},
                        "chain_type": {"type": "string", "enum": ["ethereum"], "default": "ethereum"},
                        "policy_id": {"type": "string", "description": "Existing Privy policy ID. If omitted, a default policy is created."},
                        "max_wei_per_transaction": {"type": "string", "description": "Decimal wei limit for the default policy."},
                        "caip2": {"type": "string", "description": "Allowed EVM CAIP-2 chain for the default policy, e.g. eip155:8453."}
                    },
                    "required": ["agent_id"]
                }
            }),
            json!({
                "name": "get_agent_wallet",
                "description": "Return the wallet binding for a Clawup agent and fetch current wallet details from Privy.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"agent_id": {"type": "string"}},
                    "required": ["agent_id"]
                }
            }),
            json!({
                "name": "list_agent_wallets",
                "description": "List locally registered Clawup agent wallet bindings.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"chain_type": {"type": "string", "enum": ["ethereum"]}},
                    "required": []
                }
            }),
            json!({
                "name": "get_agent_wallet_balance",
                "description": "Get a wallet balance through Privy for a bound Clawup agent.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "agent_id": {"type": "string"},
                        "asset": {"type": "string", "enum": ["eth", "usdc"]},
                        "chain": {"type": "string", "enum": ["ethereum", "arbitrum", "base", "linea", "optimism", "zksync_era"]}
                    },
                    "required": ["agent_id", "asset", "chain"]
                }
            }),
            json!({
                "name": "send_agent_transaction",
                "description": "Send an EVM transaction from a bound Clawup agent wallet. The CAIP-2 chain must be allowlisted and the wallet must have an attached Privy policy.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "agent_id": {"type": "string"},
                        "caip2": {"type": "string"},
                        "to": {"type": "string"},
                        "value_wei": {"type": "string", "default": "0"},
                        "data": {"type": "string", "default": "0x"},
                        "sponsor": {"type": "boolean", "default": false}
                    },
                    "required": ["agent_id", "caip2", "to"]
                }
            }),
            json!({
                "name": "sign_agent_message",
                "description": "Sign a message with a bound Clawup agent EVM wallet using personal_sign.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "agent_id": {"type": "string"},
                        "message": {"type": "string"},
                        "encoding": {"type": "string", "enum": ["utf-8", "hex"], "default": "utf-8"}
                    },
                    "required": ["agent_id", "message"]
                }
            }),
            json!({
                "name": "get_agent_transaction",
                "description": "Get a Privy transaction by transaction ID.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"transaction_id": {"type": "string"}},
                    "required": ["transaction_id"]
                }
            }),
        ]
    }

    pub async fn call_tool(&self, params: Value) -> Result<Value> {
        let call: ToolCall = serde_json::from_value(params)?;
        match call.name.as_str() {
            "create_agent_wallet" => self.create_agent_wallet(call.arguments).await,
            "get_agent_wallet" => self.get_agent_wallet(call.arguments).await,
            "list_agent_wallets" => self.list_agent_wallets(call.arguments).await,
            "get_agent_wallet_balance" => self.get_agent_wallet_balance(call.arguments).await,
            "send_agent_transaction" => self.send_agent_transaction(call.arguments).await,
            "sign_agent_message" => self.sign_agent_message(call.arguments).await,
            "get_agent_transaction" => self.get_agent_transaction(call.arguments).await,
            other => Err(anyhow!("unknown tool: {other}")),
        }
    }

    async fn create_agent_wallet(&self, args: Value) -> Result<Value> {
        let args: CreateAgentWalletArgs = serde_json::from_value(args)?;
        validate_agent_id(&args.agent_id)?;
        if self.store.get(&args.agent_id).await.is_some() {
            return Err(anyhow!("agent_id already has a wallet binding"));
        }

        let chain_type = args.chain_type.unwrap_or_else(|| "ethereum".to_string());
        if chain_type != "ethereum" {
            return Err(anyhow!("only ethereum chain_type is supported in this MVP"));
        }

        let policy_ids = if let Some(policy_id) = args.policy_id {
            vec![policy_id]
        } else {
            let caip2 = args.caip2.unwrap_or_else(|| "eip155:8453".to_string());
            validate_allowed_caip2(&caip2)?;
            let chain_id = chain_id_from_caip2(&caip2)?;
            let max_wei = args
                .max_wei_per_transaction
                .or_else(|| env::var("VAULT_DEFAULT_MAX_WEI").ok())
                .unwrap_or_else(|| "50000000000000000".to_string());
            validate_wei_decimal(&max_wei)?;
            let policy = self
                .privy
                .create_policy(default_policy(&args.agent_id, &chain_id, &max_wei))
                .await?;
            vec![extract_string(&policy, &["id", "policy_id"])?]
        };

        if policy_ids.is_empty() {
            return Err(anyhow!("policy_ids must not be empty"));
        }

        let wallet = self.privy.create_wallet(&chain_type, &policy_ids).await?;
        let wallet_id = extract_string(&wallet, &["id", "wallet_id"])?;
        let address = extract_string(&wallet, &["address"])?;
        let binding = AgentWallet {
            agent_id: args.agent_id,
            wallet_id,
            address,
            chain_type,
            policy_ids,
            created_at: Utc::now(),
            metadata: json!({}),
        };
        self.store.insert(binding.clone()).await?;

        tool_result(json!({
            "agent_wallet": binding,
            "privy_wallet": wallet
        }))
    }

    async fn get_agent_wallet(&self, args: Value) -> Result<Value> {
        let args: AgentIdArgs = serde_json::from_value(args)?;
        let binding = self.require_wallet(&args.agent_id).await?;
        let privy_wallet = self.privy.get_wallet(&binding.wallet_id).await?;
        tool_result(json!({
            "agent_wallet": binding,
            "privy_wallet": privy_wallet
        }))
    }

    async fn list_agent_wallets(&self, args: Value) -> Result<Value> {
        let args: ListAgentWalletsArgs = serde_json::from_value(args)?;
        let mut wallets = self.store.list().await;
        if let Some(chain_type) = args.chain_type {
            wallets.retain(|wallet| wallet.chain_type == chain_type);
        }
        tool_result(json!({ "wallets": wallets }))
    }

    async fn get_agent_wallet_balance(&self, args: Value) -> Result<Value> {
        let args: BalanceArgs = serde_json::from_value(args)?;
        let binding = self.require_wallet(&args.agent_id).await?;
        let balance = self
            .privy
            .get_balance(&binding.wallet_id, &args.asset, &args.chain)
            .await?;
        tool_result(json!({
            "agent_wallet": binding,
            "balance": balance
        }))
    }

    async fn send_agent_transaction(&self, args: Value) -> Result<Value> {
        let args: SendTransactionArgs = serde_json::from_value(args)?;
        validate_allowed_caip2(&args.caip2)?;
        let chain_id = chain_id_from_caip2(&args.caip2)?;
        validate_evm_address(&args.to)?;
        let value_wei = args.value_wei.unwrap_or_else(|| "0".to_string());
        validate_wei_decimal(&value_wei)?;
        let data = args.data.unwrap_or_else(|| "0x".to_string());
        validate_hex_data(&data)?;

        let binding = self.require_wallet(&args.agent_id).await?;
        if binding.policy_ids.is_empty() {
            return Err(anyhow!(
                "wallet binding has no policy_ids; refusing transaction"
            ));
        }

        let tx = json!({
            "method": "eth_sendTransaction",
            "caip2": args.caip2,
            "chain_type": "ethereum",
            "params": {
                "transaction": {
                    "to": args.to,
                    "value": wei_decimal_to_hex(&value_wei)?,
                    "data": data,
                    "chain_id": chain_id
                }
            },
            "sponsor": args.sponsor.unwrap_or(false)
        });

        let response = self.privy.wallet_rpc(&binding.wallet_id, tx).await?;
        tool_result(json!({
            "agent_wallet": binding,
            "transaction": response
        }))
    }

    async fn sign_agent_message(&self, args: Value) -> Result<Value> {
        let args: SignMessageArgs = serde_json::from_value(args)?;
        let binding = self.require_wallet(&args.agent_id).await?;
        let encoding = args.encoding.unwrap_or_else(|| "utf-8".to_string());
        if encoding == "hex" {
            validate_hex_data(&args.message)?;
        } else if encoding != "utf-8" {
            return Err(anyhow!("encoding must be utf-8 or hex"));
        }

        let response = self
            .privy
            .wallet_rpc(
                &binding.wallet_id,
                json!({
                    "method": "personal_sign",
                    "params": {
                        "message": args.message,
                        "encoding": encoding
                    }
                }),
            )
            .await?;
        tool_result(json!({
            "agent_wallet": binding,
            "signature": response
        }))
    }

    async fn get_agent_transaction(&self, args: Value) -> Result<Value> {
        let args: TransactionArgs = serde_json::from_value(args)?;
        if args.transaction_id.trim().is_empty() {
            return Err(anyhow!("transaction_id is required"));
        }
        let transaction = self.privy.get_transaction(&args.transaction_id).await?;
        tool_result(json!({ "transaction": transaction }))
    }

    async fn require_wallet(&self, agent_id: &str) -> Result<AgentWallet> {
        validate_agent_id(agent_id)?;
        self.store
            .get(agent_id)
            .await
            .ok_or_else(|| anyhow!("no wallet binding found for agent_id"))
    }
}

#[derive(Debug, Deserialize)]
struct ToolCall {
    name: String,
    #[serde(default)]
    arguments: Value,
}

#[derive(Debug, Deserialize)]
struct CreateAgentWalletArgs {
    agent_id: String,
    chain_type: Option<String>,
    policy_id: Option<String>,
    max_wei_per_transaction: Option<String>,
    caip2: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AgentIdArgs {
    agent_id: String,
}

#[derive(Debug, Deserialize)]
struct ListAgentWalletsArgs {
    chain_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BalanceArgs {
    agent_id: String,
    asset: String,
    chain: String,
}

#[derive(Debug, Deserialize)]
struct SendTransactionArgs {
    agent_id: String,
    caip2: String,
    to: String,
    value_wei: Option<String>,
    data: Option<String>,
    sponsor: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct SignMessageArgs {
    agent_id: String,
    message: String,
    encoding: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TransactionArgs {
    transaction_id: String,
}

fn default_policy(agent_id: &str, chain_id: &str, max_wei: &str) -> Value {
    json!({
        "version": "1.0",
        "name": format!("clawup-{agent_id}"),
        "chain_type": "ethereum",
        "rules": [
            {
                "name": "max wei per transaction",
                "method": "eth_sendTransaction",
                "conditions": [{
                    "field_source": "ethereum_transaction",
                    "field": "value",
                    "operator": "lte",
                    "value": max_wei
                }],
                "action": "ALLOW"
            },
            {
                "name": "allowed chain",
                "method": "eth_sendTransaction",
                "conditions": [{
                    "field_source": "ethereum_transaction",
                    "field": "chain_id",
                    "operator": "eq",
                    "value": chain_id
                }],
                "action": "ALLOW"
            }
        ]
    })
}

fn extract_string(value: &Value, keys: &[&str]) -> Result<String> {
    for key in keys {
        if let Some(found) = value.get(*key).and_then(Value::as_str) {
            return Ok(found.to_string());
        }
    }
    Err(anyhow!(
        "Privy response is missing one of: {}",
        keys.join(", ")
    ))
}

fn tool_result(value: Value) -> Result<Value> {
    Ok(json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string_pretty(&value)?
        }]
    }))
}
