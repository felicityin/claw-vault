use std::env;

use anyhow::{Result, anyhow};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::auth::RequestContext;
use crate::privy::PrivyClient;
use crate::store::{NewWallet, Wallet, WalletStore};
use crate::validation::{
    chain_id_from_caip2, native_units_decimal_to_hex, validate_allowed_caip2, validate_evm_address,
    validate_hex_data, validate_native_units_decimal,
};

const PRIVY_PROVIDER: &str = "privy";

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
                "description": "Create a policy-bound Privy wallet for the authenticated Clawup agent. User and agent identity come from the request JWT/context.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "policy_template": {
                            "type": "string",
                            "enum": ["base-small-spend"],
                            "default": "base-small-spend"
                        },
                        "label": {"type": "string"}
                    },
                    "required": []
                }
            }),
            json!({
                "name": "list_agent_wallets",
                "description": "List wallets owned by the authenticated user and agent.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "provider": {"type": "string", "enum": ["privy"]},
                        "chain_type": {"type": "string", "enum": ["ethereum"]}
                    },
                    "required": []
                }
            }),
            json!({
                "name": "get_agent_wallet",
                "description": "Return a wallet owned by the authenticated user and agent.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"wallet_id": {"type": "integer"}},
                    "required": ["wallet_id"]
                }
            }),
            json!({
                "name": "get_agent_wallet_balance",
                "description": "Get balance for a wallet owned by the authenticated user and agent.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "wallet_id": {"type": "integer"},
                        "asset": {"type": "string", "enum": ["eth", "usdc"]},
                        "chain": {"type": "string", "enum": ["ethereum", "arbitrum", "base", "linea", "optimism", "zksync_era"]}
                    },
                    "required": ["wallet_id", "asset", "chain"]
                }
            }),
            json!({
                "name": "send_agent_transaction",
                "description": "Send an EVM transaction from a wallet owned by the authenticated user and agent.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "wallet_id": {"type": "integer"},
                        "caip2": {"type": "string"},
                        "to": {"type": "string"},
                        "value_native_units": {"type": "string", "default": "0"},
                        "data": {"type": "string", "default": "0x"},
                        "sponsor": {"type": "boolean", "default": false}
                    },
                    "required": ["wallet_id", "caip2", "to"]
                }
            }),
            json!({
                "name": "sign_agent_message",
                "description": "Sign a message with a wallet owned by the authenticated user and agent.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "wallet_id": {"type": "integer"},
                        "message": {"type": "string"},
                        "encoding": {"type": "string", "enum": ["utf-8", "hex"], "default": "utf-8"}
                    },
                    "required": ["wallet_id", "message"]
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

    pub async fn call_tool(&self, params: Value, context: &RequestContext) -> Result<Value> {
        let call: ToolCall = serde_json::from_value(params)?;
        let name = call.name.clone();
        let result = match call.name.as_str() {
            "create_agent_wallet" => self.create_agent_wallet(call.arguments, context).await,
            "list_agent_wallets" => self.list_agent_wallets(call.arguments, context).await,
            "get_agent_wallet" => self.get_agent_wallet(call.arguments, context).await,
            "get_agent_wallet_balance" => {
                self.get_agent_wallet_balance(call.arguments, context).await
            }
            "send_agent_transaction" => self.send_agent_transaction(call.arguments, context).await,
            "sign_agent_message" => self.sign_agent_message(call.arguments, context).await,
            "get_agent_transaction" => self.get_agent_transaction(call.arguments, context).await,
            other => Err(anyhow!("unknown tool: {other}")),
        };

        if let Err(error) = &result {
            let _ = self
                .store
                .record_audit(
                    &context.user_id,
                    &context.agent_id,
                    None,
                    &name,
                    context.request_id.as_deref(),
                    "failed",
                    Some(&error.to_string()),
                    None,
                )
                .await;
        }

        result
    }

    async fn create_agent_wallet(&self, args: Value, context: &RequestContext) -> Result<Value> {
        context.require_scope("wallet:create")?;
        let args: CreateAgentWalletArgs = serde_json::from_value(args)?;
        let template = PolicyTemplate::resolve(args.policy_template.as_deref())?;
        validate_allowed_caip2(&template.caip2)?;
        let chain_id = chain_id_from_caip2(&template.caip2)?;
        validate_native_units_decimal(&template.max_native_units_per_tx)?;

        let policy = self
            .privy
            .create_policy(default_policy(
                &context.agent_id,
                &chain_id,
                &template.max_native_units_per_tx,
            ))
            .await?;
        let policy_ids = vec![extract_string(&policy, &["id", "policy_id"])?];
        let privy_wallet = self.privy.create_wallet("ethereum", &policy_ids).await?;
        let provider_wallet_id = extract_string(&privy_wallet, &["id", "wallet_id"])?;
        let address = extract_string(&privy_wallet, &["address"])?;

        let wallet = self
            .store
            .insert(NewWallet {
                user_id: context.user_id.clone(),
                agent_id: context.agent_id.clone(),
                provider: PRIVY_PROVIDER.to_string(),
                provider_wallet_id,
                address,
                chain_type: "ethereum".to_string(),
                policy_ids,
                metadata: json!({
                    "policy_template": template.name,
                    "label": args.label,
                    "request_id": context.request_id,
                }),
            })
            .await?;

        self.audit_success(context, Some(&wallet), "create_agent_wallet", None)
            .await;
        tool_result(json!({
            "wallet": wallet,
            "provider_wallet": privy_wallet
        }))
    }

    async fn list_agent_wallets(&self, args: Value, context: &RequestContext) -> Result<Value> {
        context.require_scope("wallet:read")?;
        let args: ListAgentWalletsArgs = serde_json::from_value(args)?;
        let mut wallets = self
            .store
            .list_for_agent(&context.user_id, &context.agent_id)
            .await?;
        if let Some(provider) = args.provider {
            wallets.retain(|wallet| wallet.provider == provider);
        }
        if let Some(chain_type) = args.chain_type {
            wallets.retain(|wallet| wallet.chain_type == chain_type);
        }
        tool_result(json!({ "wallets": wallets }))
    }

    async fn get_agent_wallet(&self, args: Value, context: &RequestContext) -> Result<Value> {
        context.require_scope("wallet:read")?;
        let args: WalletIdArgs = serde_json::from_value(args)?;
        let wallet = self.require_wallet(args.wallet_id, context).await?;
        ensure_privy_wallet(&wallet)?;
        let provider_wallet = self.privy.get_wallet(&wallet.provider_wallet_id).await?;
        tool_result(json!({
            "wallet": wallet,
            "provider_wallet": provider_wallet
        }))
    }

    async fn get_agent_wallet_balance(
        &self,
        args: Value,
        context: &RequestContext,
    ) -> Result<Value> {
        context.require_scope("wallet:read")?;
        let args: BalanceArgs = serde_json::from_value(args)?;
        let wallet = self.require_wallet(args.wallet_id, context).await?;
        ensure_privy_wallet(&wallet)?;
        let balance = self
            .privy
            .get_balance(&wallet.provider_wallet_id, &args.asset, &args.chain)
            .await?;
        tool_result(json!({
            "wallet": wallet,
            "balance": balance
        }))
    }

    async fn send_agent_transaction(&self, args: Value, context: &RequestContext) -> Result<Value> {
        context.require_scope("wallet:send")?;
        let args: SendTransactionArgs = serde_json::from_value(args)?;
        validate_allowed_caip2(&args.caip2)?;
        let chain_id = chain_id_from_caip2(&args.caip2)?;
        validate_evm_address(&args.to)?;
        let value_native_units = args.value_native_units.unwrap_or_else(|| "0".to_string());
        validate_native_units_decimal(&value_native_units)?;
        let data = args.data.unwrap_or_else(|| "0x".to_string());
        validate_hex_data(&data)?;

        let wallet = self.require_wallet(args.wallet_id, context).await?;
        ensure_privy_wallet(&wallet)?;
        if wallet.policy_ids.is_empty() {
            return Err(anyhow!("wallet has no policy_ids; refusing transaction"));
        }

        let tx = json!({
            "method": "eth_sendTransaction",
            "caip2": args.caip2,
            "chain_type": "ethereum",
            "params": {
                "transaction": {
                    "to": args.to,
                    "value": native_units_decimal_to_hex(&value_native_units)?,
                    "data": data,
                    "chain_id": chain_id
                }
            },
            "sponsor": args.sponsor.unwrap_or(false)
        });

        let response = self
            .privy
            .wallet_rpc(&wallet.provider_wallet_id, tx)
            .await?;
        let transaction_id = extract_optional_string(&response, &["id", "transaction_id", "hash"]);
        self.audit_success(
            context,
            Some(&wallet),
            "send_agent_transaction",
            transaction_id.as_deref(),
        )
        .await;
        tool_result(json!({
            "wallet": wallet,
            "transaction": response
        }))
    }

    async fn sign_agent_message(&self, args: Value, context: &RequestContext) -> Result<Value> {
        context.require_scope("wallet:sign")?;
        let args: SignMessageArgs = serde_json::from_value(args)?;
        let wallet = self.require_wallet(args.wallet_id, context).await?;
        ensure_privy_wallet(&wallet)?;
        let encoding = args.encoding.unwrap_or_else(|| "utf-8".to_string());
        if encoding == "hex" {
            validate_hex_data(&args.message)?;
        } else if encoding != "utf-8" {
            return Err(anyhow!("encoding must be utf-8 or hex"));
        }

        let response = self
            .privy
            .wallet_rpc(
                &wallet.provider_wallet_id,
                json!({
                    "method": "personal_sign",
                    "params": {
                        "message": args.message,
                        "encoding": encoding
                    }
                }),
            )
            .await?;
        self.audit_success(context, Some(&wallet), "sign_agent_message", None)
            .await;
        tool_result(json!({
            "wallet": wallet,
            "signature": response
        }))
    }

    async fn get_agent_transaction(&self, args: Value, context: &RequestContext) -> Result<Value> {
        context.require_scope("wallet:tx:read")?;
        let args: TransactionArgs = serde_json::from_value(args)?;
        if args.transaction_id.trim().is_empty() {
            return Err(anyhow!("transaction_id is required"));
        }
        let transaction = self.privy.get_transaction(&args.transaction_id).await?;
        tool_result(json!({ "transaction": transaction }))
    }

    async fn require_wallet(&self, wallet_id: i64, context: &RequestContext) -> Result<Wallet> {
        self.store
            .get_by_id_for_agent(wallet_id, &context.user_id, &context.agent_id)
            .await?
            .ok_or_else(|| anyhow!("wallet not found for authenticated user and agent"))
    }

    async fn audit_success(
        &self,
        context: &RequestContext,
        wallet: Option<&Wallet>,
        action: &str,
        transaction_id: Option<&str>,
    ) {
        let _ = self
            .store
            .record_audit(
                &context.user_id,
                &context.agent_id,
                wallet,
                action,
                context.request_id.as_deref(),
                "succeeded",
                None,
                transaction_id,
            )
            .await;
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
    policy_template: Option<String>,
    label: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ListAgentWalletsArgs {
    provider: Option<String>,
    chain_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WalletIdArgs {
    wallet_id: i64,
}

#[derive(Debug, Deserialize)]
struct BalanceArgs {
    wallet_id: i64,
    asset: String,
    chain: String,
}

#[derive(Debug, Deserialize)]
struct SendTransactionArgs {
    wallet_id: i64,
    caip2: String,
    to: String,
    value_native_units: Option<String>,
    data: Option<String>,
    sponsor: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct SignMessageArgs {
    wallet_id: i64,
    message: String,
    encoding: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TransactionArgs {
    transaction_id: String,
}

struct PolicyTemplate {
    name: &'static str,
    caip2: String,
    max_native_units_per_tx: String,
}

impl PolicyTemplate {
    fn resolve(name: Option<&str>) -> Result<Self> {
        match name.unwrap_or("base-small-spend") {
            "base-small-spend" => Ok(Self {
                name: "base-small-spend",
                caip2: env::var("VAULT_DEFAULT_CAIP2")
                    .unwrap_or_else(|_| "eip155:2345".to_string()),
                max_native_units_per_tx: env::var("VAULT_DEFAULT_MAX_NATIVE_UNITS")
                    .unwrap_or_else(|_| "10000000000000".to_string()), // 0.00001 BTC or 0.00001 ETH
            }),
            other => Err(anyhow!("unknown policy_template '{other}'")),
        }
    }
}

fn ensure_privy_wallet(wallet: &Wallet) -> Result<()> {
    if wallet.provider == PRIVY_PROVIDER {
        Ok(())
    } else {
        Err(anyhow!(
            "unsupported wallet provider '{}'; expected privy",
            wallet.provider
        ))
    }
}

fn default_policy(agent_id: &str, chain_id: &str, max_native_units: &str) -> Value {
    json!({
        "version": "1.0",
        "name": format!("clawup-{agent_id}"),
        "chain_type": "ethereum",
        "rules": [
            {
                "name": "max native units per transaction",
                "method": "eth_sendTransaction",
                "conditions": [{
                    "field_source": "ethereum_transaction",
                    "field": "value",
                    "operator": "lte",
                    "value": max_native_units,
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
    extract_optional_string(value, keys)
        .ok_or_else(|| anyhow!("Privy response is missing one of: {}", keys.join(", ")))
}

fn extract_optional_string(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(found) = value.get(*key).and_then(Value::as_str) {
            return Some(found.to_string());
        }
    }
    None
}

fn tool_result(value: Value) -> Result<Value> {
    Ok(json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string_pretty(&value)?
        }]
    }))
}
