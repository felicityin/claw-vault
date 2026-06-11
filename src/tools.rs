use std::env;

use anyhow::{Result, anyhow};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::auth::RequestContext;
use crate::privy::PrivyClient;
use crate::store::{
    NewWallet, NewWalletPolicy, NewWalletPolicyRule, Wallet, WalletPolicy, WalletPolicyRule,
    WalletStore,
};
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
                "description": "Create a Privy wallet for the authenticated user and agent. If policy_id is omitted, a default policy with guardrail rules is created and attached.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "policy_id": {"type": "integer"}
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
            json!({
                "name": "create_wallet_policy",
                "description": "Create a Privy policy owned by the authenticated user and agent. The policy JSON is user-controlled.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "policy": {"type": "object"},
                        "metadata": {"type": "object"},
                        "status": {"type": "string", "default": "active"}
                    },
                    "required": ["policy"]
                }
            }),
            json!({
                "name": "list_wallet_policies",
                "description": "List policies owned by the authenticated user and agent.",
                "inputSchema": {"type": "object", "properties": {}, "required": []}
            }),
            json!({
                "name": "get_wallet_policy",
                "description": "Get an owned policy by internal policy_id.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"policy_id": {"type": "integer"}},
                    "required": ["policy_id"]
                }
            }),
            json!({
                "name": "update_wallet_policy",
                "description": "Update an owned Privy policy with user-controlled policy JSON.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "policy_id": {"type": "integer"},
                        "policy": {"type": "object"},
                        "status": {"type": "string"}
                    },
                    "required": ["policy_id", "policy"]
                }
            }),
            json!({
                "name": "delete_wallet_policy",
                "description": "Delete an owned policy from Privy and local storage. Requires explicit user confirmation.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "policy_id": {"type": "integer"},
                        "confirm_delete": {"type": "string", "description": "Must equal delete policy"}
                    },
                    "required": ["policy_id", "confirm_delete"]
                }
            }),
            json!({
                "name": "create_wallet_policy_rule",
                "description": "Create a rule under an owned policy. The rule JSON is user-controlled.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "policy_id": {"type": "integer"},
                        "rule": {"type": "object"},
                        "metadata": {"type": "object"},
                        "status": {"type": "string", "default": "active"}
                    },
                    "required": ["policy_id", "rule"]
                }
            }),
            json!({
                "name": "list_wallet_policy_rules",
                "description": "List rules under an owned policy.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"policy_id": {"type": "integer"}},
                    "required": ["policy_id"]
                }
            }),
            json!({
                "name": "get_wallet_policy_rule",
                "description": "Get an owned policy rule by internal ids.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "policy_id": {"type": "integer"},
                        "rule_id": {"type": "integer"}
                    },
                    "required": ["policy_id", "rule_id"]
                }
            }),
            json!({
                "name": "update_wallet_policy_rule",
                "description": "Update an owned policy rule with user-controlled rule JSON.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "policy_id": {"type": "integer"},
                        "rule_id": {"type": "integer"},
                        "rule": {"type": "object"},
                        "status": {"type": "string"}
                    },
                    "required": ["policy_id", "rule_id", "rule"]
                }
            }),
            json!({
                "name": "delete_wallet_policy_rule",
                "description": "Delete an owned policy rule from Privy and local storage. Requires explicit user confirmation.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "policy_id": {"type": "integer"},
                        "rule_id": {"type": "integer"},
                        "confirm_delete": {"type": "string", "description": "Must equal delete policy rule"}
                    },
                    "required": ["policy_id", "rule_id", "confirm_delete"]
                }
            }),
            json!({
                "name": "attach_policy_to_wallet",
                "description": "Attach an owned active policy to an owned wallet and update the Privy wallet policy list.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "wallet_id": {"type": "integer"},
                        "policy_id": {"type": "integer"}
                    },
                    "required": ["wallet_id", "policy_id"]
                }
            }),
            json!({
                "name": "detach_policy_from_wallet",
                "description": "Detach an owned policy from an owned wallet and update the Privy wallet policy list.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "wallet_id": {"type": "integer"},
                        "policy_id": {"type": "integer"}
                    },
                    "required": ["wallet_id", "policy_id"]
                }
            }),
            json!({
                "name": "list_wallet_policies_for_wallet",
                "description": "List internal policies linked to an owned wallet.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"wallet_id": {"type": "integer"}},
                    "required": ["wallet_id"]
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
            "create_wallet_policy" => self.create_wallet_policy(call.arguments, context).await,
            "list_wallet_policies" => self.list_wallet_policies(context).await,
            "get_wallet_policy" => self.get_wallet_policy(call.arguments, context).await,
            "update_wallet_policy" => self.update_wallet_policy(call.arguments, context).await,
            "delete_wallet_policy" => self.delete_wallet_policy(call.arguments, context).await,
            "create_wallet_policy_rule" => {
                self.create_wallet_policy_rule(call.arguments, context)
                    .await
            }
            "list_wallet_policy_rules" => {
                self.list_wallet_policy_rules(call.arguments, context).await
            }
            "get_wallet_policy_rule" => self.get_wallet_policy_rule(call.arguments, context).await,
            "update_wallet_policy_rule" => {
                self.update_wallet_policy_rule(call.arguments, context)
                    .await
            }
            "delete_wallet_policy_rule" => {
                self.delete_wallet_policy_rule(call.arguments, context)
                    .await
            }
            "attach_policy_to_wallet" => {
                self.attach_policy_to_wallet(call.arguments, context).await
            }
            "detach_policy_from_wallet" => {
                self.detach_policy_from_wallet(call.arguments, context)
                    .await
            }
            "list_wallet_policies_for_wallet" => {
                self.list_wallet_policies_for_wallet(call.arguments, context)
                    .await
            }
            other => Err(anyhow!("unknown tool: {other}")),
        };

        if let Err(error) = &result {
            if is_policy_tool(&name) {
                let _ = self
                    .store
                    .record_policy_audit(
                        &context.user_id,
                        &context.agent_id,
                        None,
                        None,
                        &format!("{name}_failed"),
                        context.request_id.as_deref(),
                        "failed",
                        Some(&error.to_string()),
                    )
                    .await;
            } else {
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
        }

        result
    }

    async fn create_agent_wallet(&self, args: Value, context: &RequestContext) -> Result<Value> {
        context.require_scope("wallet:create")?;
        let args: CreateAgentWalletArgs = serde_json::from_value(args)?;
        let (policy, policy_rules, caip2, chain_type) = match args.policy_id {
            Some(policy_id) => {
                let policy = self.require_policy(policy_id, context).await?;
                ensure_privy_policy(&policy)?;
                if policy.status != "active" {
                    return Err(anyhow!("policy is not active"));
                }
                let chain_type = policy.chain_type.clone();
                if let Some(wallet) = self
                    .find_wallet_for_chain_type(context, &chain_type)
                    .await?
                {
                    self.audit_wallet_success(
                        context,
                        Some(&wallet),
                        "create_agent_wallet_existing",
                        None,
                    )
                    .await;
                    return tool_result(json!({
                        "wallet": wallet,
                        "address": wallet.address,
                        "chain_type": chain_type,
                        "existing": true
                    }));
                }
                let caip2 = policy_caip2(&policy);
                (policy, Vec::new(), caip2, chain_type)
            }
            None => {
                let chain_type = "ethereum".to_string();
                if let Some(wallet) = self
                    .find_wallet_for_chain_type(context, &chain_type)
                    .await?
                {
                    self.audit_wallet_success(
                        context,
                        Some(&wallet),
                        "create_agent_wallet_existing",
                        None,
                    )
                    .await;
                    return tool_result(json!({
                        "wallet": wallet,
                        "address": wallet.address,
                        "chain_type": chain_type,
                        "existing": true
                    }));
                }
                let (caip2, chain_id, max_native_units) = default_policy_settings()?;
                let (policy, rules) = self
                    .create_default_policy(context, caip2.clone(), chain_id, max_native_units)
                    .await?;
                (policy, rules, Some(caip2), chain_type)
            }
        };

        let policy_ids = vec![policy.provider_policy_id.clone()];
        let provider_wallet = self.privy.create_wallet(&chain_type, &policy_ids).await?;
        let provider_wallet_id = extract_string(&provider_wallet, &["id", "wallet_id"])?;
        let address = extract_string(&provider_wallet, &["address"])?;

        let wallet = self
            .store
            .insert(NewWallet {
                user_id: context.user_id.clone(),
                agent_id: context.agent_id.clone(),
                provider: PRIVY_PROVIDER.to_string(),
                provider_wallet_id,
                address,
                chain_type,
                policy_ids,
                metadata: json!({
                    "caip2": caip2,
                    "request_id": context.request_id,
                }),
            })
            .await?;
        self.store
            .attach_policy_to_wallet(wallet.id, policy.id, &context.user_id, &context.agent_id)
            .await?;

        self.audit_wallet_success(context, Some(&wallet), "create_agent_wallet", None)
            .await;
        self.audit_policy_success(context, Some(&policy), None, "policy_attached")
            .await;
        tool_result(json!({
            "wallet": wallet,
            "policy": policy,
            "policy_rules": policy_rules,
            "provider_wallet": provider_wallet
        }))
    }

    async fn create_default_policy(
        &self,
        context: &RequestContext,
        caip2: String,
        chain_id: String,
        max_native_units: String,
    ) -> Result<(WalletPolicy, Vec<WalletPolicyRule>)> {
        let rules = default_policy_rules(&chain_id, &max_native_units);
        let policy_json = default_policy(&context.agent_id, rules.clone());
        let (name, chain_type) = validate_policy_json(&policy_json)?;
        let provider_policy = self.privy.create_policy(policy_json.clone()).await?;
        let provider_policy_id = extract_string(&provider_policy, &["id", "policy_id"])?;
        let policy = self
            .store
            .create_policy(NewWalletPolicy {
                user_id: context.user_id.clone(),
                agent_id: context.agent_id.clone(),
                provider: PRIVY_PROVIDER.to_string(),
                provider_policy_id: provider_policy_id.clone(),
                name,
                chain_type,
                policy_json,
                status: "active".to_string(),
                metadata: json!({
                    "default": true,
                    "caip2": caip2,
                    "max_native_units_per_tx": max_native_units,
                    "request_id": context.request_id,
                }),
            })
            .await?;

        let provider_rules = provider_policy.get("rules").and_then(Value::as_array);
        let mut stored_rules = Vec::with_capacity(rules.len());
        for (index, rule_json) in rules.into_iter().enumerate() {
            let provider_rule_id = provider_rules
                .and_then(|rules| rules.get(index))
                .and_then(|rule| extract_optional_string(rule, &["id", "rule_id"]));
            let rule = self
                .store
                .create_policy_rule(NewWalletPolicyRule {
                    policy_id: policy.id,
                    user_id: context.user_id.clone(),
                    agent_id: context.agent_id.clone(),
                    provider: PRIVY_PROVIDER.to_string(),
                    provider_policy_id: provider_policy_id.clone(),
                    provider_rule_id,
                    rule_json,
                    status: "active".to_string(),
                    metadata: json!({
                        "default": true,
                        "rule_index": index,
                        "request_id": context.request_id,
                    }),
                })
                .await?;
            self.audit_policy_success(context, Some(&policy), Some(&rule), "policy_rule_created")
                .await;
            stored_rules.push(rule);
        }

        self.audit_policy_success(context, Some(&policy), None, "policy_created")
            .await;
        Ok((policy, stored_rules))
    }

    async fn find_wallet_for_chain_type(
        &self,
        context: &RequestContext,
        chain_type: &str,
    ) -> Result<Option<Wallet>> {
        let wallets = self
            .store
            .list_for_agent(&context.user_id, &context.agent_id)
            .await?;
        Ok(wallets
            .into_iter()
            .find(|wallet| wallet.provider == PRIVY_PROVIDER && wallet.chain_type == chain_type))
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
        tool_result(json!({ "wallet": wallet, "balance": balance }))
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
        self.audit_wallet_success(
            context,
            Some(&wallet),
            "send_agent_transaction",
            transaction_id.as_deref(),
        )
        .await;
        tool_result(json!({ "wallet": wallet, "transaction": response }))
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
                    "params": { "message": args.message, "encoding": encoding }
                }),
            )
            .await?;
        self.audit_wallet_success(context, Some(&wallet), "sign_agent_message", None)
            .await;
        tool_result(json!({ "wallet": wallet, "signature": response }))
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

    async fn create_wallet_policy(&self, args: Value, context: &RequestContext) -> Result<Value> {
        context.require_scope("policy:create")?;
        let args: CreateWalletPolicyArgs = serde_json::from_value(args)?;
        let (name, chain_type) = validate_policy_json(&args.policy)?;
        let provider_policy = self.privy.create_policy(args.policy.clone()).await?;
        let provider_policy_id = extract_string(&provider_policy, &["id", "policy_id"])?;
        let policy = self
            .store
            .create_policy(NewWalletPolicy {
                user_id: context.user_id.clone(),
                agent_id: context.agent_id.clone(),
                provider: PRIVY_PROVIDER.to_string(),
                provider_policy_id,
                name,
                chain_type,
                policy_json: args.policy,
                status: args.status.unwrap_or_else(|| "active".to_string()),
                metadata: args.metadata.unwrap_or_else(|| json!({})),
            })
            .await?;
        self.audit_policy_success(context, Some(&policy), None, "policy_created")
            .await;
        tool_result(json!({ "policy": policy, "provider_policy": provider_policy }))
    }

    async fn list_wallet_policies(&self, context: &RequestContext) -> Result<Value> {
        context.require_scope("policy:read")?;
        let policies = self
            .store
            .list_policies_for_agent(&context.user_id, &context.agent_id)
            .await?;
        tool_result(json!({ "policies": policies }))
    }

    async fn get_wallet_policy(&self, args: Value, context: &RequestContext) -> Result<Value> {
        context.require_scope("policy:read")?;
        let args: PolicyIdArgs = serde_json::from_value(args)?;
        let policy = self.require_policy(args.policy_id, context).await?;
        ensure_privy_policy(&policy)?;
        let provider_policy = self.privy.get_policy(&policy.provider_policy_id).await?;
        tool_result(json!({ "policy": policy, "provider_policy": provider_policy }))
    }

    async fn update_wallet_policy(&self, args: Value, context: &RequestContext) -> Result<Value> {
        context.require_scope("policy:update")?;
        let args: UpdateWalletPolicyArgs = serde_json::from_value(args)?;
        let policy = self.require_policy(args.policy_id, context).await?;
        ensure_privy_policy(&policy)?;
        let (name, chain_type) = validate_policy_json(&args.policy)?;
        let provider_policy = self
            .privy
            .update_policy(&policy.provider_policy_id, args.policy.clone())
            .await?;
        let status = args.status.unwrap_or(policy.status);
        self.store
            .update_policy_for_agent(
                args.policy_id,
                &context.user_id,
                &context.agent_id,
                &name,
                &chain_type,
                &args.policy,
                &status,
            )
            .await?;
        let updated = self.require_policy(args.policy_id, context).await?;
        self.audit_policy_success(context, Some(&updated), None, "policy_updated")
            .await;
        tool_result(json!({ "policy": updated, "provider_policy": provider_policy }))
    }

    async fn delete_wallet_policy(&self, args: Value, context: &RequestContext) -> Result<Value> {
        context.require_scope("policy:delete")?;
        let args: DeletePolicyArgs = serde_json::from_value(args)?;
        require_delete_confirmation(&args.confirm_delete, "delete policy")?;
        let policy = self.require_policy(args.policy_id, context).await?;
        ensure_privy_policy(&policy)?;
        let provider_response = self.privy.delete_policy(&policy.provider_policy_id).await?;
        self.store
            .delete_policy_for_agent(args.policy_id, &context.user_id, &context.agent_id)
            .await?;
        self.audit_policy_success(context, Some(&policy), None, "policy_deleted")
            .await;
        tool_result(json!({ "deleted": true, "provider_response": provider_response }))
    }

    async fn create_wallet_policy_rule(
        &self,
        args: Value,
        context: &RequestContext,
    ) -> Result<Value> {
        context.require_scope("policy:rule:create")?;
        let args: CreateWalletPolicyRuleArgs = serde_json::from_value(args)?;
        let policy = self.require_policy(args.policy_id, context).await?;
        ensure_privy_policy(&policy)?;
        validate_rule_json(&args.rule)?;
        let provider_rule = self
            .privy
            .add_rule_to_policy(&policy.provider_policy_id, args.rule.clone())
            .await?;
        let provider_rule_id = extract_optional_string(&provider_rule, &["id", "rule_id"]);
        let rule = self
            .store
            .create_policy_rule(NewWalletPolicyRule {
                policy_id: policy.id,
                user_id: context.user_id.clone(),
                agent_id: context.agent_id.clone(),
                provider: policy.provider.clone(),
                provider_policy_id: policy.provider_policy_id.clone(),
                provider_rule_id,
                rule_json: args.rule,
                status: args.status.unwrap_or_else(|| "active".to_string()),
                metadata: args.metadata.unwrap_or_else(|| json!({})),
            })
            .await?;
        self.audit_policy_success(context, Some(&policy), Some(&rule), "policy_rule_created")
            .await;
        tool_result(json!({ "rule": rule, "provider_rule": provider_rule }))
    }

    async fn list_wallet_policy_rules(
        &self,
        args: Value,
        context: &RequestContext,
    ) -> Result<Value> {
        context.require_scope("policy:read")?;
        let args: PolicyIdArgs = serde_json::from_value(args)?;
        let policy = self.require_policy(args.policy_id, context).await?;
        let rules = self
            .store
            .list_policy_rules_for_agent(policy.id, &context.user_id, &context.agent_id)
            .await?;
        tool_result(json!({ "policy": policy, "rules": rules }))
    }

    async fn get_wallet_policy_rule(&self, args: Value, context: &RequestContext) -> Result<Value> {
        context.require_scope("policy:read")?;
        let args: PolicyRuleIdArgs = serde_json::from_value(args)?;
        let policy = self.require_policy(args.policy_id, context).await?;
        let rule = self
            .require_policy_rule(args.rule_id, args.policy_id, context)
            .await?;
        let provider_rule = match rule.provider_rule_id.as_deref() {
            Some(provider_rule_id) => Some(
                self.privy
                    .get_policy_rule(&policy.provider_policy_id, provider_rule_id)
                    .await?,
            ),
            None => None,
        };
        tool_result(json!({ "policy": policy, "rule": rule, "provider_rule": provider_rule }))
    }

    async fn update_wallet_policy_rule(
        &self,
        args: Value,
        context: &RequestContext,
    ) -> Result<Value> {
        context.require_scope("policy:rule:update")?;
        let args: UpdateWalletPolicyRuleArgs = serde_json::from_value(args)?;
        let policy = self.require_policy(args.policy_id, context).await?;
        let rule = self
            .require_policy_rule(args.rule_id, args.policy_id, context)
            .await?;
        let provider_rule_id = rule
            .provider_rule_id
            .as_deref()
            .ok_or_else(|| anyhow!("rule has no provider_rule_id"))?;
        validate_rule_json(&args.rule)?;
        let provider_rule = self
            .privy
            .update_policy_rule(
                &policy.provider_policy_id,
                provider_rule_id,
                args.rule.clone(),
            )
            .await?;
        let updated_provider_rule_id =
            extract_optional_string(&provider_rule, &["id", "rule_id"]).or(rule.provider_rule_id);
        self.store
            .update_policy_rule_for_agent(
                args.rule_id,
                args.policy_id,
                &context.user_id,
                &context.agent_id,
                updated_provider_rule_id.as_deref(),
                &args.rule,
                args.status.as_deref().unwrap_or(&rule.status),
            )
            .await?;
        let updated = self
            .require_policy_rule(args.rule_id, args.policy_id, context)
            .await?;
        self.audit_policy_success(
            context,
            Some(&policy),
            Some(&updated),
            "policy_rule_updated",
        )
        .await;
        tool_result(json!({ "rule": updated, "provider_rule": provider_rule }))
    }

    async fn delete_wallet_policy_rule(
        &self,
        args: Value,
        context: &RequestContext,
    ) -> Result<Value> {
        context.require_scope("policy:rule:delete")?;
        let args: DeletePolicyRuleArgs = serde_json::from_value(args)?;
        require_delete_confirmation(&args.confirm_delete, "delete policy rule")?;
        let policy = self.require_policy(args.policy_id, context).await?;
        let rule = self
            .require_policy_rule(args.rule_id, args.policy_id, context)
            .await?;
        let provider_response = match rule.provider_rule_id.as_deref() {
            Some(provider_rule_id) => {
                self.privy
                    .delete_policy_rule(&policy.provider_policy_id, provider_rule_id)
                    .await?
            }
            None => json!({}),
        };
        self.store
            .delete_policy_rule_for_agent(
                args.rule_id,
                args.policy_id,
                &context.user_id,
                &context.agent_id,
            )
            .await?;
        self.audit_policy_success(context, Some(&policy), Some(&rule), "policy_rule_deleted")
            .await;
        tool_result(json!({ "deleted": true, "provider_response": provider_response }))
    }

    async fn attach_policy_to_wallet(
        &self,
        args: Value,
        context: &RequestContext,
    ) -> Result<Value> {
        context.require_scope("policy:attach")?;
        let args: WalletPolicyLinkArgs = serde_json::from_value(args)?;
        let wallet = self.require_wallet(args.wallet_id, context).await?;
        let policy = self.require_policy(args.policy_id, context).await?;
        ensure_privy_wallet(&wallet)?;
        ensure_privy_policy(&policy)?;
        if policy.status != "active" {
            return Err(anyhow!("policy is not active"));
        }

        self.store
            .attach_policy_to_wallet(wallet.id, policy.id, &context.user_id, &context.agent_id)
            .await?;
        let policies = self
            .store
            .list_wallet_policies(wallet.id, &context.user_id, &context.agent_id)
            .await?;
        let provider_policy_ids = provider_policy_ids(&policies);
        let provider_wallet = self
            .privy
            .update_wallet(&wallet.provider_wallet_id, &provider_policy_ids)
            .await?;
        self.store
            .update_wallet_policy_ids(
                wallet.id,
                &context.user_id,
                &context.agent_id,
                &provider_policy_ids,
            )
            .await?;
        self.audit_policy_success(context, Some(&policy), None, "policy_attached")
            .await;
        tool_result(
            json!({ "wallet_id": wallet.id, "policies": policies, "provider_wallet": provider_wallet }),
        )
    }

    async fn detach_policy_from_wallet(
        &self,
        args: Value,
        context: &RequestContext,
    ) -> Result<Value> {
        context.require_scope("policy:detach")?;
        let args: WalletPolicyLinkArgs = serde_json::from_value(args)?;
        let wallet = self.require_wallet(args.wallet_id, context).await?;
        let policy = self.require_policy(args.policy_id, context).await?;
        ensure_privy_wallet(&wallet)?;
        ensure_privy_policy(&policy)?;

        self.store
            .detach_policy_from_wallet(wallet.id, policy.id, &context.user_id, &context.agent_id)
            .await?;
        let policies = self
            .store
            .list_wallet_policies(wallet.id, &context.user_id, &context.agent_id)
            .await?;
        let provider_policy_ids = provider_policy_ids(&policies);
        let provider_wallet = self
            .privy
            .update_wallet(&wallet.provider_wallet_id, &provider_policy_ids)
            .await?;
        self.store
            .update_wallet_policy_ids(
                wallet.id,
                &context.user_id,
                &context.agent_id,
                &provider_policy_ids,
            )
            .await?;
        self.audit_policy_success(context, Some(&policy), None, "policy_detached")
            .await;
        tool_result(
            json!({ "wallet_id": wallet.id, "policies": policies, "provider_wallet": provider_wallet }),
        )
    }

    async fn list_wallet_policies_for_wallet(
        &self,
        args: Value,
        context: &RequestContext,
    ) -> Result<Value> {
        context.require_scope("policy:read")?;
        let args: WalletIdArgs = serde_json::from_value(args)?;
        let wallet = self.require_wallet(args.wallet_id, context).await?;
        let policies = self
            .store
            .list_wallet_policies(wallet.id, &context.user_id, &context.agent_id)
            .await?;
        tool_result(json!({ "wallet": wallet, "policies": policies }))
    }

    async fn require_wallet(&self, wallet_id: i64, context: &RequestContext) -> Result<Wallet> {
        self.store
            .get_by_id_for_agent(wallet_id, &context.user_id, &context.agent_id)
            .await?
            .ok_or_else(|| anyhow!("wallet not found for authenticated user and agent"))
    }

    async fn require_policy(
        &self,
        policy_id: i64,
        context: &RequestContext,
    ) -> Result<WalletPolicy> {
        self.store
            .get_policy_for_agent(policy_id, &context.user_id, &context.agent_id)
            .await?
            .ok_or_else(|| anyhow!("policy not found for authenticated user and agent"))
    }

    async fn require_policy_rule(
        &self,
        rule_id: i64,
        policy_id: i64,
        context: &RequestContext,
    ) -> Result<WalletPolicyRule> {
        self.store
            .get_policy_rule_for_agent(rule_id, policy_id, &context.user_id, &context.agent_id)
            .await?
            .ok_or_else(|| anyhow!("policy rule not found for authenticated user and agent"))
    }

    async fn audit_wallet_success(
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

    async fn audit_policy_success(
        &self,
        context: &RequestContext,
        policy: Option<&WalletPolicy>,
        rule: Option<&WalletPolicyRule>,
        action: &str,
    ) {
        let _ = self
            .store
            .record_policy_audit(
                &context.user_id,
                &context.agent_id,
                policy,
                rule,
                action,
                context.request_id.as_deref(),
                "succeeded",
                None,
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
    policy_id: Option<i64>,
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

#[derive(Debug, Deserialize)]
struct CreateWalletPolicyArgs {
    policy: Value,
    metadata: Option<Value>,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateWalletPolicyArgs {
    policy_id: i64,
    policy: Value,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PolicyIdArgs {
    policy_id: i64,
}

#[derive(Debug, Deserialize)]
struct CreateWalletPolicyRuleArgs {
    policy_id: i64,
    rule: Value,
    metadata: Option<Value>,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateWalletPolicyRuleArgs {
    policy_id: i64,
    rule_id: i64,
    rule: Value,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PolicyRuleIdArgs {
    policy_id: i64,
    rule_id: i64,
}

#[derive(Debug, Deserialize)]
struct DeletePolicyArgs {
    policy_id: i64,
    confirm_delete: String,
}

#[derive(Debug, Deserialize)]
struct DeletePolicyRuleArgs {
    policy_id: i64,
    rule_id: i64,
    confirm_delete: String,
}

#[derive(Debug, Deserialize)]
struct WalletPolicyLinkArgs {
    wallet_id: i64,
    policy_id: i64,
}

fn default_policy_settings() -> Result<(String, String, String)> {
    let caip2 = env::var("VAULT_DEFAULT_CAIP2").unwrap_or_else(|_| "eip155:2345".to_string());
    validate_allowed_caip2(&caip2)?;
    let chain_id = chain_id_from_caip2(&caip2)?;
    // 0.00001 BTC or 0.00001 ETH in native units (satoshi or wei)
    let max_native_units =
        env::var("VAULT_DEFAULT_MAX_NATIVE_UNITS").unwrap_or_else(|_| "10000000000000".to_string());
    validate_native_units_decimal(&max_native_units)?;
    Ok((caip2, chain_id, max_native_units))
}

fn default_policy(agent_id: &str, rules: Vec<Value>) -> Value {
    json!({
        "version": "1.0",
        "name": format!("clawup-default-{agent_id}"),
        "chain_type": "ethereum",
        "rules": rules
    })
}

fn default_policy_rules(chain_id: &str, max_native_units: &str) -> Vec<Value> {
    vec![
        json!({
            "name": "max native units per transaction",
            "method": "eth_sendTransaction",
            "conditions": [{
                "field_source": "ethereum_transaction",
                "field": "value",
                "operator": "lte",
                "value": max_native_units,
            }],
            "action": "ALLOW"
        }),
        json!({
            "name": "allowed chain",
            "method": "eth_sendTransaction",
            "conditions": [{
                "field_source": "ethereum_transaction",
                "field": "chain_id",
                "operator": "eq",
                "value": chain_id
            }],
            "action": "ALLOW"
        }),
    ]
}

fn policy_caip2(policy: &WalletPolicy) -> Option<String> {
    policy
        .metadata
        .get("caip2")
        .and_then(Value::as_str)
        .filter(|caip2| !caip2.trim().is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| policy_json_caip2(&policy.policy_json))
}

fn policy_json_caip2(policy: &Value) -> Option<String> {
    let rules = policy.get("rules")?.as_array()?;
    for rule in rules {
        if rule.get("method").and_then(Value::as_str) != Some("eth_sendTransaction") {
            continue;
        }
        let conditions = rule.get("conditions").and_then(Value::as_array)?;
        for condition in conditions {
            let is_chain_id = condition.get("field").and_then(Value::as_str) == Some("chain_id");
            let is_eq = condition.get("operator").and_then(Value::as_str) == Some("eq");
            if is_chain_id && is_eq {
                let chain_id = condition.get("value")?.as_str()?;
                if !chain_id.is_empty() && chain_id.chars().all(|c| c.is_ascii_digit()) {
                    return Some(format!("eip155:{chain_id}"));
                }
            }
        }
    }
    None
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

fn ensure_privy_policy(policy: &WalletPolicy) -> Result<()> {
    if policy.provider == PRIVY_PROVIDER {
        Ok(())
    } else {
        Err(anyhow!(
            "unsupported policy provider '{}'; expected privy",
            policy.provider
        ))
    }
}

fn provider_policy_ids(policies: &[WalletPolicy]) -> Vec<String> {
    policies
        .iter()
        .filter(|policy| policy.provider == PRIVY_PROVIDER && policy.status == "active")
        .map(|policy| policy.provider_policy_id.clone())
        .collect()
}

fn validate_policy_json(policy: &Value) -> Result<(String, String)> {
    let object = policy
        .as_object()
        .ok_or_else(|| anyhow!("policy must be a JSON object"))?;
    require_field(object, "version")?;
    let name = require_string_field(object, "name")?;
    let chain_type = require_string_field(object, "chain_type")?;
    let rules = object
        .get("rules")
        .ok_or_else(|| anyhow!("policy.rules is required"))?;
    if !rules.is_array() {
        return Err(anyhow!("policy.rules must be an array"));
    }
    Ok((name.to_string(), chain_type.to_string()))
}

fn validate_rule_json(rule: &Value) -> Result<()> {
    let object = rule
        .as_object()
        .ok_or_else(|| anyhow!("rule must be a JSON object"))?;
    require_string_field(object, "name")?;
    require_string_field(object, "method")?;
    let conditions = object
        .get("conditions")
        .ok_or_else(|| anyhow!("rule.conditions is required"))?;
    if !conditions.is_array() {
        return Err(anyhow!("rule.conditions must be an array"));
    }
    require_string_field(object, "action")?;
    Ok(())
}

fn require_field<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a Value> {
    object
        .get(name)
        .ok_or_else(|| anyhow!("{name} is required"))
}

fn require_string_field<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str> {
    require_field(object, name)?
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow!("{name} must be a non-empty string"))
}

fn is_policy_tool(name: &str) -> bool {
    name.contains("policy")
}

fn require_delete_confirmation(actual: &str, expected: &str) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(anyhow!("confirm_delete must equal '{expected}'"))
    }
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
