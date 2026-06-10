use std::collections::BTreeSet;
use std::env;

use anyhow::{Result, anyhow};

pub fn validate_agent_id(agent_id: &str) -> Result<()> {
    if agent_id.is_empty() || agent_id.len() > 128 {
        return Err(anyhow!("agent_id must be 1..128 characters"));
    }
    if !agent_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ':' | '.'))
    {
        return Err(anyhow!(
            "agent_id may only contain ASCII letters, digits, '-', '_', ':' and '.'"
        ));
    }
    Ok(())
}

pub fn validate_evm_address(address: &str) -> Result<()> {
    let body = address
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("EVM address must start with 0x"))?;
    if body.len() != 40 || !body.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!("EVM address must contain 40 hex characters"));
    }
    Ok(())
}

pub fn validate_hex_data(data: &str) -> Result<()> {
    let body = data
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("hex data must start with 0x"))?;
    if body.len() % 2 != 0 || !body.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "hex data must have an even number of hex characters"
        ));
    }
    Ok(())
}

pub fn validate_wei_decimal(value: &str) -> Result<()> {
    if value.is_empty() || !value.chars().all(|c| c.is_ascii_digit()) {
        return Err(anyhow!("wei value must be a decimal integer string"));
    }
    Ok(())
}

pub fn wei_decimal_to_hex(value: &str) -> Result<String> {
    validate_wei_decimal(value)?;
    let parsed = value.parse::<u128>()?;
    Ok(format!("0x{parsed:x}"))
}

pub fn allowed_caip2() -> BTreeSet<String> {
    env::var("VAULT_ALLOWED_CAIP2")
        .unwrap_or_else(|_| "eip155:8453,eip155:11155111".to_string())
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

pub fn validate_allowed_caip2(caip2: &str) -> Result<()> {
    let allowed = allowed_caip2();
    if !allowed.contains(caip2) {
        return Err(anyhow!(
            "caip2 '{caip2}' is not allowed; set VAULT_ALLOWED_CAIP2 to change the allowlist"
        ));
    }
    Ok(())
}

pub fn chain_id_from_caip2(caip2: &str) -> Result<String> {
    let id = caip2
        .strip_prefix("eip155:")
        .ok_or_else(|| anyhow!("only EVM CAIP-2 identifiers are supported for this tool"))?;
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_digit()) {
        return Err(anyhow!("invalid EVM CAIP-2 identifier"));
    }
    Ok(id.to_string())
}
