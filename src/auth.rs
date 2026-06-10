use std::collections::BTreeSet;
use std::env;

use anyhow::{Result, anyhow};
use axum::http::HeaderMap;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::Deserialize;

use crate::validation::validate_agent_id;

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub user_id: String,
    pub agent_id: String,
    pub scopes: BTreeSet<String>,
    pub request_id: Option<String>,
}

impl RequestContext {
    pub fn require_scope(&self, scope: &str) -> Result<()> {
        if self.scopes.contains(scope) {
            Ok(())
        } else {
            Err(anyhow!("forbidden: missing required scope '{scope}'"))
        }
    }
}

#[derive(Clone)]
pub struct Authenticator {
    mode: AuthMode,
}

#[derive(Clone)]
enum AuthMode {
    /// Production-style JWT mode. Current implementation supports HS256 shared-secret JWTs
    Jwt {
        secret: String,
        issuer: Option<String>,
        audience: Option<String>,
    },
    /// Local/dev mode
    ApiKey {
        api_key: Option<String>,
        user_id: String,
        agent_id: String,
    },
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Claims {
    sub: Option<String>,
    user_id: Option<String>,
    agent_id: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    scope: Option<String>,
    exp: usize,
    #[serde(default)]
    nbf: Option<usize>,
    #[serde(default)]
    jti: Option<String>,
}

impl Authenticator {
    pub fn from_env() -> Result<Self> {
        let mode = env::var("VAULT_AUTH_MODE").unwrap_or_else(|_| {
            if env::var("VAULT_JWT_SECRET").is_ok() {
                "jwt".to_string()
            } else {
                "api_key".to_string()
            }
        });

        let mode = match mode.as_str() {
            "jwt" => AuthMode::Jwt {
                secret: env::var("VAULT_JWT_SECRET")?,
                issuer: env::var("VAULT_JWT_ISSUER").ok(),
                audience: env::var("VAULT_JWT_AUDIENCE").ok(),
            },
            "api_key" => AuthMode::ApiKey {
                api_key: env::var("VAULT_MCP_API_KEY").ok().filter(|v| !v.is_empty()),
                user_id: env::var("VAULT_USER_ID").unwrap_or_else(|_| "dev-user".to_string()),
                agent_id: env::var("VAULT_AGENT_ID").unwrap_or_else(|_| "dev-agent".to_string()),
            },
            other => return Err(anyhow!("unsupported VAULT_AUTH_MODE '{other}'")),
        };

        Ok(Self { mode })
    }

    pub fn dev_context_from_env() -> RequestContext {
        RequestContext {
            user_id: env::var("VAULT_USER_ID").unwrap_or_else(|_| "dev-user".to_string()),
            agent_id: env::var("VAULT_AGENT_ID").unwrap_or_else(|_| "dev-agent".to_string()),
            scopes: [
                "wallet:read",
                "wallet:create",
                "wallet:sign",
                "wallet:send",
                "wallet:tx:read",
                "policy:read",
                "policy:create",
                "policy:update",
                "policy:delete",
                "policy:rule:create",
                "policy:rule:update",
                "policy:rule:delete",
                "policy:attach",
                "policy:detach",
            ]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect(),
            request_id: None,
        }
    }

    pub fn authenticate_headers(&self, headers: &HeaderMap) -> Result<RequestContext> {
        match &self.mode {
            AuthMode::Jwt {
                secret,
                issuer,
                audience,
            } => self.authenticate_jwt(headers, secret, issuer.as_deref(), audience.as_deref()),
            AuthMode::ApiKey {
                api_key,
                user_id,
                agent_id,
            } => self.authenticate_api_key(headers, api_key.as_deref(), user_id, agent_id),
        }
    }

    fn authenticate_jwt(
        &self,
        headers: &HeaderMap,
        secret: &str,
        issuer: Option<&str>,
        audience: Option<&str>,
    ) -> Result<RequestContext> {
        let token = bearer_token(headers).ok_or_else(|| anyhow!("missing bearer token"))?;
        let mut validation = Validation::new(Algorithm::HS256);
        if let Some(issuer) = issuer {
            validation.set_issuer(&[issuer]);
        }
        if let Some(audience) = audience {
            validation.set_audience(&[audience]);
        } else {
            validation.validate_aud = false;
        }

        let data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )?;
        let claims = data.claims;
        let user_id = claims
            .user_id
            .or(claims.sub)
            .ok_or_else(|| anyhow!("JWT is missing user_id/sub"))?;
        validate_agent_id(&claims.agent_id)?;
        let mut scopes: BTreeSet<String> = claims.scopes.into_iter().collect();
        if let Some(scope) = claims.scope {
            scopes.extend(scope.split_whitespace().map(ToOwned::to_owned));
        }

        Ok(RequestContext {
            user_id,
            agent_id: claims.agent_id,
            scopes,
            request_id: claims.jti,
        })
    }

    fn authenticate_api_key(
        &self,
        headers: &HeaderMap,
        expected: Option<&str>,
        user_id: &str,
        agent_id: &str,
    ) -> Result<RequestContext> {
        if let Some(expected) = expected {
            let provided = headers
                .get("x-api-key")
                .and_then(|value| value.to_str().ok())
                .or_else(|| bearer_token(headers));
            if provided != Some(expected) {
                return Err(anyhow!("missing or invalid MCP API key"));
            }
        }

        Ok(RequestContext {
            user_id: user_id.to_string(),
            agent_id: agent_id.to_string(),
            scopes: [
                "wallet:read",
                "wallet:create",
                "wallet:sign",
                "wallet:send",
                "wallet:tx:read",
                "policy:read",
                "policy:create",
                "policy:update",
                "policy:delete",
                "policy:rule:create",
                "policy:rule:update",
                "policy:rule:delete",
                "policy:attach",
                "policy:detach",
            ]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect(),
            request_id: header_value(headers, "x-request-id"),
        })
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}
