# Claw Vault

Claw Vault is a Rust MCP server for Clawup agent wallets backed by Privy.

It exposes constrained agent-facing wallet tools instead of the full Privy admin surface. Wallet creation requires a policy, transactions are validated before calling Privy, and wallet ownership is stored in MySQL by `user_id + agent_id`.

## Tools

Wallet tools:

- `create_agent_wallet`
- `list_agent_wallets`
- `get_agent_wallet`
- `get_agent_wallet_balance`
- `send_agent_transaction`
- `sign_agent_message`
- `get_agent_transaction`

Policy tools:

- `create_wallet_policy`
- `list_wallet_policies`
- `get_wallet_policy`
- `update_wallet_policy`
- `delete_wallet_policy`
- `create_wallet_policy_rule`
- `list_wallet_policy_rules`
- `get_wallet_policy_rule`
- `update_wallet_policy_rule`
- `delete_wallet_policy_rule`
- `attach_policy_to_wallet`
- `detach_policy_from_wallet`
- `list_wallet_policies_for_wallet`

## Configuration

Required:

```sh
export PRIVY_APP_ID=...
export PRIVY_APP_SECRET=...
export VAULT_DATABASE_URL=mysql://vault_user:vault_password@127.0.0.1:3306/claw_vault
```

Auth modes:

```sh
# Production-style JWT mode. Current implementation supports HS256 shared-secret JWTs.
export VAULT_AUTH_MODE=jwt
export VAULT_JWT_SECRET=...
export VAULT_JWT_ISSUER=https://clawup.example.com
export VAULT_JWT_AUDIENCE=claw-vault

# Local/dev mode.
export VAULT_AUTH_MODE=api_key
export VAULT_MCP_API_KEY=dev-secret
export VAULT_USER_ID=user_dev
export VAULT_AGENT_ID=agent_dev
```

Optional:

```sh
export PRIVY_API_BASE_URL=https://api.privy.io/v1
export VAULT_ALLOWED_CAIP2=eip155:2345,eip155:48816
export VAULT_DEFAULT_MAX_NATIVE_UNITS=10000000000000 # 0.00001 BTC or 0.00001 ETH
export VAULT_TRANSPORT=stdio
export VAULT_HTTP_BIND=0.0.0.0:8080
export VAULT_DB_MAX_CONNECTIONS=5
```

## MySQL

Create a database and user before starting the server:

```sql
CREATE DATABASE claw_vault CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'vault_user'@'%' IDENTIFIED BY 'vault_password';
GRANT ALL PRIVILEGES ON claw_vault.* TO 'vault_user'@'%';
FLUSH PRIVILEGES;
```

The server automatically creates the `wallets`, `wallet_audit_logs`, `wallet_policies`, `wallet_policy_rules`, `wallet_policy_links`, and `policy_audit_logs` tables on startup.

Core ownership model:

```text
JWT/API-key context -> user_id + agent_id
wallets.id          -> internal wallet id used by tools
provider            -> privy
provider_wallet_id  -> Privy wallet id
```

Sensitive wallet calls are recorded in `wallet_audit_logs`. Policy, rule, attach, and detach calls are recorded in `policy_audit_logs`.

Users may freely manage the raw Privy policy JSON and raw Privy rule JSON for policies owned by their authenticated `user_id + agent_id`. Claw Vault validates ownership, scopes, and minimal JSON shape; it does not apply risk restrictions to user-owned policy/rule content. Deleting a policy or rule requires an explicit `confirm_delete` value (`delete policy` or `delete policy rule`) to prevent accidental guardrail removal.

## JWT Claims and Scopes

In `VAULT_AUTH_MODE=jwt`, requests to `/mcp` must include:

```http
Authorization: Bearer <jwt>
```

The current implementation verifies HS256 JWTs with `VAULT_JWT_SECRET`. The token must include `agent_id` and either `user_id` or `sub`:

```json
{
  "sub": "user_123",
  "user_id": "user_123",
  "agent_id": "agent_456",
  "iss": "https://clawup.example.com",
  "aud": "claw-vault",
  "exp": 1760000000,
  "scopes": ["wallet:read", "wallet:create", "wallet:send"]
}
```

A space-delimited `scope` claim is also accepted:

```json
{
  "sub": "user_123",
  "agent_id": "agent_456",
  "scope": "wallet:read wallet:create wallet:send"
}
```

Scope requirements:

```text
wallet:read          list_agent_wallets, get_agent_wallet, get_agent_wallet_balance
wallet:create        create_agent_wallet
wallet:send          send_agent_transaction
wallet:sign          sign_agent_message
wallet:tx:read       get_agent_transaction
policy:read          list/get policy and rule tools, list_wallet_policies_for_wallet
policy:create        create_wallet_policy
policy:update        update_wallet_policy
policy:delete        delete_wallet_policy
policy:rule:create   create_wallet_policy_rule
policy:rule:update   update_wallet_policy_rule
policy:rule:delete   delete_wallet_policy_rule
policy:attach        attach_policy_to_wallet
policy:detach        detach_policy_from_wallet
```

Tools do not accept `user_id` or `agent_id` as trusted inputs. Ownership comes from the authenticated request context.

## Local stdio

Stdio uses the configured context from `VAULT_USER_ID` and `VAULT_AGENT_ID`.

```sh
export PRIVY_APP_ID=...
export PRIVY_APP_SECRET=...
export VAULT_DATABASE_URL=mysql://vault_user:vault_password@127.0.0.1:3306/claw_vault
export VAULT_USER_ID=user_dev
export VAULT_AGENT_ID=agent_dev
cargo run --release
```

## Local HTTP Debugging

Start the HTTP MCP server locally:

```sh
export PRIVY_APP_ID=...
export PRIVY_APP_SECRET=...
export VAULT_DATABASE_URL=mysql://vault_user:vault_password@127.0.0.1:3306/claw_vault
export VAULT_TRANSPORT=http
export VAULT_AUTH_MODE=api_key
export VAULT_HTTP_BIND=127.0.0.1:8080
export VAULT_MCP_API_KEY=dev-secret
export VAULT_USER_ID=user_dev
export VAULT_AGENT_ID=agent_dev
cargo run
```

List MCP tools:

```sh
curl \
  -H 'x-api-key: dev-secret' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  http://127.0.0.1:8080/mcp
```

Create a wallet for the authenticated `user_id + agent_id` context:

```sh
curl \
  -H 'x-api-key: dev-secret' \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "create_agent_wallet",
      "arguments": {
        "chain_type": "ethereum"
      }
    }
  }' \
  http://127.0.0.1:8080/mcp
```

When `policy_id` is omitted, the server creates a default Privy policy for the requested `chain_type` before creating the wallet. `chain_type` is optional and defaults to `ethereum`.

Default policy behavior:

```text
ethereum: max native units per transaction <= VAULT_DEFAULT_MAX_NATIVE_UNITS
other chain_type values: deny all transactions by default
```

For non-`ethereum` chain types, use the policy/rule tools to replace or relax the default deny-all rules before expecting the wallet to transact.

If the same authenticated `user_id + agent_id` already has a wallet for that Privy `chain_type`, `create_agent_wallet` returns the existing wallet address with `existing: true` and does not create another Privy wallet. Otherwise, the response includes internal `policy.id`, `policy_rules`, and `wallet.id`. Use `wallet.id` for later wallet operations.

To use a custom policy instead, create it with `create_wallet_policy`, then pass the internal `policy_id` to `create_agent_wallet`:

```json
{
  "name": "create_agent_wallet",
  "arguments": {
    "policy_id": 1,
    "chain_type": "ethereum"
  }
}
```

Tool calls that operate on a wallet use the internal `wallet_id` from the `wallets.id` column. They do not accept Privy's wallet id directly. The service loads the wallet with:

```sql
WHERE id = ?
AND user_id = ?
AND agent_id = ?
```

and only then calls Privy with `provider_wallet_id`.

Create a raw policy rule under an owned policy:

```sh
curl \
  -H 'x-api-key: dev-secret' \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc": "2.0",
    "id": 4,
    "method": "tools/call",
    "params": {
      "name": "create_wallet_policy_rule",
      "arguments": {
        "policy_id": 1,
        "rule": {
          "name": "allowed chain",
          "method": "eth_sendTransaction",
          "conditions": [{
            "field_source": "ethereum_transaction",
            "field": "chain_id",
            "operator": "eq",
            "value": "2345"
          }],
          "action": "ALLOW"
        }
      }
    }
  }' \
  http://127.0.0.1:8080/mcp
```

Fetch a wallet binding:

```sh
curl \
  -H 'x-api-key: dev-secret' \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "get_agent_wallet",
      "arguments": {
        "wallet_id": 1
      }
    }
  }' \
  http://127.0.0.1:8080/mcp
```

List wallets for the authenticated agent:

```sh
curl \
  -H 'x-api-key: dev-secret' \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "list_agent_wallets",
      "arguments": {}
    }
  }' \
  http://127.0.0.1:8080/mcp
```

## HTTP Deployment for ClawUp

ClawUp requires a public HTTPS MCP endpoint with `http` or `sse` transport. For this server, deploy the HTTP transport and submit the public `/mcp` URL.

### 1. Build the server

```sh
cargo build --release
```

### 2. Start HTTP mode

```sh
export PRIVY_APP_ID=...
export PRIVY_APP_SECRET=...
export VAULT_DATABASE_URL=mysql://vault_user:vault_password@127.0.0.1:3306/claw_vault
export VAULT_TRANSPORT=http
export VAULT_AUTH_MODE=jwt
export VAULT_JWT_SECRET=...
export VAULT_JWT_ISSUER=https://clawup.example.com
export VAULT_JWT_AUDIENCE=claw-vault
export VAULT_HTTP_BIND=127.0.0.1:8080
./target/release/claw-vault
```

Use `127.0.0.1:8080` when a reverse proxy terminates TLS on the same host. Use `0.0.0.0:8080` only when the service must listen on the network interface directly.

### 3. Put it behind HTTPS

Example Nginx reverse proxy:

```nginx
server {
    listen 443 ssl;
    server_name wallet.example.com;

    ssl_certificate /etc/letsencrypt/live/wallet.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/wallet.example.com/privkey.pem;

    location /health {
        proxy_pass http://127.0.0.1:8080/health;
    }

    location /mcp {
        proxy_pass http://127.0.0.1:8080/mcp;
        proxy_set_header Host $host;
        proxy_set_header Authorization $http_authorization;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### 4. Verify the endpoint

Health check:

```sh
curl https://wallet.example.com/health
```

Authorized MCP tool listing with JWT:

```sh
curl \
  -H 'Authorization: Bearer <jwt>' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  https://wallet.example.com/mcp
```

### 5. Submit to ClawUp

In ClawUp Dashboard, submit the MCP tool with:

```text
Name: Claw Vault
Endpoint URL: https://wallet.example.com/mcp
Transport: http
Auth: bearer / jwt gateway
```

If ClawUp does not issue JWTs directly to third-party MCP servers, place this service behind a gateway that validates ClawUp identity and mints the short-lived JWT expected by Claw Vault.

Do not submit `PRIVY_APP_SECRET` to ClawUp. Privy credentials stay only in this server's deployment environment.

## Notes

This implementation uses Privy REST calls directly. That keeps the Privy boundary small and stable for MCP submission. The client module can be replaced with `privy-rs` generated types later without changing the MCP tool contract.
