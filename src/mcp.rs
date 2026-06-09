use crate::tools::ToolService;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: Option<String>,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

pub enum McpOutcome {
    Response(JsonRpcResponse),
    Notification,
}

pub struct McpDispatcher {
    service: ToolService,
}

impl McpDispatcher {
    pub fn new(service: ToolService) -> Self {
        Self { service }
    }

    pub async fn dispatch(&self, payload: Value) -> McpOutcome {
        match serde_json::from_value::<JsonRpcRequest>(payload) {
            Ok(request) => self.handle_request(request).await,
            Err(error) => McpOutcome::Response(JsonRpcResponse {
                jsonrpc: "2.0",
                id: Value::Null,
                result: None,
                error: Some(JsonRpcError {
                    code: -32700,
                    message: format!("Parse error: {error}"),
                }),
            }),
        }
    }

    async fn handle_request(&self, request: JsonRpcRequest) -> McpOutcome {
        let is_notification = request.id.is_none();
        let id = request.id.unwrap_or(Value::Null);

        if is_notification {
            return McpOutcome::Notification;
        }

        if request.jsonrpc.as_deref() != Some("2.0") {
            return McpOutcome::Response(error_response(id, -32600, "Invalid JSON-RPC version"));
        }

        McpOutcome::Response(match request.method.as_str() {
            "initialize" => ok_response(
                id,
                json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "claw-vault",
                        "version": env!("CARGO_PKG_VERSION")
                    },
                    "instructions": "Use these tools to manage policy-bound Clawup agent wallets backed by Privy. Never create or use wallets without policies."
                }),
            ),
            "tools/list" => ok_response(
                id,
                json!({
                    "tools": self.service.tool_definitions()
                }),
            ),
            "tools/call" => match self.service.call_tool(request.params).await {
                Ok(result) => ok_response(id, result),
                Err(error) => error_response(id, -32603, &error.to_string()),
            },
            _ => error_response(id, -32601, "Method not found"),
        })
    }
}

pub struct McpServer {
    dispatcher: McpDispatcher,
}

impl McpServer {
    pub fn new(service: ToolService) -> Self {
        Self {
            dispatcher: McpDispatcher::new(service),
        }
    }

    pub async fn serve_stdio(self) -> Result<()> {
        let stdin = tokio::io::stdin();
        let stdout = tokio::io::stdout();
        let mut reader = BufReader::new(stdin).lines();
        let mut writer = stdout;

        while let Some(line) = reader.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }

            let payload = match serde_json::from_str::<Value>(&line) {
                Ok(payload) => payload,
                Err(error) => {
                    let response = JsonRpcResponse {
                        jsonrpc: "2.0",
                        id: Value::Null,
                        result: None,
                        error: Some(JsonRpcError {
                            code: -32700,
                            message: format!("Parse error: {error}"),
                        }),
                    };
                    let encoded = serde_json::to_vec(&response)?;
                    writer.write_all(&encoded).await?;
                    writer.write_all(b"\n").await?;
                    writer.flush().await?;
                    continue;
                }
            };

            if let McpOutcome::Response(response) = self.dispatcher.dispatch(payload).await {
                let encoded = serde_json::to_vec(&response)?;
                writer.write_all(&encoded).await?;
                writer.write_all(b"\n").await?;
                writer.flush().await?;
            }
        }

        Ok(())
    }
}

fn ok_response(id: Value, result: Value) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: Some(result),
        error: None,
    }
}

fn error_response(id: Value, code: i64, message: &str) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(JsonRpcError {
            code,
            message: message.to_string(),
        }),
    }
}
