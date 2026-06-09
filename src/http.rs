use crate::mcp::{McpDispatcher, McpOutcome};
use crate::tools::ToolService;
use anyhow::Result;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};

#[derive(Clone)]
struct HttpState {
    dispatcher: Arc<McpDispatcher>,
    api_key: Option<String>,
}

pub async fn serve_http(service: ToolService) -> Result<()> {
    let bind = env::var("VAULT_HTTP_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let addr: SocketAddr = bind.parse()?;
    let state = HttpState {
        dispatcher: Arc::new(McpDispatcher::new(service)),
        api_key: env::var("VAULT_MCP_API_KEY")
            .ok()
            .filter(|v| !v.is_empty()),
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any);

    let app = Router::new()
        .route("/health", get(health))
        .route("/mcp", post(mcp_post).get(mcp_get))
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("claw-vault HTTP MCP listening on http://{addr}/mcp");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> impl IntoResponse {
    Json(json!({
        "ok": true,
        "service": "claw-vault",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

async fn mcp_get(State(state): State<HttpState>, headers: HeaderMap) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }

    (
        StatusCode::OK,
        Json(json!({
            "name": "claw-vault",
            "version": env!("CARGO_PKG_VERSION"),
            "transport": "http",
            "endpoint": "/mcp"
        })),
    )
        .into_response()
}

async fn mcp_post(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }

    match state.dispatcher.dispatch(payload).await {
        McpOutcome::Response(response) => Json(response).into_response(),
        McpOutcome::Notification => StatusCode::ACCEPTED.into_response(),
    }
}

fn authorize(state: &HttpState, headers: &HeaderMap) -> std::result::Result<(), Response> {
    let Some(expected) = &state.api_key else {
        return Ok(());
    };

    let provided = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .or_else(|| bearer_token(headers));

    if provided == Some(expected.as_str()) {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "unauthorized",
                "message": "Missing or invalid MCP API key"
            })),
        )
            .into_response())
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}
