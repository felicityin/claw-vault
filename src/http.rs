use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use tower_http::cors::{Any, CorsLayer};

use crate::auth::Authenticator;
use crate::mcp::{McpDispatcher, McpOutcome};
use crate::tools::ToolService;

#[derive(Clone)]
struct HttpState {
    dispatcher: Arc<McpDispatcher>,
    authenticator: Authenticator,
}

pub async fn serve_http(service: ToolService) -> Result<()> {
    let bind = env::var("VAULT_HTTP_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let addr: SocketAddr = bind.parse()?;
    let state = HttpState {
        dispatcher: Arc::new(McpDispatcher::new(service)),
        authenticator: Authenticator::from_env()?,
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
    if let Err(response) = authenticate(&state, &headers) {
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
    let context = match authenticate(&state, &headers) {
        Ok(context) => context,
        Err(response) => return response,
    };

    match state.dispatcher.dispatch(payload, context).await {
        McpOutcome::Response(response) => Json(response).into_response(),
        McpOutcome::Notification => StatusCode::ACCEPTED.into_response(),
    }
}

#[allow(clippy::result_large_err)]
fn authenticate(
    state: &HttpState,
    headers: &HeaderMap,
) -> std::result::Result<crate::auth::RequestContext, Response> {
    state
        .authenticator
        .authenticate_headers(headers)
        .map_err(|error| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "unauthorized",
                    "message": error.to_string()
                })),
            )
                .into_response()
        })
}
