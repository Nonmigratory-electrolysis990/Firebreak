use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::Value;
use std::sync::Arc;

use super::protocol::*;
use crate::{tools, AppState};

pub async fn handle_mcp(
    State(state): State<Arc<AppState>>,
    body: String,
) -> Response {
    let request: JsonRpcRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => {
            return Json(JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id: None,
                result: None,
                error: Some(JsonRpcError {
                    code: -32700,
                    message: format!("Parse error: {e}"),
                    data: None,
                }),
            })
            .into_response();
        }
    };

    if request.id.is_none() {
        return axum::http::StatusCode::ACCEPTED.into_response();
    }

    let response = dispatch(&request, &state).await;
    Json(response).into_response()
}

pub async fn dispatch(req: &JsonRpcRequest, state: &AppState) -> JsonRpcResponse {
    match req.method.as_str() {
        "initialize" => success(req, initialize()),
        "ping" => success(req, Value::Object(Default::default())),
        "tools/list" => success(req, tools_list()),
        "tools/call" => success(req, tools_call(req.params.as_ref(), state).await),
        _ => JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: req.id.clone(),
            result: None,
            error: Some(JsonRpcError {
                code: -32601,
                message: format!("Method not found: {}", req.method),
                data: None,
            }),
        },
    }
}

fn success(req: &JsonRpcRequest, result: Value) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".into(),
        id: req.id.clone(),
        result: Some(result),
        error: None,
    }
}

fn initialize() -> Value {
    serde_json::to_value(InitializeResult {
        protocol_version: "2025-03-26".into(),
        capabilities: ServerCapabilities {
            tools: Some(ToolsCapability {}),
        },
        server_info: ServerInfo {
            name: "Firebreak".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        },
    })
    .unwrap()
}

fn tools_list() -> Value {
    serde_json::to_value(ToolsListResult {
        tools: tools::definitions(),
    })
    .unwrap()
}

async fn tools_call(params: Option<&Value>, state: &AppState) -> Value {
    let empty = Value::Null;
    let params = params.unwrap_or(&empty);
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| Value::Object(Default::default()));

    serde_json::to_value(tools::call(name, &args, state).await).unwrap()
}
