//! Relay Token API Handlers（对应 docs/api/node.md 的 relay-tokens 部分）
//!
//! Token 由服务端生成（`psk_` + 48 位），数据库只存 SHA-256 哈希与前缀，
//! 全文仅创建时返回一次。

use super::audit;
use crate::api::extractors::{AdminAuth, ClientIp};
use crate::api::{ApiState, codes, err, ok, ok_created};
use crate::db::{generate_relay_token, sha256_hex};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::Response,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct CreateTokenRequest {
    #[serde(default)]
    pub remark: String,
}

pub async fn create_token(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<CreateTokenRequest>,
) -> Response {
    if req.remark.len() > 256 {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "remark too long (max 256)",
        );
    }

    let token = generate_relay_token();
    let token_hash = sha256_hex(token.as_bytes());
    let prefix = format!("{}****", &token[..8]);

    match state
        .db
        .create_relay_token(&token_hash, &prefix, &req.remark)
    {
        Ok(record) => {
            audit(
                &state,
                &claims,
                &ip,
                "relay_token.create",
                Some(&record.id),
                &req.remark,
            );
            ok_created(json!({
                "id": record.id,
                "token": token,
                "token_prefix": prefix,
                "remark": record.remark,
                "created_at": record.created_at,
            }))
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string()),
    }
}

pub async fn list_tokens(
    AdminAuth(_): AdminAuth,
    State(state): State<ApiState>,
) -> Response {
    match state.db.list_relay_tokens() {
        Ok(items) => ok(json!({ "items": items })),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string()),
    }
}

pub async fn delete_token(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> Response {
    match state.db.delete_relay_token(&id) {
        Ok(_) => {
            audit(&state, &claims, &ip, "relay_token.delete", Some(&id), "");
            ok(json!(null))
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string()),
    }
}
