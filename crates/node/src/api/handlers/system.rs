//! System API Handlers

use crate::api::ApiState;
use crate::auth::jwt::AuthClaims;
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct SetConfigRequest {
    pub key: String,
    pub value: String,
    pub description: Option<String>,
}

pub async fn get_configs(_claims: AuthClaims, State(state): State<ApiState>) -> impl IntoResponse {
    let audit_logs = state.db.list_audit_logs().unwrap_or_default();
    (
        StatusCode::OK,
        Json(json!({
            "version": env!("CARGO_PKG_VERSION"),
            "status": "running",
            "audit_logs": audit_logs
        })),
    )
        .into_response()
}

pub async fn set_config(
    _claims: AuthClaims,
    State(state): State<ApiState>,
    Json(req): Json<SetConfigRequest>,
) -> impl IntoResponse {
    match state
        .db
        .set_config(&req.key, &req.value, req.description.as_deref())
    {
        Ok(_) => (StatusCode::OK, Json(json!({ "success": true }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}
