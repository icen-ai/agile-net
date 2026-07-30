//! Groups API Handlers

use crate::api::ApiState;
use crate::auth::jwt::AuthClaims;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub remark: Option<String>,
}

pub async fn list_groups(_claims: AuthClaims, State(state): State<ApiState>) -> impl IntoResponse {
    match state.db.list_groups() {
        Ok(groups) => (StatusCode::OK, Json(json!({ "groups": groups }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn create_group(
    _claims: AuthClaims,
    State(state): State<ApiState>,
    Json(req): Json<CreateGroupRequest>,
) -> impl IntoResponse {
    let remark = req.remark.as_deref().unwrap_or("");
    match state.db.create_group(&req.name, remark) {
        Ok(group) => (StatusCode::CREATED, Json(json!(group))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn delete_group(
    _claims: AuthClaims,
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.db.delete_group(&id) {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}
