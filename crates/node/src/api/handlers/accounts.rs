//! Accounts API Handlers

use crate::api::ApiState;
use crate::auth::jwt::AuthClaims;
use crate::db::hash_password;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct CreateAccountRequest {
    pub username: String,
    pub password: String,
    pub group_id: String,
    pub remark: Option<String>,
}

pub async fn list_accounts(_claims: AuthClaims, State(state): State<ApiState>) -> impl IntoResponse {
    match state.db.list_accounts() {
        Ok(accounts) => (StatusCode::OK, Json(json!({ "accounts": accounts }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn create_account(
    _claims: AuthClaims,
    State(state): State<ApiState>,
    Json(req): Json<CreateAccountRequest>,
) -> impl IntoResponse {
    let password_hash = match hash_password(&req.password) {
        Ok(h) => h,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    };
    let remark = req.remark.as_deref().unwrap_or("");
    match state.db.create_account(&req.username, &password_hash, &req.group_id, remark) {
        Ok(account) => (StatusCode::CREATED, Json(json!(account))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn delete_account(
    _claims: AuthClaims,
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.db.delete_account(&id) {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}
