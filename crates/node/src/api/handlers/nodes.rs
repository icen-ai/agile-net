//! Node API Handlers

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
pub struct CreateNodeRequest {
    pub name: String,
    pub token: String,
}

pub async fn list_nodes(
    _claims: AuthClaims,
    State(state): State<ApiState>,
) -> impl IntoResponse {
    match state.db.list_nodes() {
        Ok(nodes) => (StatusCode::OK, Json(json!({ "nodes": nodes }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn create_node(
    _claims: AuthClaims,
    State(state): State<ApiState>,
    Json(req): Json<CreateNodeRequest>,
) -> impl IntoResponse {
    match state.db.create_node(&req.name, &req.token) {
        Ok(node) => (StatusCode::CREATED, Json(node)).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn delete_node(
    _claims: AuthClaims,
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.db.delete_node(&id) {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}
