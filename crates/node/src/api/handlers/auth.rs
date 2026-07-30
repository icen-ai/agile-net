//! Auth API Handlers

use crate::api::ApiState;
use crate::auth::jwt::{generate_token, AuthClaims};
use crate::db::verify_password;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub username: String,
    pub role: String,
}

pub async fn login(
    State(state): State<ApiState>,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    let user = match state.db.get_user_by_username(&req.username) {
        Ok(Some(u)) => u,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "invalid username or password"})),
            )
                .into_response();
        }
    };

    match verify_password(&req.password, &user.password_hash) {
        Ok(true) => {
            let token = match generate_token(&user.id, &user.username, user.role.clone()) {
                Ok(t) => t,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": e.to_string()})),
                    )
                        .into_response()
                }
            };

            (
                StatusCode::OK,
                Json(LoginResponse {
                    token,
                    username: user.username,
                    role: user.role.as_str().to_string(),
                }),
            )
                .into_response()
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid username or password"})),
        )
            .into_response(),
    }
}

pub async fn me(AuthClaims(claims): AuthClaims) -> impl IntoResponse {
    Json(json!({
        "id": claims.sub,
        "username": claims.username,
        "role": claims.role,
    }))
}
