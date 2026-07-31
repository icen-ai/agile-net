//! Admin 管理员管理（列表/新建/删除/修改密码）

use super::audit;
use crate::api::extractors::{AdminAuth, ClientIp};
use crate::api::{ApiState, codes, err, ok};
use crate::db::hash_password;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::Response,
};
use serde::Deserialize;
use serde_json::json;

pub async fn list_admins(
    AdminAuth(_): AdminAuth,
    State(state): State<ApiState>,
) -> Response {
    match state.db.list_admins() {
        Ok(admins) => {
            let items: Vec<_> = admins
                .into_iter()
                .map(|a| {
                    json!({
                        "id": a.id,
                        "username": a.username,
                        "created_at": a.created_at,
                        "updated_at": a.updated_at,
                    })
                })
                .collect();
            ok(json!({ "items": items }))
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct CreateAdminRequest {
    pub username: String,
    pub password: String,
}

pub async fn create_admin(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<CreateAdminRequest>,
) -> Response {
    if let Err(msg) = validate_admin_credentials(&req.username, &req.password) {
        return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, msg);
    }
    if state
        .db
        .get_admin_by_username(&req.username)
        .unwrap_or(None)
        .is_some()
    {
        return err(
            StatusCode::CONFLICT,
            codes::DUPLICATE,
            "admin username already exists",
        );
    }
    let hash = match hash_password(&req.password) {
        Ok(h) => h,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string()),
    };
    match state.db.create_admin(&req.username, &hash) {
        Ok(admin) => {
            audit(
                &state,
                &claims,
                &ip,
                "admin.create",
                Some(&admin.id),
                &req.username,
            );
            ok(json!({
                "id": admin.id,
                "username": admin.username,
                "created_at": admin.created_at,
            }))
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string()),
    }
}

pub async fn delete_admin(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> Response {
    if id == claims.sub {
        return err(
            StatusCode::BAD_REQUEST,
            codes::BAD_REQUEST,
            "cannot delete yourself",
        );
    }
    if state.db.count_admins().unwrap_or(0) <= 1 {
        return err(
            StatusCode::BAD_REQUEST,
            codes::BAD_REQUEST,
            "cannot delete the last admin",
        );
    }
    let Some(target) = state.db.get_admin_by_id(&id).unwrap_or(None) else {
        return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "admin not found");
    };
    match state.db.delete_admin(&id) {
        Ok(_) => {
            // 吊销被删管理员的全部会话
            let _ = state.jwt.revoke_all(&id);
            audit(
                &state,
                &claims,
                &ip,
                "admin.delete",
                Some(&id),
                &target.username,
            );
            ok(json!(null))
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

/// 修改自己的密码（任意已认证 admin；成功后吊销本人全部 refresh token）。
pub async fn change_password(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<ChangePasswordRequest>,
) -> Response {
    let Some(admin) = state.db.get_admin_by_id(&claims.sub).unwrap_or(None) else {
        return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "admin not found");
    };
    if !crate::db::verify_password(&req.old_password, &admin.password_hash).unwrap_or(false) {
        return err(
            StatusCode::UNAUTHORIZED,
            codes::INVALID_CREDENTIALS,
            "old password incorrect",
        );
    }
    if let Err(msg) = validate_admin_credentials(&claims.username, &req.new_password) {
        return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, msg);
    }
    let hash = match hash_password(&req.new_password) {
        Ok(h) => h,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string()),
    };
    if let Err(e) = state.db.update_admin_password(&claims.sub, &hash) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string());
    }
    let _ = state.jwt.revoke_all(&claims.sub);
    audit(&state, &claims, &ip, "admin.change_password", Some(&claims.sub), "");
    ok(json!({ "changed": true, "message": "请使用新密码重新登录" }))
}

fn validate_admin_credentials(username: &str, password: &str) -> Result<(), String> {
    if username.is_empty() || username.len() > 32 {
        return Err("username must be 1-32 characters".into());
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("username may only contain [a-zA-Z0-9_-]".into());
    }
    if password.len() < 10 {
        return Err("password must be at least 10 characters".into());
    }
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    if !(has_lower && has_upper && has_digit) {
        return Err("password must contain lower, upper and digit characters".into());
    }
    Ok(())
}
