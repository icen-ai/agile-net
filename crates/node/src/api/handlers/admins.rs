//! Admin management (list/create/delete/change password)

use super::audit;
use super::auth::validate_admin_credentials;
use crate::api::extractors::{AdminAuth, ClientIp};
use crate::api::{ApiState, codes, err, ok, offload};
use crate::db::hash_password;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::Response,
};
use serde::Deserialize;
use serde_json::json;

pub async fn list_admins(AdminAuth(_): AdminAuth, State(state): State<ApiState>) -> Response {
    match state.db_call(|db| db.list_admins()).await {
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
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        ),
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
    let uname = req.username.clone();
    let exists = state
        .db_call(move |db| db.get_admin_by_username(&uname))
        .await
        .unwrap_or(None)
        .is_some();
    if exists {
        return err(
            StatusCode::CONFLICT,
            codes::DUPLICATE,
            "admin username already exists",
        );
    }
    // argon2id hash offloaded to the blocking pool
    let password = req.password.clone();
    let hash = match offload(move || hash_password(&password)).await {
        Ok(h) => h,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            );
        }
    };
    let uname = req.username.clone();
    match state
        .db_call(move |db| db.create_admin(&uname, &hash))
        .await
    {
        Ok(admin) => {
            audit(
                &state,
                &claims,
                &ip,
                "admin.create",
                Some(&admin.id),
                &req.username,
            )
            .await;
            ok(json!({
                "id": admin.id,
                "username": admin.username,
                "created_at": admin.created_at,
            }))
        }
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        ),
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
    if state.db_call(|db| db.count_admins()).await.unwrap_or(0) <= 1 {
        return err(
            StatusCode::BAD_REQUEST,
            codes::BAD_REQUEST,
            "cannot delete the last admin",
        );
    }
    let aid = id.clone();
    let Some(target) = state
        .db_call(move |db| db.get_admin_by_id(&aid))
        .await
        .unwrap_or(None)
    else {
        return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "admin not found");
    };
    match state.db_call(move |db| db.delete_admin(&id)).await {
        Ok(_) => {
            // Revoke all sessions of the deleted admin
            let jwt = state.jwt.clone();
            let aid = target.id.clone();
            let _ = offload(move || jwt.revoke_all(&aid)).await;
            audit(
                &state,
                &claims,
                &ip,
                "admin.delete",
                Some(&target.id),
                &target.username,
            )
            .await;
            ok(json!(null))
        }
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        ),
    }
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

/// Change own password (any authenticated admin; all own refresh tokens revoked on success).
pub async fn change_password(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<ChangePasswordRequest>,
) -> Response {
    let sub = claims.sub.clone();
    let Some(admin) = state
        .db_call(move |db| db.get_admin_by_id(&sub))
        .await
        .unwrap_or(None)
    else {
        return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "admin not found");
    };
    // argon2id verify/hash offloaded to the blocking pool
    let (old, hash) = (req.old_password.clone(), admin.password_hash.clone());
    let verified = offload(move || crate::db::verify_password(&old, &hash))
        .await
        .unwrap_or(false);
    if !verified {
        return err(
            StatusCode::UNAUTHORIZED,
            codes::INVALID_CREDENTIALS,
            "old password incorrect",
        );
    }
    if let Err(msg) = validate_admin_credentials(&claims.username, &req.new_password) {
        return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, msg);
    }
    let new_password = req.new_password.clone();
    let hash = match offload(move || hash_password(&new_password)).await {
        Ok(h) => h,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            );
        }
    };
    let sub = claims.sub.clone();
    if let Err(e) = state
        .db_call(move |db| db.update_admin_password(&sub, &hash))
        .await
    {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        );
    }
    let jwt = state.jwt.clone();
    let sub = claims.sub.clone();
    let _ = offload(move || jwt.revoke_all(&sub)).await;
    audit(
        &state,
        &claims,
        &ip,
        "admin.change_password",
        Some(&claims.sub),
        "",
    )
    .await;
    ok(json!({ "changed": true, "message": "请使用新密码重新登录" }))
}
