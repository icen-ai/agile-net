//! Axum 提取器：角色化认证与客户端 IP

use crate::api::{ApiState, codes, err};
use crate::auth::jwt::Claims;
use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{StatusCode, header, request::Parts},
    response::Response,
};
use std::net::{IpAddr, SocketAddr};

/// 从请求头解析并验证 Bearer JWT，返回 Claims。
fn extract_claims(parts: &Parts) -> Result<Claims, Response> {
    let auth_header = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            err(
                StatusCode::UNAUTHORIZED,
                codes::INVALID_CREDENTIALS,
                "missing authorization header",
            )
        })?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, codes::INVALID_CREDENTIALS, "invalid authorization scheme"))?;

    let state = parts
        .extensions
        .get::<ApiState>()
        .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, "state unavailable"))?;

    let claims = state.jwt.verify(token).map_err(|_| {
        err(
            StatusCode::UNAUTHORIZED,
            codes::TOKEN_EXPIRED,
            "invalid or expired token",
        )
    })?;

    if claims.typ != "access" {
        return Err(err(
            StatusCode::UNAUTHORIZED,
            codes::INVALID_CREDENTIALS,
            "access token required",
        ));
    }

    Ok(claims)
}

/// Admin 角色认证（管理面 API 强制）。
pub struct AdminAuth(pub Claims);

impl FromRequestParts<ApiState> for AdminAuth {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        parts.extensions.insert(state.clone());
        let claims = extract_claims(parts)?;
        if claims.role != "admin" {
            return Err(err(
                StatusCode::FORBIDDEN,
                codes::ADMIN_ONLY,
                "admin role required",
            ));
        }
        Ok(AdminAuth(claims))
    }
}

/// Client 角色认证（客户端 API 强制）。
pub struct ClientAuth(pub Claims);

impl FromRequestParts<ApiState> for ClientAuth {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        parts.extensions.insert(state.clone());
        let claims = extract_claims(parts)?;
        if claims.role != "client" {
            return Err(err(
                StatusCode::FORBIDDEN,
                codes::FORBIDDEN,
                "client role required",
            ));
        }
        Ok(ClientAuth(claims))
    }
}

/// 任意已认证身份。
pub struct AnyAuth(pub Claims);

impl FromRequestParts<ApiState> for AnyAuth {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        parts.extensions.insert(state.clone());
        Ok(AnyAuth(extract_claims(parts)?))
    }
}

/// 客户端来源 IP（需要 ConnectInfo）。
pub struct ClientIp(pub IpAddr);

impl FromRequestParts<ApiState> for ClientIp {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip())
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        Ok(ClientIp(ip))
    }
}
