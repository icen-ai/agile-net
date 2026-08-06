//! Axum extractors: role-based auth and client IP

use crate::api::{ApiState, codes, err};
use crate::auth::jwt::Claims;
use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{StatusCode, header, request::Parts},
    response::Response,
};
use std::net::{IpAddr, SocketAddr};

/// Parse and verify the Bearer JWT from request headers, returning Claims.
///
/// Err carrying an axum Response is the idiomatic extractor pattern (size for one less wrapper).
#[allow(clippy::result_large_err)]
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

    let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        err(
            StatusCode::UNAUTHORIZED,
            codes::INVALID_CREDENTIALS,
            "invalid authorization scheme",
        )
    })?;

    let state = parts.extensions.get::<ApiState>().ok_or_else(|| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            "state unavailable",
        )
    })?;

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

/// Admin role auth (enforced on control-plane APIs).
///
/// Three scope tiers enforced (restricted admin sessions from admin links / relay tickets):
/// - `full`: all admin endpoints
/// - `rules`: GET + rule endpoint writes (/api/v1/admin/rules*)
/// - `ro`: GET only
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
        let scope_allowed = match claims.scope.as_str() {
            "full" => true,
            "rules" => {
                parts.method == axum::http::Method::GET
                    || parts.uri.path().starts_with("/api/v1/admin/rules")
            }
            "ro" => parts.method == axum::http::Method::GET,
            // Unknown tiers degrade to read-only (fail-closed)
            _ => parts.method == axum::http::Method::GET,
        };
        if !scope_allowed {
            return Err(err(
                StatusCode::FORBIDDEN,
                codes::FORBIDDEN,
                "admin scope insufficient for this operation",
            ));
        }
        Ok(AdminAuth(claims))
    }
}

/// Any authenticated identity.
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

/// Client source IP (requires ConnectInfo).
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
