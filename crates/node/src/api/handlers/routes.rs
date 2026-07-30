//! Routes API Handlers

use crate::api::ApiState;
use crate::auth::jwt::AuthClaims;
use crate::db::models::RoutePatternType;
use agile_net_core::proxy::router::{Outbound, ProxyRouter};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct CreateRouteRequest {
    pub pattern: String,
    pub pattern_type: String, // "cidr", "exact_host", "wildcard_host"
    pub outbound_type: String, // "direct", "tunnel"
    pub node_id: Option<String>,
}

pub async fn list_routes(
    _claims: AuthClaims,
    State(state): State<ApiState>,
) -> impl IntoResponse {
    match state.db.list_routes() {
        Ok(routes) => (StatusCode::OK, Json(json!({ "routes": routes }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn create_route(
    _claims: AuthClaims,
    State(state): State<ApiState>,
    Json(req): Json<CreateRouteRequest>,
) -> impl IntoResponse {
    let p_type = RoutePatternType::parse(&req.pattern_type);

    let route = match state.db.create_route(
        &req.pattern,
        p_type.clone(),
        &req.outbound_type,
        req.node_id.as_deref(),
    ) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    };

    // 热重载 ProxyRouter
    if let Ok(all_routes) = state.db.list_routes() {
        let mut new_router = ProxyRouter::new();
        for r in all_routes {
            if !r.enabled {
                continue;
            }
            let outbound = if r.outbound_type == "tunnel" {
                if let Some(nid) = r.node_id {
                    Outbound::tunnel(nid)
                } else {
                    Outbound::Direct
                }
            } else {
                Outbound::Direct
            };

            match r.pattern_type {
                RoutePatternType::Cidr => {
                    let _ = new_router.add_cidr(&r.pattern, outbound);
                }
                RoutePatternType::ExactHost => {
                    new_router.add_host_exact(&r.pattern, outbound);
                }
                RoutePatternType::WildcardHost => {
                    new_router.add_host_suffix(&r.pattern, outbound);
                }
            }
        }
        state.router.store(std::sync::Arc::new(new_router));
    }

    (StatusCode::CREATED, Json(route)).into_response()
}

pub async fn delete_route(
    _claims: AuthClaims,
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.db.delete_route(&id) {
        Ok(_) => {
            // 热重载 ProxyRouter
            if let Ok(all_routes) = state.db.list_routes() {
                let mut new_router = ProxyRouter::new();
                for r in all_routes {
                    if !r.enabled {
                        continue;
                    }
                    let outbound = if r.outbound_type == "tunnel" {
                        if let Some(nid) = r.node_id {
                            Outbound::tunnel(nid)
                        } else {
                            Outbound::Direct
                        }
                    } else {
                        Outbound::Direct
                    };

                    match r.pattern_type {
                        RoutePatternType::Cidr => {
                            let _ = new_router.add_cidr(&r.pattern, outbound);
                        }
                        RoutePatternType::ExactHost => {
                            new_router.add_host_exact(&r.pattern, outbound);
                        }
                        RoutePatternType::WildcardHost => {
                            new_router.add_host_suffix(&r.pattern, outbound);
                        }
                    }
                }
                state.router.store(std::sync::Arc::new(new_router));
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}
