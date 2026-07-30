//! HTTP API 路由与 Handler 接口

pub mod handlers;

use crate::db::Database;
use agile_net_core::proxy::router::ProxyRouter;
use arc_swap::ArcSwap;
use axum::{
    routing::{delete, get, post},
    Router,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct ApiState {
    pub db: Database,
    pub router: Arc<ArcSwap<ProxyRouter>>,
}

pub fn create_app(db: Database, router: Arc<ArcSwap<ProxyRouter>>) -> Router {
    let state = ApiState { db, router };

    Router::new()
        // Auth API (Public)
        .route("/api/v1/auth/login", post(handlers::auth::login))
        // Protected Admin / Management API
        .route("/api/v1/auth/me", get(handlers::auth::me))
        // Node API
        .route(
            "/api/v1/nodes",
            get(handlers::nodes::list_nodes).post(handlers::nodes::create_node),
        )
        .route("/api/v1/nodes/{id}", delete(handlers::nodes::delete_node))
        // Route Rules API
        .route(
            "/api/v1/routes",
            get(handlers::routes::list_routes).post(handlers::routes::create_route),
        )
        .route(
            "/api/v1/routes/{id}",
            delete(handlers::routes::delete_route),
        )
        // Groups API
        .route(
            "/api/v1/groups",
            get(handlers::groups::list_groups).post(handlers::groups::create_group),
        )
        .route(
            "/api/v1/groups/{id}",
            delete(handlers::groups::delete_group),
        )
        // Accounts API
        .route(
            "/api/v1/accounts",
            get(handlers::accounts::list_accounts).post(handlers::accounts::create_account),
        )
        .route(
            "/api/v1/accounts/{id}",
            delete(handlers::accounts::delete_account),
        )
        // System Config API
        .route(
            "/api/v1/system/configs",
            get(handlers::system::get_configs).put(handlers::system::set_config),
        )
        .with_state(state)
}
