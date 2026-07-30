//! M5 里程碑 Database & HTTP API 集成测试
//!
//! 包含 AT-M5-01 ~ AT-M5-06 测试套件

use agile_net_core::proxy::router::{Outbound, ProxyRouter};
use agile_net_node::api::create_app;
use agile_net_node::db::Database;
use arc_swap::ArcSwap;
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt; // for oneshot

fn setup_test_app() -> (axum::Router, Arc<ArcSwap<ProxyRouter>>) {
    let db = Database::in_memory().unwrap();
    let router = Arc::new(ArcSwap::from_pointee(ProxyRouter::new()));
    let app = create_app(db, router.clone());
    (app, router)
}

/// AT-M5-01：管理员登录并获取 JWT Token
#[tokio::test]
async fn admin_login_success() {
    let (app, _) = setup_test_app();

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "username": "admin",
                "password": "admin123"
            })
            .to_string(),
        ))
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body_bytes).unwrap();

    assert!(json["token"].is_string());
    assert_eq!(json["username"], "admin");
    assert_eq!(json["role"], "admin");
}

/// AT-M5-02：错误密码拒绝登录
#[tokio::test]
async fn login_invalid_password() {
    let (app, _) = setup_test_app();

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "username": "admin",
                "password": "wrong_password"
            })
            .to_string(),
        ))
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// AT-M5-03：未授权访问受保护 API 返回 401
#[tokio::test]
async fn protected_api_unauthorized() {
    let (app, _) = setup_test_app();

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/nodes")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// AT-M5-04：节点 CRUD API 测试
#[tokio::test]
async fn node_crud_api() {
    let (app, _) = setup_test_app();

    // 1. Login
    let login_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "username": "admin", "password": "admin123" }).to_string(),
        ))
        .unwrap();

    let login_resp = app.clone().oneshot(login_req).await.unwrap();
    let body = axum::body::to_bytes(login_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let login_json: Value = serde_json::from_slice(&body).unwrap();
    let token = login_json["token"].as_str().unwrap();

    // 2. Create Node
    let create_req = Request::builder()
        .method("POST")
        .uri("/api/v1/nodes")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "name": "node-hk-01",
                "token": "secret_hk_token"
            })
            .to_string(),
        ))
        .unwrap();

    let create_resp = app.clone().oneshot(create_req).await.unwrap();
    assert_eq!(create_resp.status(), StatusCode::CREATED);

    let create_body = axum::body::to_bytes(create_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let node_json: Value = serde_json::from_slice(&create_body).unwrap();
    let node_id = node_json["id"].as_str().unwrap();
    assert_eq!(node_json["name"], "node-hk-01");

    // 3. List Nodes
    let list_req = Request::builder()
        .method("GET")
        .uri("/api/v1/nodes")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let list_resp = app.clone().oneshot(list_req).await.unwrap();
    assert_eq!(list_resp.status(), StatusCode::OK);

    let list_body = axum::body::to_bytes(list_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let list_json: Value = serde_json::from_slice(&list_body).unwrap();
    assert_eq!(list_json["nodes"].as_array().unwrap().len(), 1);

    // 4. Delete Node
    let delete_req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/nodes/{node_id}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();

    let delete_resp = app.oneshot(delete_req).await.unwrap();
    assert_eq!(delete_resp.status(), StatusCode::NO_CONTENT);
}

/// AT-M5-05：路由规则 CRUD API 及 ProxyRouter 热重载
#[tokio::test]
async fn route_crud_and_router_hot_reload() {
    let (app, router) = setup_test_app();

    // 1. Login
    let login_req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "username": "admin", "password": "admin123" }).to_string(),
        ))
        .unwrap();

    let login_resp = app.clone().oneshot(login_req).await.unwrap();
    let body = axum::body::to_bytes(login_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let login_json: Value = serde_json::from_slice(&body).unwrap();
    let token = login_json["token"].as_str().unwrap();

    // 2. 先创建 Node (满足外键约束)
    let create_node_req = Request::builder()
        .method("POST")
        .uri("/api/v1/nodes")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "name": "node-a-test",
                "token": "token_a"
            })
            .to_string(),
        ))
        .unwrap();

    let node_resp = app.clone().oneshot(create_node_req).await.unwrap();
    assert_eq!(node_resp.status(), StatusCode::CREATED);
    let node_body = axum::body::to_bytes(node_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let node_json: Value = serde_json::from_slice(&node_body).unwrap();
    let node_id = node_json["id"].as_str().unwrap();

    // 初始路由未命中任何规则
    {
        let r = router.load();
        assert_eq!(*r.route_target("10.0.0.1:80"), Outbound::Direct);
    }

    // 3. 添加路由规则: 10.0.0.0/8 -> Tunnel(node_id)
    let create_route_req = Request::builder()
        .method("POST")
        .uri("/api/v1/routes")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "pattern": "10.0.0.0/8",
                "pattern_type": "cidr",
                "outbound_type": "tunnel",
                "node_id": node_id
            })
            .to_string(),
        ))
        .unwrap();

    let route_resp = app.clone().oneshot(create_route_req).await.unwrap();
    assert_eq!(route_resp.status(), StatusCode::CREATED);

    // 验证 Router 热更新生效
    {
        let r = router.load();
        assert_eq!(
            *r.route_target("10.0.0.1:80"),
            Outbound::Tunnel {
                node_id: node_id.to_string()
            }
        );
    }
}
