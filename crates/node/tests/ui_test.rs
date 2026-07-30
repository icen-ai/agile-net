//! M6 里程碑 Web Admin UI 单页面板集成测试

use agile_net_node::ui::create_ui_router;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt; // for oneshot

/// AT-M6-01：访问根路径 / 成功返回 Dashboard 网页 HTML
#[tokio::test]
async fn admin_ui_index_returns_html() {
    let app = create_ui_router();

    let req = Request::builder()
        .method("GET")
        .uri("/")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8(body_bytes.to_vec()).unwrap();

    assert!(html.contains("AgileNet Dashboard"));
    assert!(html.contains("AgileNet 控制台"));
}

/// AT-M6-02：访问 /admin 别名路由亦返回完整面板 HTML
#[tokio::test]
async fn admin_ui_alias_route_works() {
    let app = create_ui_router();

    let req = Request::builder()
        .method("GET")
        .uri("/admin")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8(body_bytes.to_vec()).unwrap();

    assert!(html.contains("doLogin()"));
    assert!(html.contains("nodes-table-body"));
}
