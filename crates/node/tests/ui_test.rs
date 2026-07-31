//! Web Admin UI 单页应用集成测试

use agile_net_node::ui::create_ui_router;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

async fn get_html(uri: &str) -> (StatusCode, String, axum::http::HeaderMap) {
    let app = create_ui_router();
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(req).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        String::from_utf8(body_bytes.to_vec()).unwrap(),
        headers,
    )
}

/// 根路径返回控制台 SPA
#[tokio::test]
async fn admin_ui_index_returns_html() {
    let (status, html, _) = get_html("/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("AgileNet 控制台"));
    assert!(html.contains("switchView"));
}

/// /admin 别名同样可用，且登录框不预填任何凭据
#[tokio::test]
async fn admin_ui_alias_and_no_prefilled_credentials() {
    let (status, html, _) = get_html("/admin").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("doLogin"));
    // 严禁预填默认凭据
    assert!(!html.contains("admin123"));
    assert!(!html.contains("value=\"admin\""));
}

/// XSS 安全：渲染函数必须转义动态内容
#[tokio::test]
async fn admin_ui_escapes_dynamic_content() {
    let (_, html, _) = get_html("/").await;
    // esc() 函数存在且被用于渲染
    assert!(html.contains("function esc(s)"));
    assert!(html.contains("&amp;"));
    // 不直接把接口数据 innerHTML（全部经 esc/pager/shortId 包装）
    assert!(!html.contains("innerHTML = (d.items||[]).map(a =>\n      '<tr><td><b>' + a.username"));
}

/// 安全响应头
#[tokio::test]
async fn admin_ui_security_headers() {
    let (_, _, headers) = get_html("/").await;
    assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert!(headers.get("content-security-policy").is_some());
}
