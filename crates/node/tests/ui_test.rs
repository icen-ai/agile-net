//! Web Admin UI 单页应用集成测试
//!
//! 文件布局（AGENTS.md §6）：index.html / app.js / style.css + 共享 tokens.css 分路服务。

use agile_net_node::ui::create_ui_router;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

async fn get(uri: &str) -> (StatusCode, String, axum::http::HeaderMap) {
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

/// 根路径返回控制台 SPA（逻辑在 /ui/app.js，样式经 tokens.css + style.css 外链）
#[tokio::test]
async fn admin_ui_index_returns_html() {
    let (status, html, _) = get("/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("AgileNet 控制台"));
    assert!(html.contains("/ui/app.js"));
    assert!(html.contains("/ui/tokens.css"));
    assert!(html.contains("/ui/style.css"));
}

/// 应用逻辑经 /ui/app.js 服务：视图切换与登录均在其中
#[tokio::test]
async fn admin_ui_serves_app_js() {
    let (status, js, headers) = get("/ui/app.js").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get("content-type").unwrap(),
        "text/javascript; charset=utf-8"
    );
    assert!(js.contains("switchView"));
    assert!(js.contains("doLogin"));
    // 严禁预填默认凭据
    assert!(!js.contains("admin123"));
}

/// 共享设计 token（桌面端唯一权威文件）经 /ui/tokens.css 服务
#[tokio::test]
async fn admin_ui_serves_shared_tokens() {
    let (status, css, _) = get("/ui/tokens.css").await;
    assert_eq!(status, StatusCode::OK);
    assert!(css.contains("--accent"));
    assert!(css.contains("--ok-text"));
}

/// /admin 别名同样可用，且登录框不预填任何凭据
#[tokio::test]
async fn admin_ui_alias_and_no_prefilled_credentials() {
    let (status, html, _) = get("/admin").await;
    assert_eq!(status, StatusCode::OK);
    assert!(!html.contains("admin123"));
    assert!(!html.contains("value=\"admin\""));
}

/// XSS 安全：渲染函数必须转义动态内容
#[tokio::test]
async fn admin_ui_escapes_dynamic_content() {
    let (_, js, _) = get("/ui/app.js").await;
    // esc() 函数存在且被用于渲染
    assert!(js.contains("function esc(s)"));
    assert!(js.contains("&amp;"));
    // 不直接把接口数据 innerHTML（全部经 esc/pager/shortId 包装）
    assert!(!js.contains("innerHTML = (d.items||[]).map(a =>\n      '<tr><td><b>' + a.username"));
}

/// 安全响应头（frame-ancestors 放行桌面壳 iframe 内嵌，外部站点仍被禁）
#[tokio::test]
async fn admin_ui_security_headers() {
    let (_, _, headers) = get("/").await;
    assert_eq!(headers.get("x-frame-options").unwrap(), "SAMEORIGIN");
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    let csp = headers
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(csp.contains("frame-ancestors"));
    assert!(csp.contains("tauri.localhost"));
    // 外链脚本/样式必须被 CSP 放行（拆分后 app.js / style.css 为外部资源）
    assert!(csp.contains("script-src 'self'"));
    assert!(csp.contains("style-src 'self'"));
}
