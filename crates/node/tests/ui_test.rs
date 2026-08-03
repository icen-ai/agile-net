//! Web Admin UI single-page app integration tests
//!
//! File layout (AGENTS.md §6): index.html / app.js / style.css + shared tokens.css, served on separate routes.

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

/// Root path returns the console SPA (logic in /ui/app.js, styles via tokens.css + style.css links)
#[tokio::test]
async fn admin_ui_index_returns_html() {
    let (status, html, _) = get("/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("AgileNet 控制台"));
    assert!(html.contains("/ui/app.js"));
    assert!(html.contains("/ui/tokens.css"));
    assert!(html.contains("/ui/style.css"));
}

/// App logic served via /ui/app.js: view switching and login both live there
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
    // never prefill default credentials
    assert!(!js.contains("admin123"));
}

/// Shared design tokens (desktop-authoritative file) served via /ui/tokens.css
#[tokio::test]
async fn admin_ui_serves_shared_tokens() {
    let (status, css, _) = get("/ui/tokens.css").await;
    assert_eq!(status, StatusCode::OK);
    assert!(css.contains("--accent"));
    assert!(css.contains("--ok-text"));
}

/// /admin alias also works, and the login form prefills no credentials
#[tokio::test]
async fn admin_ui_alias_and_no_prefilled_credentials() {
    let (status, html, _) = get("/admin").await;
    assert_eq!(status, StatusCode::OK);
    assert!(!html.contains("admin123"));
    assert!(!html.contains("value=\"admin\""));
}

/// XSS safety: render functions must escape dynamic content
#[tokio::test]
async fn admin_ui_escapes_dynamic_content() {
    let (_, js, _) = get("/ui/app.js").await;
    // esc() lives in the shared layer /ui/agutil.js; app.js gets it via the shared script
    let (_, util, _) = get("/ui/agutil.js").await;
    assert!(util.contains("function esc(s)") || util.contains("esc ="));
    assert!(util.contains("&amp;"));
    // never innerHTML raw API data (everything wrapped by esc/pager/shortId)
    assert!(!js.contains("innerHTML = (d.items||[]).map(a =>\n      '<tr><td><b>' + a.username"));
}

/// Security response headers (frame-ancestors allows desktop-shell iframe embedding, external sites still blocked)
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
    // external scripts/styles must pass CSP (after the split, app.js / style.css are external resources)
    assert!(csp.contains("script-src 'self'"));
    assert!(csp.contains("style-src 'self'"));
}

/// Bilingual assets: agi18n runtime / shared dictionary / admin dictionary shard all served embedded,
/// and index.html includes them in dependency order (agi18n → aglang → admin shard → app.js)
#[tokio::test]
async fn admin_ui_serves_i18n_assets() {
    for uri in ["/ui/agi18n.js", "/ui/aglang.js", "/ui/lang/admin.js"] {
        let (status, js, headers) = get(uri).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert_eq!(
            headers.get("content-type").unwrap(),
            "text/javascript; charset=utf-8",
            "{uri}"
        );
        assert!(js.contains("AgI18n"), "{uri}");
    }
    let (_, html, _) = get("/").await;
    let i0 = html.find("/ui/agi18n.js").expect("agi18n.js 引用缺失");
    let i1 = html.find("/ui/aglang.js").expect("aglang.js 引用缺失");
    let i2 = html.find("/ui/lang/admin.js").expect("lang/admin.js 引用缺失");
    let i3 = html.find("/ui/app.js").expect("app.js 引用缺失");
    assert!(i0 < i1 && i1 < i2 && i2 < i3, "i18n 脚本引入顺序错误");
    // language switcher present without inline events (CSP discipline)
    assert!(html.contains("id=\"lang-select\""));
    assert!(!html.contains("onchange="));
}
