//! Web 管理后台单页应用 (Admin Web UI)：路由与内嵌服务。
//!
//! - 文件布局：`crates/node/ui/`（index.html / app.js / style.css），经 `include_str!` 内嵌，
//!   严禁再把界面代码写进 Rust 字符串（AGENTS.md §6）
//! - 设计 token 唯一权威文件为 `apps/desktop/ui/tokens.css`，经 `/ui/tokens.css` 共享服务
//! - 安全响应头：CSP 放行桌面壳 iframe 内嵌（frame-ancestors 含 tauri 源）+ nosniff 等
//! - 主窗内嵌时 `?embed=1`：SPA 隐藏自身侧栏与标题栏，导航/主题经 postMessage 由主窗驱动

use axum::{
    Router,
    http::{HeaderValue, header},
    response::{Html, IntoResponse, Response},
    routing::get,
};

const ADMIN_HTML: &str = include_str!("../../ui/index.html");
const ADMIN_JS: &str = include_str!("../../ui/app.js");
const ADMIN_CSS: &str = include_str!("../../ui/style.css");
/// 共享设计 token（唯一权威文件在桌面端，AGENTS.md §6）
const TOKENS_CSS: &str = include_str!("../../../../apps/desktop/ui/tokens.css");

/// 基础安全响应头（全部静态响应统一附加）。
fn base_headers(resp: &mut Response) {
    let headers = resp.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
}

/// 管理页面（frame-ancestors 放行自身与 Tauri 桌面壳 iframe 内嵌）
pub async fn admin_page_handler() -> impl IntoResponse {
    let mut resp = Html(ADMIN_HTML).into_response();
    base_headers(&mut resp);
    let headers = resp.headers_mut();
    headers.insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("SAMEORIGIN"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; img-src 'self' data:; frame-ancestors 'self' http://tauri.localhost https://tauri.localhost tauri://localhost",
        ),
    );
    resp
}

async fn admin_js_handler() -> impl IntoResponse {
    let mut resp = ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], ADMIN_JS).into_response();
    base_headers(&mut resp);
    resp
}

async fn admin_css_handler() -> impl IntoResponse {
    let mut resp = ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], ADMIN_CSS).into_response();
    base_headers(&mut resp);
    resp
}

async fn tokens_css_handler() -> impl IntoResponse {
    let mut resp = ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], TOKENS_CSS).into_response();
    base_headers(&mut resp);
    resp
}

pub fn create_ui_router() -> Router {
    Router::new()
        .route("/", get(admin_page_handler))
        .route("/admin", get(admin_page_handler))
        .route("/ui/app.js", get(admin_js_handler))
        .route("/ui/style.css", get(admin_css_handler))
        .route("/ui/tokens.css", get(tokens_css_handler))
}
