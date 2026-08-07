//! Admin Web UI single-page app: routing and embedded serving.
//!
//! - File layout: `crates/node/ui/` (index.html / app.js / style.css), embedded via `include_str!`;
//!   never write UI code into Rust strings again (AGENTS.md §6)
//! - The single source of truth for design tokens is `apps/desktop/ui/tokens.css`, served shared at `/ui/tokens.css`;
//!   shared component styles `apps/desktop/ui/components.css` served the same way at `/ui/components.css`;
//!   shared chart component `apps/desktop/ui/agchart.js` served the same way at `/ui/agchart.js`;
//!   shared icon table `apps/desktop/ui/icons.js` served the same way at `/ui/icons.js`;
//!   shared base utilities `apps/desktop/ui/agutil.js` served the same way at `/ui/agutil.js`
//! - Security response headers: CSP allows embedding in the desktop shell iframe
//!   (frame-ancestors includes tauri origins) + nosniff etc.
//! - `?embed=1` when embedded in the main window: the SPA hides its own sidebar and title bar;
//!   navigation/theme are driven by the main window via postMessage

use axum::{
    Router,
    http::{HeaderValue, header},
    response::{Html, IntoResponse, Response},
    routing::get,
};

const ADMIN_HTML: &str = include_str!("../../ui/index.html");
const ADMIN_JS: &str = include_str!("../../ui/app.js");
const ADMIN_CSS: &str = include_str!("../../ui/style.css");
/// Shared design tokens (single source of truth lives in the desktop app, AGENTS.md §6).
const TOKENS_CSS: &str = include_str!("../../../../apps/desktop/ui/tokens.css");
/// Shared component styles (settled into the desktop app via the same mechanism as tokens.css).
const COMPONENTS_CSS: &str = include_str!("../../../../apps/desktop/ui/components.css");
/// Shared chart component (first shared JS, embedded the same way; desktop uses <script src> directly).
const AGCHART_JS: &str = include_str!("../../../../apps/desktop/ui/agchart.js");
/// Shared icon table (single source for both ends, embedded the same way; desktop uses <script src="icons.js">).
const AGICONS_JS: &str = include_str!("../../../../apps/desktop/ui/icons.js");
/// Shared base utilities (esc/ahelp/$ with identical semantics on both ends, embedded the same way).
const AGUTIL_JS: &str = include_str!("../../../../apps/desktop/ui/agutil.js");
/// Shared table framework (AgTbl: row reconcile + implicit header chrome; desktop uses <script src> directly).
const AGTBL_JS: &str = include_str!("../../../../apps/desktop/ui/agtbl.js");
/// Shared unified link parser (anet:// connect/fanout, federation P1; the single parser for all forms on both ends).
const AGLINK_JS: &str = include_str!("../../../../apps/desktop/ui/aglink.js");
/// Shared .anet credential file builder/parser (federation P1 §2.8; WebCrypto, both ends).
const AGANET_JS: &str = include_str!("../../../../apps/desktop/ui/aganet.js");
/// Shared universal import wizard (blind-plug anet:// link / .anet file / QR image dialog, both ends).
const AGIMPORT_JS: &str = include_str!("../../../../apps/desktop/ui/agimport.js");
/// Shared i18n runtime (single source of the bilingual mechanism, embedded the same way).
const AGI18N_JS: &str = include_str!("../../../../apps/desktop/ui/agi18n.js");
/// Shared bilingual dictionary (single source for both ends, embedded the same way).
const AGLANG_JS: &str = include_str!("../../../../apps/desktop/ui/aglang.js");
/// Admin-end bilingual dictionary shard (embedded the same way as aglang.js; desktop dictionary shards live in apps/desktop/ui/lang/).
const ADMIN_LANG_JS: &str = include_str!("../../../../apps/desktop/ui/lang/admin.js");
/// Client-role SPA (crates/client/ui, embedded the same way as the admin SPA; shared assets
/// are referenced from the existing /ui/* routes, not re-served).
const CLIENT_HTML: &str = include_str!("../../../client/ui/index.html");
const CLIENT_JS: &str = include_str!("../../../client/ui/app.js");
const CLIENT_CSS: &str = include_str!("../../../client/ui/style.css");
const CLIENT_LANG_JS: &str = include_str!("../../../client/ui/lang.js");

/// Base security response headers (attached to all static responses).
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

/// Admin page (frame-ancestors allows self plus the Tauri desktop shell iframe).
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

async fn components_css_handler() -> impl IntoResponse {
    let mut resp = ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], COMPONENTS_CSS).into_response();
    base_headers(&mut resp);
    resp
}

async fn agchart_js_handler() -> impl IntoResponse {
    let mut resp = ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], AGCHART_JS).into_response();
    base_headers(&mut resp);
    resp
}

async fn agicons_js_handler() -> impl IntoResponse {
    let mut resp = ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], AGICONS_JS).into_response();
    base_headers(&mut resp);
    resp
}

async fn agutil_js_handler() -> impl IntoResponse {
    let mut resp = ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], AGUTIL_JS).into_response();
    base_headers(&mut resp);
    resp
}

async fn agtbl_js_handler() -> impl IntoResponse {
    let mut resp = ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], AGTBL_JS).into_response();
    base_headers(&mut resp);
    resp
}

async fn aglink_js_handler() -> impl IntoResponse {
    let mut resp = ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], AGLINK_JS).into_response();
    base_headers(&mut resp);
    resp
}

async fn aganet_js_handler() -> impl IntoResponse {
    let mut resp = ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], AGANET_JS).into_response();
    base_headers(&mut resp);
    resp
}

async fn agimport_js_handler() -> impl IntoResponse {
    let mut resp = ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], AGIMPORT_JS).into_response();
    base_headers(&mut resp);
    resp
}

async fn agi18n_js_handler() -> impl IntoResponse {
    let mut resp = ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], AGI18N_JS).into_response();
    base_headers(&mut resp);
    resp
}

async fn aglang_js_handler() -> impl IntoResponse {
    let mut resp = ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], AGLANG_JS).into_response();
    base_headers(&mut resp);
    resp
}

async fn admin_lang_js_handler() -> impl IntoResponse {
    let mut resp = ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], ADMIN_LANG_JS).into_response();
    base_headers(&mut resp);
    resp
}

/// Client console page (same headers as the admin page; may be embedded in the desktop shell).
pub async fn client_page_handler() -> impl IntoResponse {
    let mut resp = Html(CLIENT_HTML).into_response();
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

async fn client_js_handler() -> impl IntoResponse {
    let mut resp = ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], CLIENT_JS).into_response();
    base_headers(&mut resp);
    resp
}

async fn client_css_handler() -> impl IntoResponse {
    let mut resp = ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], CLIENT_CSS).into_response();
    base_headers(&mut resp);
    resp
}

async fn client_lang_js_handler() -> impl IntoResponse {
    let mut resp = ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], CLIENT_LANG_JS).into_response();
    base_headers(&mut resp);
    resp
}

pub fn create_ui_router() -> Router {
    Router::new()
        .route("/", get(admin_page_handler))
        .route("/admin", get(admin_page_handler))
        .route("/client", get(client_page_handler))
        .route("/client/", get(client_page_handler))
        .route("/client/app.js", get(client_js_handler))
        .route("/client/style.css", get(client_css_handler))
        .route("/client/lang.js", get(client_lang_js_handler))
        .route("/ui/app.js", get(admin_js_handler))
        .route("/ui/style.css", get(admin_css_handler))
        .route("/ui/tokens.css", get(tokens_css_handler))
        .route("/ui/components.css", get(components_css_handler))
        .route("/ui/agchart.js", get(agchart_js_handler))
        .route("/ui/icons.js", get(agicons_js_handler))
        .route("/ui/agutil.js", get(agutil_js_handler))
        .route("/ui/agtbl.js", get(agtbl_js_handler))
        .route("/ui/aglink.js", get(aglink_js_handler))
        .route("/ui/aganet.js", get(aganet_js_handler))
        .route("/ui/agimport.js", get(agimport_js_handler))
        .route("/ui/agi18n.js", get(agi18n_js_handler))
        .route("/ui/aglang.js", get(aglang_js_handler))
        .route("/ui/lang/admin.js", get(admin_lang_js_handler))
}

#[cfg(test)]
mod tests {
    //! UI regression guards (the embedded SPA ships verbatim; these catch structural breaks early).

    /// openModal(title, bodyHtml, actions) arity: the actions argument must be an array (or absent,
    /// defaulting to the close button). A stray comma in the body concatenation silently promotes the
    /// body tail into `actions` → `(string).forEach is not a function` and a dead dialog button with
    /// zero feedback (the 签发委托 incident: nameTriplet(...)`,` instead of `+`).
    #[test]
    fn open_modal_calls_have_valid_arity() {
        let s = super::ADMIN_JS;
        let mut rest = s;
        while let Some(pos) = rest.find("openModal(") {
            // skip the definition itself
            if rest[..pos].ends_with("function ") {
                rest = &rest[pos + 10..];
                continue;
            }
            let mut depth = 0i32;
            let mut top_commas = 0;
            let mut end = pos + 10;
            for (i, c) in rest[pos + 9..].char_indices() {
                match c {
                    '(' | '[' | '{' => depth += 1,
                    ')' | ']' | '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = pos + 9 + i + 1;
                            break;
                        }
                    }
                    ',' if depth == 1 => top_commas += 1,
                    _ => {}
                }
            }
            let args = top_commas + 1;
            assert!(
                args == 2 || args == 3,
                "openModal call with {args} args at byte {pos} (only 2 or 3 allowed)"
            );
            rest = &rest[end..];
        }
    }
}
