//! curl — HTTP requests (P0, thin reqwest wrapper).
//!
//! Implementation: status code, response headers, response body (truncated), elapsed time; `-k` skips cert verification.

use super::ToolOutcome;
use std::time::{Duration, Instant};

/// Maximum response-body bytes shown in human/json output; longer bodies are truncated with the total size noted.
const BODY_PREVIEW_LIMIT: usize = 4096;

/// `anet tool curl <url>`: perform an HTTP request and print a summary.
pub async fn curl(
    url: &str,
    method: &str,
    headers: &[(String, String)],
    body: Option<&str>,
    insecure: bool,
    max_time: Duration,
) -> ToolOutcome {
    // Default scheme follows curl convention: prepend http://
    let url = if url.contains("://") {
        url.to_string()
    } else {
        format!("http://{url}")
    };

    let method = match reqwest::Method::from_bytes(method.as_bytes()) {
        Ok(m) => m,
        Err(_) => return ToolOutcome::usage_error(format!("无效 HTTP 方法: {method}")),
    };

    let mut header_map = reqwest::header::HeaderMap::new();
    for (name, value) in headers {
        let name = match reqwest::header::HeaderName::from_bytes(name.as_bytes()) {
            Ok(n) => n,
            Err(_) => return ToolOutcome::usage_error(format!("无效请求头名称: {name}")),
        };
        let value = match reqwest::header::HeaderValue::from_str(value) {
            Ok(v) => v,
            Err(_) => return ToolOutcome::usage_error(format!("请求头 {name} 含非法字符")),
        };
        header_map.append(name, value);
    }

    // Match curl's default: do not follow redirects
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(max_time)
        .danger_accept_invalid_certs(insecure)
        .build()
    {
        Ok(c) => c,
        Err(e) => return ToolOutcome::usage_error(format!("HTTP 客户端构建失败: {e}")),
    };

    let mut req = client.request(method.clone(), &url).headers(header_map);
    if let Some(body) = body {
        req = req.body(body.to_string());
    }

    let start = Instant::now();
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => return request_fail(&url, method.as_str(), start.elapsed(), &e, insecure),
    };

    let status = resp.status();
    let version = format!("{:?}", resp.version());
    let mut resp_headers = serde_json::Map::new();
    let mut header_lines = String::new();
    for (name, value) in resp.headers() {
        let value = value.to_str().unwrap_or("<binary>").to_string();
        resp_headers
            .entry(name.as_str().to_string())
            .or_insert_with(|| serde_json::json!([]))
            .as_array_mut()
            .expect("刚插入的数组")
            .push(serde_json::json!(value));
        header_lines.push_str(&format!("< {name}: {value}\n"));
    }

    // Read the full body to report the real size; truncate only for display
    let body_bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => return request_fail(&url, method.as_str(), start.elapsed(), &e, insecure),
    };
    let duration_ms = start.elapsed().as_millis() as u64;

    let truncated = body_bytes.len() > BODY_PREVIEW_LIMIT;
    let preview = String::from_utf8_lossy(&body_bytes[..body_bytes.len().min(BODY_PREVIEW_LIMIT)])
        .into_owned();
    let status_text = status.canonical_reason().unwrap_or("-");

    let mut human = format!(
        "{version} {} {status_text} · {duration_ms} ms · {url}",
        status.as_u16()
    );
    if insecure {
        human.push_str("\n注意: -k 已跳过 TLS 证书校验（仅调试用）");
    }
    if !header_lines.is_empty() {
        human.push('\n');
        human.push_str(header_lines.trim_end());
    }
    if !preview.is_empty() {
        human.push_str("\n\n");
        human.push_str(&preview);
    }
    if truncated {
        human.push_str(&format!(
            "\n（响应体共 {} 字节，仅展示前 {BODY_PREVIEW_LIMIT} 字节）",
            body_bytes.len()
        ));
    }

    let json = serde_json::json!({
        "url": url,
        "method": method.as_str(),
        "status": status.as_u16(),
        "status_text": status_text,
        "http_version": version,
        "duration_ms": duration_ms,
        "insecure_skip_verify": insecure,
        "headers": resp_headers,
        "body_bytes": body_bytes.len(),
        "body_truncated": truncated,
        "body_preview": preview,
    });
    // curl semantics: receiving an HTTP response is success (4xx/5xx is the target's answer, not a probe failure)
    ToolOutcome::ok(human, json)
}

/// Request-level failure (timeout/connect/TLS etc.): a failed probe is normal output (exit 1), not a process error.
fn request_fail(
    url: &str,
    method: &str,
    elapsed: Duration,
    err: &reqwest::Error,
    insecure: bool,
) -> ToolOutcome {
    let kind = if err.is_timeout() {
        "timeout"
    } else if err.is_connect() {
        "connect"
    } else if err.is_request() {
        "request"
    } else {
        "other"
    };
    // Full error chain (curl -v style; the diagnostic value is mostly in the underlying cause)
    let mut detail = err.to_string();
    let mut source = std::error::Error::source(&err);
    while let Some(e) = source {
        detail.push_str(&format!(" <- {e}"));
        source = e.source();
    }
    let mut human = format!("请求失败（{kind}，{} ms）: {detail}", elapsed.as_millis());
    // Point https certificate problems at -k (debug only)
    if !insecure && url.starts_with("https://") && detail.contains("certificate") {
        human.push_str("\n提示: 若为自签名证书可加 -k 跳过校验（仅调试用）");
    }
    let json = serde_json::json!({
        "url": url,
        "method": method,
        "duration_ms": elapsed.as_millis() as u64,
        "error": detail,
        "error_kind": kind,
    });
    ToolOutcome::fail(human, json)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Start a temporary axum server and return its actual listen port.
    async fn spawn_http(app: axum::Router) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        port
    }

    #[tokio::test]
    async fn get_ok_status_headers_body() {
        let app = axum::Router::new().route(
            "/hello",
            axum::routing::get(|| async { ([("x-test", "world")], "hi") }),
        );
        let port = spawn_http(app).await;
        let out = curl(
            &format!("http://127.0.0.1:{port}/hello"),
            "GET",
            &[],
            None,
            false,
            Duration::from_secs(5),
        )
        .await;
        assert!(out.success, "human: {}", out.human);
        assert_eq!(out.exit_code, 0);
        assert_eq!(out.json["status"], 200);
        assert_eq!(out.json["headers"]["x-test"][0], "world");
        assert_eq!(out.json["body_preview"], "hi");
        assert_eq!(out.json["body_truncated"], false);
        assert!(out.human.contains("200 OK"));
        assert!(out.human.contains("x-test: world"));
    }

    #[tokio::test]
    async fn scheme_default_http() {
        let app = axum::Router::new().route("/", axum::routing::get(|| async { "ok" }));
        let port = spawn_http(app).await;
        // With no scheme, prepend http:// per curl convention
        let out = curl(
            &format!("127.0.0.1:{port}/"),
            "GET",
            &[],
            None,
            false,
            Duration::from_secs(5),
        )
        .await;
        assert!(out.success, "human: {}", out.human);
        assert_eq!(out.json["url"], format!("http://127.0.0.1:{port}/"));
    }

    #[tokio::test]
    async fn post_body_and_custom_header_echo() {
        async fn echo(
            method: axum::http::Method,
            headers: axum::http::HeaderMap,
            body: String,
        ) -> String {
            let echo = headers
                .get("x-echo")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("-")
                .to_string();
            format!("{method}|{echo}|{body}")
        }
        let app = axum::Router::new().route("/echo", axum::routing::post(echo));
        let port = spawn_http(app).await;
        let headers = vec![("X-Echo".to_string(), "anet".to_string())];
        let out = curl(
            &format!("http://127.0.0.1:{port}/echo"),
            "POST",
            &headers,
            Some("ping"),
            false,
            Duration::from_secs(5),
        )
        .await;
        assert!(out.success, "human: {}", out.human);
        assert_eq!(out.json["body_preview"], "POST|anet|ping");
    }

    #[tokio::test]
    async fn body_truncation_marked() {
        let big = "x".repeat(BODY_PREVIEW_LIMIT + 100);
        let app = axum::Router::new().route(
            "/big",
            axum::routing::get(move || {
                let big = big.clone();
                async move { big }
            }),
        );
        let port = spawn_http(app).await;
        let out = curl(
            &format!("http://127.0.0.1:{port}/big"),
            "GET",
            &[],
            None,
            false,
            Duration::from_secs(5),
        )
        .await;
        assert!(out.success);
        assert_eq!(out.json["body_bytes"], BODY_PREVIEW_LIMIT + 100);
        assert_eq!(out.json["body_truncated"], true);
        assert_eq!(
            out.json["body_preview"].as_str().unwrap().len(),
            BODY_PREVIEW_LIMIT
        );
        assert!(out.human.contains("仅展示前"));
    }

    #[tokio::test]
    async fn redirect_not_followed() {
        let app = axum::Router::new().route(
            "/redir",
            axum::routing::get(|| async {
                (axum::http::StatusCode::FOUND, [("location", "/hello")], "")
            }),
        );
        let port = spawn_http(app).await;
        let out = curl(
            &format!("http://127.0.0.1:{port}/redir"),
            "GET",
            &[],
            None,
            false,
            Duration::from_secs(5),
        )
        .await;
        // Match curl's default: redirects are not followed; the 302 itself is the server's answer (exit 0)
        assert!(out.success);
        assert_eq!(out.json["status"], 302);
        assert_eq!(out.json["headers"]["location"][0], "/hello");
    }

    #[tokio::test]
    async fn connect_refused_is_fail() {
        // Bind a temporary port and release it immediately, guaranteeing nothing listens there
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let out = curl(
            &format!("http://127.0.0.1:{port}/"),
            "GET",
            &[],
            None,
            false,
            Duration::from_secs(2),
        )
        .await;
        assert!(!out.success);
        assert_eq!(out.exit_code, 1);
        // Most environments yield connect (refused); some proxy/TUN environments drop packets, yielding timeout — both are legitimate probe failures
        let kind = out.json["error_kind"].as_str().unwrap();
        assert!(
            kind == "connect" || kind == "timeout",
            "unexpected kind={kind}, human: {}",
            out.human
        );
    }

    #[tokio::test]
    async fn timeout_is_fail() {
        let app = axum::Router::new().route(
            "/slow",
            axum::routing::get(|| async {
                tokio::time::sleep(Duration::from_secs(2)).await;
                "late"
            }),
        );
        let port = spawn_http(app).await;
        let out = curl(
            &format!("http://127.0.0.1:{port}/slow"),
            "GET",
            &[],
            None,
            false,
            Duration::from_millis(100),
        )
        .await;
        assert!(!out.success);
        assert_eq!(out.exit_code, 1);
        assert_eq!(out.json["error_kind"], "timeout");
    }

    #[tokio::test]
    async fn invalid_method_is_usage_error() {
        let out = curl(
            "http://127.0.0.1:1/",
            "BAD METHOD",
            &[],
            None,
            false,
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(out.exit_code, 2);
    }

    #[tokio::test]
    async fn invalid_header_is_usage_error() {
        let headers = vec![("X Bad".to_string(), "v".to_string())];
        let out = curl(
            "http://127.0.0.1:1/",
            "GET",
            &headers,
            None,
            false,
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(out.exit_code, 2);
    }

    #[tokio::test]
    async fn https_self_signed_requires_k() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        // Temporary HTTPS server with a self-signed certificate
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
            cert.cert.pem().into_bytes(),
            cert.key_pair.serialize_pem().into_bytes(),
        )
        .await
        .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = axum::Router::new().route("/", axum::routing::get(|| async { "secure" }));
        tokio::spawn(async move {
            axum_server::from_tcp_rustls(listener, tls)
                .serve(app.into_make_service())
                .await
                .unwrap()
        });
        let url = format!("https://127.0.0.1:{port}/");

        // Without skip-verify: the self-signed cert must fail (exit 1) and human must hint at -k
        let out = curl(&url, "GET", &[], None, false, Duration::from_secs(5)).await;
        assert!(!out.success, "human: {}", out.human);
        assert_eq!(out.exit_code, 1);
        assert!(out.human.contains("-k"), "human: {}", out.human);

        // With -k skipping verification: success
        let out = curl(&url, "GET", &[], None, true, Duration::from_secs(5)).await;
        assert!(out.success, "human: {}", out.human);
        assert_eq!(out.json["status"], 200);
        assert_eq!(out.json["body_preview"], "secure");
        assert_eq!(out.json["insecure_skip_verify"], true);
    }
}
