//! Unified `anet://` link primitives (federation P1 §2.7) — the single Rust parse/build base.
//!
//! Link shapes (three-piece set: entry address + credential + entry cert fingerprint):
//! - fan-in account: `anet://connect?server=H&port=P&account=U&password=W&fp=FP[&admin=1]`
//! - fan-out peer:   `anet://fanout?server=H&port=P&token=psk_...&sni=SNI&fp=FP`
//!
//! `server` may be a full `https://host[:port]` form (API behind a reverse proxy; the port
//! param is then ignored). Generation always uses the new `anet://` scheme; parsing accepts
//! the legacy `agilenet://` scheme forever (smooth migration). The frontend twin is
//! `apps/desktop/ui/aglink.js` (shared by desktop and admin UI) — keep behaviors aligned.

use serde::{Deserialize, Serialize};

/// Current link scheme (generation target).
pub const LINK_SCHEME: &str = "anet://";
/// Legacy scheme (parse-only, forever compatible).
pub const LEGACY_LINK_SCHEME: &str = "agilenet://";

/// Default admin API port (connect links).
pub const DEFAULT_API_PORT: u16 = 59090;
/// Default relay listener port (fanout links).
pub const DEFAULT_RELAY_PORT: u16 = 54430;

/// Parsed fan-in account link (`anet://connect?...`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectLink {
    /// API endpoint address (host:port; or the full scheme form when server carried one)
    pub addr: String,
    pub account: String,
    pub password: String,
    #[serde(default)]
    pub pinned_fingerprint: Option<String>,
    #[serde(default)]
    pub insecure: bool,
    /// Admin link flag (admin=1: the holder can manage the node; strong warning on import)
    #[serde(default)]
    pub admin: bool,
}

/// Parsed fan-out peer link (`anet://fanout?...`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FanoutLink {
    /// Upstream relay address (host:port)
    pub addr: String,
    /// Fan-out token (psk_..., issued by the peer)
    pub token: String,
    #[serde(default)]
    pub sni_hostname: String,
    #[serde(default)]
    pub pinned_fingerprint: Option<String>,
    #[serde(default)]
    pub insecure: bool,
}

/// Strip the scheme + role prefix (`anet://connect?` / `agilenet://connect?` etc.); None on mismatch.
fn strip_role_prefix<'a>(url: &'a str, role: &str) -> Option<&'a str> {
    for scheme in [LINK_SCHEME, LEGACY_LINK_SCHEME] {
        if let Some(rest) = url.strip_prefix(scheme)
            && let Some(rest) = rest.strip_prefix(role)
            && let Some(rest) = rest.strip_prefix('?')
        {
            return Some(rest);
        }
    }
    None
}

/// Resolve the server field: a full `https://host[:port]` form wins as-is; otherwise bare
/// host[:port] with the port param (or the role default) filled in.
fn resolve_server(server: &str, port: Option<u16>, default_port: u16) -> String {
    let server = server.trim().trim_end_matches('/');
    if server.starts_with("http://") || server.starts_with("https://") {
        return server.to_string();
    }
    if server.contains(':') {
        server.to_string()
    } else {
        format!("{}:{}", server, port.unwrap_or(default_port))
    }
}

fn truthy(v: &str) -> bool {
    v == "1" || v.eq_ignore_ascii_case("true")
}

/// Parse an `anet://connect?...` URL (legacy `agilenet://` accepted).
pub fn parse_connect_url(url: &str) -> std::result::Result<ConnectLink, String> {
    let rest = strip_role_prefix(url.trim(), "connect")
        .ok_or_else(|| "无效的接入链接前缀".to_string())?;
    let mut server = String::new();
    let mut port: Option<u16> = None;
    let mut account = String::new();
    let mut password = String::new();
    let mut fp: Option<String> = None;
    let mut insecure = false;
    let mut admin = false;
    for pair in rest.split('&') {
        let mut kv = pair.splitn(2, '=');
        let (k, v) = (kv.next().unwrap_or(""), kv.next().unwrap_or(""));
        let v = url_decode(v);
        match k {
            "server" => server = v,
            "port" => port = v.parse().ok(),
            "account" => account = v,
            "password" => password = v,
            "fp" => fp = Some(v),
            "insecure" => insecure = truthy(&v),
            "admin" => admin = truthy(&v),
            _ => {}
        }
    }
    if server.is_empty() || account.is_empty() || password.is_empty() {
        return Err("接入链接缺少必要参数 (server/account/password)".into());
    }
    Ok(ConnectLink {
        addr: resolve_server(&server, port, DEFAULT_API_PORT),
        account,
        password,
        pinned_fingerprint: fp,
        insecure,
        admin,
    })
}

/// Parse an `anet://fanout?...` URL (legacy `agilenet://` accepted).
pub fn parse_fanout_url(url: &str) -> std::result::Result<FanoutLink, String> {
    let rest = strip_role_prefix(url.trim(), "fanout")
        .ok_or_else(|| "无效的扇出链接前缀".to_string())?;
    let mut server = String::new();
    let mut port: Option<u16> = None;
    let mut token = String::new();
    let mut sni = String::new();
    let mut fp: Option<String> = None;
    let mut insecure = false;
    for pair in rest.split('&') {
        let mut kv = pair.splitn(2, '=');
        let (k, v) = (kv.next().unwrap_or(""), kv.next().unwrap_or(""));
        let v = url_decode(v);
        match k {
            "server" => server = v,
            "port" => port = v.parse().ok(),
            "token" => token = v,
            "sni" => sni = v,
            "fp" => fp = Some(v),
            "insecure" => insecure = truthy(&v),
            _ => {}
        }
    }
    if server.is_empty() || token.is_empty() {
        return Err("扇出链接缺少必要参数 (server/token)".into());
    }
    Ok(FanoutLink {
        addr: resolve_server(&server, port, DEFAULT_RELAY_PORT),
        token,
        sni_hostname: sni,
        pinned_fingerprint: fp,
        insecure,
    })
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// Split an addr into (server, port) query values (full-scheme addrs stay whole in server).
fn server_params(addr: &str) -> (String, Option<u16>) {
    let a = addr
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');
    match a.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => (h.to_string(), p.parse::<u16>().ok()),
        _ => (a.to_string(), None),
    }
}

/// Build an anet://connect URL (contains the plaintext password; share with care).
/// A full-scheme addr (`https://host[:port]`, reverse-proxy fronted API) stays whole in the
/// server param (the port param carries a relay/API-port semantic and must not apply).
pub fn build_connect_url(
    addr: &str,
    account: &str,
    password: &str,
    pinned_fingerprint: Option<&str>,
) -> String {
    let server = server_query(addr, DEFAULT_API_PORT);
    let mut url = format!(
        "anet://connect?{server}&account={}&password={}",
        url_encode(account),
        url_encode(password),
    );
    if let Some(fp) = pinned_fingerprint.filter(|s| !s.is_empty()) {
        url.push_str(&format!("&tls=1&fp={fp}"));
    }
    url
}

/// Build an anet://fanout URL (contains the fan-out token; share with care).
pub fn build_fanout_url(
    addr: &str,
    token: &str,
    sni: &str,
    pinned_fingerprint: Option<&str>,
) -> String {
    let server = server_query(addr, DEFAULT_RELAY_PORT);
    let mut url = format!("anet://fanout?{server}&token={}", url_encode(token));
    if !sni.is_empty() {
        url.push_str(&format!("&sni={}", url_encode(sni)));
    }
    if let Some(fp) = pinned_fingerprint.filter(|s| !s.is_empty()) {
        url.push_str(&format!("&fp={fp}"));
    }
    url
}

/// `server=H&port=P` query fragment for an addr (full-scheme addrs collapse to a single server param).
fn server_query(addr: &str, default_port: u16) -> String {
    let a = addr.trim().trim_end_matches('/');
    if a.starts_with("http://") || a.starts_with("https://") {
        return format!("server={}", url_encode(a));
    }
    let (host, port) = server_params(a);
    format!(
        "server={host}&port={}",
        port.map(|p| p.to_string())
            .unwrap_or_else(|| default_port.to_string())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_new_scheme_connect() {
        let p = parse_connect_url(
            "anet://connect?server=anet.example.com&port=59090&account=alice&password=sk-x&fp=ab12",
        )
        .expect("parse");
        assert_eq!(p.addr, "anet.example.com:59090");
        assert_eq!(p.account, "alice");
        assert_eq!(p.password, "sk-x");
        assert_eq!(p.pinned_fingerprint.as_deref(), Some("ab12"));
        assert!(!p.admin);
    }

    #[test]
    fn parse_legacy_scheme_still_works() {
        let p = parse_connect_url("agilenet://connect?server=1.2.3.4&port=59090&account=a&password=b")
            .expect("legacy parse");
        assert_eq!(p.addr, "1.2.3.4:59090");
    }

    #[test]
    fn parse_full_scheme_server_wins() {
        let p = parse_connect_url(
            "anet://connect?server=https%3A%2F%2Fanet.example.com&account=a&password=b",
        )
        .expect("parse");
        assert_eq!(p.addr, "https://anet.example.com");
        let p = parse_connect_url(
            "anet://connect?server=https%3A%2F%2Fanet.example.com%3A8443&account=a&password=b",
        )
        .expect("parse with port");
        assert_eq!(p.addr, "https://anet.example.com:8443");
    }

    #[test]
    fn parse_admin_flag() {
        let p = parse_connect_url("anet://connect?server=h:1&account=a&password=b&admin=1").unwrap();
        assert!(p.admin);
    }

    #[test]
    fn fanout_roundtrip() {
        let url = build_fanout_url("b.example.com:54430", "psk_secret-123", "cdn.cloudflare.com", Some("ff00aa"));
        assert_eq!(
            url,
            "anet://fanout?server=b.example.com&port=54430&token=psk_secret-123&sni=cdn.cloudflare.com&fp=ff00aa"
        );
        let p = parse_fanout_url(&url).expect("parse");
        assert_eq!(p.addr, "b.example.com:54430");
        assert_eq!(p.token, "psk_secret-123");
        assert_eq!(p.sni_hostname, "cdn.cloudflare.com");
        assert_eq!(p.pinned_fingerprint.as_deref(), Some("ff00aa"));
        assert!(!p.insecure);
    }

    #[test]
    fn connect_roundtrip_and_admin_flag() {
        let url = build_connect_url("1.2.3.4:59090", "u", "p", Some("ab"));
        assert!(url.starts_with("anet://connect?"));
        let p = parse_connect_url(&url).expect("roundtrip");
        assert_eq!(p.account, "u");
        assert_eq!(p.password, "p");
        assert_eq!(p.pinned_fingerprint.as_deref(), Some("ab"));
    }

    #[test]
    fn rejects_missing_params() {
        assert!(parse_fanout_url("anet://fanout?server=b:54430").is_err());
        assert!(parse_connect_url("anet://connect?server=b:1").is_err());
        assert!(parse_connect_url("http://connect?server=b:1&account=a&password=c").is_err());
    }

    #[test]
    fn build_full_scheme_addr_kept_whole() {
        let url = build_connect_url("https://anet.example.com", "u", "p", None);
        assert_eq!(url, "anet://connect?server=https%3A%2F%2Fanet.example.com&account=u&password=p");
        let p = parse_connect_url(&url).unwrap();
        assert_eq!(p.addr, "https://anet.example.com");
    }

    #[test]
    fn password_special_chars_encoded() {
        let url = build_connect_url("h:1", "u", "p&=x%", None);
        let p = parse_connect_url(&url).unwrap();
        assert_eq!(p.password, "p&=x%");
    }
}
