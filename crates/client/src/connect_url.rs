//! 接入链接（agilenet://connect?...）解析与生成。

use serde::{Deserialize, Serialize};

use crate::credential::Credential;

/// 解析后的接入参数（桌面 IPC 与 Web REST 共用同一形状）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedConnect {
    pub addr: String,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub pinned_cert_path: Option<String>,
    #[serde(default)]
    pub pinned_fingerprint: Option<String>,
    #[serde(default)]
    pub manage_hosts: bool,
    /// 连接成功后是否保存凭据
    #[serde(default)]
    pub save_credential: bool,
    /// 管理版接入链接标记（admin=1：持链接者可管理该节点，导入时强警示）
    #[serde(default)]
    pub admin: Option<String>,
}

/// 解析 agilenet://connect?... 接入链接。
pub fn parse_connect_url(url: &str) -> std::result::Result<ParsedConnect, String> {
    let rest = url
        .strip_prefix("agilenet://connect?")
        .ok_or_else(|| "无效的接入链接前缀".to_string())?;
    let mut server = String::new();
    let mut port: Option<u16> = None;
    let mut account = String::new();
    let mut password = String::new();
    let mut fp: Option<String> = None;
    let mut insecure = false;
    let mut admin: Option<String> = None;
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
            "insecure" => insecure = v == "1" || v.eq_ignore_ascii_case("true"),
            "admin" => admin = Some(v),
            _ => {}
        }
    }
    if server.is_empty() || account.is_empty() || password.is_empty() {
        return Err("接入链接缺少必要参数 (server/account/password)".into());
    }
    // server 未含端口时用 port 参数补全
    let addr = if server.contains(':') {
        server
    } else {
        format!("{}:{}", server, port.unwrap_or(59090))
    };
    Ok(ParsedConnect {
        addr,
        username: account,
        password,
        insecure,
        pinned_cert_path: None,
        pinned_fingerprint: fp,
        manage_hosts: false,
        save_credential: true,
        admin,
    })
}

/// 由已保存凭据生成 agilenet://connect 接入链接（含明文密码，谨慎分享）。
pub fn connect_url_of(c: &Credential) -> String {
    let stripped = c
        .addr
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');
    let (host, port) = match stripped.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => (h.to_string(), p.to_string()),
        _ => (stripped.to_string(), "59090".to_string()),
    };
    let mut url = format!(
        "agilenet://connect?server={host}&port={port}&account={}&password={}",
        c.username, c.password
    );
    if let Some(fp) = &c.pinned_fingerprint {
        url.push_str(&format!("&tls=1&fp={fp}"));
    }
    if c.insecure {
        url.push_str("&insecure=1");
    }
    url
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
