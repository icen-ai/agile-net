//! Shared facilities across command domains: session persistence, API client, table/JSON output, ID prefix resolution, and common arg structs.

use anyhow::{Result, anyhow, bail};
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::PathBuf;

// ---------- Common args ----------

#[derive(Args, Debug)]
pub struct ListArgs {
    /// 搜索关键字
    #[arg(short, long)]
    pub q: Option<String>,
    /// 页码
    #[arg(long, default_value = "1")]
    pub page: u32,
    /// 类型过滤（ip-cidr / host）
    #[arg(long = "type")]
    pub type_filter: Option<String>,
}

#[derive(Args, Debug)]
pub struct IdArgs {
    /// 资源 ID（支持前缀）
    pub id: String,
    /// 强制删除（解除引用/级联）
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct IdOnlyArgs {
    pub id: String,
}

// ==================== Session management ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub api: String,
    pub access_token: String,
    pub refresh_token: String,
}

fn session_path() -> PathBuf {
    agile_net_core::util::brand_root().join("session.json")
}

impl Session {
    pub fn load() -> Option<Self> {
        let path = session_path();
        let data = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&data).ok()
    }

    pub fn save(&self) -> Result<()> {
        let path = session_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, serde_json::to_string_pretty(self)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    pub fn clear() {
        let _ = std::fs::remove_file(session_path());
    }
}

// ==================== API client ====================

pub struct AnetClient {
    http: reqwest::Client,
    pub(crate) session: Session,
}

impl AnetClient {
    pub fn from_session(api_override: Option<String>) -> Result<Self> {
        let mut session = Session::load().ok_or_else(|| anyhow!("未登录，请先执行 anet login"))?;
        if let Some(api) = api_override {
            session.api = api.trim_end_matches('/').to_string();
        }
        Ok(Self {
            http: reqwest::Client::new(),
            session,
        })
    }

    async fn raw(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.session.api, path);
        let mut req = match method {
            "GET" => self.http.get(&url),
            "POST" => self.http.post(&url),
            "PUT" => self.http.put(&url),
            "DELETE" => self.http.delete(&url),
            _ => bail!("unsupported method"),
        };
        req = req.bearer_auth(&self.session.access_token);
        if let Some(b) = body {
            req = req.json(b);
        }
        Ok(req.send().await?)
    }

    async fn try_refresh(&mut self) -> Result<()> {
        let url = format!("{}/api/v1/auth/refresh", self.session.api);
        let resp = self
            .http
            .post(&url)
            .json(&json!({ "refresh_token": self.session.refresh_token }))
            .send()
            .await?;
        if !resp.status().is_success() {
            bail!("会话已过期，请重新 anet login");
        }
        let j: Value = resp.json().await?;
        self.session.access_token = j["data"]["access_token"]
            .as_str()
            .ok_or_else(|| anyhow!("bad refresh response"))?
            .to_string();
        if let Some(r) = j["data"]["refresh_token"].as_str() {
            self.session.refresh_token = r.to_string();
        }
        self.session.save()?;
        Ok(())
    }

    /// Call the API and unwrap the unified response envelope (auto-refresh and retry once on 401).
    pub async fn api(&mut self, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
        let mut resp = self.raw(method, path, body.as_ref()).await?;
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            self.try_refresh().await?;
            resp = self.raw(method, path, body.as_ref()).await?;
        }
        let status = resp.status();
        let j: Value = resp
            .json()
            .await
            .unwrap_or(json!({"code": -1, "message": "invalid response"}));
        let code = j["code"].as_i64().unwrap_or(-1);
        if code != 0 {
            bail!(
                "API 错误 (HTTP {status}, code {code}): {}",
                j["message"].as_str().unwrap_or("unknown")
            );
        }
        Ok(j["data"].clone())
    }
}

// ==================== Output ====================

pub(crate) fn print_json(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap());
}

pub(crate) fn print_table(headers: &[&str], rows: Vec<Vec<String>>) {
    let mut widths: Vec<usize> = headers.iter().map(|h| display_width(h)).collect();
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(display_width(cell));
            }
        }
    }
    let header_line: Vec<String> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| pad(h, widths[i]))
        .collect();
    println!("{}", header_line.join("  "));
    println!(
        "{}",
        widths
            .iter()
            .map(|w| "─".repeat(*w))
            .collect::<Vec<_>>()
            .join("──")
    );
    for row in rows {
        let line: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(i, c)| pad(c, *widths.get(i).unwrap_or(&0)))
            .collect();
        println!("{}", line.join("  "));
    }
}

fn display_width(s: &str) -> usize {
    s.chars()
        .map(|c| if c as u32 > 0x2E7F { 2 } else { 1 })
        .sum()
}

fn pad(s: &str, width: usize) -> String {
    let w = display_width(s);
    if w >= width {
        s.to_string()
    } else {
        format!("{}{}", s, " ".repeat(width - w))
    }
}

/// Parse a comma-separated list (trim + drop empty segments), used by advertise etc.
pub(crate) fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .map(|p| p.to_string())
        .collect()
}

/// ID prefix resolution: fetch from the list endpoint and match a unique prefix.
/// Also supports exact match by name/username (e.g. `--group dev-team`).
pub(crate) async fn resolve_id(
    client: &mut AnetClient,
    list_path: &str,
    prefix: &str,
) -> Result<String> {
    let data = client.api("GET", list_path, None).await?;
    let items = data["items"].as_array().cloned().unwrap_or_default();
    let matches: Vec<&Value> = items
        .iter()
        .filter(|i| {
            i["id"].as_str().unwrap_or_default().starts_with(prefix)
                || i["name"].as_str() == Some(prefix)
                || i["username"].as_str() == Some(prefix)
        })
        .collect();
    match matches.len() {
        1 => Ok(matches[0]["id"].as_str().unwrap().to_string()),
        0 => bail!("未找到 ID 前缀/名称为 {prefix} 的资源"),
        _ => bail!(
            "前缀 {prefix} 匹配到 {} 个资源，请输入更长前缀",
            matches.len()
        ),
    }
}
