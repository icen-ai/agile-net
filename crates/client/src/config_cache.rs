//! 配置离线缓存（断网沿用旧规则）。

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::client::ClientRule;

/// 节点配置缓存（断网沿用旧规则：docs/architecture/config-file.md 承诺）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedNodeConfig {
    pub addr: String,
    pub username: String,
    pub node_name: String,
    pub rules: Vec<ClientRule>,
    pub config_version: u64,
    pub tunnel_server: String,
    pub tunnel_port: u16,
    pub tunnel_token: String,
    pub refresh_token: String,
    pub insecure: bool,
    pub pinned_fingerprint: Option<String>,
    pub updated_at: String,
}

/// 缓存目录（~/.agile-net/cache/），文件权限 0600。
pub struct ConfigCache {
    dir: PathBuf,
}

impl ConfigCache {
    pub fn new() -> Result<Self> {
        let dir = crate::home_dir().join(".agile-net").join("cache");
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// 指定缓存目录（主要用于测试与降级兜底）
    pub fn with_dir(dir: PathBuf) -> Self {
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }

    fn key_for(addr: &str, username: &str) -> String {
        let raw = format!("{addr}|{username}");
        raw.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    }

    fn path_for(&self, addr: &str, username: &str) -> PathBuf {
        self.dir
            .join(format!("{}.json", Self::key_for(addr, username)))
    }

    pub fn save(&self, cfg: &CachedNodeConfig) {
        let path = self.path_for(&cfg.addr, &cfg.username);
        if let Ok(data) = serde_json::to_string_pretty(cfg) {
            let _ = std::fs::write(&path, data);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
        }
    }

    pub fn load(&self, addr: &str, username: &str) -> Option<CachedNodeConfig> {
        let path = self.path_for(addr, username);
        let data = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&data).ok()
    }

    pub fn remove(&self, addr: &str, username: &str) {
        let _ = std::fs::remove_file(self.path_for(addr, username));
    }
}

impl Default for ConfigCache {
    fn default() -> Self {
        Self::new().expect("create config cache dir")
    }
}
