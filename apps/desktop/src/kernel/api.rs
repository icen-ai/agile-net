//! Split from subscription.rs: REST control plane client (pure move, zero logic change)

use super::config::MIHOMO_CTRL_PORT;
use super::store::load_store;

// ==================== REST control plane (loopback + secret) ====================

pub struct KernelApi {
    client: reqwest::Client,
    base: String,
    secret: String,
}

impl KernelApi {
    fn new(secret: String) -> Self {
        Self {
            // no_proxy: the controller is hardcoded loopback — reqwest's default system-proxy would
            // otherwise read the engaged Windows system proxy (our own inbound!) and loop control-plane
            // calls back into the proxy, breaking every controller call while the system proxy is on.
            client: reqwest::Client::builder()
                .no_proxy()
                .build()
                .expect("reqwest client init"),
            base: format!("http://127.0.0.1:{MIHOMO_CTRL_PORT}"),
            secret,
        }
    }

    fn req(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, format!("{}{}", self.base, path))
            .header("Authorization", format!("Bearer {}", self.secret))
    }

    pub async fn version(&self) -> Result<String, String> {
        let v: serde_json::Value = self
            .req(reqwest::Method::GET, "/version")
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        v["version"].as_str().map(|s| s.to_string()).ok_or_else(|| "版本解析失败".into())
    }

    /// Full proxies and groups info (mihomo JSON passed through verbatim)
    pub async fn proxies(&self) -> Result<serde_json::Value, String> {
        self.req(reqwest::Method::GET, "/proxies")
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())
    }

    /// Select a node within a group
    pub async fn select(&self, group: &str, name: &str) -> Result<(), String> {
        let resp = self
            .req(reqwest::Method::PUT, &format!("/proxies/{group}"))
            .json(&serde_json::json!({"name": name}))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("切换失败 (HTTP {})", resp.status()))
        }
    }

    /// Group delays (name → ms): provider nodes are not registered in global /proxies, so per-node
    /// `/proxies/{name}/delay` always 404s; must use `/group/{group}/delay` (the kernel probes the whole
    /// group concurrently, failed nodes report the timeout value and are filtered out here).
    pub async fn group_delay(
        &self,
        group: &str,
    ) -> Result<std::collections::HashMap<String, u32>, String> {
        const TIMEOUT_MS: u32 = 5000;
        let raw = self
            .group_delay_raw(group, TIMEOUT_MS, "http://www.gstatic.com/generate_204")
            .await?;
        Ok(raw.into_iter().filter(|(_, d)| *d < TIMEOUT_MS).collect())
    }

    /// Group speed test ("daily pick": HTTPS 204 probe, failed nodes kept):
    /// failed/timed-out nodes (mihomo reports the timeout value) get delay normalized to 0.
    pub async fn group_delay_all(
        &self,
        group: &str,
        timeout_ms: u32,
    ) -> Result<Vec<(String, u32)>, String> {
        let raw = self
            .group_delay_raw(group, timeout_ms, "https://www.gstatic.com/generate_204")
            .await?;
        Ok(raw
            .into_iter()
            .map(|(name, d)| (name, if d >= timeout_ms { 0 } else { d }))
            .collect())
    }

    /// Raw group speed test request: full name → ms map (failed nodes report the timeout value; no normalization/filtering).
    async fn group_delay_raw(
        &self,
        group: &str,
        timeout_ms: u32,
        url: &str,
    ) -> Result<std::collections::HashMap<String, u32>, String> {
        let resp = self
            .req(reqwest::Method::GET, &format!("/group/{group}/delay"))
            .query(&[("timeout", timeout_ms.to_string()), ("url", url.to_string())])
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("测速失败 (HTTP {})", resp.status()));
        }
        let v: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        let obj = v.as_object().ok_or("测速失败")?;
        Ok(obj
            .iter()
            .filter_map(|(k, val)| Some((k.clone(), val.as_u64()? as u32)))
            .collect())
    }

    /// Provider node details (type/history; provider nodes are not in the global /proxies registry)
    pub async fn provider_proxies(&self) -> Result<serde_json::Value, String> {
        self.req(reqwest::Method::GET, "/providers/proxies")
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())
    }

    /// Trigger a manual subscription (provider) refresh (single provider always named main, see render_config)
    pub async fn update_provider(&self) -> Result<(), String> {
        let resp = self
            .req(reqwest::Method::PUT, "/providers/proxies/main")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("刷新失败 (HTTP {})", resp.status()))
        }
    }

    /// Hot-switch outbound mode (PATCH /configs; mihomo supports hot mode updates, no kernel restart needed)
    pub async fn set_mode(&self, mode: &str) -> Result<(), String> {
        let resp = self
            .req(reqwest::Method::PATCH, "/configs")
            .json(&serde_json::json!({"mode": mode}))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("模式切换失败 (HTTP {})", resp.status()))
        }
    }

    /// Close a single connection (DELETE /connections/{id}; mihomo returns 204 with no body)
    pub async fn close_connection(&self, id: &str) -> Result<(), String> {
        let resp = self
            .req(reqwest::Method::DELETE, &format!("/connections/{id}"))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("关闭连接失败 (HTTP {})", resp.status()))
        }
    }

    /// Current effective config (GET /configs; used by E2E to assert the TUN skeleton is loaded)
    #[cfg(test)]
    pub async fn configs(&self) -> Result<serde_json::Value, String> {
        self.req(reqwest::Method::GET, "/configs")
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())
    }
}

/// Build a control plane client with the currently persisted secret.
pub async fn kernel_api() -> Result<KernelApi, String> {
    let store = load_store();
    if store.secret.is_empty() {
        return Err("内核尚未初始化".into());
    }
    Ok(KernelApi::new(store.secret))
}
