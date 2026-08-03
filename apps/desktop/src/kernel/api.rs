//! 从 subscription.rs 拆分：REST 控制面客户端（纯搬运，零逻辑变更）

use super::config::MIHOMO_CTRL_PORT;
use super::store::load_store;

// ==================== REST 控制面（loopback + secret） ====================

pub struct KernelApi {
    client: reqwest::Client,
    base: String,
    secret: String,
}

impl KernelApi {
    fn new(secret: String) -> Self {
        Self {
            client: reqwest::Client::new(),
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

    /// 全量代理与组信息（原样透传 mihomo JSON）
    pub async fn proxies(&self) -> Result<serde_json::Value, String> {
        self.req(reqwest::Method::GET, "/proxies")
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())
    }

    /// 选择组内节点
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

    /// 组延迟（name → ms）：provider 节点不注册进全局 /proxies，单节点
    /// `/proxies/{name}/delay` 恒 404，必须走 `/group/{group}/delay`（内核并发测全组，
    /// 失败节点记为 timeout 值，此处过滤剔除）。
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

    /// 组测速（「每日选妃」：HTTPS 204 探测，不剔除失败节点）：
    /// 失败/超时节点（mihomo 记为 timeout 值）延迟归一为 0。
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

    /// 组测速原始请求：name → ms 全量（失败节点记 timeout 值，不做归一/过滤）。
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

    /// provider 节点明细（type/history；provider 节点不在全局 /proxies 注册表）
    pub async fn provider_proxies(&self) -> Result<serde_json::Value, String> {
        self.req(reqwest::Method::GET, "/providers/proxies")
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())
    }

    /// 触发订阅（provider）手动刷新（单 provider 恒名 main，见 render_config）
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

    /// 出站模式热切（PATCH /configs，mihomo 支持 mode 热更新，无需重启内核）
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

    /// 关闭单条连接（DELETE /connections/{id}；mihomo 204 无体）
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

    /// 当前生效配置（GET /configs；E2E 断言 TUN 骨架已加载用）
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

/// 以当前持久化 secret 构建控制面客户端。
pub async fn kernel_api() -> Result<KernelApi, String> {
    let store = load_store();
    if store.secret.is_empty() {
        return Err("内核尚未初始化".into());
    }
    Ok(KernelApi::new(store.secret))
}
