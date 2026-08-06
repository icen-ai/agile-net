//! Thin OpenAI-compatible LLM client for the built-in network agent (chat completions + SSE streaming + function calling).
//!
//! One protocol covers every preset (DeepSeek / Kimi / OpenAI / Qwen / Zhipu / custom OpenAI-compatible endpoints
//! incl. local ollama-style servers), so no vendor SDK dependency — reqwest only.
//!
//! Network pinning (deliberate, see discussion): the HTTP client NEVER follows the system/environment proxy by
//! default — a defense run may legitimately change or stop the local proxy, and the model conversation must not
//! die mid-defense. Route policy hangs on the endpoint preset:
//! - Direct (domestic vendors): `no_proxy()`, immune to system-proxy/TUN churn; the caller additionally
//!   auto-injects the API host into the custom bypass rules so TUN mode also DIRECTs it.
//! - Proxy (overseas vendors): pinned to the local proxy 127.0.0.1:57890 explicitly; a proxy-stopping action
//!   then surfaces as a retryable transport error, and the agent layer auto-resumes with the same history.

use futures_util::StreamExt;
use serde::Serialize;
use std::collections::BTreeMap;
use std::time::Duration;

/// Route policy of an endpoint preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Pinned direct (system/env proxy disabled)
    Direct,
    /// Pinned via the anet local proxy (127.0.0.1:57890, HTTP CONNECT)
    Proxy,
}

impl Route {
    pub fn as_str(&self) -> &'static str {
        match self {
            Route::Direct => "direct",
            Route::Proxy => "proxy",
        }
    }
}

/// Endpoint preset (BYOK; api key comes from the OS keyring, never stored here).
pub struct Preset {
    pub id: &'static str,
    pub name: &'static str,
    pub base_url: &'static str,
    pub default_model: &'static str,
    pub route: Route,
    /// API host auto-injected into the custom bypass rules when the route is Direct (TUN-proofing)
    pub bypass_host: &'static str,
}

pub const PRESETS: &[Preset] = &[
    Preset { id: "deepseek", name: "DeepSeek", base_url: "https://api.deepseek.com/v1", default_model: "deepseek-chat", route: Route::Direct, bypass_host: "api.deepseek.com" },
    Preset { id: "kimi", name: "Kimi（月之暗面）", base_url: "https://api.moonshot.cn/v1", default_model: "moonshot-v1-8k", route: Route::Direct, bypass_host: "api.moonshot.cn" },
    Preset { id: "qwen", name: "通义千问", base_url: "https://dashscope.aliyuncs.com/compatible-mode/v1", default_model: "qwen-plus", route: Route::Direct, bypass_host: "dashscope.aliyuncs.com" },
    Preset { id: "zhipu", name: "智谱 GLM", base_url: "https://open.bigmodel.cn/api/paas/v4", default_model: "glm-4-flash", route: Route::Direct, bypass_host: "open.bigmodel.cn" },
    Preset { id: "openai", name: "OpenAI", base_url: "https://api.openai.com/v1", default_model: "gpt-4o-mini", route: Route::Proxy, bypass_host: "api.openai.com" },
    Preset { id: "custom", name: "自定义（OpenAI 兼容）", base_url: "", default_model: "", route: Route::Direct, bypass_host: "" },
];

pub fn preset_of(id: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|p| p.id == id)
}

/// One tool call parsed from the model output (arguments are the raw JSON string, accumulated from deltas).
#[derive(Debug, Clone)]
pub struct ToolCallReq {
    pub id: String,
    pub name: String,
    pub args: String,
}

/// Outbound chat message (API wire form).
#[derive(Debug, Clone, Serialize)]
pub struct ChatMsg {
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

impl ChatMsg {
    pub fn user(text: impl Into<String>) -> Self {
        Self { role: "user".into(), content: Some(text.into()), tool_calls: None, tool_call_id: None }
    }
    pub fn system(text: impl Into<String>) -> Self {
        Self { role: "system".into(), content: Some(text.into()), tool_calls: None, tool_call_id: None }
    }
    pub fn assistant(content: Option<String>, tool_calls: Option<Vec<serde_json::Value>>) -> Self {
        Self { role: "assistant".into(), content, tool_calls, tool_call_id: None }
    }
    pub fn tool(call_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self { role: "tool".into(), content: Some(content.into()), tool_calls: None, tool_call_id: Some(call_id.into()) }
    }
}

/// What a completed assistant turn looks like to the agent loop.
#[derive(Debug)]
pub struct AssistantTurn {
    pub content: String,
    pub tool_calls: Vec<ToolCallReq>,
}

fn http_client(route: Route) -> Result<reqwest::Client, String> {
    let b = reqwest::Client::builder().connect_timeout(Duration::from_secs(15));
    let b = match route {
        // Pinned off any proxy: system/env proxy never consulted
        Route::Direct => b.no_proxy(),
        // Pinned to the anet local proxy explicitly (NOT "the system proxy", so changing the system
        // proxy preference mid-defense does not silently re-route this client)
        Route::Proxy => b
            .no_proxy()
            .proxy(reqwest::Proxy::all("http://127.0.0.1:57890").map_err(|e| e.to_string())?),
    };
    b.build().map_err(|e| e.to_string())
}

/// One streaming chat completion. `on_delta` fires per content fragment (for live rendering).
/// Tool calls are accumulated from indexed deltas and returned whole.
pub async fn chat_stream(
    base_url: &str,
    api_key: &str,
    model: &str,
    route: Route,
    messages: &[ChatMsg],
    tools: &[serde_json::Value],
    on_delta: &(dyn Fn(&str) + Send + Sync),
) -> Result<AssistantTurn, String> {
    let mut body = serde_json::json!({
        "model": model,
        "messages": messages,
        "stream": true,
    });
    if !tools.is_empty() {
        body["tools"] = serde_json::Value::Array(tools.to_vec());
        body["tool_choice"] = serde_json::json!("auto");
    }
    let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));
    let resp = http_client(route)?
        .post(url)
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("连接模型服务失败: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        let short: String = text.chars().take(300).collect();
        return Err(format!("模型服务返回 {status}: {short}"));
    }

    let mut stream = resp.bytes_stream();
    let mut buf = String::new();
    let mut content = String::new();
    // index → (id, name, args)
    let mut calls: BTreeMap<usize, (String, String, String)> = BTreeMap::new();

    'outer: while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("读取流式响应失败: {e}"))?;
        buf.push_str(&String::from_utf8_lossy(&chunk));
        while let Some(pos) = buf.find('\n') {
            let line: String = buf[..pos].trim().to_string();
            buf.drain(..pos + 1);
            if line.is_empty() || line.starts_with(':') {
                continue;
            }
            let Some(data) = line.strip_prefix("data:") else { continue };
            let data = data.trim();
            if data == "[DONE]" {
                break 'outer;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(data) else { continue };
            let delta = &v["choices"][0]["delta"];
            if let Some(c) = delta["content"].as_str() {
                content.push_str(c);
                on_delta(c);
            }
            if let Some(tcs) = delta["tool_calls"].as_array() {
                for tc in tcs {
                    let idx = tc["index"].as_u64().unwrap_or(0) as usize;
                    let e = calls.entry(idx).or_default();
                    if let Some(id) = tc["id"].as_str() {
                        e.0 = id.to_string();
                    }
                    if let Some(n) = tc["function"]["name"].as_str() {
                        e.1 = n.to_string();
                    }
                    if let Some(a) = tc["function"]["arguments"].as_str() {
                        e.2.push_str(a);
                    }
                }
            }
        }
    }

    let tool_calls = calls
        .into_values()
        .filter(|(id, name, _)| !id.is_empty() && !name.is_empty())
        .map(|(id, name, args)| ToolCallReq { id, name, args })
        .collect();
    Ok(AssistantTurn { content, tool_calls })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_have_unique_ids_and_direct_presets_carry_bypass_host() {
        let mut seen = std::collections::HashSet::new();
        for p in PRESETS {
            assert!(seen.insert(p.id), "duplicate preset id {}", p.id);
            if p.route == Route::Direct && p.id != "custom" {
                assert!(!p.bypass_host.is_empty(), "{} direct preset needs bypass_host", p.id);
            }
        }
        assert!(preset_of("deepseek").is_some());
        assert!(preset_of("nope").is_none());
    }

    #[test]
    fn chatmsg_wire_skips_none_fields() {
        let m = ChatMsg::user("hi");
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["role"], "user");
        assert_eq!(v["content"], "hi");
        assert!(v.get("tool_calls").is_none());
        assert!(v.get("tool_call_id").is_none());
        let t = ChatMsg::tool("call_1", "result");
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["tool_call_id"], "call_1");
    }
}
