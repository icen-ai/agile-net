//! Built-in network security agent (white-hat assistant; design discussion 2026-08).
//!
//! Architecture:
//! - The conversation is session-scoped and owned HERE (Rust side), not in the webview: closing the drawer,
//!   minimizing to tray, or reopening the window never interrupts a running turn; the frontend re-renders
//!   from `agent_get_state` and live `agent-ev` events. There is deliberately no history management —
//!   one running conversation, the user clears it manually (functional tool, not a chat product).
//! - Tool layer is a standalone registry {name / JSON schema / handler / confirm flag} from day one:
//!   the same table drives the built-in function calling now and can be exposed as an MCP server later
//!   (no free-form shell anywhere — hallucination containment is a hard boundary).
//! - Mutation tools (confirm=true) park on a oneshot until `agent_confirm` answers (5min timeout = deny,
//!   fail-closed). Read-only tools run straight through.
//! - Network pinning: the LLM route comes from the endpoint preset (see llm.rs); Direct presets also
//!   auto-inject their API host into the custom bypass rules so TUN/proxy churn can't break the session.
//!   Transport failures mid-turn auto-retry with the same history (max 2 retries, status surfaced).

use crate::{llm, roles, AppState};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex as StdMutex;
use tauri::{AppHandle, Emitter, Manager, State};

/// Key storage: OS keyring on Windows/macOS (same keyring scheme as crates/client credentials),
/// 0600 file fallback elsewhere (Android).
#[cfg(any(windows, target_os = "macos"))]
const KEY_SERVICE: &str = "ai.icen.agilenet.gui";
#[cfg(any(windows, target_os = "macos"))]
const KEY_USER: &str = "llm-api-key";
/// Tool execution timeout (defense against a hung probe stalling the whole turn)
const TOOL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Confirm-card wait before default deny
const CONFIRM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);
/// Max tool-call rounds per user message (loop guard)
const MAX_ROUNDS: usize = 10;
/// Tool result cap fed back to the model (chars)
const TOOL_RESULT_CAP: usize = 4000;

// ==================== Config / skills persistence ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub preset: String,
    pub base_url: String,
    pub model: String,
}

impl Default for AgentConfig {
    fn default() -> Self {
        let p = &llm::PRESETS[0];
        Self { preset: p.id.into(), base_url: p.base_url.into(), model: p.default_model.into() }
    }
}

fn config_path() -> std::path::PathBuf {
    roles::data_dir().join("agent-config.json")
}
fn skills_path() -> std::path::PathBuf {
    roles::data_dir().join("agent-skills.json")
}

/// Playbook skill (prompt fragment appended to the system prompt; builtin ships with code,
/// user skills persist to agent-skills.json; builtin prompts refresh from code each boot,
/// only their enabled flag is kept from disk — so prompt upgrades ship with the app).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Skill {
    pub id: String,
    pub name: String,
    pub desc: String,
    pub prompt: String,
    pub enabled: bool,
    pub builtin: bool,
}

fn builtin_skills() -> Vec<Skill> {
    vec![
        Skill {
            id: "net-down".into(),
            name: "网络不通排查".into(),
            desc: "由近及远定位断点：代理/TUN → 网关 → DNS → 出口".into(),
            prompt: "排查「网络不通」时按此顺序：1) proxy_overview 看总代理/TUN/内核状态；2) sysproxy_status 看系统代理是否被改；3) net_ping 网关（如 192.168.1.1）与 223.5.5.5；4) net_dns 查一个常见域名；5) doctor_run 收尾确认。每一步用一句话告诉小白用户你在查什么。".into(),
            enabled: true, builtin: true,
        },
        Skill {
            id: "net-slow".into(),
            name: "网速变慢排查".into(),
            desc: "出口、节点延迟、大流量连接与异常占用".into(),
            prompt: "排查「网速变慢」时：1) proxy_overview 看当前出口模式；2) net_tcping 到常用服务（如 443）对比延迟；3) conlog_recent 找上下行最大的连接，指出占流量域名；4) 需要时 net_trace 看哪一跳变慢。给出「直连/换节点/关闭占速应用」级别的可执行建议。".into(),
            enabled: true, builtin: true,
        },
        Skill {
            id: "under-attack".into(),
            name: "疑似被攻击应急".into(),
            desc: "扫描/爆破/异常外联的证据收集与防御建议".into(),
            prompt: "用户怀疑被攻击（扫描、爆破、木马外联）时：1) conlog_recent 看失败聚簇与可疑域名/端口；2) net_sockets 找异常监听与已建立外联（含进程名）；3) recent_events 看近期配置变更是否本人所为；4) doctor_run 补全环境。结论分三档：正常/可疑/高危，并给防御动作清单（打断连接、封域名、收缩监听、吊销令牌——变更类由用户确认后执行）。严禁建议反打对方：防御只限本机（阻断、收缩、取证、上报）。".into(),
            enabled: true, builtin: true,
        },
        Skill {
            id: "proxy-hijack".into(),
            name: "代理被劫持检查".into(),
            desc: "系统代理/DNS/hosts 是否被第三方篡改".into(),
            prompt: "检查「代理被劫持/网络被篡改」时：1) sysproxy_status 对比期望值与当前值（冲突即被改）；2) net_dns 用 223.5.5.5 与系统默认各查一次对比结果；3) net_sockets 看 57890/59291 等本机端口被谁占用；4) conlog_recent 找你不认识的域名。被篡改时给出一键收回/断开/查杀建议。".into(),
            enabled: true, builtin: true,
        },
    ]
}

fn load_config() -> AgentConfig {
    std::fs::read_to_string(config_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn load_skills() -> Vec<Skill> {
    let saved: Vec<Skill> = std::fs::read_to_string(skills_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let mut out = Vec::new();
    for mut b in builtin_skills() {
        if let Some(s) = saved.iter().find(|s| s.id == b.id) {
            b.enabled = s.enabled; // only the toggle persists for builtins
        }
        out.push(b);
    }
    out.extend(saved.into_iter().filter(|s| !s.builtin));
    out
}

fn save_skills(skills: &[Skill]) -> Result<(), String> {
    std::fs::create_dir_all(roles::data_dir()).map_err(|e| e.to_string())?;
    std::fs::write(
        skills_path(),
        serde_json::to_string_pretty(skills).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

// ==================== API key storage ====================

#[cfg(any(windows, target_os = "macos"))]
fn store_api_key(key: &str) -> Result<(), String> {
    keyring::Entry::new(KEY_SERVICE, KEY_USER)
        .map_err(|e| e.to_string())?
        .set_password(key)
        .map_err(|e| e.to_string())
}
#[cfg(any(windows, target_os = "macos"))]
fn get_api_key() -> Option<String> {
    keyring::Entry::new(KEY_SERVICE, KEY_USER)
        .ok()?
        .get_password()
        .ok()
        .filter(|s| !s.is_empty())
}

#[cfg(not(any(windows, target_os = "macos")))]
fn key_file() -> std::path::PathBuf {
    roles::data_dir().join("agent-key")
}
#[cfg(not(any(windows, target_os = "macos")))]
fn store_api_key(key: &str) -> Result<(), String> {
    use std::io::Write;
    let _ = std::fs::create_dir_all(roles::data_dir());
    let mut f = std::fs::File::create(key_file()).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    f.write_all(key.as_bytes()).map_err(|e| e.to_string())
}
#[cfg(not(any(windows, target_os = "macos")))]
fn get_api_key() -> Option<String> {
    std::fs::read_to_string(key_file()).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

// ==================== Conversation model (UI-facing; derives the LLM wire form) ====================

#[derive(Debug, Clone, Serialize)]
pub struct ToolRun {
    pub id: String,
    pub name: String,
    pub args: String,
    /// running | confirm | done | failed | denied
    pub status: String,
    pub result: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentItem {
    /// "user" | "assistant"
    pub role: String,
    pub text: String,
    pub tools: Vec<ToolRun>,
}

pub struct PendingConfirm {
    pub call_id: String,
    pub name: String,
    pub args: String,
    pub tx: tokio::sync::oneshot::Sender<bool>,
}

#[derive(Default)]
pub struct AgentState {
    pub conv: StdMutex<Vec<AgentItem>>,
    pub running: AtomicBool,
    pub abort: StdMutex<Option<tauri::async_runtime::JoinHandle<()>>>,
    pub pending: StdMutex<Option<PendingConfirm>>,
    pub config: StdMutex<AgentConfig>,
    pub skills: StdMutex<Vec<Skill>>,
}

impl AgentState {
    pub fn new() -> Self {
        Self {
            config: StdMutex::new(load_config()),
            skills: StdMutex::new(load_skills()),
            ..Default::default()
        }
    }
}

// ==================== Tool registry ====================

struct ToolDef {
    name: &'static str,
    desc: &'static str,
    params: serde_json::Value,
    confirm: bool,
}

fn registry() -> Vec<ToolDef> {
    use serde_json::json;
    let obj = |props: serde_json::Value, req: &[&str]| json!({"type":"object","properties":props,"required":req});
    vec![
        ToolDef { name: "doctor_run", desc: "运行 AgileNet 自我诊断（系统/网络/代理/TUN/订阅等多节检查，含自动修复结果）。网络问题的首选起点。", params: obj(json!({}), &[]), confirm: false },
        ToolDef { name: "net_ping", desc: "对目标 ping（ICMP 失败自动 TCP 回退），返回丢包率与延迟。", params: obj(json!({"host":{"type":"string","description":"域名或 IP"}}), &["host"]), confirm: false },
        ToolDef { name: "net_tcping", desc: "TCP 端口连通性探测（端口是否可达、握手延迟）。", params: obj(json!({"host":{"type":"string"},"port":{"type":"integer"}}), &["host","port"]), confirm: false },
        ToolDef { name: "net_dns", desc: "DNS 解析查询（可指定 DNS 服务器），用于判断 DNS 故障/劫持。", params: obj(json!({"domain":{"type":"string"},"server":{"type":"string","description":"可选，如 223.5.5.5"}}), &["domain"]), confirm: false },
        ToolDef { name: "net_trace", desc: "路由追踪（逐跳延迟），定位断点/慢点在哪一跳。", params: obj(json!({"host":{"type":"string"}}), &["host"]), confirm: false },
        ToolDef { name: "net_sockets", desc: "本机套接字表（监听/已建立连接，含进程名），发现异常监听与外联。", params: obj(json!({}), &[]), confirm: false },
        ToolDef { name: "conlog_recent", desc: "查询连接记录（anet 入站全收录：域名/出站/命中层/上下行/状态/时间）。用户未开启记录开关时会返回提示。", params: obj(json!({"keyword":{"type":"string","description":"可选，域名包含词"},"limit":{"type":"integer","description":"可选，默认 30"}}), &[]), confirm: false },
        ToolDef { name: "sysproxy_status", desc: "系统代理状态与被篡改检测（期望值 vs 当前值，冲突即疑似被第三方修改）。", params: obj(json!({}), &[]), confirm: false },
        ToolDef { name: "proxy_overview", desc: "AgileNet 运行概览：总代理/扇入/扇出/订阅内核/TUN/系统代理偏好与监听端口。", params: obj(json!({}), &[]), confirm: false },
        ToolDef { name: "recent_events", desc: "本机近期事件审计（角色切换/系统代理变更/规则变更/内核事件）。", params: obj(json!({"limit":{"type":"integer","description":"可选，默认 20"}}), &[]), confirm: false },
        ToolDef { name: "conlog_kill", desc: "【防御动作】强制打断指定活动连接（conlog_recent 结果里的 id），用于切断可疑外联。", params: obj(json!({"id":{"type":"integer","description":"连接记录 id"}}), &["id"]), confirm: true },
    ]
}

fn tool_schemas() -> Vec<serde_json::Value> {
    registry()
        .iter()
        .map(|t| serde_json::json!({"type":"function","function":{"name":t.name,"description":t.desc,"parameters":t.params}}))
        .collect()
}

fn cap_result(s: String) -> String {
    if s.chars().count() > TOOL_RESULT_CAP {
        let cut: String = s.chars().take(TOOL_RESULT_CAP).collect();
        format!("{cut}\n…（结果过长已截断）")
    } else {
        s
    }
}

/// Execute a registry tool; every return is a String fed back to the model (never panics).
async fn exec_tool(app: &AppHandle, state: &AppState, name: &str, args: &serde_json::Value) -> String {
    use agile_net_node::tool;
    let dur = std::time::Duration::from_secs;
    let s = |k: &str| args[k].as_str().unwrap_or("").to_string();
    let out = match name {
        "doctor_run" => match crate::run_doctor(app.clone()).await {
            Ok(r) => serde_json::to_string_pretty(&r).unwrap_or_default(),
            Err(e) => format!("诊断运行失败: {e}"),
        },
        "net_ping" => tool::ping::ping(&s("host"), 4, dur(2), 443).await.human,
        "net_tcping" => {
            tool::tcping::tcping(&s("host"), args["port"].as_u64().unwrap_or(443) as u16, 4, dur(2)).await.human
        }
        "net_dns" => {
            let server = s("server");
            tool::dns::dns_query(&s("domain"), if server.is_empty() { None } else { Some(server.as_str()) }, "A").await.human
        }
        "net_trace" => tool::traceroute::trace(&s("host"), 20, dur(2)).await.human,
        "net_sockets" => match tool::netstat::sockets() {
            Ok(list) => {
                let mut lines: Vec<String> = list
                    .iter()
                    .filter(|x| matches!(x.state.as_deref(), Some("LISTEN") | Some("ESTABLISHED")))
                    .take(80)
                    .map(|x| {
                        format!(
                            "{} {} {} {} {}",
                            x.proto,
                            x.local,
                            x.remote.clone().unwrap_or_default(),
                            x.state.clone().unwrap_or_default(),
                            x.process.clone().unwrap_or_default()
                        )
                    })
                    .collect();
                lines.insert(0, format!("共 {} 条（仅 LISTEN/ESTABLISHED，前 80 条）：", lines.len()));
                lines.join("\n")
            }
            Err(e) => format!("读取失败: {e}"),
        },
        "conlog_recent" => {
            let log = state.client.conn_log();
            if !log.is_enabled() {
                "用户尚未开启「连接记录」开关（日志页 → 连接记录 → 记录连接）。请提示用户开启后再查；开启是隐私 opt-in，不要替他开启。".to_string()
            } else {
                let kw = s("keyword");
                let f = agile_net_core::proxy::conlog::ConnFilter {
                    keyword: if kw.is_empty() { None } else { Some(kw) },
                    limit: args["limit"].as_u64().unwrap_or(30) as usize,
                    source: Some("all".into()),
                    ..Default::default()
                };
                let out = log.query(&f);
                let mut rows = vec![format!("共 {} 条匹配，返回 {} 条：", out.total, out.items.len())];
                for r in out.items {
                    let st = match &r.state {
                        agile_net_core::proxy::conlog::RecState::Active => "活动".to_string(),
                        agile_net_core::proxy::conlog::RecState::Closed => "关闭".to_string(),
                        agile_net_core::proxy::conlog::RecState::Failed { reason } => format!("失败({reason})"),
                    };
                    rows.push(format!(
                        "id={} {}:{} {:?} 命中={:?} ↓{}B ↑{}B {}",
                        r.id, r.host, r.port, r.outbound, r.hit, r.down, r.up, st
                    ));
                }
                rows.join("\n")
            }
        }
        "sysproxy_status" => {
            let (managed, expected) = {
                let r = state.roles.lock().await;
                (
                    r.system_proxy || r.tun_mode || r.sysproxy_lock,
                    format!("127.0.0.1:{}", state.client.proxy_port()),
                )
            };
            match tokio::task::spawn_blocking(move || crate::sysproxy::inspect(managed, &expected)).await {
                Ok(Ok(st)) => serde_json::to_string_pretty(&st).unwrap_or_default(),
                Ok(Err(e)) => format!("读取失败: {e}"),
                Err(e) => format!("读取失败: {e}"),
            }
        }
        "proxy_overview" => {
            let port = state.client.proxy_port();
            let kernel = state.kernel.status().await;
            let r = state.roles.lock().await;
            serde_json::json!({
                "local_proxy": { "on": port > 0, "detail": if port > 0 { format!("127.0.0.1:{port}") } else { "已停止".to_string() } },
                "subscription_kernel": { "running": kernel.running, "version": kernel.version },
                "roles": { "client": r.client, "server": r.server, "web": r.web, "system_proxy": r.system_proxy, "tun_mode": r.tun_mode, "sysproxy_lock": r.sysproxy_lock },
            })
            .to_string()
        }
        "recent_events" => {
            let n = args["limit"].as_u64().unwrap_or(20).clamp(1, 100) as usize;
            let evs = roles::recent_events(n);
            serde_json::to_string_pretty(&evs).unwrap_or_default()
        }
        "conlog_kill" => {
            let id = args["id"].as_u64().unwrap_or(0);
            if state.client.conn_log().kill(id) {
                format!("连接 {id} 已打断")
            } else {
                format!("连接 {id} 不存在或已结束")
            }
        }
        other => format!("未知工具: {other}"),
    };
    cap_result(out)
}

// ==================== System prompt ====================

fn build_system_prompt(skills: &[Skill]) -> String {
    let mut p = String::from(
        "你是 AgileNet 内置的网络安全助手（白帽）。运行环境：一台装有 AgileNet 的桌面机（网络穿透/代理链路由系统）。\
        你能通过工具直接查看和操作本机网络状态。\n\
        纪律：\n\
        1. 先诊断后动作：变更类操作前必须有诊断依据，并在回答里说明理由；系统会对变更类工具强制要求用户确认。\n\
        2. 严禁建议攻击性或违法操作（扫描/攻击/反打他人）。防御只限本机：阻断、收缩暴露面、取证、上报。\n\
        3. 面向网络小白：通俗中文，术语首次出现给一句解释；回答分步骤、简洁。\n\
        4. 引用数据要具体（数值、域名、端口），不要泛泛而谈；信息不足就说明缺什么、怎么补。\n\
        5. 工具结果可能被截断（标记「已截断」），需要更多就换更精确的参数再查。",
    );
    let active: Vec<&Skill> = skills.iter().filter(|s| s.enabled).collect();
    if !active.is_empty() {
        p.push_str("\n\n场景技能（用户点对应卡片或描述对应场景时遵循）：");
        for s in active {
            p.push_str(&format!("\n## {}\n{}", s.name, s.prompt));
        }
    }
    p
}

// ==================== LLM wire form ====================

fn build_messages(items: &[AgentItem], skills: &[Skill]) -> Vec<llm::ChatMsg> {
    let mut msgs = vec![llm::ChatMsg::system(build_system_prompt(skills))];
    for it in items {
        if it.role == "user" {
            msgs.push(llm::ChatMsg::user(it.text.clone()));
        } else {
            let wire_calls = if it.tools.is_empty() {
                None
            } else {
                Some(
                    it.tools
                        .iter()
                        .map(|t| serde_json::json!({"id": t.id, "type": "function", "function": {"name": t.name, "arguments": t.args}}))
                        .collect(),
                )
            };
            let content = if it.text.is_empty() { None } else { Some(it.text.clone()) };
            msgs.push(llm::ChatMsg::assistant(content, wire_calls));
            for t in &it.tools {
                let body = if t.result.is_empty() {
                    format!("（工具未执行：{}）", t.status)
                } else {
                    t.result.clone()
                };
                msgs.push(llm::ChatMsg::tool(t.id.clone(), body));
            }
        }
    }
    msgs
}

// ==================== Events / run loop ====================

fn emit(app: &AppHandle, v: serde_json::Value) {
    let _ = app.emit("agent-ev", v);
}

fn set_running(state: &AppState, app: &AppHandle, on: bool) {
    state.agent.running.store(on, Ordering::Relaxed);
    emit(app, serde_json::json!({"k":"running","v":on}));
}

pub async fn run_agent(app: AppHandle) {
    let state = app.state::<AppState>();
    let st = state.inner();
    'rounds: for _ in 0..MAX_ROUNDS {
        let (msgs, base_url, model, route, key) = {
            let cfg = st.agent.config.lock().unwrap().clone();
            let preset = llm::preset_of(&cfg.preset);
            let base_url = if cfg.preset == "custom" { cfg.base_url.clone() } else { preset.map(|p| p.base_url.to_string()).unwrap_or(cfg.base_url.clone()) };
            let model = if cfg.model.is_empty() { preset.map(|p| p.default_model.to_string()).unwrap_or_default() } else { cfg.model.clone() };
            let route = preset.map(|p| p.route).unwrap_or(llm::Route::Direct);
            let key = get_api_key().unwrap_or_default();
            let msgs = {
                let items = st.agent.conv.lock().unwrap();
                let skills = st.agent.skills.lock().unwrap();
                build_messages(&items, &skills)
            };
            (msgs, base_url, model, route, key)
        };
        if key.is_empty() {
            emit(&app, serde_json::json!({"k":"error","t":"尚未配置 API Key：设置 → AI 助手"}));
            break 'rounds;
        }

        // Fresh assistant item; deltas stream into it live (drawer reopen mid-stream shows partial text)
        st.agent.conv.lock().unwrap().push(AgentItem { role: "assistant".into(), text: String::new(), tools: Vec::new() });
        let app2 = app.clone();
        let on_delta = move |frag: &str| {
            let st = app2.state::<AppState>();
            let s = st.inner();
            if let Some(last) = s.agent.conv.lock().unwrap().last_mut() {
                last.text.push_str(frag);
            }
            emit(&app2, serde_json::json!({"k":"delta","t":frag}));
        };

        // Transport-failure resume: same history, up to 2 retries (defense actions may legitimately break the path)
        let mut turn = None;
        for attempt in 0..3usize {
            match llm::chat_stream(&base_url, &key, &model, route, &msgs, &tool_schemas(), &on_delta).await {
                Ok(t) => {
                    turn = Some(t);
                    break;
                }
                Err(e) => {
                    if attempt >= 2 {
                        emit(&app, serde_json::json!({"k":"error","t":format!("{e}（已重试 2 次）")}));
                        break;
                    }
                    emit(&app, serde_json::json!({"k":"retry","n":attempt + 1,"t":e}));
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
        let Some(turn) = turn else { break 'rounds };

        // Authoritative content sync (deltas streamed live; this corrects any drift) + keeps AssistantTurn.content read
        if let Some(last) = st.agent.conv.lock().unwrap().last_mut() {
            if last.text != turn.content {
                last.text = turn.content.clone();
            }
        }

        if turn.tool_calls.is_empty() {
            break 'rounds; // final text answer
        }

        // Register tool runs on the current assistant item
        {
            let mut conv = st.agent.conv.lock().unwrap();
            if let Some(last) = conv.last_mut() {
                last.tools = turn
                    .tool_calls
                    .iter()
                    .map(|c| ToolRun { id: c.id.clone(), name: c.name.clone(), args: c.args.clone(), status: "running".into(), result: String::new() })
                    .collect();
            }
        }

        for call in &turn.tool_calls {
            let def = registry().into_iter().find(|t| t.name == call.name);
            let need_confirm = def.map(|d| d.confirm).unwrap_or(false);
            let args_pretty = serde_json::from_str::<serde_json::Value>(&call.args)
                .ok()
                .map(|v| serde_json::to_string_pretty(&v).unwrap_or(call.args.clone()))
                .unwrap_or_else(|| call.args.clone());
            emit(&app, serde_json::json!({"k":"tool","id":call.id,"name":call.name,"args":args_pretty,"status":"running"}));

            if need_confirm {
                let (tx, rx) = tokio::sync::oneshot::channel();
                *st.agent.pending.lock().unwrap() = Some(PendingConfirm { call_id: call.id.clone(), name: call.name.clone(), args: args_pretty.clone(), tx });
                emit(&app, serde_json::json!({"k":"confirm","id":call.id,"name":call.name,"args":args_pretty}));
                crate::float_notify(&app, format!("网络助手请求执行：{}", call.name));
                let allow = match tokio::time::timeout(CONFIRM_TIMEOUT, rx).await {
                    Ok(Ok(v)) => v,
                    _ => false, // timeout / dropped = deny (fail-closed)
                };
                *st.agent.pending.lock().unwrap() = None;
                emit(&app, serde_json::json!({"k":"confirm_clear"}));
                if !allow {
                    let stt = state.inner();
                    if let Some(last) = stt.agent.conv.lock().unwrap().last_mut() {
                        if let Some(t) = last.tools.iter_mut().find(|t| t.id == call.id) {
                            t.status = "denied".into();
                        }
                    }
                    emit(&app, serde_json::json!({"k":"tool","id":call.id,"name":call.name,"status":"denied","result":"用户拒绝或未在 5 分钟内确认"}));
                    continue;
                }
            }

            let result = match tokio::time::timeout(
                TOOL_TIMEOUT,
                exec_tool(&app, st, &call.name, &serde_json::from_str(&call.args).unwrap_or_default()),
            )
            .await
            {
                Ok(r) => r,
                Err(_) => format!("工具执行超时（{}s）", TOOL_TIMEOUT.as_secs()),
            };
            {
                let stt = state.inner();
                if let Some(last) = stt.agent.conv.lock().unwrap().last_mut() {
                    if let Some(t) = last.tools.iter_mut().find(|t| t.id == call.id) {
                        t.status = "done".into();
                        t.result = result.clone();
                    }
                }
            }
            emit(&app, serde_json::json!({"k":"tool","id":call.id,"name":call.name,"status":"done","result":result}));
        }
        // next round: tool results fold into the history via build_messages
    }
    set_running(st, &app, false);
}

// ==================== Commands ====================

#[derive(Serialize)]
pub struct ConfigView {
    pub preset: String,
    pub preset_name: String,
    pub base_url: String,
    pub model: String,
    pub route: String,
    pub has_key: bool,
}

#[derive(Serialize)]
pub struct PendingView {
    pub id: String,
    pub name: String,
    pub args: String,
}

#[derive(Serialize)]
pub struct AgentSnapshot {
    pub items: Vec<AgentItem>,
    pub running: bool,
    pub pending: Option<PendingView>,
    pub config: ConfigView,
    pub skills: Vec<Skill>,
}

fn config_view(cfg: &AgentConfig) -> ConfigView {
    let preset = llm::preset_of(&cfg.preset);
    ConfigView {
        preset: cfg.preset.clone(),
        preset_name: preset.map(|p| p.name.to_string()).unwrap_or_else(|| cfg.preset.clone()),
        base_url: cfg.base_url.clone(),
        model: cfg.model.clone(),
        route: preset.map(|p| p.route.as_str()).unwrap_or("direct").to_string(),
        has_key: get_api_key().is_some(),
    }
}

#[tauri::command]
pub(crate) async fn agent_get_state(state: State<'_, AppState>) -> Result<AgentSnapshot, String> {
    let st = state.inner();
    let items = st.agent.conv.lock().unwrap().clone();
    let running = st.agent.running.load(Ordering::Relaxed);
    let pending = st
        .agent
        .pending
        .lock()
        .unwrap()
        .as_ref()
        .map(|p| PendingView { id: p.call_id.clone(), name: p.name.clone(), args: p.args.clone() });
    let config = config_view(&st.agent.config.lock().unwrap());
    let skills = st.agent.skills.lock().unwrap().clone();
    Ok(AgentSnapshot { items, running, pending, config, skills })
}

#[tauri::command]
pub(crate) async fn agent_send(app: AppHandle, state: State<'_, AppState>, text: String) -> Result<(), String> {
    let text = text.trim().to_string();
    if text.is_empty() {
        return Err("消息为空".into());
    }
    let st = state.inner();
    if st.agent.running.swap(true, Ordering::Relaxed) {
        return Err("助手正在工作，请先停止或等待完成".into());
    }
    st.agent.conv.lock().unwrap().push(AgentItem { role: "user".into(), text, tools: Vec::new() });
    set_running(st, &app, true);
    let handle = tauri::async_runtime::spawn(run_agent(app.clone()));
    *st.agent.abort.lock().unwrap() = Some(handle);
    Ok(())
}

#[tauri::command]
pub(crate) async fn agent_stop(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    let st = state.inner();
    if let Some(h) = st.agent.abort.lock().unwrap().take() {
        h.abort();
    }
    if let Some(p) = st.agent.pending.lock().unwrap().take() {
        let _ = p.tx.send(false); // deny whatever was parked
    }
    set_running(st, &app, false);
    Ok(())
}

#[tauri::command]
pub(crate) async fn agent_clear(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    let st = state.inner();
    if let Some(h) = st.agent.abort.lock().unwrap().take() {
        h.abort();
    }
    if let Some(p) = st.agent.pending.lock().unwrap().take() {
        let _ = p.tx.send(false);
    }
    st.agent.conv.lock().unwrap().clear();
    st.agent.running.store(false, Ordering::Relaxed);
    emit(&app, serde_json::json!({"k":"cleared"}));
    emit(&app, serde_json::json!({"k":"running","v":false}));
    Ok(())
}

#[tauri::command]
pub(crate) async fn agent_confirm(app: AppHandle, state: State<'_, AppState>, allow: bool) -> Result<(), String> {
    let st = state.inner();
    if let Some(p) = st.agent.pending.lock().unwrap().take() {
        let _ = p.tx.send(allow);
    }
    emit(&app, serde_json::json!({"k":"confirm_clear"}));
    Ok(())
}

/// Save endpoint config (api key goes to the OS keyring / 0600 file, never to disk JSON, never echoed back).
/// Direct-route presets auto-inject their API host into the custom bypass rules (TUN/proxy churn can't break the session).
#[tauri::command]
pub(crate) async fn agent_config_set(
    state: State<'_, AppState>,
    preset: String,
    base_url: Option<String>,
    model: Option<String>,
    api_key: Option<String>,
) -> Result<(), String> {
    let st = state.inner();
    let p = llm::preset_of(&preset).ok_or_else(|| format!("未知服务商: {preset}"))?;
    let mut cfg = st.agent.config.lock().unwrap().clone();
    cfg.preset = preset.clone();
    cfg.base_url = if preset == "custom" {
        base_url.unwrap_or_default().trim().trim_end_matches('/').to_string()
    } else {
        p.base_url.to_string()
    };
    if preset == "custom" && cfg.base_url.is_empty() {
        return Err("自定义端点需要填写 Base URL".into());
    }
    cfg.model = model.unwrap_or_default().trim().to_string();
    if cfg.model.is_empty() {
        cfg.model = p.default_model.to_string();
    }
    if let Some(k) = api_key {
        let k = k.trim().to_string();
        if !k.is_empty() {
            store_api_key(&k)?;
        }
    }
    std::fs::create_dir_all(roles::data_dir()).map_err(|e| e.to_string())?;
    std::fs::write(config_path(), serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    // Auto-bypass the API host when the route is Direct (idempotent: an existing same-pattern rule counts)
    let bypass_host = if preset == "custom" {
        url_host(&cfg.base_url)
    } else if p.route == llm::Route::Direct {
        Some(p.bypass_host.to_string())
    } else {
        None
    };
    if let Some(host) = bypass_host {
        if !host.is_empty() {
            let exists = crate::custom_rules::snapshot()
                .bypass
                .iter()
                .any(|r| r.pattern.eq_ignore_ascii_case(&host));
            if !exists {
                let _ = crate::custom_rules::add_bypass(&state.client, &host, false);
            }
        }
    }
    *st.agent.config.lock().unwrap() = cfg;
    roles::audit("gui.agent_config", serde_json::json!({"preset": preset, "model": st.agent.config.lock().unwrap().model}));
    Ok(())
}

fn url_host(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let host = rest.split(['/', ':']).next()?;
    if host.is_empty() { None } else { Some(host.to_string()) }
}

/// Skills: save (create/update user skill), toggle enabled, delete (user skills only).
#[tauri::command]
pub(crate) async fn agent_skill_save(
    state: State<'_, AppState>,
    id: Option<String>,
    name: String,
    desc: Option<String>,
    prompt: String,
) -> Result<(), String> {
    if name.trim().is_empty() || prompt.trim().is_empty() {
        return Err("名称与提示词不能为空".into());
    }
    let st = state.inner();
    let mut skills = st.agent.skills.lock().unwrap();
    if let Some(id) = id {
        let s = skills.iter_mut().find(|s| s.id == id).ok_or("技能不存在")?;
        if s.builtin {
            return Err("内置技能不可编辑（可开关）".into());
        }
        s.name = name.trim().to_string();
        s.desc = desc.unwrap_or_default();
        s.prompt = prompt;
    } else {
        let id = format!("u{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0));
        skills.push(Skill { id, name: name.trim().to_string(), desc: desc.unwrap_or_default(), prompt, enabled: true, builtin: false });
    }
    save_skills(&skills)
}

#[tauri::command]
pub(crate) async fn agent_skill_toggle(state: State<'_, AppState>, id: String, enabled: bool) -> Result<(), String> {
    let st = state.inner();
    let mut skills = st.agent.skills.lock().unwrap();
    let s = skills.iter_mut().find(|s| s.id == id).ok_or("技能不存在")?;
    s.enabled = enabled;
    save_skills(&skills)
}

#[tauri::command]
pub(crate) async fn agent_skill_delete(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let st = state.inner();
    let mut skills = st.agent.skills.lock().unwrap();
    if skills.iter().find(|s| s.id == id).map(|s| s.builtin).unwrap_or(false) {
        return Err("内置技能不可删除".into());
    }
    skills.retain(|s| s.id != id);
    save_skills(&skills)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_wire_form_interleaves_tool_results() {
        let items = vec![
            AgentItem { role: "user".into(), text: "查一下".into(), tools: vec![] },
            AgentItem {
                role: "assistant".into(),
                text: "先看状态".into(),
                tools: vec![ToolRun { id: "c1".into(), name: "proxy_overview".into(), args: "{}".into(), status: "done".into(), result: "{\"on\":true}".into() }],
            },
        ];
        let msgs = build_messages(&items, &[]);
        assert_eq!(msgs[0].role, "system");
        assert_eq!(msgs[1].role, "user");
        assert_eq!(msgs[2].role, "assistant");
        assert!(msgs[2].tool_calls.is_some());
        assert_eq!(msgs[3].role, "tool");
        assert_eq!(msgs[3].tool_call_id.as_deref(), Some("c1"));
    }

    #[test]
    fn system_prompt_includes_only_enabled_skills() {
        let skills = vec![
            Skill { id: "a".into(), name: "甲".into(), desc: String::new(), prompt: "P-A".into(), enabled: true, builtin: false },
            Skill { id: "b".into(), name: "乙".into(), desc: String::new(), prompt: "P-B".into(), enabled: false, builtin: false },
        ];
        let p = build_system_prompt(&skills);
        assert!(p.contains("P-A"));
        assert!(!p.contains("P-B"));
    }

    #[test]
    fn url_host_parses_common_forms() {
        assert_eq!(url_host("https://api.x.com/v1"), Some("api.x.com".into()));
        assert_eq!(url_host("http://127.0.0.1:11434/v1"), Some("127.0.0.1".into()));
        assert!(url_host("").is_none());
    }
}
