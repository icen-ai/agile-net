//! AgileNet CLI（`anet-svc` 顶层管理命令）— 企业级命令行管理工具
//!
//! 特性：
//! - 会话持久化（~/.anet/session.json，Unix 0600），access_token 过期自动刷新
//! - 全量管理命令：node / rule / group / account / token / connector / admin / audit
//! - ID 前缀解析（输入前几位即可，如 `anet-svc rule delete 3f2a`）
//! - --json 机器可读输出，默认表格输出

use anyhow::{Context as _, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "anet cli",
    version,
    about = "AgileNet CLI — 网络穿透与代理链路由管理工具"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// 节点 API 地址（默认读取会话或 http://127.0.0.1:59090）
    #[arg(global = true, long)]
    pub api: Option<String>,

    /// 机器可读 JSON 输出
    #[arg(global = true, long)]
    pub json: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// 登录端点并保存会话
    Login(LoginArgs),
    /// 登出并清除会话
    Logout,
    /// 端点运行状态总览（等同 `node status`）
    Status,
    /// 路由规则管理
    Rule(RuleArgs),
    /// 权限组管理
    Group(GroupArgs),
    /// 客户端账号管理
    Account(AccountArgs),
    /// Relay 令牌管理
    Token(TokenArgs),
    /// 扇出对端管理
    Connector(ConnectorArgs),
    /// 管理员管理
    Admin(AdminArgs),
    /// 审计日志查询
    Audit(AuditArgs),
    /// 内置网络诊断工具集（tcping/curl/dns/scan/ping…，本机诊断；bandwidth 除外需登录）
    Tool(crate::tool::ToolArgs),
    /// 自我诊断（端口/系统代理/内核/网络/配置/规则体检，自动修复可修项；本机操作无需登录）
    Doctor,
    /// 启动本地 TUI 控制台（直连数据库）
    Tui,
}

#[derive(Args, Debug)]
pub struct LoginArgs {
    #[arg(short, long)]
    pub username: Option<String>,
    #[arg(short, long)]
    pub password: Option<String>,
}

// ---------- Rule ----------
#[derive(Args, Debug)]
pub struct RuleArgs {
    #[command(subcommand)]
    pub command: RuleSub,
}

#[derive(Subcommand, Debug)]
pub enum RuleSub {
    /// 列出规则
    List(ListArgs),
    /// 新建规则
    Add(RuleAddArgs),
    /// 更新规则
    Update(RuleUpdateArgs),
    /// 删除规则
    Delete(IdArgs),
    /// 批量导入（JSON 文件）
    Batch(BatchArgs),
}

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
pub struct RuleAddArgs {
    /// 类型：ip-cidr 或 host
    #[arg(long = "type")]
    pub rule_type: String,
    /// 匹配值（10.12.0.0/16 或 git.internal）
    #[arg(long)]
    pub value: String,
    /// host 需要客户端写入系统 hosts
    #[arg(long)]
    pub resolve: bool,
    #[arg(long)]
    pub remark: Option<String>,
}

#[derive(Args, Debug)]
pub struct RuleUpdateArgs {
    pub id: String,
    #[arg(long)]
    pub value: Option<String>,
    #[arg(long)]
    pub resolve: Option<bool>,
    #[arg(long)]
    pub remark: Option<String>,
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
pub struct BatchArgs {
    /// JSON 文件路径
    pub file: String,
    /// 冲突处理：skip / overwrite / error
    #[arg(long, default_value = "skip")]
    pub on_conflict: String,
}

// ---------- Group ----------
#[derive(Args, Debug)]
pub struct GroupArgs {
    #[command(subcommand)]
    pub command: GroupSub,
}

#[derive(Subcommand, Debug)]
pub enum GroupSub {
    /// 列出权限组（支持搜索/分页）
    List(ListArgs),
    /// 查看权限组详情（含绑定规则）
    Show(IdOnlyArgs),
    /// 新建权限组（可同时绑定规则）
    Add(GroupAddArgs),
    /// 更新权限组名称/备注
    Update(GroupUpdateArgs),
    /// 删除权限组（--force 解除账号引用）
    Delete(IdArgs),
    /// 全量设置绑定规则（传规则 ID 列表）
    SetRules(SetRulesArgs),
}

#[derive(Args, Debug)]
pub struct IdOnlyArgs {
    pub id: String,
}

#[derive(Args, Debug)]
pub struct GroupAddArgs {
    #[arg(long)]
    pub name: String,
    #[arg(long)]
    pub remark: Option<String>,
    /// 逗号分隔的规则 ID
    #[arg(long)]
    pub rule_ids: Option<String>,
}

#[derive(Args, Debug)]
pub struct GroupUpdateArgs {
    pub id: String,
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub remark: Option<String>,
}

#[derive(Args, Debug)]
pub struct SetRulesArgs {
    pub id: String,
    /// 规则 ID 列表（空格分隔，支持前缀）
    pub rule_ids: Vec<String>,
}

// ---------- Account ----------
#[derive(Args, Debug)]
pub struct AccountArgs {
    #[command(subcommand)]
    pub command: AccountSub,
}

#[derive(Subcommand, Debug)]
pub enum AccountSub {
    /// 列出账号（搜索/权限组/状态过滤）
    List(AccountListArgs),
    /// 新建账号（密码与接入链接仅显示一次；--admin 签发管理版链接）
    Add(AccountAddArgs),
    /// 更新账号（换组/启停/备注/管理权限收放）
    Update(AccountUpdateArgs),
    /// 删除账号
    Delete(IdArgs),
    /// 重置密码（新密码与接入链接仅显示一次）
    ResetPassword(IdOnlyArgs),
}

#[derive(Args, Debug)]
pub struct AccountListArgs {
    #[arg(short, long)]
    pub q: Option<String>,
    #[arg(long)]
    pub page: Option<u32>,
    /// 按权限组过滤（组 ID 或前缀）
    #[arg(long)]
    pub group: Option<String>,
    /// 按状态过滤
    #[arg(long)]
    pub enabled: Option<bool>,
}

#[derive(Args, Debug)]
pub struct AccountAddArgs {
    #[arg(long)]
    pub username: String,
    /// 权限组（ID 或前缀）
    #[arg(long)]
    pub group: String,
    #[arg(long)]
    pub remark: Option<String>,
    /// 同时授予管理权限（签发管理版接入链接，签发记审计，仅发给可信管理员）
    #[arg(long)]
    pub admin: bool,
}

#[derive(Args, Debug)]
pub struct AccountUpdateArgs {
    pub id: String,
    #[arg(long)]
    pub group: Option<String>,
    #[arg(long)]
    pub enabled: Option<bool>,
    #[arg(long)]
    pub remark: Option<String>,
    /// 管理权限收放（true 授予 / false 收回，变更记审计）
    #[arg(long)]
    pub admin: Option<bool>,
}

// ---------- Token ----------
#[derive(Args, Debug)]
pub struct TokenArgs {
    #[command(subcommand)]
    pub command: TokenSub,
}

#[derive(Subcommand, Debug)]
pub enum TokenSub {
    /// 列出令牌（前缀/权限组/暴露控制面/档位/最近使用）
    List,
    /// 生成令牌（明文仅显示一次；--group 收敛到权限组，--expose-control 暴露控制面）
    #[command(alias = "create")]
    Add(TokenAddArgs),
    /// 吊销令牌（在线下游立即被踢）
    Delete(IdOnlyArgs),
}

#[derive(Args, Debug)]
pub struct TokenAddArgs {
    #[arg(long)]
    pub remark: Option<String>,
    /// 允许持该令牌的下游中继管理本端点（暴露控制面，默认关）
    #[arg(long)]
    pub expose_control: bool,
    /// 控制面授权档位：ro（只读）/ rules（可改规则）/ full（全权）
    #[arg(long, default_value = "full", value_parser = ["ro", "rules", "full"])]
    pub scope: String,
    /// 收敛权限组（名称或 ID；缺省 = 不收敛，放行一切）
    #[arg(long)]
    pub group: Option<String>,
}

// ---------- Connector ----------
#[derive(Args, Debug)]
pub struct ConnectorArgs {
    #[command(subcommand)]
    pub command: ConnectorSub,
}

#[derive(Subcommand, Debug)]
pub enum ConnectorSub {
    /// 列出扇出对端（含实时状态）
    List,
    /// 新增扇出对端（token 为对端签发凭据，加密落库不回显）
    Add(ConnectorAddArgs),
    /// 更新扇出对端（缺省参数保留原值；--token 留空 = 保留原 token）
    Update(ConnectorUpdateArgs),
    /// 删除扇出对端
    Remove(IdOnlyArgs),
    /// 启用扇出对端（装配起连）
    Enable(IdOnlyArgs),
    /// 禁用扇出对端（断开移除，记录保留）
    Disable(IdOnlyArgs),
}

#[derive(Args, Debug)]
pub struct ConnectorAddArgs {
    /// 对端显示名（管理端列表/审计用）
    #[arg(long)]
    pub name: String,
    /// 上游地址（host:port）
    #[arg(long)]
    pub addr: String,
    /// 扇出 token（对端签发；加密落库，创建后不回显）
    #[arg(long)]
    pub token: String,
    /// SNI 主机名（TLS 校验用）
    #[arg(long)]
    pub sni: Option<String>,
    /// 跳过 TLS 证书校验（仅调试用）
    #[arg(long)]
    pub insecure: bool,
    /// 宣告路由（逗号分隔，如 10.0.0.0/8,git.internal）
    #[arg(long)]
    pub advertise: Option<String>,
    /// 收敛权限组（名称或 ID；缺省 = 不收敛，放行一切）
    #[arg(long)]
    pub group: Option<String>,
    #[arg(long)]
    pub remark: Option<String>,
}

#[derive(Args, Debug)]
pub struct ConnectorUpdateArgs {
    /// 对端 ID（支持前缀）或名称
    pub id: String,
    #[arg(long)]
    pub name: Option<String>,
    /// 上游地址（host:port）
    #[arg(long)]
    pub addr: Option<String>,
    /// 重置扇出 token（留空 = 保留原值）
    #[arg(long)]
    pub token: Option<String>,
    #[arg(long)]
    pub sni: Option<String>,
    #[arg(long)]
    pub insecure: Option<bool>,
    /// 宣告路由（逗号分隔；缺省 = 保留原值）
    #[arg(long)]
    pub advertise: Option<String>,
    /// 收敛权限组（名称或 ID；缺省 = 保持原组）
    #[arg(long)]
    pub group: Option<String>,
    #[arg(long)]
    pub remark: Option<String>,
}

// ---------- Admin ----------
#[derive(Args, Debug)]
pub struct AdminArgs {
    #[command(subcommand)]
    pub command: AdminSub,
}

#[derive(Subcommand, Debug)]
pub enum AdminSub {
    /// 列出管理员
    List,
    /// 新建管理员
    Add(AdminAddArgs),
    /// 删除管理员
    Delete(IdOnlyArgs),
    /// 修改自己的密码
    Passwd(PasswdArgs),
}

#[derive(Args, Debug)]
pub struct AdminAddArgs {
    #[arg(long)]
    pub username: String,
    #[arg(long)]
    pub password: Option<String>,
}

#[derive(Args, Debug)]
pub struct PasswdArgs {
    /// 旧密码（缺省交互输入）
    #[arg(long)]
    pub old_password: Option<String>,
    /// 新密码（缺省交互输入）
    #[arg(long)]
    pub new_password: Option<String>,
}

// ---------- Audit ----------
#[derive(Args, Debug)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub command: AuditSub,
}

#[derive(Subcommand, Debug)]
pub enum AuditSub {
    List(AuditListArgs),
}

#[derive(Args, Debug)]
pub struct AuditListArgs {
    /// 按动作过滤（如 account.create）
    #[arg(long)]
    pub action: Option<String>,
    #[arg(long, default_value = "1")]
    pub page: u32,
}

// ==================== 会话管理 ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub api: String,
    pub access_token: String,
    pub refresh_token: String,
}

fn session_path() -> PathBuf {
    home_dir().join(".anet").join("session.json")
}

fn home_dir() -> PathBuf {
    std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
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

// ==================== API 客户端 ====================

pub struct AnetClient {
    http: reqwest::Client,
    session: Session,
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

    /// 调用 API 并解包统一响应体（401 自动刷新重试一次）。
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

// ==================== 输出 ====================

fn print_json(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap());
}

fn print_table(headers: &[&str], rows: Vec<Vec<String>>) {
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

/// 逗号分隔列表解析（trim + 忽略空段），advertise 等用。
fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .map(|p| p.to_string())
        .collect()
}

/// ID 前缀解析：列表接口拉取并匹配前缀唯一项。
/// 同时支持按 name/username 精确匹配（如 `--group 开发组`）。
async fn resolve_id(client: &mut AnetClient, list_path: &str, prefix: &str) -> Result<String> {
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

// ==================== 命令执行 ====================

pub async fn run_cli(cli: Cli) -> Result<()> {
    dispatch(cli.command, cli.api, cli.json).await
}

/// 顶层命令分派（`anet-svc <rule|group|...>` 与旧式 `anet-svc cli ...` 共用）。
pub async fn dispatch(command: Commands, api: Option<String>, json_out: bool) -> Result<()> {
    match command {
        // 诊断工具集在会话校验之前分流：本机诊断，不登录、不读库、不记审计
        // （bandwidth 臂例外：经管理 API 在服务端执行，arm 内自行检查会话）
        Commands::Tool(args) => {
            let code = crate::tool::run(args, json_out, api).await;
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
        // 自我诊断同为会话校验前分流：本机操作，不登录、不写审计
        Commands::Doctor => {
            let report = crate::tool::doctor::run(crate::tool::doctor::DoctorContext::cli()).await;
            if json_out {
                print_json(&serde_json::to_value(&report).unwrap_or_default());
            } else {
                println!("{}", crate::tool::doctor::render(&report));
            }
            let code = crate::tool::doctor::exit_code(&report);
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
        Commands::Login(args) => cmd_login(api, args).await,
        Commands::Logout => {
            if let Ok(mut client) = AnetClient::from_session(api) {
                let _ = client
                    .api(
                        "POST",
                        "/api/v1/auth/logout",
                        Some(json!({ "refresh_token": client.session.refresh_token })),
                    )
                    .await;
            }
            Session::clear();
            println!("已登出并清除本地会话");
            Ok(())
        }
        Commands::Tui => {
            let db_path =
                std::env::var("DATABASE_PATH").unwrap_or_else(|_| "agile-net.db".to_string());
            crate::tui::run_tui(crate::tui::TuiOptions {
                offline: false,
                db_path,
                api: None,
            })?;
            Ok(())
        }
        Commands::Status => cmd_node_status(api, json_out).await,
        Commands::Rule(args) => cmd_rule(api, args, json_out).await,
        Commands::Group(args) => cmd_group(api, args, json_out).await,
        Commands::Account(args) => cmd_account(api, args, json_out).await,
        Commands::Token(args) => cmd_token(api, args, json_out).await,
        Commands::Connector(args) => cmd_connector(api, args, json_out).await,
        Commands::Admin(args) => cmd_admin(api, args, json_out).await,
        Commands::Audit(args) => cmd_audit(api, args, json_out).await,
    }
}

/// 节点运行状态总览（`anet-svc node status`）。
pub async fn cmd_node_status(api: Option<String>, json_out: bool) -> Result<()> {
    let mut client = AnetClient::from_session(api)?;
    let d = client.api("GET", "/api/v1/admin/node/status", None).await?;
    if json_out {
        print_json(&d);
    } else {
        println!("端点状态");
        println!("  名称:     {}", d["node_name"].as_str().unwrap_or("-"));
        println!("  版本:     v{}", d["version"].as_str().unwrap_or("-"));
        println!("  运行时长: {}s", d["uptime"].as_u64().unwrap_or(0));
        let l = &d["roles"]["listener"];
        println!(
            "  Relay:    {} (扇入 {} · 在线客户端 {})",
            if l["enabled"].as_bool().unwrap_or(false) {
                l["addr"].as_str().unwrap_or("启用")
            } else {
                "未启用"
            },
            l["connected_connectors"].as_u64().unwrap_or(0),
            l["online_clients"].as_u64().unwrap_or(0)
        );
        let cs_summary = d["roles"]["connector_status"].as_str().unwrap_or("disabled");
        println!(
            "  扇出:     {}",
            if cs_summary == "disabled" {
                "未配置".to_string()
            } else {
                d["roles"]["connectors"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .map(|c| {
                                format!(
                                    "{} [{}]",
                                    c["upstream"].as_str().unwrap_or("-"),
                                    c["status"].as_str().unwrap_or("-")
                                )
                            })
                            .collect::<Vec<_>>()
                            .join(" · ")
                    })
                    .unwrap_or_else(|| "-".into())
            }
        );
        let a = &d["accounts"];
        println!(
            "  账号:     共 {} · 在线 {} · 禁用 {}",
            a["total"].as_i64().unwrap_or(0),
            a["online"].as_i64().unwrap_or(0),
            a["disabled"].as_i64().unwrap_or(0)
        );
    }
    Ok(())
}

/// 端点更名（`anet-svc node rename <name>`，写入配置立即生效并落审计）。
pub async fn cmd_node_rename(api: Option<String>, name: String) -> Result<()> {
    let mut client = AnetClient::from_session(api)?;
    client
        .api(
            "PUT",
            "/api/v1/admin/node/settings",
            Some(json!({ "node_name": name })),
        )
        .await?;
    println!("端点已更名");
    Ok(())
}

async fn cmd_login(api: Option<String>, args: LoginArgs) -> Result<()> {    let base = api
        .or_else(|| Session::load().map(|s| s.api))
        .unwrap_or_else(|| "http://127.0.0.1:59090".to_string());
    let base = base.trim_end_matches('/').to_string();

    let username = match args.username {
        Some(u) => u,
        None => {
            eprint!("用户名: ");
            let mut s = String::new();
            std::io::stdin().read_line(&mut s)?;
            s.trim().to_string()
        }
    };
    let password = match args.password {
        Some(p) => {
            eprintln!(
                "提示：通过命令行参数传递密码会留在 shell 历史中，建议使用交互式输入（省略 -p）"
            );
            p
        }
        None => rpassword::prompt_password("密码: ").context("读取密码失败")?,
    };

    let http = reqwest::Client::new();
    let resp = http
        .post(format!("{base}/api/v1/auth/login"))
        .json(&json!({ "username": username, "password": password }))
        .send()
        .await
        .context("无法连接节点 API")?;
    let j: Value = resp.json().await?;
    if j["code"].as_i64() != Some(0) {
        bail!("登录失败: {}", j["message"].as_str().unwrap_or("unknown"));
    }
    let session = Session {
        api: base.clone(),
        access_token: j["data"]["access_token"].as_str().unwrap().to_string(),
        refresh_token: j["data"]["refresh_token"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    };
    session.save()?;
    println!("登录成功（{}），会话已保存", base);
    Ok(())
}

// ---------- Rule ----------

async fn cmd_rule(api: Option<String>, args: RuleArgs, json_out: bool) -> Result<()> {
    let mut client = AnetClient::from_session(api)?;
    match args.command {
        RuleSub::List(l) => {
            let mut path = format!("/api/v1/admin/rules?page={}&page_size=20", l.page);
            if let Some(q) = &l.q {
                path += &format!("&q={q}");
            }
            if let Some(t) = &l.type_filter {
                path += &format!("&type={t}");
            }
            let d = client.api("GET", &path, None).await?;
            if json_out {
                print_json(&d);
            } else {
                let rows = d["items"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .map(|r| {
                        vec![
                            r["id"].as_str().unwrap_or("")[..8].to_string(),
                            r["type"].as_str().unwrap_or("-").to_string(),
                            r["value"].as_str().unwrap_or("-").to_string(),
                            if r["resolve"].as_bool().unwrap_or(false) {
                                "是"
                            } else {
                                "否"
                            }
                            .to_string(),
                            r["group_count"].as_i64().unwrap_or(0).to_string(),
                            r["remark"].as_str().unwrap_or("-").to_string(),
                        ]
                    })
                    .collect();
                print_table(&["ID", "类型", "匹配值", "解析", "引用组", "备注"], rows);
                println!("共 {} 条", d["total"].as_i64().unwrap_or(0));
            }
        }
        RuleSub::Add(a) => {
            let d = client
                .api(
                    "POST",
                    "/api/v1/admin/rules",
                    Some(json!({
                        "type": a.rule_type, "value": a.value,
                        "resolve": a.resolve, "remark": a.remark.unwrap_or_default(),
                    })),
                )
                .await?;
            if json_out {
                print_json(&d);
            } else {
                println!("规则已创建: {}", d["value"].as_str().unwrap_or("-"));
            }
        }
        RuleSub::Update(u) => {
            let id = resolve_id(&mut client, "/api/v1/admin/rules?page_size=100", &u.id).await?;
            let mut body = json!({});
            if let Some(v) = u.value {
                body["value"] = json!(v);
            }
            if let Some(r) = u.resolve {
                body["resolve"] = json!(r);
            }
            if let Some(r) = u.remark {
                body["remark"] = json!(r);
            }
            let d = client
                .api("PUT", &format!("/api/v1/admin/rules/{id}"), Some(body))
                .await?;
            if json_out {
                print_json(&d);
            } else {
                println!("规则已更新: {}", d["value"].as_str().unwrap_or("-"));
            }
        }
        RuleSub::Delete(d) => {
            let id = resolve_id(&mut client, "/api/v1/admin/rules?page_size=100", &d.id).await?;
            let path = if d.force {
                format!("/api/v1/admin/rules/{id}?force=true")
            } else {
                format!("/api/v1/admin/rules/{id}")
            };
            client.api("DELETE", &path, None).await?;
            println!("规则已删除");
        }
        RuleSub::Batch(b) => {
            let text = std::fs::read_to_string(&b.file)
                .with_context(|| format!("读取文件失败: {}", b.file))?;
            let rules: Value = serde_json::from_str(&text).context("JSON 解析失败")?;
            let d = client
                .api(
                    "POST",
                    "/api/v1/admin/rules/batch",
                    Some(json!({
                        "rules": rules, "on_conflict": b.on_conflict,
                    })),
                )
                .await?;
            if json_out {
                print_json(&d);
            } else {
                println!(
                    "导入完成: 新建 {} · 跳过 {} · 更新 {} · 错误 {}",
                    d["created"],
                    d["skipped"],
                    d["updated"],
                    d["errors"].as_array().map(|e| e.len()).unwrap_or(0)
                );
            }
        }
    }
    Ok(())
}

// ---------- Group ----------

async fn cmd_group(api: Option<String>, args: GroupArgs, json_out: bool) -> Result<()> {
    let mut client = AnetClient::from_session(api)?;
    match args.command {
        GroupSub::List(l) => {
            let mut path = format!("/api/v1/admin/groups?page={}&page_size=20", l.page);
            if let Some(q) = &l.q {
                path += &format!("&q={q}");
            }
            let d = client.api("GET", &path, None).await?;
            if json_out {
                print_json(&d);
            } else {
                let rows = d["items"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .map(|g| {
                        vec![
                            g["id"].as_str().unwrap_or("")[..8].to_string(),
                            g["name"].as_str().unwrap_or("-").to_string(),
                            g["rule_count"].as_i64().unwrap_or(0).to_string(),
                            g["account_count"].as_i64().unwrap_or(0).to_string(),
                            g["remark"].as_str().unwrap_or("-").to_string(),
                        ]
                    })
                    .collect();
                print_table(&["ID", "名称", "规则数", "账号数", "备注"], rows);
                println!("共 {} 条", d["total"].as_i64().unwrap_or(0));
            }
        }
        GroupSub::Show(s) => {
            let id = resolve_id(&mut client, "/api/v1/admin/groups?page_size=100", &s.id).await?;
            let d = client
                .api("GET", &format!("/api/v1/admin/groups/{id}"), None)
                .await?;
            print_json(&d);
        }
        GroupSub::Add(a) => {
            let rule_ids: Vec<String> = match &a.rule_ids {
                Some(s) => {
                    let mut ids = Vec::new();
                    for part in s.split(',').map(|p| p.trim()).filter(|p| !p.is_empty()) {
                        ids.push(
                            resolve_id(&mut client, "/api/v1/admin/rules?page_size=100", part)
                                .await?,
                        );
                    }
                    ids
                }
                None => Vec::new(),
            };
            let d = client.api("POST", "/api/v1/admin/groups", Some(json!({
                "name": a.name, "remark": a.remark.unwrap_or_default(), "rule_ids": rule_ids,
            }))).await?;
            if json_out {
                print_json(&d);
            } else {
                println!("权限组已创建: {}", d["name"].as_str().unwrap_or("-"));
            }
        }
        GroupSub::Update(u) => {
            let id = resolve_id(&mut client, "/api/v1/admin/groups?page_size=100", &u.id).await?;
            let mut body = json!({});
            if let Some(n) = u.name {
                body["name"] = json!(n);
            }
            if let Some(r) = u.remark {
                body["remark"] = json!(r);
            }
            let d = client
                .api("PUT", &format!("/api/v1/admin/groups/{id}"), Some(body))
                .await?;
            if json_out {
                print_json(&d);
            } else {
                println!("权限组已更新: {}", d["name"].as_str().unwrap_or("-"));
            }
        }
        GroupSub::Delete(d) => {
            let id = resolve_id(&mut client, "/api/v1/admin/groups?page_size=100", &d.id).await?;
            let path = if d.force {
                format!("/api/v1/admin/groups/{id}?force=true")
            } else {
                format!("/api/v1/admin/groups/{id}")
            };
            client.api("DELETE", &path, None).await?;
            println!("权限组已删除");
        }
        GroupSub::SetRules(s) => {
            let id = resolve_id(&mut client, "/api/v1/admin/groups?page_size=100", &s.id).await?;
            let mut ids = Vec::new();
            for prefix in &s.rule_ids {
                ids.push(
                    resolve_id(&mut client, "/api/v1/admin/rules?page_size=100", prefix).await?,
                );
            }
            let d = client
                .api(
                    "PUT",
                    &format!("/api/v1/admin/groups/{id}/rules"),
                    Some(json!({
                        "rule_ids": ids,
                    })),
                )
                .await?;
            println!(
                "规则绑定已更新（{} 条）",
                d["rule_count"].as_i64().unwrap_or(0)
            );
        }
    }
    Ok(())
}

// ---------- Account ----------

async fn cmd_account(api: Option<String>, args: AccountArgs, json_out: bool) -> Result<()> {
    let mut client = AnetClient::from_session(api)?;
    match args.command {
        AccountSub::List(l) => {
            let mut path = format!(
                "/api/v1/admin/accounts?page={}&page_size=20",
                l.page.unwrap_or(1)
            );
            if let Some(q) = &l.q {
                path += &format!("&q={q}");
            }
            if let Some(g) = &l.group {
                let gid = resolve_id(&mut client, "/api/v1/admin/groups?page_size=100", g).await?;
                path += &format!("&group_id={gid}");
            }
            if let Some(e) = l.enabled {
                path += &format!("&enabled={e}");
            }
            let d = client.api("GET", &path, None).await?;
            if json_out {
                print_json(&d);
            } else {
                let rows = d["items"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .map(|a| {
                        vec![
                            a["username"].as_str().unwrap_or("-").to_string(),
                            a["group_name"].as_str().unwrap_or("-").to_string(),
                            if a["online"].as_bool().unwrap_or(false) {
                                "在线"
                            } else {
                                "离线"
                            }
                            .to_string(),
                            if a["enabled"].as_bool().unwrap_or(false) {
                                "启用"
                            } else {
                                "禁用"
                            }
                            .to_string(),
                            a["last_seen_at"].as_str().unwrap_or("从未").to_string(),
                            a["remark"].as_str().unwrap_or("-").to_string(),
                            a["id"].as_str().unwrap_or("")[..8].to_string(),
                        ]
                    })
                    .collect();
                print_table(
                    &["账号", "权限组", "在线", "状态", "最后在线", "备注", "ID"],
                    rows,
                );
                println!("共 {} 条", d["total"].as_i64().unwrap_or(0));
            }
        }
        AccountSub::Add(a) => {
            let gid =
                resolve_id(&mut client, "/api/v1/admin/groups?page_size=100", &a.group).await?;
            let d = client.api("POST", "/api/v1/admin/accounts", Some(json!({
                "username": a.username, "group_id": gid, "remark": a.remark.unwrap_or_default(),
                "admin_console": a.admin,
            }))).await?;
            if json_out {
                print_json(&d);
            } else {
                println!("账号已创建: {}", d["username"].as_str().unwrap_or("-"));
                println!(
                    "   密码（仅此一次）: {}",
                    d["password"].as_str().unwrap_or("-")
                );
                println!("   接入链接: {}", d["connect_url"].as_str().unwrap_or("-"));
                if a.admin {
                    println!("   已授予管理权限：该链接可登录端点控制台，请按管理员凭据级别保管");
                }
                println!("   请立即保存，密码不可找回");
            }
        }
        AccountSub::Update(u) => {
            let id = resolve_id(&mut client, "/api/v1/admin/accounts?page_size=100", &u.id).await?;
            let mut body = json!({});
            if let Some(g) = &u.group {
                let gid = resolve_id(&mut client, "/api/v1/admin/groups?page_size=100", g).await?;
                body["group_id"] = json!(gid);
            }
            if let Some(e) = u.enabled {
                body["enabled"] = json!(e);
            }
            if let Some(r) = u.remark {
                body["remark"] = json!(r);
            }
            if let Some(adm) = u.admin {
                body["admin_console"] = json!(adm);
            }
            client
                .api("PUT", &format!("/api/v1/admin/accounts/{id}"), Some(body))
                .await?;
            println!("账号已更新");
        }
        AccountSub::Delete(d) => {
            let id = resolve_id(&mut client, "/api/v1/admin/accounts?page_size=100", &d.id).await?;
            client
                .api("DELETE", &format!("/api/v1/admin/accounts/{id}"), None)
                .await?;
            println!("账号已删除");
        }
        AccountSub::ResetPassword(r) => {
            let id = resolve_id(&mut client, "/api/v1/admin/accounts?page_size=100", &r.id).await?;
            let d = client
                .api(
                    "POST",
                    &format!("/api/v1/admin/accounts/{id}/reset-password"),
                    None,
                )
                .await?;
            if json_out {
                print_json(&d);
            } else {
                println!(
                    "密码已重置（仅此一次）: {}",
                    d["password"].as_str().unwrap_or("-")
                );
                println!("   接入链接: {}", d["connect_url"].as_str().unwrap_or("-"));
            }
        }
    }
    Ok(())
}

// ---------- Token ----------

async fn cmd_token(api: Option<String>, args: TokenArgs, json_out: bool) -> Result<()> {
    let mut client = AnetClient::from_session(api)?;
    match args.command {
        TokenSub::List => {
            let d = client
                .api("GET", "/api/v1/admin/node/relay-tokens", None)
                .await?;
            if json_out {
                print_json(&d);
            } else {
                let rows = d["items"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .map(|t| {
                        vec![
                            t["id"].as_str().unwrap_or("")[..8].to_string(),
                            t["token_prefix"].as_str().unwrap_or("-").to_string(),
                            t["group_name"].as_str().unwrap_or("不收敛").to_string(),
                            if t["expose_control"].as_bool().unwrap_or(false) {
                                t["control_scope"].as_str().unwrap_or("开").to_string()
                            } else {
                                "关".to_string()
                            },
                            t["remark"].as_str().unwrap_or("-").to_string(),
                            t["last_used_at"].as_str().unwrap_or("未使用").to_string(),
                            t["created_at"].as_str().unwrap_or("-").to_string(),
                        ]
                    })
                    .collect();
                print_table(
                    &["ID", "前缀", "权限组", "暴露面", "备注", "最近使用", "创建时间"],
                    rows,
                );
            }
        }
        TokenSub::Add(a) => {
            let group_id = match &a.group {
                Some(g) => {
                    Some(resolve_id(&mut client, "/api/v1/admin/groups?page_size=100", g).await?)
                }
                None => None,
            };
            let d = client
                .api(
                    "POST",
                    "/api/v1/admin/node/relay-tokens",
                    Some(json!({
                        "remark": a.remark.unwrap_or_default(),
                        "expose_control": a.expose_control,
                        "control_scope": a.scope,
                        "group_id": group_id,
                    })),
                )
                .await?;
            if json_out {
                print_json(&d);
            } else {
                println!(
                    "Relay 令牌已生成（仅此一次）: {}",
                    d["token"].as_str().unwrap_or("-")
                );
                if let Some(g) = &a.group {
                    println!("   已收敛到权限组: {g}");
                }
                if a.expose_control {
                    println!("   已暴露控制面（档位 {}）：持令牌下游可管理本端点", a.scope);
                }
                println!("   服务端只存哈希，请立即保存");
            }
        }
        TokenSub::Delete(d) => {
            let id = resolve_id(&mut client, "/api/v1/admin/node/relay-tokens", &d.id).await?;
            client
                .api(
                    "DELETE",
                    &format!("/api/v1/admin/node/relay-tokens/{id}"),
                    None,
                )
                .await?;
            println!("令牌已吊销");
        }
    }
    Ok(())
}

// ---------- Connector ----------

async fn cmd_connector(api: Option<String>, args: ConnectorArgs, json_out: bool) -> Result<()> {
    let mut client = AnetClient::from_session(api)?;
    match args.command {
        ConnectorSub::List => {
            let d = client.api("GET", "/api/v1/admin/connectors", None).await?;
            if json_out {
                print_json(&d);
            } else {
                let rows = d["items"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .map(|c| {
                        vec![
                            c["id"].as_str().unwrap_or("")[..8].to_string(),
                            c["name"].as_str().unwrap_or("-").to_string(),
                            c["upstream_addr"].as_str().unwrap_or("-").to_string(),
                            c["group_name"].as_str().unwrap_or("不收敛").to_string(),
                            c["state"].as_str().unwrap_or("-").to_string(),
                            if c["enabled"].as_bool().unwrap_or(false) {
                                "启用"
                            } else {
                                "禁用"
                            }
                            .to_string(),
                            c["remark"].as_str().unwrap_or("-").to_string(),
                        ]
                    })
                    .collect();
                print_table(
                    &["ID", "名称", "上游地址", "权限组", "状态", "启用", "备注"],
                    rows,
                );
            }
        }
        ConnectorSub::Add(a) => {
            let group_id = match &a.group {
                Some(g) => {
                    Some(resolve_id(&mut client, "/api/v1/admin/groups?page_size=100", g).await?)
                }
                None => None,
            };
            let d = client
                .api(
                    "POST",
                    "/api/v1/admin/connectors",
                    Some(json!({
                        "name": a.name, "upstream_addr": a.addr, "token": a.token,
                        "sni_hostname": a.sni.unwrap_or_default(), "insecure": a.insecure,
                        "advertise": split_csv(a.advertise.as_deref().unwrap_or_default()),
                        "group_id": group_id, "remark": a.remark.unwrap_or_default(),
                    })),
                )
                .await?;
            if json_out {
                print_json(&d);
            } else {
                println!("扇出对端已创建: {}", d["name"].as_str().unwrap_or("-"));
                println!("   token 已加密落库不再回显；更换请用 update --token 重置");
            }
        }
        ConnectorSub::Update(u) => {
            let id = resolve_id(&mut client, "/api/v1/admin/connectors", &u.id).await?;
            // PUT 为全量替换（缺省 group_id 即置不收敛）：先取现值合并，缺省参数一律保留原值
            let d = client.api("GET", "/api/v1/admin/connectors", None).await?;
            let cur = d["items"]
                .as_array()
                .and_then(|items| items.iter().find(|c| c["id"].as_str() == Some(id.as_str())))
                .cloned()
                .ok_or_else(|| anyhow!("未找到扇出对端 {id}"))?;
            let advertise = match &u.advertise {
                Some(s) => split_csv(s),
                None => split_csv(cur["advertise"].as_str().unwrap_or_default()),
            };
            let mut body = json!({
                "name": u.name.unwrap_or_else(|| cur["name"].as_str().unwrap_or_default().to_string()),
                "upstream_addr": u.addr.unwrap_or_else(|| cur["upstream_addr"].as_str().unwrap_or_default().to_string()),
                "sni_hostname": u.sni.unwrap_or_else(|| cur["sni_hostname"].as_str().unwrap_or_default().to_string()),
                "insecure": u.insecure.unwrap_or_else(|| cur["insecure"].as_bool().unwrap_or(false)),
                "ca_cert_path": cur["ca_cert_path"].as_str().unwrap_or_default(),
                "pinned_cert_path": cur["pinned_cert_path"].as_str().unwrap_or_default(),
                "advertise": advertise,
                "group_id": cur["group_id"],
                "remark": u.remark.unwrap_or_else(|| cur["remark"].as_str().unwrap_or_default().to_string()),
            });
            // token 留空 = 保留原值（服务端空串/null 视为未提供，绝不回显）
            if let Some(t) = u.token.filter(|t| !t.is_empty()) {
                body["token"] = json!(t);
            }
            // 显式 --group 才换组（名称或 ID 解析）
            if let Some(g) = &u.group {
                body["group_id"] = json!(
                    resolve_id(&mut client, "/api/v1/admin/groups?page_size=100", g).await?
                );
            }
            let d = client
                .api("PUT", &format!("/api/v1/admin/connectors/{id}"), Some(body))
                .await?;
            if json_out {
                print_json(&d);
            } else {
                println!("扇出对端已更新: {}", d["name"].as_str().unwrap_or("-"));
            }
        }
        ConnectorSub::Remove(r) => {
            let id = resolve_id(&mut client, "/api/v1/admin/connectors", &r.id).await?;
            client
                .api("DELETE", &format!("/api/v1/admin/connectors/{id}"), None)
                .await?;
            println!("扇出对端已删除");
        }
        ConnectorSub::Enable(e) => {
            let id = resolve_id(&mut client, "/api/v1/admin/connectors", &e.id).await?;
            let d = client
                .api("POST", &format!("/api/v1/admin/connectors/{id}/enable"), None)
                .await?;
            if json_out {
                print_json(&d);
            } else {
                println!("扇出对端已启用: {}", d["name"].as_str().unwrap_or("-"));
            }
        }
        ConnectorSub::Disable(e) => {
            let id = resolve_id(&mut client, "/api/v1/admin/connectors", &e.id).await?;
            let d = client
                .api("POST", &format!("/api/v1/admin/connectors/{id}/disable"), None)
                .await?;
            if json_out {
                print_json(&d);
            } else {
                println!("扇出对端已禁用: {}", d["name"].as_str().unwrap_or("-"));
            }
        }
    }
    Ok(())
}

// ---------- Admin ----------

async fn cmd_admin(api: Option<String>, args: AdminArgs, json_out: bool) -> Result<()> {
    let mut client = AnetClient::from_session(api)?;
    match args.command {
        AdminSub::List => {
            let d = client.api("GET", "/api/v1/admin/admins", None).await?;
            if json_out {
                print_json(&d);
            } else {
                let rows = d["items"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .map(|a| {
                        vec![
                            a["id"].as_str().unwrap_or("")[..8].to_string(),
                            a["username"].as_str().unwrap_or("-").to_string(),
                            a["created_at"].as_str().unwrap_or("-").to_string(),
                        ]
                    })
                    .collect();
                print_table(&["ID", "用户名", "创建时间"], rows);
            }
        }
        AdminSub::Add(a) => {
            let password = match a.password {
                Some(p) => p,
                None => rpassword::prompt_password("新管理员密码: ").context("读取密码失败")?,
            };
            let d = client
                .api(
                    "POST",
                    "/api/v1/admin/admins",
                    Some(json!({
                        "username": a.username, "password": password,
                    })),
                )
                .await?;
            if json_out {
                print_json(&d);
            } else {
                println!("管理员已创建: {}", d["username"].as_str().unwrap_or("-"));
            }
        }
        AdminSub::Delete(d) => {
            let id = resolve_id(&mut client, "/api/v1/admin/admins", &d.id).await?;
            client
                .api("DELETE", &format!("/api/v1/admin/admins/{id}"), None)
                .await?;
            println!("管理员已删除（其会话已吊销）");
        }
        AdminSub::Passwd(p) => {
            let old_password = match p.old_password {
                Some(v) => v,
                None => rpassword::prompt_password("旧密码: ").context("读取密码失败")?,
            };
            let new_password = match p.new_password {
                Some(v) => v,
                None => rpassword::prompt_password("新密码（≥10位含大小写数字）: ")
                    .context("读取密码失败")?,
            };
            let d = client
                .api(
                    "PUT",
                    "/api/v1/auth/password",
                    Some(json!({
                        "old_password": old_password, "new_password": new_password,
                    })),
                )
                .await?;
            println!("{}", d["message"].as_str().unwrap_or("密码已修改"));
        }
    }
    Ok(())
}

// ---------- Audit ----------

async fn cmd_audit(api: Option<String>, args: AuditArgs, json_out: bool) -> Result<()> {
    let mut client = AnetClient::from_session(api)?;
    match args.command {
        AuditSub::List(l) => {
            let mut path = format!("/api/v1/admin/audit-logs?page={}&page_size=20", l.page);
            if let Some(a) = &l.action {
                path += &format!("&action={a}");
            }
            let d = client.api("GET", &path, None).await?;
            if json_out {
                print_json(&d);
            } else {
                let rows = d["items"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .map(|l| {
                        vec![
                            l["created_at"]
                                .as_str()
                                .unwrap_or("-")
                                .replace('T', " ")
                                .replace('Z', ""),
                            l["operator"].as_str().unwrap_or("-").to_string(),
                            l["action"].as_str().unwrap_or("-").to_string(),
                            l["target"]
                                .as_str()
                                .unwrap_or("-")
                                .chars()
                                .take(8)
                                .collect(),
                            l["ip"].as_str().unwrap_or("-").to_string(),
                        ]
                    })
                    .collect();
                print_table(&["时间", "操作人", "动作", "目标", "来源 IP"], rows);
                println!("共 {} 条", d["total"].as_i64().unwrap_or(0));
            }
        }
    }
    Ok(())
}
