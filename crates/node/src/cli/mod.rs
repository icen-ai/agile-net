//! AgileNet CLI (`anet-svc` top-level admin commands) — enterprise-grade command-line admin tool.
//!
//! Features:
//! - Session persistence (~/.anet/session.json, Unix 0600), auto-refresh of expired access_token
//! - Full admin commands: node / rule / group / account / token / connector / admin / audit
//! - ID prefix resolution (type the first few chars, e.g. `anet-svc rule delete 3f2a`)
//! - --json machine-readable output, table output by default

mod account;
mod admin;
mod audit;
mod common;
mod connector;
mod group;
mod login;
mod node;
mod rule;
mod token;

// Public visibility matches the original single-file cli.rs (tests/cli_test.rs etc. reference the *Sub enums directly).
pub use account::{AccountAddArgs, AccountArgs, AccountListArgs, AccountSub, AccountUpdateArgs};
pub use admin::{AdminAddArgs, AdminArgs, AdminSub, PasswdArgs};
pub use audit::{AuditArgs, AuditListArgs, AuditSub};
pub use common::{AnetClient, IdArgs, IdOnlyArgs, ListArgs, Session};
pub use connector::{ConnectorAddArgs, ConnectorArgs, ConnectorSub, ConnectorUpdateArgs};
pub use group::{GroupAddArgs, GroupArgs, GroupSub, GroupUpdateArgs, SetRulesArgs};
pub use login::LoginArgs;
pub use node::{cmd_node_rename, cmd_node_status};
pub use rule::{BatchArgs, RuleAddArgs, RuleArgs, RuleSub, RuleUpdateArgs};
pub use token::{TokenAddArgs, TokenArgs, TokenSub};

use anyhow::Result;
use clap::{Parser, Subcommand};
use common::print_json;
use serde_json::json;

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

// ==================== Command execution ====================

pub async fn run_cli(cli: Cli) -> Result<()> {
    dispatch(cli.command, cli.api, cli.json).await
}

/// Top-level command dispatch (shared by `anet-svc <rule|group|...>` and the legacy `anet-svc cli ...`).
pub async fn dispatch(command: Commands, api: Option<String>, json_out: bool) -> Result<()> {
    match command {
        // The diagnostic toolkit is split off before session validation: local diagnostics, no login, no DB reads, no audit
        // (the bandwidth arm is the exception: it runs server-side via the admin API and checks the session itself)
        Commands::Tool(args) => {
            let code = crate::tool::run(args, json_out, api).await;
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
        // Doctor is likewise split off before session validation: local operation, no login, no audit writes
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
        Commands::Login(args) => login::cmd_login(api, args).await,
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
        Commands::Status => node::cmd_node_status(api, json_out).await,
        Commands::Rule(args) => rule::cmd_rule(api, args, json_out).await,
        Commands::Group(args) => group::cmd_group(api, args, json_out).await,
        Commands::Account(args) => account::cmd_account(api, args, json_out).await,
        Commands::Token(args) => token::cmd_token(api, args, json_out).await,
        Commands::Connector(args) => connector::cmd_connector(api, args, json_out).await,
        Commands::Admin(args) => admin::cmd_admin(api, args, json_out).await,
        Commands::Audit(args) => audit::cmd_audit(api, args, json_out).await,
    }
}
