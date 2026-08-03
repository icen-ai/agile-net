//! anet-svc — AgileNet server binary (same kernel, no GUI).
//!
//! Subcommands (community conventions):
//! - `start [config.toml] [-d|--daemon]`: start the node service (foreground by default; bare `anet-svc` equals start)
//! - `stop` / `restart [config.toml]` / `status`: service management (PID file, no login required)
//! - `node status|rename <name>`: node info (admin surface, login required)
//! - `rule|group|account|token|connector|admin|audit`: resource management (login required, aligned with the Web admin UI)
//! - `login|logout`: session management (~/.anet/session.json, 0600)
//! - `tool <sub>`: built-in network diagnostic toolkit (tcping/curl/dns/scan/ping…, local, no login required)
//! - `doctor`: self-diagnostics (ports/system proxy/kernel/network/config/rules checkup, auto-fix where possible, no login required)
//! - `client [config.toml]`: client role (connect to fan-out endpoints + local proxy)
//! - `tui [--db path]`: TUI console (direct database read-only fallback)
//!
//! Compatibility (hidden): `serve` = `start`; `cli ...` = legacy admin entry (same as the top-level command of the same name)

use crate::cli as anet_cli;
use crate::logs::{LogBuffer, LogBufferLayer};
use crate::service::{NodeServer, load_config};
use crate::svc;

use anyhow::Result;
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser, Debug)]
#[command(
    version,
    about = "AgileNet — init/start/stop/restart/status + 扇入扇出管理 + TUI",
    long_about = "AgileNet 命令行（anet / anet-svc 同一实现，按 argv[0] 分人格）。\n\n命令分组：\n  服务    start / stop / restart / status / init\n  扇入    client（消费连接：作为客户端引入外部端点）\n  扇出    rule / group / account / token / connector（对外服务：扇入消费者的规则/权限/账号/令牌，主动连出的对端）\n  管理    node / login / logout / admin / audit / tui（端点自身管理与控制台）\n  诊断    tool / doctor（内置网络诊断与自我体检，本机操作，无需登录）\n\n所有管理操作经节点 API 并落审计；TUI 默认走 API，--offline 数据库只读兜底。\n双入口：anet = 管理命令（推荐），anet-svc = 服务器进程（裸跑等同 start）。\n\ntool     内置网络诊断工具集（tcping/curl/dns/scan/ping…），详见文档站「网络工具详解」"
)]
struct App {
    #[command(subcommand)]
    command: Option<Cmd>,

    /// 节点 API 地址（默认读取会话或 http://127.0.0.1:59090）
    #[arg(global = true, long)]
    api: Option<String>,

    /// 机器可读 JSON 输出
    #[arg(global = true, long)]
    json: bool,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// 启动节点服务（默认前台运行；-d 后台守护）
    Start(StartArgs),
    /// 停止运行中的节点服务
    Stop,
    /// 重启节点服务（先 stop 再以前台 start）
    Restart(StartArgs),
    /// 查看节点服务运行状态（进程/配置/API 可达性，无需登录）
    Status,
    /// 节点信息（管理面）：状态总览 / 端点更名
    Node(NodeArgs),
    /// 以客户端角色运行（扇入：消费外部端点连接 + 本地代理）
    Client(ClientArgs),
    /// 打开 TUI 控制台（管理；默认走 API，--offline 数据库只读兜底）
    Tui(TuiArgs),
    /// 交互式初始化向导（服务；配置/管理员/系统服务/启动，首装推荐）
    Init(crate::init::InitArgs),
    /// 登录节点并保存会话（管理；~/.anet/session.json，0600）
    Login(anet_cli::LoginArgs),
    /// 登出并清除会话（管理）
    Logout,
    /// 路由规则管理（扇出：扇入消费者可访问的网段/域名）
    Rule(anet_cli::RuleArgs),
    /// 权限组管理（扇出：规则的组合授权）
    Group(anet_cli::GroupArgs),
    /// 客户端账号管理（扇出：扇入消费者凭据）
    Account(anet_cli::AccountArgs),
    /// Relay 令牌管理（扇出：扇入中继凭据，可暴露控制面）
    Token(anet_cli::TokenArgs),
    /// 扇出对端管理（扇出：主动连出的对端，可挂权限组收敛）
    Connector(anet_cli::ConnectorArgs),
    /// 管理员管理（管理）
    Admin(anet_cli::AdminArgs),
    /// 审计日志查询（管理）
    Audit(anet_cli::AuditArgs),
    /// 内置网络诊断工具集（诊断：tcping/curl/dns/scan/ping…，本机诊断，无需登录）
    Tool(crate::tool::ToolArgs),
    /// 自我诊断（诊断：端口/系统代理/内核/网络/配置/规则体检，自动修复可修项，无需登录）
    Doctor,
    /// 已废弃：`serve` 等同 `start`（保留兼容）
    #[command(hide = true)]
    Serve(StartArgs),
    /// 已废弃：`cli ...` 旧式管理入口（保留兼容，等同顶层同名命令）
    #[command(hide = true, trailing_var_arg = true, allow_hyphen_values = true)]
    Cli(LegacyArgs),
}

#[derive(Args, Debug)]
struct StartArgs {
    /// 配置文件路径
    #[arg(default_value = "agile-net.toml")]
    config: String,
    /// 后台守护（分离进程后立即返回；PID 文件由子进程写入）
    #[arg(short = 'd', long)]
    daemon: bool,
}

#[derive(Args, Debug)]
struct ClientArgs {
    /// 客户端配置文件路径
    #[arg(default_value = "agile-net-client.toml")]
    config: String,
}

#[derive(Args, Debug)]
struct TuiArgs {
    /// 数据库路径（--offline 或 API 降级时使用；也可经 DATABASE_PATH 环境变量指定）
    #[arg(long)]
    db: Option<String>,
    /// 强制数据库直连只读模式（默认走 API 管理，失败自动降级只读）
    #[arg(long)]
    offline: bool,
}

#[derive(Args, Debug)]
struct NodeArgs {
    #[command(subcommand)]
    command: NodeSub,
}

#[derive(Subcommand, Debug)]
enum NodeSub {
    /// 节点运行状态总览（需登录）
    Status,
    /// 端点更名（写入节点配置并立即生效）
    Rename {
        /// 新端点名称（1-64 字符）
        name: String,
    },
}

#[derive(Args, Debug)]
struct LegacyArgs {
    args: Vec<String>,
}

/// Legacy no-subcommand invocation compatibility: `anet-svc config.toml` → `anet-svc start config.toml`.
fn shim_legacy_config(args: &mut Vec<String>) {
    const KNOWN: &[&str] = &[
        "start", "stop", "restart", "status", "node", "client", "tui", "init", "login", "logout",
        "rule", "group", "account", "token", "connector", "admin", "audit", "tool", "serve",
        "cli", "help", "doctor",
    ];
    if let Some(first) = args.get(1)
        && !first.starts_with('-')
        && !KNOWN.contains(&first.as_str())
    {
        args.insert(1, "start".into());
    }
}

pub async fn run() -> Result<()> {
    let mut args: Vec<String> = std::env::args().collect();
    // Dual persona: entry point decided by the argv[0] file name (anet = admin commands, anet-svc = server).
    let prog = std::path::Path::new(args.first().map(|s| s.as_str()).unwrap_or("anet-svc"))
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("anet-svc")
        .to_string();
    shim_legacy_config(&mut args);
    let app = {
        let matches = App::command()
            .bin_name(prog.clone())
            .get_matches_from(args);
        match App::from_arg_matches(&matches) {
            Ok(a) => a,
            Err(e) => e.exit(),
        }
    };

    match app.command {
        None => {
            if prog == "anet" {
                // Bare admin entry: print help instead of starting the service.
                App::command().bin_name(prog).print_help()?;
                println!();
                Ok(())
            } else {
                run_server("agile-net.toml".into(), false).await
            }
        }
        Some(Cmd::Start(a)) | Some(Cmd::Serve(a)) => run_server(a.config, a.daemon).await,
        Some(Cmd::Stop) => svc::cmd_stop(),
        Some(Cmd::Restart(a)) => {
            svc::cmd_stop()?;
            run_server(a.config, a.daemon).await
        }
        Some(Cmd::Status) => svc::cmd_status(),
        Some(Cmd::Node(n)) => {
            init_plain_logging();
            match n.command {
                NodeSub::Status => anet_cli::cmd_node_status(app.api, app.json).await,
                NodeSub::Rename { name } => anet_cli::cmd_node_rename(app.api, name).await,
            }
        }
        Some(Cmd::Client(c)) => {
            init_plain_logging();
            agile_net_client::daemon::run(&c.config).await
        }
        Some(Cmd::Tui(t)) => {
            let db_path = t
                .db
                .or_else(|| std::env::var("DATABASE_PATH").ok())
                .unwrap_or_else(|| "agile-net.db".to_string());
            crate::tui::run_tui(crate::tui::TuiOptions {
                offline: t.offline,
                db_path,
                api: app.api,
            })
            .map_err(Into::into)
        }
        Some(Cmd::Init(a)) => {
            init_plain_logging();
            crate::init::run(a).await
        }
        Some(Cmd::Login(a)) => {
            init_plain_logging();
            anet_cli::dispatch(anet_cli::Commands::Login(a), app.api, app.json).await
        }
        Some(Cmd::Logout) => {
            init_plain_logging();
            anet_cli::dispatch(anet_cli::Commands::Logout, app.api, app.json).await
        }
        Some(Cmd::Rule(a)) => {
            init_plain_logging();
            anet_cli::dispatch(anet_cli::Commands::Rule(a), app.api, app.json).await
        }
        Some(Cmd::Group(a)) => {
            init_plain_logging();
            anet_cli::dispatch(anet_cli::Commands::Group(a), app.api, app.json).await
        }
        Some(Cmd::Account(a)) => {
            init_plain_logging();
            anet_cli::dispatch(anet_cli::Commands::Account(a), app.api, app.json).await
        }
        Some(Cmd::Token(a)) => {
            init_plain_logging();
            anet_cli::dispatch(anet_cli::Commands::Token(a), app.api, app.json).await
        }
        Some(Cmd::Connector(a)) => {
            init_plain_logging();
            anet_cli::dispatch(anet_cli::Commands::Connector(a), app.api, app.json).await
        }
        Some(Cmd::Admin(a)) => {
            init_plain_logging();
            anet_cli::dispatch(anet_cli::Commands::Admin(a), app.api, app.json).await
        }
        Some(Cmd::Audit(a)) => {
            init_plain_logging();
            anet_cli::dispatch(anet_cli::Commands::Audit(a), app.api, app.json).await
        }
        Some(Cmd::Tool(a)) => {
            // The diagnostic toolkit skips session validation (split off first inside dispatch).
            anet_cli::dispatch(anet_cli::Commands::Tool(a), app.api, app.json).await
        }
        Some(Cmd::Doctor) => {
            // Doctor is likewise a login-free local operation (dispatch prints and maps the exit code by error count).
            anet_cli::dispatch(anet_cli::Commands::Doctor, app.api, app.json).await
        }
        Some(Cmd::Cli(l)) => {
            eprintln!("提示：`anet cli ...` 已废弃，请直接使用顶层同名命令（如 `anet rule list`）");
            use clap::Parser as _;
            let legacy_args: Vec<String> = std::iter::once("anet cli".to_string())
                .chain(l.args)
                .collect();
            let cli = anet_cli::Cli::parse_from(legacy_args);
            anet_cli::run_cli(cli).await
        }
    }
}

/// Assemble and run the node service (foreground; --daemon is split off by the caller via svc::spawn_daemon first).
async fn run_server(config_path: String, daemon: bool) -> Result<()> {
    svc::ensure_not_running()?;
    if daemon {
        let pid = svc::spawn_daemon(&config_path)?;
        println!("anet-svc 已后台启动 (PID {pid})，配置 {config_path}");
        println!("  状态: anet status · 停止: anet stop");
        return Ok(());
    }

    // 1. Load the config file first (decides the file log target; parse failures go straight to stderr).
    let config = match load_config(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to load config {config_path}: {e}");
            return Err(e);
        }
    };
    let api_addr = config.api.addr.clone();

    // 2. Logging init (in-memory ring buffer + stdout + optional file logging).
    let log_buffer = LogBuffer::new();
    let registry = tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .compact(),
        )
        .with(LogBufferLayer::new(log_buffer.clone()));

    let log_dir = std::env::var("AGILE_LOG_DIR")
        .ok()
        .or_else(|| config.log.as_ref().map(|l| l.dir.clone()));
    if let Some(dir) = &log_dir {
        std::fs::create_dir_all(dir).ok();
        let prefix = config
            .log
            .as_ref()
            .map(|l| l.prefix.clone())
            .unwrap_or_else(|| "agile-net".to_string());
        let file_appender = tracing_appender::rolling::daily(dir, format!("{prefix}.log"));
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        std::mem::forget(guard); // keep the writer alive for the process lifetime
        registry
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(non_blocking)
                    .with_ansi(false),
            )
            .init();
        tracing::info!(dir = %dir, "file logging enabled (daily rolling)");
    } else {
        registry.init();
    }

    tracing::info!("anet-svc v{VERSION} starting");
    tracing::info!(name = %config.name, "node config loaded");

    // 3. Assemble and start the node (all role logic lives in NodeServer).
    let server = NodeServer::start_with(
        config,
        crate::service::NodeServerOptions {
            log_buffer: Some(log_buffer),
            ..Default::default()
        },
    )
    .await?;

    // 4. Write the PID file only after a successful start (no phantom record on bind failure).
    let rec = svc::PidRecord {
        pid: std::process::id(),
        config: config_path.clone(),
        api_addr,
        started_at: svc::now_ts(),
    };
    if let Err(e) = svc::write_pid(&rec) {
        tracing::warn!(error = %e, "failed to write pid file");
    }

    tracing::info!("anet-svc v{VERSION} ready");

    // 5. Wait for the shutdown signal.
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down anet-svc");
    server.stop().await;
    svc::remove_pid();

    Ok(())
}

/// Lightweight logging for client/cli subcommands (no ring buffer / file logging assembly).
fn init_plain_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();
}
