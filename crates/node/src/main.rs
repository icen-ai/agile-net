//! anet-svc — AgileNet 服务器二进制（同一内核无 GUI）。
//!
//! 子命令：
//! - `serve [config.toml]`（默认）：节点全角色（relay listener/connector/client 隧道/proxy/api）
//! - `tui`：本地 TUI 控制台（直连数据库）
//! - `client [config.toml]`：客户端角色（连上游 + 本地代理，替代原 agile-net-client）
//! - `cli <args...>`：命令行管理工具（替代原 anet）

use agile_net_node::db::Database;
use agile_net_node::logs::{LogBuffer, LogBufferLayer};
use agile_net_node::service::{NodeServer, load_config};
use agile_net_node::tui::run_tui;

use anyhow::Result;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("anet-svc {VERSION}");
        return Ok(());
    }

    let sub = args.get(1).map(|s| s.as_str());
    match sub {
        // TUI 模式
        Some("tui") => {
            let db_path =
                std::env::var("DATABASE_PATH").unwrap_or_else(|_| "agile-net.db".to_string());
            let db = Database::open(&db_path)?;
            return run_tui(db).map_err(Into::into);
        }
        // 客户端角色（连上游 + 本地代理）
        Some("client") => {
            init_plain_logging();
            let config_path = args
                .get(2)
                .cloned()
                .unwrap_or_else(|| "agile-net-client.toml".into());
            return agile_net_client::daemon::run(&config_path).await;
        }
        // CLI 管理工具（原 anet 收编）
        Some("cli") => {
            use clap::Parser;
            let cli_args: Vec<String> = std::iter::once("anet-svc cli".to_string())
                .chain(args.iter().skip(2).cloned())
                .collect();
            let cli = agile_net_node::cli::Cli::parse_from(cli_args);
            return agile_net_node::cli::run_cli(cli).await;
        }
        Some("serve") | Some(_) | None => {}
    }

    // serve（默认）：配置文件路径为子命令后的首个位置参数
    let config_path = match sub {
        Some("serve") => args.get(2).cloned(),
        _ => args.get(1).cloned(),
    }
    .unwrap_or_else(|| "agile-net.toml".into());

    // 1. 先加载配置文件（决定文件日志目标；解析失败直接输出到 stderr）
    let config = match load_config(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to load config {config_path}: {e}");
            return Err(e);
        }
    };

    // 2. 日志初始化（内存环形缓冲 + stdout + 可选文件日志）
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
        std::mem::forget(guard); // 进程生命周期内保持写入器存活
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

    // 3. 装配并启动节点（全部角色逻辑在 NodeServer）
    let server = NodeServer::start_with(
        config,
        agile_net_node::service::NodeServerOptions {
            log_buffer: Some(log_buffer),
            ..Default::default()
        },
    )
    .await?;

    tracing::info!("anet-svc v{VERSION} ready");

    // 4. 等待 shutdown 信号
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down anet-svc");
    server.stop().await;

    Ok(())
}

/// client/cli 子命令的轻量日志（无内存缓冲/文件日志装配）。
fn init_plain_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();
}
