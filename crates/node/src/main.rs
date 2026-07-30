use anyhow::Result;
use tracing_subscriber::EnvFilter;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<()> {
    // 检查 --version 参数
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("agile-net-node {VERSION}");
        return Ok(());
    }

    // 初始化日志
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    tracing::info!("agile-net-node v{VERSION} starting");

    // 加载配置
    let config_path = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "agile-net.toml".into());

    let config = load_config(&config_path)?;
    tracing::info!(name = %config.name, "node config loaded");

    // TODO M5: 初始化数据库
    // TODO M5: 启动 API Server
    // TODO M2: 启动 Relay Listener / Connector

    tracing::info!("agile-net-node v{VERSION} ready");

    // 等待 shutdown 信号
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");

    Ok(())
}

fn load_config(path: &str) -> Result<agile_net_core::config::NodeConfig> {
    match std::fs::read_to_string(path) {
        Ok(content) => {
            let config: agile_net_core::config::NodeConfig = toml::from_str(&content)?;
            Ok(config)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!("config file not found: {path}, using defaults");
            Ok(agile_net_core::config::NodeConfig::default())
        }
        Err(e) => Err(e.into()),
    }
}
