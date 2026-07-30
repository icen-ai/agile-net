use agile_net_core::proxy::inbound::ProxyInbound;
use agile_net_core::proxy::router::ProxyRouter;
use agile_net_core::relay::RelayListener;
use agile_net_node::api::create_app;
use agile_net_node::db::Database;
use agile_net_node::ui::create_ui_router;

use anyhow::Result;
use arc_swap::ArcSwap;
use std::net::SocketAddr;
use std::sync::Arc;
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

    // 1. 加载配置文件
    let config_path = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "agile-net.toml".into());

    let config = load_config(&config_path)?;
    tracing::info!(name = %config.name, "node config loaded");

    // 2. 初始化数据库 (SQLite)
    let db_path = std::env::var("DATABASE_PATH").unwrap_or_else(|_| config.db_path.clone());
    let db = Database::open(&db_path)?;
    tracing::info!(db_path = %db_path, "database initialized");

    // 3. 初始化 ProxyRouter 路由表
    let mut router = ProxyRouter::new();
    if let Ok(routes) = db.list_routes() {
        for r in routes {
            if !r.enabled {
                continue;
            }
            let outbound = if r.outbound_type == "tunnel" {
                if let Some(nid) = r.node_id {
                    agile_net_core::proxy::router::Outbound::tunnel(nid)
                } else {
                    agile_net_core::proxy::router::Outbound::Direct
                }
            } else {
                agile_net_core::proxy::router::Outbound::Direct
            };

            match r.pattern_type {
                agile_net_node::db::models::RoutePatternType::Cidr => {
                    let _ = router.add_cidr(&r.pattern, outbound);
                }
                agile_net_node::db::models::RoutePatternType::ExactHost => {
                    router.add_host_exact(&r.pattern, outbound);
                }
                agile_net_node::db::models::RoutePatternType::WildcardHost => {
                    router.add_host_suffix(&r.pattern, outbound);
                }
            }
        }
    }

    let shared_router = Arc::new(ArcSwap::from_pointee(router));

    // 4. 启动 Relay Listener (如果配置了 listener)
    let mut relay_listener: Option<Arc<RelayListener>> = None;
    if let Some(listener_cfg) = &config.listener {
        let addr: SocketAddr = listener_cfg.addr.parse()?;
        let token = "relay_token_secret"; // 允许从配置或系统表载入
        let listener = Arc::new(RelayListener::new(addr, token)?);
        let listener_clone = listener.clone();

        tokio::spawn(async move {
            if let Err(e) = listener_clone.start().await {
                tracing::error!(error = %e, "relay listener error");
            }
        });
        tracing::info!(addr = %addr, "relay listener started");
        relay_listener = Some(listener);
    }

    // 5. 启动 ProxyInbound (如果配置了代理入站端口)
    let proxy_addr_str = std::env::var("PROXY_LISTEN").unwrap_or_else(|_| "0.0.0.0:1080".to_string());
    if let Ok(proxy_addr) = proxy_addr_str.parse::<SocketAddr>() {
        let mut inbound = ProxyInbound::new(proxy_addr, shared_router.clone());
        if let Some(rl) = relay_listener.clone() {
            inbound = inbound.with_relay_listener(rl);
        }

        tokio::spawn(async move {
            if let Err(e) = inbound.start().await {
                tracing::error!(error = %e, "proxy inbound error");
            }
        });
        tracing::info!(addr = %proxy_addr, "proxy inbound started");
    }

    // 6. 启动 API & Web Dashboard Server
    let api_app = create_app(db, shared_router);
    let ui_app = create_ui_router();
    let app = api_app.merge(ui_app);

    let api_listen_addr = std::env::var("API_LISTEN").unwrap_or_else(|_| config.api.addr.clone());
    let listener = tokio::net::TcpListener::bind(&api_listen_addr).await?;
    tracing::info!(addr = %api_listen_addr, "Web Dashboard & API Server started (http://{api_listen_addr})");

    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    tracing::info!("agile-net-node v{VERSION} ready");

    // 7. 等待 shutdown 信号
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down agile-net-node");

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
