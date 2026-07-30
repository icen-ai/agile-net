use agile_net_core::config::NodeConfig;
use agile_net_core::proxy::inbound::ProxyInbound;
use agile_net_core::proxy::router::{Outbound, ProxyRouter};
use agile_net_core::relay::{RelayConnector, RelayListener};
use agile_net_core::tunnel::opener::{ChannelOpener, PeerAutoOpener};
use agile_net_core::tunnel::tls::{TlsConfigBuilder, load_or_generate_self_signed};
use agile_net_node::api::{ApiState, NodeRuntime, create_app};
use agile_net_node::auth::jwt::JwtService;
use agile_net_node::db::{Database, hash_password};
use agile_net_node::logs::{LogBuffer, LogBufferLayer};
use agile_net_node::relay_auth::DbTokenValidator;
use agile_net_node::tui::run_tui;
use agile_net_node::ui::create_ui_router;

use anyhow::Result;
use arc_swap::ArcSwap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("agile-net-node {VERSION}");
        return Ok(());
    }

    // TUI 模式
    if args.get(1).map(|s| s.as_str()) == Some("tui") {
        let db_path = std::env::var("DATABASE_PATH").unwrap_or_else(|_| "agile-net.db".to_string());
        let db = Database::open(&db_path)?;
        return run_tui(db).map_err(Into::into);
    }

    // 日志（同时写入内存环形缓冲，供 /admin/node/logs 查询）
    let log_buffer = LogBuffer::new();
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .compact(),
        )
        .with(LogBufferLayer::new(log_buffer.clone()))
        .init();

    tracing::info!("agile-net-node v{VERSION} starting");

    // 1. 加载配置文件
    let config_path = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "agile-net.toml".into());
    let config = load_config(&config_path)?;
    tracing::info!(name = %config.name, "node config loaded");

    // 2. 初始化数据库
    let db_path = std::env::var("DATABASE_PATH").unwrap_or_else(|_| config.db_path.clone());
    let db = Database::open(&db_path)?;
    db.cleanup_expired_refresh_tokens()?;
    tracing::info!(db_path = %db_path, "database initialized");

    // 节点名称写入配置（若未设置）
    if db.get_config("node_name")?.is_none() {
        db.set_config("node_name", &config.name)?;
    }

    // 环境变量预置管理员（容器/自动化部署用）
    seed_admin_from_env(&db)?;
    if !db.has_admin()? {
        tracing::warn!(
            "no admin account exists — create one via POST /api/v1/auth/init or set AGILE_ADMIN_PASSWORD"
        );
    }

    // 环境变量预置 Relay Tokens（AGILE_RELAY_TOKENS，逗号分隔，容器编排用）
    seed_relay_tokens_from_env(&db)?;

    // 3. JWT 服务（密钥从数据库装载或生成）
    let jwt = Arc::new(JwtService::load_or_create(db.clone())?);

    // 4. 路由表（节点本地代理由全部规则驱动，命中 → 自动选路隧道，未命中 → 直连）
    let shared_router = Arc::new(ArcSwap::from_pointee(build_router(&db)));

    // 5. Relay Listener
    let mut relay_listener: Option<Arc<RelayListener>> = None;
    if let Some(listener_cfg) = &config.listener {
        let addr: SocketAddr = listener_cfg.addr.parse()?;
        let (certs, key) = load_or_generate_self_signed(
            std::path::Path::new(&listener_cfg.cert_path),
            std::path::Path::new(&listener_cfg.key_path),
            &listener_cfg.sni_hostname,
        )?;
        let fingerprint = agile_net_core::tunnel::tls::cert_fingerprint_sha256(&certs[0]);
        tracing::info!(sha256 = %fingerprint, "relay TLS certificate ready (可用于客户端证书固定)");

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| anyhow::anyhow!("tls server config: {e}"))?;
        let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let validator = Arc::new(DbTokenValidator::new(db.clone()));
        let listener = Arc::new(RelayListener::with_validator(addr, validator, tls_acceptor));
        let l = listener.clone();
        tokio::spawn(async move {
            if let Err(e) = l.start().await {
                tracing::error!(error = %e, "relay listener error");
            }
        });
        tracing::info!(addr = %addr, "relay listener started");
        relay_listener = Some(listener);
    }

    // 6. Relay Connector（下游角色，自动重连）
    let mut relay_connector: Option<Arc<RelayConnector>> = None;
    if let Some(connector_cfg) = &config.connector {
        let upstream: SocketAddr = resolve_upstream(&connector_cfg.upstream_addr).await?;
        let mut tls_builder = TlsConfigBuilder::new().sni_hostname(&connector_cfg.sni_hostname);

        if let Some(pinned_path) = &connector_cfg.pinned_cert_path {
            let certs = load_pem_certs(pinned_path)?;
            tls_builder = tls_builder.pinned_certs(certs);
            tracing::info!("connector TLS: certificate pinning enabled");
        } else if let Some(ca_path) = &connector_cfg.ca_cert_path {
            let certs = load_pem_certs(ca_path)?;
            tls_builder = tls_builder.ca_certs(certs);
        } else if connector_cfg.insecure {
            tracing::warn!("connector TLS: INSECURE mode (no certificate verification) — dev only!");
            tls_builder = tls_builder.allow_self_signed(true);
        }

        let mut connector = RelayConnector::with_tls_builder(
            upstream,
            &config.name,
            &connector_cfg.token,
            tls_builder,
        )?
        .with_advertise(connector_cfg.advertise.clone());

        if let Some(l) = &relay_listener {
            connector = connector.with_peer_router(l.clone());
        }
        let connector = Arc::new(connector);
        let c = connector.clone();
        tokio::spawn(async move {
            c.run().await;
        });
        tracing::info!(upstream = %upstream, "relay connector running");
        relay_connector = Some(connector);
    }

    // 7. 本地代理入站（可选）
    let mut proxy_stats = None;
    let mut proxy_listen = None;
    if let Some(proxy_cfg) = &config.proxy {
        let proxy_addr: SocketAddr = proxy_cfg.addr.parse()?;
        let mut inbound = ProxyInbound::new(proxy_addr, shared_router.clone());
        if let (Some(u), Some(p)) = (&proxy_cfg.username, &proxy_cfg.password) {
            inbound = inbound.with_auth(u.clone(), p.clone());
        }
        if let Some(l) = &relay_listener {
            inbound = inbound.with_default_opener(
                Arc::new(PeerAutoOpener::new(l.clone())) as Arc<dyn ChannelOpener>
            );
        }
        proxy_stats = Some(inbound.stats());
        proxy_listen = Some(proxy_addr.to_string());
        tokio::spawn(async move {
            if let Err(e) = inbound.start().await {
                tracing::error!(error = %e, "proxy inbound error");
            }
        });
        tracing::info!(addr = %proxy_addr, "proxy inbound started");
    }

    // 8. API & Web Dashboard
    let runtime = Arc::new(NodeRuntime {
        started_at: Instant::now(),
        listener: relay_listener.clone(),
        connector: relay_connector.clone(),
        proxy_stats,
        proxy_listen,
        log_buffer,
    });

    let relay_port = relay_listener
        .as_ref()
        .map(|l| l.listen_addr().port())
        .unwrap_or(443);
    let public_host = std::env::var("AGILE_PUBLIC_HOST")
        .ok()
        .or_else(|| config.public_host.clone())
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let api_port: u16 = std::env::var("API_LISTEN")
        .ok()
        .or_else(|| Some(config.api.addr.clone()))
        .and_then(|a| a.rsplit(':').next()?.parse().ok())
        .unwrap_or(9090);

    let state = ApiState::new(db.clone(), jwt, runtime, public_host, api_port, relay_port);
    let app = create_app(state).merge(create_ui_router());

    let api_listen_addr = std::env::var("API_LISTEN").unwrap_or_else(|_| config.api.addr.clone());
    let api_listener = tokio::net::TcpListener::bind(&api_listen_addr).await?;
    tracing::info!(addr = %api_listen_addr, "Web Dashboard & API Server started (http://{api_listen_addr})");

    tokio::spawn(async move {
        let _ = axum::serve(
            api_listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });

    tracing::info!("agile-net-node v{VERSION} ready");

    // 9. 等待 shutdown 信号
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down agile-net-node");
    if let Some(c) = &relay_connector {
        c.disconnect().await;
    }

    Ok(())
}

fn load_config(path: &str) -> Result<NodeConfig> {
    match std::fs::read_to_string(path) {
        Ok(content) => Ok(toml::from_str(&content)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!("config file not found: {path}, using defaults");
            Ok(NodeConfig::default())
        }
        Err(e) => Err(e.into()),
    }
}

/// 环境变量预置管理员：AGILE_ADMIN_USERNAME / AGILE_ADMIN_PASSWORD。
fn seed_admin_from_env(db: &Database) -> Result<()> {
    if db.has_admin()? {
        return Ok(());
    }
    let Ok(password) = std::env::var("AGILE_ADMIN_PASSWORD") else {
        return Ok(());
    };
    let username = std::env::var("AGILE_ADMIN_USERNAME").unwrap_or_else(|_| "admin".to_string());
    if password.len() < 10 {
        anyhow::bail!("AGILE_ADMIN_PASSWORD must be at least 10 characters");
    }
    let hash = hash_password(&password)?;
    db.create_admin(&username, &hash)?;
    tracing::info!(username = %username, "admin account seeded from environment");
    Ok(())
}

/// 环境变量预置 Relay Tokens：AGILE_RELAY_TOKENS="psk_aaa,psk_bbb"（逗号分隔）。
///
/// 容器编排场景下，下游节点的 connector token 需要预先存在于上游数据库。
/// 已存在（按哈希判重）的 token 会跳过，保证幂等。
fn seed_relay_tokens_from_env(db: &Database) -> Result<()> {
    let Ok(tokens) = std::env::var("AGILE_RELAY_TOKENS") else {
        return Ok(());
    };
    for token in tokens.split(',').map(|t| t.trim()).filter(|t| !t.is_empty()) {
        let hash = agile_net_node::db::sha256_hex(token.as_bytes());
        if db.check_relay_token(&hash)? {
            continue;
        }
        let prefix = format!("{}****", &token[..token.len().min(8)]);
        db.create_relay_token(&hash, &prefix, "seeded from environment")?;
        tracing::info!(prefix = %prefix, "relay token seeded from environment");
    }
    Ok(())
}

/// 从数据库全部规则构建本地代理路由表（命中 → 自动选路隧道）。
fn build_router(db: &Database) -> ProxyRouter {
    let mut router = ProxyRouter::new();
    if let Ok((rules, _)) = db.list_rules(1, 1000, None, None) {
        for r in rules {
            // 节点本地代理：命中规则的流量经 PeerAutoOpener 自动选择下游节点
            let outbound = Outbound::tunnel("");
            match r.rule_type.as_str() {
                "ip-cidr" => {
                    let _ = router.add_cidr(&r.value, outbound);
                }
                "host" => {
                    if r.value.contains('*') {
                        router.add_host_suffix(&r.value, outbound);
                    } else {
                        router.add_host_exact(&r.value, outbound);
                    }
                }
                _ => {}
            }
        }
    }
    router
}

/// 加载 PEM 证书链。
fn load_pem_certs(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let data = std::fs::read(path)?;
    let certs: Vec<_> = rustls_pemfile::certs(&mut data.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("parse PEM certs {path}: {e}"))?;
    if certs.is_empty() {
        anyhow::bail!("no certificates in {path}");
    }
    Ok(certs)
}

/// 解析上游地址（支持域名）。
async fn resolve_upstream(addr: &str) -> Result<SocketAddr> {
    if let Ok(a) = addr.parse::<SocketAddr>() {
        return Ok(a);
    }
    let resolved: Vec<SocketAddr> = tokio::net::lookup_host(addr).await?.collect();
    resolved
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("cannot resolve upstream: {addr}"))
}
