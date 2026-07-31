//! 节点装配根：`NodeServer::start/stop`。
//!
//! 把原本散落在 `main.rs` 的装配逻辑（数据库 / JWT / Relay listener /
//! connector / 本地代理 / API & Web 后台 / 后台任务）收敛为可嵌入的
//! 服务对象：`anet-svc` 的 `serve` 子命令与 `anet-gui` 的内嵌节点
//! 共用同一套装配代码。

use crate::api::{ApiState, NodeRuntime, create_app};
use crate::auth::jwt::JwtService;
use crate::db::{Database, hash_password};
use crate::logs::LogBuffer;
use crate::relay_auth::DbTokenValidator;
use crate::ui::create_ui_router;

use agile_net_core::config::NodeConfig;
use agile_net_core::proxy::inbound::ProxyInbound;
use agile_net_core::proxy::router::{Outbound, ProxyRouter};
use agile_net_core::relay::{RelayConnector, RelayListener};
use agile_net_core::tunnel::opener::{ChannelOpener, PeerAutoOpener};
use agile_net_core::tunnel::tls::{TlsConfigBuilder, load_or_generate_self_signed};

use anyhow::Result;
use arc_swap::ArcSwap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

/// 启动覆盖项（嵌入场景用；全部缺省时行为与原 main 一致）。
#[derive(Clone, Default)]
pub struct NodeServerOptions {
    /// 覆盖数据库路径（优先级高于 DATABASE_PATH 环境变量与 config.db_path）
    pub db_path: Option<String>,
    /// 覆盖 API 监听地址（优先级高于 API_LISTEN 环境变量与 config.api.addr；支持端口 0 动态分配）
    pub api_listen: Option<String>,
    /// 覆盖对外接入地址（优先级高于 AGILE_PUBLIC_HOST 环境变量与 config.public_host）
    pub public_host: Option<String>,
    /// 跳过环境变量预置（AGILE_ADMIN_PASSWORD / AGILE_RELAY_TOKENS），嵌入场景避免宿主进程环境污染
    pub skip_env_seed: bool,
    /// 复用调用方的内存日志缓冲（缺省新建）
    pub log_buffer: Option<LogBuffer>,
}

/// 运行中的节点实例（`stop` 幂等）。
pub struct NodeServer {
    db: Database,
    jwt: Arc<JwtService>,
    runtime: Arc<NodeRuntime>,
    state: ApiState,
    api_addr: SocketAddr,
    relay_connector: Option<Arc<RelayConnector>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    api_shutdown: Option<axum_server::Handle>,
    api_stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl NodeServer {
    /// 以默认覆盖项启动（等价于原 `agile-net-node` 主流程）。
    pub async fn start(config: NodeConfig) -> Result<Self> {
        Self::start_with(config, NodeServerOptions::default()).await
    }

    /// 装配并启动全部角色（listener/connector/proxy/api），返回运行句柄。
    pub async fn start_with(config: NodeConfig, opts: NodeServerOptions) -> Result<Self> {
        // rustls 过程级 CryptoProvider（ring）——任何 ServerConfig/ClientConfig 构建前必须安装
        agile_net_core::init_crypto_provider();

        let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        let log_buffer = opts.log_buffer.unwrap_or_else(LogBuffer::new);

        // 1. 数据库
        let db_path = opts
            .db_path
            .clone()
            .or_else(|| std::env::var("DATABASE_PATH").ok())
            .unwrap_or_else(|| config.db_path.clone());
        let db = Database::open(&db_path)?;
        db.cleanup_expired_refresh_tokens()?;
        tracing::info!(db_path = %db_path, "database initialized");

        if db.get_config("node_name")?.is_none() {
            db.set_config("node_name", &config.name)?;
        }

        if !opts.skip_env_seed {
            seed_admin_from_env(&db)?;
            if !db.has_admin()? {
                tracing::warn!(
                    "no admin account exists — create one via POST /api/v1/auth/init or set AGILE_ADMIN_PASSWORD"
                );
            }
            seed_relay_tokens_from_env(&db)?;
        }

        // 2. JWT 服务（密钥从数据库装载或生成）
        let jwt = Arc::new(JwtService::load_or_create(db.clone())?);

        // 3. 路由表（节点本地代理由全部规则驱动，命中 → 自动选路隧道，未命中 → 直连）
        let shared_router = Arc::new(ArcSwap::from_pointee(build_router(&db)));

        // 4. Relay Listener
        let mut relay_listener: Option<Arc<RelayListener>> = None;
        let mut cert_fingerprint: Option<String> = None;
        if let Some(listener_cfg) = &config.listener {
            let addr: SocketAddr = listener_cfg.addr.parse()?;
            let validator = Arc::new(DbTokenValidator::new(db.clone()));

            let tls_acceptor = if let Some(acme_cfg) = &config.acme {
                // ACME 模式：ALPN 多路复用解析器（签发/续期免停机热替换）
                let cert_path = std::path::PathBuf::from(&acme_cfg.cert_path);
                let key_path = std::path::PathBuf::from(&acme_cfg.key_path);
                let (certs, key) = if cert_path.exists() && key_path.exists() {
                    load_pem_certs_and_key(&cert_path, &key_path)?
                } else {
                    tracing::info!("no ACME cert yet, using temporary self-signed for boot");
                    agile_net_core::tunnel::tls::generate_self_signed(&acme_cfg.domain)?
                };
                let resolver = crate::acme::AlpnCertResolver::new(certs, key)?;
                let server_config = rustls::ServerConfig::builder_with_protocol_versions(&[
                    &rustls::version::TLS13,
                ])
                .with_no_client_auth()
                .with_cert_resolver(resolver.clone());

                let manager = Arc::new(crate::acme::AcmeManager::new(
                    crate::acme::AcmeConfig {
                        domain: acme_cfg.domain.clone(),
                        email: acme_cfg.email.clone(),
                        staging: acme_cfg.staging,
                        renew_days: acme_cfg.renew_days,
                        directory_url: acme_cfg.directory_url.clone(),
                        cert_path,
                        key_path,
                    },
                    resolver,
                    db.clone(),
                ));
                tasks.push(tokio::spawn(async move {
                    manager.run().await;
                }));
                tracing::info!(domain = %acme_cfg.domain, "ACME manager running");
                tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
            } else {
                // 静态/自签证书模式
                let (certs, key) = load_or_generate_self_signed(
                    std::path::Path::new(&listener_cfg.cert_path),
                    std::path::Path::new(&listener_cfg.key_path),
                    &listener_cfg.sni_hostname,
                )?;
                let fingerprint = agile_net_core::tunnel::tls::cert_fingerprint_sha256(&certs[0]);
                tracing::info!(sha256 = %fingerprint, "relay TLS certificate ready (可用于客户端证书固定)");
                cert_fingerprint = Some(fingerprint);

                let server_config = rustls::ServerConfig::builder_with_protocol_versions(&[
                    &rustls::version::TLS13,
                ])
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| anyhow::anyhow!("tls server config: {e}"))?;
                tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
            };

            let listener = {
                let l = RelayListener::with_validator(addr, validator, tls_acceptor);
                match &config.limits {
                    Some(lim) => Arc::new(l.with_limits(
                        lim.max_connections,
                        lim.max_pending_auth,
                        lim.auth_failures_per_minute,
                    )),
                    None => Arc::new(l),
                }
            };
            let l = listener.clone();
            tasks.push(tokio::spawn(async move {
                if let Err(e) = l.start().await {
                    tracing::error!(error = %e, "relay listener error");
                }
            }));
            tracing::info!(addr = %addr, "relay listener started");
            relay_listener = Some(listener);
        }

        // 5. Relay Connector（下游角色，自动重连）
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
            tasks.push(tokio::spawn(async move {
                c.run().await;
            }));
            tracing::info!(upstream = %upstream, "relay connector running");
            relay_connector = Some(connector);
        }

        // 6. 本地代理入站（可选）
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
            tasks.push(tokio::spawn(async move {
                if let Err(e) = inbound.start().await {
                    tracing::error!(error = %e, "proxy inbound error");
                }
            }));
            tracing::info!(addr = %proxy_addr, "proxy inbound started");
        }

        // 7. API & Web Dashboard
        let runtime = Arc::new(NodeRuntime {
            started_at: Instant::now(),
            listener: relay_listener.clone(),
            connector: relay_connector.clone(),
            proxy_stats,
            proxy_listen,
            log_buffer,
            cert_fingerprint,
        });

        // 路由热更新监视：config_version 变化即重建节点本地代理路由表。
        {
            let db = db.clone();
            let shared_router = shared_router.clone();
            tasks.push(tokio::spawn(async move {
                let mut last_version = db.config_version().unwrap_or(0);
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    interval.tick().await;
                    let current = db.config_version().unwrap_or(last_version);
                    if current != last_version {
                        last_version = current;
                        let new_router = build_router(&db);
                        let count = new_router.route_count();
                        shared_router.store(Arc::new(new_router));
                        tracing::debug!(version = current, rules = count, "proxy router hot-reloaded");
                    }
                }
            }));
        }

        // 数据留存清理任务：审计日志 90 天 + 过期 refresh token，每 24h 执行
        {
            let db = db.clone();
            tasks.push(tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(24 * 3600));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    interval.tick().await;
                    match db.cleanup_audit_log(90) {
                        Ok(n) if n > 0 => tracing::info!(removed = n, "audit log retention cleanup"),
                        _ => {}
                    }
                    let _ = db.cleanup_expired_refresh_tokens();
                }
            }));
        }

        let relay_port = relay_listener
            .as_ref()
            .map(|l| l.listen_addr().port())
            .unwrap_or(443);
        let public_host = opts
            .public_host
            .clone()
            .or_else(|| std::env::var("AGILE_PUBLIC_HOST").ok())
            .or_else(|| config.public_host.clone())
            .unwrap_or_else(|| "127.0.0.1".to_string());
        let api_listen_addr = opts
            .api_listen
            .clone()
            .or_else(|| std::env::var("API_LISTEN").ok())
            .unwrap_or_else(|| config.api.addr.clone());
        let api_socket_addr: SocketAddr = api_listen_addr.parse()?;
        // connect_url / tunnel 端点使用声明端口；端口 0（动态分配）时回读实际端口
        let api_port = api_socket_addr.port();

        let state = {
            let mut st = ApiState::new(db.clone(), jwt.clone(), runtime.clone(), public_host, api_port, relay_port);
            if let Some(lim) = &config.limits {
                st.login_limiter = st.login_limiter.clone().with_config(
                    lim.login_per_minute,
                    lim.login_lock_threshold,
                    lim.login_lock_minutes,
                );
            }
            st
        };
        let app = create_app(state.clone()).merge(create_ui_router());

        let api_tls_cert = std::env::var("API_TLS_CERT")
            .ok()
            .or_else(|| config.api.tls_cert_path.clone());
        let api_tls_key = std::env::var("API_TLS_KEY")
            .ok()
            .or_else(|| config.api.tls_key_path.clone());

        let api_shutdown = axum_server::Handle::new();
        let mut api_stop_tx = None;
        let bound_api_addr: SocketAddr = match (api_tls_cert, api_tls_key) {
            (Some(cert), Some(key)) => {
                // HTTPS 模式（内置 TLS，可复用 ACME/静态证书；生产推荐）
                let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key)
                    .await
                    .map_err(|e| anyhow::anyhow!("api tls config: {e}"))?;
                tracing::info!(addr = %api_socket_addr, "Web Dashboard & API Server started (https://{api_socket_addr})");
                let handle = api_shutdown.clone();
                tasks.push(tokio::spawn(async move {
                    let _ = axum_server::bind_rustls(api_socket_addr, tls_config)
                        .handle(handle)
                        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                        .await;
                }));
                api_socket_addr
            }
            _ => {
                if api_socket_addr.ip().is_unspecified() {
                    tracing::warn!(
                        "API 以明文 HTTP 监听 {api_socket_addr} — 生产环境请配置 [api] tls_cert_path/tls_key_path 或前置 HTTPS 反代"
                    );
                }
                // 先绑定再服务：支持端口 0 动态分配（嵌入/测试），并消除启动竞态
                let api_listener = tokio::net::TcpListener::bind(api_socket_addr).await?;
                let actual = api_listener.local_addr()?;
                tracing::info!(addr = %actual, "Web Dashboard & API Server started (http://{actual})");
                let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
                api_stop_tx = Some(stop_tx);
                tasks.push(tokio::spawn(async move {
                    let _ = axum::serve(
                        api_listener,
                        app.into_make_service_with_connect_info::<SocketAddr>(),
                    )
                    .with_graceful_shutdown(async move {
                        let _ = stop_rx.await;
                    })
                    .await;
                }));
                actual
            }
        };

        // 动态端口（0）时回填实际端口，保证 connect_url / config.tunnel 指向真实端点
        let state = if state.api_port() != bound_api_addr.port() {
            let mut st = state;
            st.set_api_port(bound_api_addr.port());
            st
        } else {
            state
        };

        Ok(Self {
            db,
            jwt,
            runtime,
            state,
            api_addr: bound_api_addr,
            relay_connector,
            tasks,
            api_shutdown: Some(api_shutdown),
            api_stop_tx,
        })
    }

    /// API 实际监听地址（端口 0 动态分配时为回读值）。
    pub fn api_addr(&self) -> SocketAddr {
        self.api_addr
    }

    pub fn db(&self) -> Database {
        self.db.clone()
    }

    pub fn jwt(&self) -> Arc<JwtService> {
        self.jwt.clone()
    }

    pub fn runtime(&self) -> Arc<NodeRuntime> {
        self.runtime.clone()
    }

    /// API 共享状态（含限流器与 connect_url 缓存）。
    pub fn api_state(&self) -> ApiState {
        self.state.clone()
    }

    /// 停止节点：API 优雅停机 → connector 断开 → 中止全部后台任务。幂等。
    pub async fn stop(mut self) {
        if let Some(tx) = self.api_stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.api_shutdown.take() {
            handle.graceful_shutdown(Some(std::time::Duration::from_secs(2)));
        }
        if let Some(c) = &self.relay_connector {
            c.disconnect().await;
        }
        for t in &self.tasks {
            t.abort();
        }
        // 等待任务真正退出（listener/proxy 的 TcpListener 随任务析构释放端口）
        for t in self.tasks.drain(..) {
            let _ = t.await;
        }
        tracing::info!("node server stopped");
    }
}

/// 从配置文件路径加载节点配置（文件缺失时回落默认配置）。
pub fn load_config(path: &str) -> Result<NodeConfig> {
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
        let hash = crate::db::sha256_hex(token.as_bytes());
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

/// 加载 PEM 证书链与私钥。
fn load_pem_certs_and_key(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<(Vec<rustls::pki_types::CertificateDer<'static>>, rustls::pki_types::PrivateKeyDer<'static>)> {
    let cert_data = std::fs::read(cert_path)?;
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_data.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("parse cert PEM: {e}"))?;
    if certs.is_empty() {
        anyhow::bail!("no certificates in {}", cert_path.display());
    }
    let key_data = std::fs::read(key_path)?;
    let key = rustls_pemfile::private_key(&mut key_data.as_slice())
        .map_err(|e| anyhow::anyhow!("parse key PEM: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("no private key in {}", key_path.display()))?;
    Ok((certs, key))
}

/// 解析上游地址（支持域名；IPv4 优先，规避双栈网络中 IPv6 不可达问题）。
async fn resolve_upstream(addr: &str) -> Result<SocketAddr> {
    if let Ok(a) = addr.parse::<SocketAddr>() {
        return Ok(a);
    }
    let resolved: Vec<SocketAddr> = tokio::net::lookup_host(addr).await?.collect();
    resolved
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| resolved.first())
        .copied()
        .ok_or_else(|| anyhow::anyhow!("cannot resolve upstream: {addr}"))
}
