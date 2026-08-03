//! 节点装配根：`NodeServer::start/stop`。
//!
//! 把原本散落在 `main.rs` 的装配逻辑（数据库 / JWT / Relay listener /
//! connector / 本地代理 / API & Web 后台 / 后台任务）收敛为可嵌入的
//! 服务对象：`anet-svc` 的 `serve` 子命令与 `anet-gui` 的内嵌节点
//! 共用同一套装配代码。

pub mod acl;
pub mod connectors;
pub mod rate_limit;

use crate::api::{ApiState, NodeRuntime, create_app};
use crate::auth::jwt::JwtService;
use crate::db::{Database, hash_password};
use crate::logs::LogBuffer;
use crate::relay_auth::DbTokenValidator;
use crate::service::acl::PeerAclRegistry;
use crate::service::connectors::ConnectorManager;
use crate::ui::create_ui_router;

use agile_net_core::config::NodeConfig;
use agile_net_core::proxy::inbound::ProxyInbound;
use agile_net_core::proxy::router::{Outbound, ProxyRouter};
use agile_net_core::relay::RelayListener;
use agile_net_core::relay::transit::TransitMeter;
use agile_net_core::tunnel::opener::{ChannelOpener, PeerAutoOpener};
use agile_net_core::tunnel::tls::load_or_generate_self_signed;

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
    /// 路由再发布：客户端引擎合并路由 + 开启器注册表（GUI 内嵌场景；
    /// 客户端隧道规则转售给下游，Open 命中时经对应隧道转发）
    pub client_routes: Option<ClientRoutes>,
    /// 客户端角色代理状态槽（GUI 内嵌场景宿主写入；缺省为空槽 = 未上报，
    /// status API 的 proxy 段回落 proxy_listen 旧行为）
    pub client_proxy_slot: ClientProxySlot,
}

/// 路由再发布注入件：客户端引擎的合并路由表 + 通道开启器注册表。
pub type ClientRoutes = (
    Arc<ArcSwap<ProxyRouter>>,
    Arc<dashmap::DashMap<String, Arc<dyn ChannelOpener>>>,
);

/// 客户端角色代理状态（GUI 宿主进程写入：反映客户端引擎代理真实状态，
/// 与节点角色 proxy_listen 是两个东西）。
#[derive(Debug, Clone)]
pub struct ClientProxyInfo {
    /// 客户端代理是否在监听
    pub enabled: bool,
    /// 代理模式："system" = 接管系统代理 / "local" = 仅监听端口
    pub mode: String,
    /// 监听地址（127.0.0.1:port；未启用时为空串）
    pub listen: String,
}

/// 客户端代理状态槽（宿主与内嵌节点共享，ArcSwap 无锁热更；
/// 槽值 None = 未上报，status 的 proxy 段维持节点 proxy_listen 行为）。
pub type ClientProxySlot = Arc<ArcSwap<Option<ClientProxyInfo>>>;

/// 新建客户端代理状态槽（初值 None = 未上报）。
pub fn new_client_proxy_slot() -> ClientProxySlot {
    Arc::new(ArcSwap::from_pointee(None))
}

/// 运行中的节点实例（`stop` 幂等）。
pub struct NodeServer {
    db: Database,
    jwt: Arc<JwtService>,
    runtime: Arc<NodeRuntime>,
    state: ApiState,
    api_addr: SocketAddr,
    connector_manager: Arc<ConnectorManager>,
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
        let log_buffer = opts.log_buffer.unwrap_or_default();

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

        // 握手 v2：控制端点槽（API 装配后回填）与可管理上游注册表（connector 同步）
        let control_api_slot: Arc<arc_swap::ArcSwapOption<(String, u16)>> =
            Arc::new(arc_swap::ArcSwapOption::from_pointee(None));
        let manageable_registry = crate::relay_auth::ManageableRegistry::default();

        // 对端收敛注册表：组规则 → PeerAcl（扇入/扇出共享；热重载循环随 config_version 重建）
        let acl_registry = Arc::new(PeerAclRegistry::new());
        acl_registry.rebuild(&db);

        // 中继途径核算表（listener/connector/proxy 三处共享打点；status transit 段数据源）
        let transit_meter = TransitMeter::new();

        // 4. Relay Listener
        let mut relay_listener: Option<Arc<RelayListener>> = None;
        let mut cert_fingerprint: Option<String> = None;
        if let Some(listener_cfg) = &config.listener {
            let addr: SocketAddr = listener_cfg.addr.parse()?;
            let validator = Arc::new(
                DbTokenValidator::new(db.clone())
                    .with_control_api(control_api_slot.clone())
                    .with_manageable(manageable_registry.clone())
                    .with_acl_registry(acl_registry.clone()),
            );

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
                // 会话带宽限速接线：relay_token.rate_limit_kbps → core TokenBucket（B/s）
                let db_rl = db.clone();
                let l = RelayListener::with_validator(addr, validator, tls_acceptor)
                    .with_transit_meter(transit_meter.clone())
                    .with_session_rate_limit(move |id, hash| {
                        rate_limit::token_rate_limit_bps(id, hash, &db_rl)
                    });
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
            // 扇入收敛拒绝事件 → 审计（对端身份 = node_id；按 peer+target 每分钟去重）
            tasks.push(connectors::spawn_acl_audit_task(
                db.clone(),
                "listener".to_string(),
                listener.subscribe_events(),
            ));
            relay_listener = Some(listener);
        }

        // 5. Relay Connector（扇出角色，多目标扇出/容灾；DB 为唯一事实来源，热操作经 ConnectorManager）
        // TOML `[[connectors]]` 降级为初始导入：同名已存在则跳过（TOML 无 name 字段，以地址为名；
        // 无组概念 → 不收敛），运行时以 DB 为准
        for connector_cfg in &config.connectors {
            let advertise = connector_cfg.advertise.join(",");
            match db.import_connector_if_absent(
                &connector_cfg.upstream_addr,
                &connector_cfg.upstream_addr,
                &connector_cfg.token,
                &connector_cfg.sni_hostname,
                connector_cfg.insecure,
                connector_cfg.ca_cert_path.as_deref().unwrap_or(""),
                connector_cfg.pinned_cert_path.as_deref().unwrap_or(""),
                &advertise,
                None,
                "toml import",
            ) {
                Ok(true) => {
                    tracing::info!(upstream = %connector_cfg.upstream_addr, "connector imported from TOML")
                }
                Ok(false) => {}
                Err(e) => {
                    tracing::error!(upstream = %connector_cfg.upstream_addr, error = %e, "connector import failed")
                }
            }
        }
        let connector_manager = Arc::new(
            ConnectorManager::new(db.clone())
                .with_node_id(config.name.clone())
                .with_listener(relay_listener.clone())
                .with_client_routes(opts.client_routes.clone())
                .with_acl_registry(acl_registry.clone())
                .with_manageable(manageable_registry.clone())
                .with_transit_meter(transit_meter.clone()),
        );
        connector_manager.start_all().await;

        // 6. 本地代理入站（可选）
        let mut proxy_stats = None;
        let mut proxy_listen = None;
        if let Some(proxy_cfg) = &config.proxy {
            let proxy_addr: SocketAddr = proxy_cfg.addr.parse()?;
            let mut inbound = ProxyInbound::new(proxy_addr, shared_router.clone())
                .with_transit_meter(transit_meter.clone());
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
            connector_manager: connector_manager.clone(),
            proxy_stats,
            proxy_listen,
            log_buffer,
            cert_fingerprint,
            manageable: manageable_registry.clone(),
            client_proxy_slot: opts.client_proxy_slot.clone(),
            transit_meter: transit_meter.clone(),
        });

        // 路由热更新监视：config_version 变化即重建节点本地代理路由表与对端收敛组路由。
        {
            let db = db.clone();
            let shared_router = shared_router.clone();
            let acl_registry = acl_registry.clone();
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
                        acl_registry.rebuild(&db);
                        tracing::debug!(
                            version = current,
                            rules = count,
                            "proxy router & peer acl hot-reloaded"
                        );
                    }
                }
            }));
        }

        // 节点级流量采样：分钟级把实时计数差分入 node_traffic_log（扇入对端/扇出/中继三维）。
        // 各源计数均为累计值：fanin/fanout 随会话重连归零（回退视为重置，按当前值入账）；
        // transit meter 进程内只增不减；三维互为独立视角（同一字节可在多个维度各计一次）。
        {
            let db = db.clone();
            let listener = relay_listener.clone();
            let connector_manager = connector_manager.clone();
            let meter = transit_meter.clone();
            tasks.push(tokio::spawn(async move {
                let mut last_fanin: std::collections::HashMap<String, (u64, u64)> =
                    Default::default();
                let mut last_fanout: std::collections::HashMap<String, (u64, u64)> =
                    Default::default();
                let mut last_transit: std::collections::HashMap<(String, String), (u64, u64)> =
                    Default::default();
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    interval.tick().await;

                    // 扇入对端（last 表随当前在线对端收敛，防无界增长）
                    if let Some(l) = &listener {
                        let cur: Vec<(String, u64, u64)> = l.peer_traffic();
                        last_fanin.retain(|k, _| cur.iter().any(|(id, _, _)| id == k));
                        for (node_id, up, down) in cur {
                            let (du, dd) = counter_delta(&mut last_fanin, node_id.clone(), up, down);
                            let _ = db.add_node_traffic("fanin", &node_id, "", du, dd);
                        }
                    }

                    // 扇出 connector（同上按当前句柄收敛）
                    let cur = connector_manager.traffic();
                    last_fanout.retain(|k, _| cur.iter().any(|(name, _, _)| name == k));
                    for (name, up, down) in cur {
                        let (du, dd) = counter_delta(&mut last_fanout, name.clone(), up, down);
                        let _ = db.add_node_traffic("fanout", &name, "", du, dd);
                    }

                    // 中继途径对
                    let (_, _, pairs) = meter.snapshot();
                    for p in pairs {
                        let key = (p.from, p.to);
                        let (du, dd) =
                            counter_delta(&mut last_transit, key.clone(), p.bytes_up, p.bytes_down);
                        let _ = db.add_node_traffic("transit", &key.0, &key.1, du, dd);
                    }
                }
            }));
        }

        // 数据留存清理任务：审计日志 90 天 + 节点级流量 30 天 + 过期 refresh token，每 24h 执行
        {
            let db = db.clone();
            tasks.push(tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(24 * 3600));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    interval.tick().await;
                    match db.cleanup_audit_log(90) {
                        Ok(n) if n > 0 => {
                            tracing::info!(removed = n, "audit log retention cleanup")
                        }
                        _ => {}
                    }
                    match db.cleanup_node_traffic(30) {
                        Ok(n) if n > 0 => {
                            tracing::info!(removed = n, "node traffic retention cleanup")
                        }
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
            let mut st = ApiState::new(
                db.clone(),
                jwt.clone(),
                runtime.clone(),
                public_host.clone(),
                api_port,
                relay_port,
            );
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

        // 握手 v2：回填本节点管理 API 端点（relay_token 暴露控制面下发内容）
        control_api_slot.store(Some(Arc::new((public_host.clone(), bound_api_addr.port()))));

        Ok(Self {
            db,
            jwt,
            runtime,
            state,
            api_addr: bound_api_addr,
            connector_manager,
            tasks,
            api_shutdown: Some(api_shutdown),
            api_stop_tx,
        })
    }

    /// API 实际监听地址（端口 0 动态分配时为回读值）。
    pub fn api_addr(&self) -> SocketAddr {
        self.api_addr
    }

    /// 各上游 connector 的（地址, 状态）（GUI 上游列表展示用）。
    pub fn connector_states(&self) -> Vec<(String, String)> {
        self.connector_manager.states()
    }

    /// 扇出 Connector 管理器（GUI 进程内热操作 / 管理 API 共用）。
    pub fn connector_manager(&self) -> Arc<ConnectorManager> {
        self.connector_manager.clone()
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

    /// 停止节点：API 优雅停机 → 全部 connector 断开 → 中止全部后台任务。幂等。
    pub async fn stop(mut self) {
        if let Some(tx) = self.api_stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.api_shutdown.take() {
            handle.graceful_shutdown(Some(std::time::Duration::from_secs(2)));
        }
        self.connector_manager.shutdown().await;
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

/// 累计计数差分：回退视为会话重置（按当前值入账），返回 (up, down) 增量。
fn counter_delta<K: Eq + std::hash::Hash>(
    map: &mut std::collections::HashMap<K, (u64, u64)>,
    key: K,
    up: u64,
    down: u64,
) -> (i64, i64) {
    let prev = map.insert(key, (up, down)).unwrap_or((0, 0));
    let du = if up >= prev.0 { up - prev.0 } else { up };
    let dd = if down >= prev.1 { down - prev.1 } else { down };
    (du as i64, dd as i64)
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
    crate::api::handlers::auth::validate_admin_credentials(&username, &password)
        .map_err(|e| anyhow::anyhow!("AGILE_ADMIN_PASSWORD/USERNAME 强度不足: {e}"))?;
    let hash = hash_password(&password)?;
    db.create_admin(&username, &hash)?;
    tracing::info!(username = %username, "admin account seeded from environment");
    Ok(())
}

/// 环境变量预置 Relay Tokens：AGILE_RELAY_TOKENS="psk_aaa,psk_bbb"（逗号分隔）。
///
/// 容器编排场景下，下游节点的 connector token 需要预先存在于上游数据库。
/// 已存在（按哈希判重）的 token 会跳过，保证幂等。
/// 语法扩展：`psk_xxx|expose:rules` 或 `psk_xxx|expose`（暴露控制面，档位缺省 full）。
fn seed_relay_tokens_from_env(db: &Database) -> Result<()> {
    let Ok(tokens) = std::env::var("AGILE_RELAY_TOKENS") else {
        return Ok(());
    };
    for entry in tokens
        .split(',')
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
    {
        let (token, expose, scope) = match entry.split_once('|') {
            Some((t, flags)) => {
                let mut expose = false;
                let mut scope = "full";
                for f in flags.split(':') {
                    match f {
                        "expose" => expose = true,
                        "ro" | "rules" | "full" => scope = f,
                        _ => {}
                    }
                }
                (t, expose, scope)
            }
            None => (entry, false, "full"),
        };
        let hash = crate::db::sha256_hex(token.as_bytes());
        if db.check_relay_token(&hash)? {
            continue;
        }
        let prefix = format!("{}****", &token[..token.len().min(8)]);
        db.create_relay_token_with_quota(&hash, &prefix, "seeded from environment", expose, scope, None, None)?;
        tracing::info!(prefix = %prefix, expose, scope, "relay token seeded from environment");
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
) -> Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
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

#[cfg(test)]
mod tests {
    use super::counter_delta;
    use std::collections::HashMap;

    /// 采样差分：常规递增 / 会话重置（计数回退按当前值入账）/ 双零
    #[test]
    fn counter_delta_handles_growth_reset_and_zero() {
        let mut map: HashMap<String, (u64, u64)> = HashMap::new();

        // 首次：全额为增量
        assert_eq!(counter_delta(&mut map, "a".into(), 100, 200), (100, 200));
        // 递增：差额入账
        assert_eq!(counter_delta(&mut map, "a".into(), 130, 260), (30, 60));
        // 回退（会话重连计数归零）：按当前值入账
        assert_eq!(counter_delta(&mut map, "a".into(), 10, 5), (10, 5));
        // 双零：无增量
        assert_eq!(counter_delta(&mut map, "a".into(), 10, 5), (0, 0));
        // 多 key 互不影响
        assert_eq!(counter_delta(&mut map, "b".into(), 7, 8), (7, 8));
        assert_eq!(counter_delta(&mut map, "a".into(), 12, 9), (2, 4));
    }
}
