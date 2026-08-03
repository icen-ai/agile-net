//! Node assembly root: `NodeServer::start/stop`.
//!
//! Consolidates the assembly logic previously scattered in `main.rs` (database / JWT /
//! Relay listener / connector / local proxy / API & Web dashboard / background tasks)
//! into an embeddable service object: the `anet-svc` `serve` subcommand and the
//! `anet-gui` embedded node share the same assembly code.

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

/// Startup overrides (for embedding; all-default behaves like the old main).
#[derive(Clone, Default)]
pub struct NodeServerOptions {
    /// Override the database path (takes precedence over DATABASE_PATH env and config.db_path)
    pub db_path: Option<String>,
    /// Override the API listen address (over API_LISTEN env and config.api.addr; port 0 = dynamic)
    pub api_listen: Option<String>,
    /// Override the public endpoint address (over AGILE_PUBLIC_HOST env and config.public_host)
    pub public_host: Option<String>,
    /// Skip env seeding (AGILE_ADMIN_PASSWORD / AGILE_RELAY_TOKENS); avoids host-process env pollution when embedded
    pub skip_env_seed: bool,
    /// Reuse the caller's in-memory log buffer (a new one otherwise)
    pub log_buffer: Option<LogBuffer>,
    /// Route re-publish: client engine merged router + opener registry (GUI embedding;
    /// client tunnel routes resold downstream; an Open hit forwards via the matching tunnel)
    pub client_routes: Option<ClientRoutes>,
    /// Client-role proxy state slot (written by the GUI host; default empty slot = unreported,
    /// status API's proxy section falls back to the legacy proxy_listen behavior)
    pub client_proxy_slot: ClientProxySlot,
}

/// Route re-publish injection: client engine's merged router + channel opener registry.
pub type ClientRoutes = (
    Arc<ArcSwap<ProxyRouter>>,
    Arc<dashmap::DashMap<String, Arc<dyn ChannelOpener>>>,
);

/// Client-role proxy state (written by the GUI host process: reflects the client engine's
/// real proxy state — distinct from the node-role proxy_listen).
#[derive(Debug, Clone)]
pub struct ClientProxyInfo {
    /// Whether the client proxy is listening
    pub enabled: bool,
    /// Proxy mode: "system" = takes over the system proxy / "local" = listen-only
    pub mode: String,
    /// Listen address (127.0.0.1:port; empty when disabled)
    pub listen: String,
}

/// Client proxy state slot (shared by host and embedded node; lock-free hot update via ArcSwap;
/// None = unreported, status proxy section keeps the node proxy_listen behavior).
pub type ClientProxySlot = Arc<ArcSwap<Option<ClientProxyInfo>>>;

/// Create a client proxy state slot (initial None = unreported).
pub fn new_client_proxy_slot() -> ClientProxySlot {
    Arc::new(ArcSwap::from_pointee(None))
}

/// Running node instance (`stop` is idempotent).
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
    /// Start with default overrides (equivalent to the old `agile-net-node` main flow).
    pub async fn start(config: NodeConfig) -> Result<Self> {
        Self::start_with(config, NodeServerOptions::default()).await
    }

    /// Assemble and start all roles (listener/connector/proxy/api); returns the running handle.
    pub async fn start_with(config: NodeConfig, opts: NodeServerOptions) -> Result<Self> {
        // rustls process-level CryptoProvider (ring) — must be installed before any ServerConfig/ClientConfig is built
        agile_net_core::init_crypto_provider();

        let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        let log_buffer = opts.log_buffer.unwrap_or_default();

        // 1. Database
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

        // 2. JWT service (secret loaded from the database or generated)
        let jwt = Arc::new(JwtService::load_or_create(db.clone())?);

        // 3. Router (the node's local proxy is driven by all rules: hit -> auto-pick tunnel, miss -> direct)
        let shared_router = Arc::new(ArcSwap::from_pointee(build_router(&db)));

        // handshake v2: control endpoint slot (backfilled after API assembly) and manageable upstream registry (connector sync)
        let control_api_slot: Arc<arc_swap::ArcSwapOption<(String, u16)>> =
            Arc::new(arc_swap::ArcSwapOption::from_pointee(None));
        let manageable_registry = crate::relay_auth::ManageableRegistry::default();

        // peer ACL registry: group rules -> PeerAcl (shared by fan-in/fan-out; hot-reload loop rebuilds on config_version change)
        let acl_registry = Arc::new(PeerAclRegistry::new());
        acl_registry.rebuild(&db);

        // transit meter (shared instrumentation across listener/connector/proxy; data source of the status transit section)
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
                // ACME mode: ALPN multiplexing resolver (zero-downtime hot swap on issue/renewal)
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
                // static/self-signed cert mode
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
                // session rate-limit wiring: relay_token.rate_limit_kbps -> core TokenBucket (B/s)
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
            // fan-in ACL-denied events -> audit (peer identity = node_id; deduped per peer+target per minute)
            tasks.push(connectors::spawn_acl_audit_task(
                db.clone(),
                "listener".to_string(),
                listener.subscribe_events(),
            ));
            relay_listener = Some(listener);
        }

        // 5. Relay Connector (fan-out role: multi-target fan-out/failover; DB is the single source of truth, hot ops via ConnectorManager)
        // TOML `[[connectors]]` is degraded to seed import: skipped when a same-named record exists
        // (TOML has no name field, the address acts as the name; no group concept -> unrestricted);
        // at runtime the DB wins
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

        // 6. Local proxy inbound (optional)
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

        // Route hot-reload watcher: rebuild the local proxy router and peer ACL group routers on config_version change.
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

        // Node-level traffic sampling: every minute, diff live counters into node_traffic_log
        // (three dimensions: fan-in peer / fan-out / transit). All source counters are cumulative:
        // fanin/fanout reset on session reconnect (a rollback counts as a reset, booked at the current
        // value); the transit meter only grows within the process; the three dimensions are
        // independent views (the same byte may count once in each).
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

                    // fan-in peers (last map pruned to currently online peers, avoiding unbounded growth)
                    if let Some(l) = &listener {
                        let cur: Vec<(String, u64, u64)> = l.peer_traffic();
                        last_fanin.retain(|k, _| cur.iter().any(|(id, _, _)| id == k));
                        for (node_id, up, down) in cur {
                            let (du, dd) = counter_delta(&mut last_fanin, node_id.clone(), up, down);
                            let _ = db.add_node_traffic("fanin", &node_id, "", du, dd);
                        }
                    }

                    // fan-out connectors (same pruning by current handles)
                    let cur = connector_manager.traffic();
                    last_fanout.retain(|k, _| cur.iter().any(|(name, _, _)| name == k));
                    for (name, up, down) in cur {
                        let (du, dd) = counter_delta(&mut last_fanout, name.clone(), up, down);
                        let _ = db.add_node_traffic("fanout", &name, "", du, dd);
                    }

                    // transit route pairs
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

        // Data retention cleanup: audit log 90d + node traffic 30d + expired refresh tokens, every 24h
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
        // connect_url / tunnel endpoint uses the declared port; with port 0 (dynamic), read back the actual port
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
                // HTTPS mode (built-in TLS, can reuse ACME/static certs; recommended for production)
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
                // bind before serving: supports port 0 dynamic allocation (embedding/tests) and removes the startup race
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

        // with a dynamic port (0), backfill the actual port so connect_url / config.tunnel point at the real endpoint
        let state = if state.api_port() != bound_api_addr.port() {
            let mut st = state;
            st.set_api_port(bound_api_addr.port());
            st
        } else {
            state
        };

        // handshake v2: backfill this node's admin API endpoint (sent to relay_tokens flagged to expose the control plane)
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

    /// Actual API listen address (read-back value when port 0 was dynamically allocated).
    pub fn api_addr(&self) -> SocketAddr {
        self.api_addr
    }

    /// (addr, state) of each upstream connector (for the GUI upstream list).
    pub fn connector_states(&self) -> Vec<(String, String)> {
        self.connector_manager.states()
    }

    /// Fan-out connector manager (shared by GUI in-process hot ops and the admin API).
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

    /// API shared state (includes rate limiters and the connect_url cache).
    pub fn api_state(&self) -> ApiState {
        self.state.clone()
    }

    /// Stop the node: graceful API shutdown -> disconnect all connectors -> abort all background tasks. Idempotent.
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
        // wait for tasks to actually exit (listener/proxy TcpListeners release their ports on task drop)
        for t in self.tasks.drain(..) {
            let _ = t.await;
        }
        tracing::info!("node server stopped");
    }
}

/// Cumulative counter delta: a rollback counts as a session reset (booked at the current value); returns (up, down) deltas.
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

/// Load node config from a file path (falls back to defaults when the file is missing).
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

/// Seed the admin from env: AGILE_ADMIN_USERNAME / AGILE_ADMIN_PASSWORD.
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

/// Seed relay tokens from env: AGILE_RELAY_TOKENS="psk_aaa,psk_bbb" (comma-separated).
///
/// In container orchestration, a downstream node's connector token must pre-exist in the
/// upstream database. Tokens already present (deduped by hash) are skipped, keeping it
/// idempotent. Syntax extension: `psk_xxx|expose:rules` or `psk_xxx|expose` (expose the
/// control plane; scope tier defaults to full).
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

/// Build the local proxy router from all DB rules (hit -> auto-pick tunnel).
fn build_router(db: &Database) -> ProxyRouter {
    let mut router = ProxyRouter::new();
    if let Ok((rules, _)) = db.list_rules(1, 1000, None, None) {
        for r in rules {
            // node-local proxy: rule-hit traffic picks a downstream node automatically via PeerAutoOpener
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

/// Load a PEM certificate chain.
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

/// Load a PEM certificate chain and private key.
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

/// Resolve an upstream address (domains supported; IPv4 preferred to avoid unreachable IPv6 on dual-stack networks).
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

    /// Sampling deltas: normal growth / session reset (rollback booked at current value) / double zero
    #[test]
    fn counter_delta_handles_growth_reset_and_zero() {
        let mut map: HashMap<String, (u64, u64)> = HashMap::new();

        // first sample: full value is the delta
        assert_eq!(counter_delta(&mut map, "a".into(), 100, 200), (100, 200));
        // growth: difference booked
        assert_eq!(counter_delta(&mut map, "a".into(), 130, 260), (30, 60));
        // rollback (session reconnect zeroed the counter): booked at current value
        assert_eq!(counter_delta(&mut map, "a".into(), 10, 5), (10, 5));
        // double zero: no delta
        assert_eq!(counter_delta(&mut map, "a".into(), 10, 5), (0, 0));
        // keys are independent
        assert_eq!(counter_delta(&mut map, "b".into(), 7, 8), (7, 8));
        assert_eq!(counter_delta(&mut map, "a".into(), 12, 9), (2, 4));
    }
}
