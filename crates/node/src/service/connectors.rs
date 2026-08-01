//! 扇出 Connector 管理器：DB 为唯一事实来源的运行时装配与热操作。
//!
//! 启动时从 DB 装配全部 enabled connector（TOML `[[connectors]]` 已在
//! NodeServer 启动早期导入为初始数据）；运行期经 `upsert_from_db` / `remove`
//! 响应管理面变更，先断旧再起新，全程无需重启节点。

use crate::db::Database;
use crate::relay_auth::ManageableRegistry;
use crate::service::acl::PeerAclRegistry;
use crate::service::{ClientRoutes, load_pem_certs, resolve_upstream};
use agile_net_core::relay::{ConnectionState, PeerEvent, RelayConnector, RelayListener};
use agile_net_core::tunnel::tls::TlsConfigBuilder;
use anyhow::Result;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// 单个 connector 的运行时句柄（connector 实例 + 其全部后台任务）。
struct ConnectorHandle {
    connector: Arc<RelayConnector>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

/// 扇出 Connector 管理器（connector_id → 运行时句柄）。
pub struct ConnectorManager {
    db: Database,
    /// 本节点名（握手时对上游表明身份）
    node_id: String,
    /// 下游路由 Listener（多级串联时 Open 请求继续向下游转发）
    listener: Option<Arc<RelayListener>>,
    /// 路由再发布：客户端引擎合并路由 + 开启器注册表（GUI 内嵌场景注入）
    client_routes: Option<ClientRoutes>,
    /// 对端收敛注册表（connector.group_id → 反向流量允许集合）
    acl: Arc<PeerAclRegistry>,
    /// 可管理上游注册表（握手 v2 发现同步）
    manageable: ManageableRegistry,
    handles: DashMap<String, ConnectorHandle>,
}

impl ConnectorManager {
    /// 最小构造（测试/嵌入场景）；运行时依赖经 with_* 注入。
    pub fn new(db: Database) -> Self {
        Self {
            db,
            node_id: "anet-node".to_string(),
            listener: None,
            client_routes: None,
            acl: Arc::new(PeerAclRegistry::new()),
            manageable: Arc::new(DashMap::new()),
            handles: DashMap::new(),
        }
    }

    pub fn with_node_id(mut self, node_id: String) -> Self {
        self.node_id = node_id;
        self
    }

    pub fn with_listener(mut self, listener: Option<Arc<RelayListener>>) -> Self {
        self.listener = listener;
        self
    }

    pub fn with_client_routes(mut self, client_routes: Option<ClientRoutes>) -> Self {
        self.client_routes = client_routes;
        self
    }

    pub fn with_acl_registry(mut self, registry: Arc<PeerAclRegistry>) -> Self {
        self.acl = registry;
        self
    }

    pub fn with_manageable(mut self, registry: ManageableRegistry) -> Self {
        self.manageable = registry;
        self
    }

    /// 启动装配：从 DB 拉起全部 enabled connector（单条失败只记日志不影响其余）。
    pub async fn start_all(&self) {
        let views = match self.db.list_connectors() {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "list connectors failed");
                return;
            }
        };
        for v in views.into_iter().filter(|v| v.enabled) {
            if let Err(e) = self.upsert_from_db(&v.id).await {
                tracing::error!(connector = %v.name, error = %e, "connector start failed");
            }
        }
    }

    /// 新建或重建指定 connector（先断旧再起新；记录缺失/禁用则仅移除）。
    pub async fn upsert_from_db(&self, id: &str) -> Result<()> {
        self.remove(id).await;
        if let Some(handle) = self.build(id).await? {
            self.handles.insert(id.to_string(), handle);
        }
        Ok(())
    }

    /// 断开并移除指定 connector（幂等）。
    pub async fn remove(&self, id: &str) {
        if let Some((_, handle)) = self.handles.remove(id) {
            handle.connector.disconnect().await;
            for t in handle.tasks {
                t.abort();
            }
        }
    }

    /// 全部断开（节点停机用）。
    pub async fn shutdown(&self) {
        let ids: Vec<String> = self.handles.iter().map(|e| e.key().clone()).collect();
        for id in ids {
            self.remove(&id).await;
        }
    }

    /// 各 connector 的（上游地址, 状态）（沿用原 connector_states 语义）。
    pub fn states(&self) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = self
            .handles
            .iter()
            .map(|h| {
                (
                    h.connector.upstream_addr().to_string(),
                    state_str(h.connector.state()).to_string(),
                )
            })
            .collect();
        out.sort();
        out
    }

    /// 单条 connector 的实时状态（无运行时句柄 = None，调用方按 disconnected 展示）。
    pub fn state_of(&self, id: &str) -> Option<&'static str> {
        self.handles.get(id).map(|h| state_str(h.connector.state()))
    }

    /// 扇出汇总状态：任一连通则 connected，全无扇出则 disabled。
    pub fn aggregate_status(&self) -> &'static str {
        if self.handles.is_empty() {
            return "disabled";
        }
        let mut any_connected = false;
        let mut any_active = false;
        for h in self.handles.iter() {
            match h.connector.state() {
                ConnectionState::Connected => any_connected = true,
                ConnectionState::Connecting | ConnectionState::Reconnecting => any_active = true,
                ConnectionState::Disconnected => {}
            }
        }
        if any_connected {
            "connected"
        } else if any_active {
            "connecting"
        } else {
            "disconnected"
        }
    }

    /// 解析带宽测试的发起对端（`anet tool bandwidth` / tool API 用）：
    /// - `Some(p)`：按 connector 名称或上游地址匹配，且须处于 connected；
    /// - `None`：取第一个 connected connector。
    ///
    /// 返回 (对端显示名, connector 句柄) 或明确错误。
    pub fn resolve_bandwidth_peer(
        &self,
        peer: Option<&str>,
    ) -> std::result::Result<(String, Arc<RelayConnector>), BandwidthPeerError> {
        let views = self.db.list_connectors().unwrap_or_default();
        match peer {
            Some(p) => {
                let Some(rec) = views.iter().find(|c| c.name == p || c.upstream_addr == p)
                else {
                    return Err(BandwidthPeerError::NotFound(format!(
                        "connector not found: {p}"
                    )));
                };
                match self.handles.get(&rec.id) {
                    Some(h) if h.connector.is_connected() => {
                        Ok((rec.name.clone(), h.connector.clone()))
                    }
                    _ => Err(BandwidthPeerError::NotConnected(format!(
                        "对端未连接: {}（connector 存在但当前非 connected）",
                        rec.name
                    ))),
                }
            }
            None => {
                for h in self.handles.iter() {
                    if h.connector.is_connected() {
                        let label = views
                            .iter()
                            .find(|c| c.id == *h.key())
                            .map(|c| c.name.clone())
                            .unwrap_or_else(|| h.connector.upstream_addr().to_string());
                        return Ok((label, h.connector.clone()));
                    }
                }
                Err(BandwidthPeerError::NotConnected(
                    "无已连接的扇出对端（无 connected 状态的 connector）".into(),
                ))
            }
        }
    }

    /// 按 DB 记录构建并拉起一个 connector（None = 记录缺失或已禁用）。
    async fn build(&self, id: &str) -> Result<Option<ConnectorHandle>> {
        let Some(rec) = self.db.get_connector(id)? else {
            return Ok(None);
        };
        if !rec.enabled {
            return Ok(None);
        }

        let upstream = resolve_upstream(&rec.upstream_addr).await?;
        let mut tls_builder = TlsConfigBuilder::new().sni_hostname(&rec.sni_hostname);
        // 证书校验优先级与原 TOML 装配一致：pinned > ca > insecure
        if !rec.pinned_cert_path.is_empty() {
            let certs = load_pem_certs(&rec.pinned_cert_path)?;
            tls_builder = tls_builder.pinned_certs(certs);
            tracing::info!(connector = %rec.name, "connector TLS: certificate pinning enabled");
        } else if !rec.ca_cert_path.is_empty() {
            let certs = load_pem_certs(&rec.ca_cert_path)?;
            tls_builder = tls_builder.ca_certs(certs);
        } else if rec.insecure {
            tracing::warn!(
                connector = %rec.name,
                "connector TLS: INSECURE mode (no certificate verification) — dev only!"
            );
            tls_builder = tls_builder.allow_self_signed(true);
        }

        // token 明文仅建连使用（解密自加密库），严禁日志/审计输出
        let token = self.db.get_connector_secret(id)?;
        let mut connector = RelayConnector::with_tls_builder(
            upstream,
            self.node_id.clone(),
            token,
            tls_builder,
        )?
        .with_advertise(parse_advertise(&rec.advertise))
        .with_acl(self.acl.handle(rec.group_id.as_deref()));

        if let Some(l) = &self.listener {
            connector = connector.with_peer_router(l.clone());
        }
        // 路由再发布：客户端隧道规则转售给下游（GUI 内嵌场景注入）
        if let Some((cr, ops)) = &self.client_routes {
            connector = connector.with_client_routes(cr.clone(), ops.clone());
        }
        let connector = Arc::new(connector);

        let mut tasks = Vec::new();
        let c = connector.clone();
        tasks.push(tokio::spawn(async move {
            c.run().await;
        }));
        tracing::info!(connector = %rec.name, upstream = %upstream, "relay connector running");

        // 握手 v2：同步上游暴露的控制端点到可管理注册表
        {
            let c = connector.clone();
            let registry = self.manageable.clone();
            tasks.push(tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(2));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    interval.tick().await;
                    match c.control_offer() {
                        Some(offer) => {
                            let key = if offer.node_name.is_empty() {
                                "upstream".to_string()
                            } else {
                                offer.node_name.clone()
                            };
                            let stale = registry
                                .get(&key)
                                .map(|old| old.ticket != offer.ticket)
                                .unwrap_or(true);
                            if stale {
                                tracing::info!(upstream = %key, api = %format!("{:?}:{}", offer.api_host, offer.api_port), "manageable upstream discovered");
                            }
                            registry.insert(key, offer);
                        }
                        None => {
                            if !registry.is_empty() {
                                registry.clear();
                            }
                        }
                    }
                }
            }));
        }

        // 收敛拒绝事件 → 审计（detail 含 connector name 与目标；按 peer+target 每分钟去重）
        tasks.push(spawn_acl_audit_task(
            self.db.clone(),
            format!("connector={}", rec.name),
            connector.subscribe_events(),
        ));

        Ok(Some(ConnectorHandle { connector, tasks }))
    }
}

/// 收敛拒绝审计任务：订阅 `PeerEvent::AclDenied`，同一 peer+target 每分钟最多一条（防刷）。
/// `source` 标注来源（`connector=<name>` / `listener`）；审计只记对端标识与目标，严禁敏感值。
pub(crate) fn spawn_acl_audit_task(
    db: Database,
    source: String,
    mut rx: tokio::sync::broadcast::Receiver<PeerEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut seen: std::collections::HashMap<String, Instant> = std::collections::HashMap::new();
        loop {
            match rx.recv().await {
                Ok(PeerEvent::AclDenied { peer_label, target }) => {
                    let now = Instant::now();
                    // 惰性清扫：防去重表无上限增长
                    if seen.len() > 4096 {
                        seen.retain(|_, t| now.duration_since(*t) < Duration::from_secs(60));
                    }
                    let key = format!("{peer_label}|{target}");
                    if seen
                        .get(&key)
                        .is_some_and(|t| now.duration_since(*t) < Duration::from_secs(60))
                    {
                        continue;
                    }
                    seen.insert(key, now);
                    let _ = db.record_audit_log(
                        None,
                        "system",
                        "peer.acl_denied",
                        Some(&peer_label),
                        Some(&format!("{source} target={target}")),
                        None,
                    );
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(skipped = n, source = %source, "acl audit events lagged");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

/// DB 中的 advertise 序列化（逗号拼接）还原为条目列表。
fn parse_advertise(advertise: &str) -> Vec<String> {
    advertise
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// 连接状态字面值（与 API 展示口径一致）。
fn state_str(state: ConnectionState) -> &'static str {
    match state {
        ConnectionState::Connected => "connected",
        ConnectionState::Connecting => "connecting",
        ConnectionState::Reconnecting => "reconnecting",
        ConnectionState::Disconnected => "disconnected",
    }
}

/// 带宽测试目标对端解析错误（kind 供 API 映射错误码）。
#[derive(Debug)]
pub enum BandwidthPeerError {
    /// 指定的名称/上游地址无对应 connector 记录
    NotFound(String),
    /// connector 存在但未连接（或未指定时无任何 connected connector）
    NotConnected(String),
}

impl std::fmt::Display for BandwidthPeerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BandwidthPeerError::NotFound(m) | BandwidthPeerError::NotConnected(m) => {
                write!(f, "{m}")
            }
        }
    }
}
