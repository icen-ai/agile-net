//! Relay 数据面 Token 校验器（桥接数据库与 core::relay::listener）
//!
//! - 节点认证：relay_token 表（SHA-256 哈希比对）；令牌带「暴露控制面」标记时
//!   签发管理引导票据并随 AuthOk 下发控制端点（握手 v2）
//! - 客户端认证：account.tunnel_token_hash（SHA-256），并装载权限组规则作为 ACL；
//!   「管理此节点」账号隐式放开本机 loopback API 与可管理上游端点

use crate::db::{Database, sha256_hex};
use agile_net_core::proto::message::{AuthKind, AuthRequest, ControlOffer};
use agile_net_core::relay::listener::{AuthIdentity, TokenValidator};
use std::sync::Arc;

/// 可管理上游注册表：上游节点名 → 控制端点（握手 v2 发现，connector 同步任务维护）。
pub type ManageableRegistry = Arc<dashmap::DashMap<String, ControlOffer>>;

/// 管理引导票据参数：TTL 7 天、限 10000 次。
///
/// 安全边界等同中继令牌本身：psk 持有者随时可重连换新票，TTL 仅约束泄露窗口；
/// 吊销令牌 + 踢会话即全线回收（refresh token 可单独吊销）。
const RELAY_TICKET_TTL_SECS: i64 = 7 * 24 * 3600;
const RELAY_TICKET_MAX_USES: i32 = 10000;

pub struct DbTokenValidator {
    db: Database,
    /// 本节点管理 API 端点（public_host, api_port），NodeServer 装配后回填
    control_api: Arc<arc_swap::ArcSwapOption<(String, u16)>>,
    /// 可管理上游注册表（隐式 ACL 用；无 connector 时恒空）
    manageable: ManageableRegistry,
}

impl DbTokenValidator {
    pub fn new(db: Database) -> Self {
        Self {
            db,
            control_api: Arc::new(arc_swap::ArcSwapOption::from_pointee(None)),
            manageable: Arc::new(dashmap::DashMap::new()),
        }
    }

    /// 回填本节点管理 API 端点（握手 v2 下发内容）。
    pub fn with_control_api(mut self, slot: Arc<arc_swap::ArcSwapOption<(String, u16)>>) -> Self {
        self.control_api = slot;
        self
    }

    /// 注入可管理上游注册表（admin_console 账号隐式 ACL 用）。
    pub fn with_manageable(mut self, registry: ManageableRegistry) -> Self {
        self.manageable = registry;
        self
    }

    /// 本节点显示名（下发给下游的可管理节点卡片）。
    fn node_name(&self) -> String {
        self.db
            .get_config("node_name")
            .ok()
            .flatten()
            .unwrap_or_else(|| "AgileNet Node".into())
    }
}

impl TokenValidator for DbTokenValidator {
    fn validate(&self, auth: &AuthRequest) -> Option<AuthIdentity> {
        let token_hash = sha256_hex(auth.token.as_bytes());
        match auth.kind {
            AuthKind::Node => {
                if !self.db.check_relay_token(&token_hash).ok()? {
                    return None;
                }
                // 握手 v2：令牌带暴露标记 → 签发管理引导票据 + 下发控制端点
                let control = match self.db.get_relay_token_control(&token_hash) {
                    Ok(Some((prefix, true, scope))) => {
                        let (host, port) = self.control_api.load_full().map(|a| (*a).clone())?;
                        let subject = format!("{}@{}", prefix, auth.node_id);
                        match self.db.create_admin_ticket(
                            "relay",
                            &subject,
                            &scope,
                            RELAY_TICKET_MAX_USES,
                            RELAY_TICKET_TTL_SECS,
                        ) {
                            Ok(ticket) => {
                                tracing::info!(
                                    token = %prefix,
                                    downstream = %auth.node_id,
                                    scope = %scope,
                                    "control plane exposed to downstream (handshake v2)"
                                );
                                Some(ControlOffer {
                                    exposed: true,
                                    api_host: Some(host),
                                    api_port: port,
                                    node_name: self.node_name(),
                                    ticket,
                                    scope,
                                })
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "mint relay admin ticket failed");
                                None
                            }
                        }
                    }
                    _ => None,
                };
                Some(AuthIdentity::Node {
                    node_id: auth.node_id.clone(),
                    advertise: auth.advertise.clone(),
                    control,
                })
            }
            AuthKind::Client => {
                let account = self.db.find_account_by_tunnel_hash(&token_hash).ok()??;
                if !account.enabled {
                    return None;
                }
                // 装载该账号权限组的全部规则作为数据面 ACL
                let rules = self.db.rules_of_account(&account.id).ok()?;
                let mut acl: Vec<String> = rules.into_iter().map(|r| r.value).collect();
                // 「管理此节点」权限：隐式放开节点自身 loopback API 与可管理上游端点
                // （收回权限后下次隧道认证即失去通路，对应「收回规则即失去管理通路」）
                if account.admin_console {
                    acl.push("127.0.0.1/32".to_string());
                    for item in self.manageable.iter() {
                        let offer = item.value();
                        if let Some(host) = &offer.api_host {
                            acl.push(acl_rule_for_host(host));
                        }
                    }
                }
                let _ = self.db.touch_account_seen(&account.id);
                Some(AuthIdentity::Client {
                    account_id: account.id,
                    acl,
                })
            }
        }
    }
}

/// 主机名/IP → ACL 规则字面值（IP 给 /32，域名给精确主机）。
fn acl_rule_for_host(host: &str) -> String {
    if host.parse::<std::net::IpAddr>().is_ok() {
        format!("{host}/32")
    } else {
        host.to_string()
    }
}
