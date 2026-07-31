//! Relay 数据面 Token 校验器（桥接数据库与 core::relay::listener）
//!
//! - 节点认证：relay_token 表（SHA-256 哈希比对）
//! - 客户端认证：account.tunnel_token_hash（SHA-256），并装载权限组规则作为 ACL

use crate::db::{Database, sha256_hex};
use agile_net_core::proto::message::{AuthKind, AuthRequest};
use agile_net_core::relay::listener::{AuthIdentity, TokenValidator};

pub struct DbTokenValidator {
    db: Database,
}

impl DbTokenValidator {
    pub fn new(db: Database) -> Self {
        Self { db }
    }
}

impl TokenValidator for DbTokenValidator {
    fn validate(&self, auth: &AuthRequest) -> Option<AuthIdentity> {
        let token_hash = sha256_hex(auth.token.as_bytes());
        match auth.kind {
            AuthKind::Node => {
                if self.db.check_relay_token(&token_hash).ok()? {
                    Some(AuthIdentity::Node {
                        node_id: auth.node_id.clone(),
                        advertise: auth.advertise.clone(),
                    })
                } else {
                    None
                }
            }
            AuthKind::Client => {
                let account = self.db.find_account_by_tunnel_hash(&token_hash).ok()??;
                if !account.enabled {
                    return None;
                }
                // 装载该账号权限组的全部规则作为数据面 ACL
                let rules = self.db.rules_of_account(&account.id).ok()?;
                let mut acl: Vec<String> = rules.into_iter().map(|r| r.value).collect();
                // 「管理此节点」权限：隐式放开节点自身 loopback API（控制台通道；
                // 收回权限后下次隧道认证即失去该通路，对应「收回规则即失去管理通路」）
                if account.admin_console {
                    acl.push("127.0.0.1/32".to_string());
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
