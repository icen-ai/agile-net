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
                let acl = rules.into_iter().map(|r| r.value).collect();
                let _ = self.db.touch_account_seen(&account.id);
                Some(AuthIdentity::Client {
                    account_id: account.id,
                    acl,
                })
            }
        }
    }
}
