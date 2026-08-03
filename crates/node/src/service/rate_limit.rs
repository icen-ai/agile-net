//! Relay 会话限速配额供给：relay_token.rate_limit_kbps（KB/s）→ core TokenBucket（B/s）。
//!
//! 配额按 relay_token 行配置（扇入对端维度）；客户端账号（AuthIdentity::Client）
//! 走 account 表隧道认证，不在本模块配额范围，恒返回 None。

use crate::db::Database;
use agile_net_core::relay::listener::AuthIdentity;

/// KB/s → B/s 换算（1024 进制；与配额列单位约定一致）。
fn kbps_to_bps(kbps: i64) -> Option<u64> {
    u64::try_from(kbps).ok()?.checked_mul(1024)
}

/// 按 token 哈希查配额并换算为字节/秒（None = 不限：无此行/未设配额/值非法）。
pub fn relay_token_rate_limit_bps_by_hash(db: &Database, token_hash: &str) -> Option<u64> {
    db.get_relay_token_rate_limit(token_hash)
        .ok()
        .flatten()
        .filter(|v| *v > 0)
        .and_then(kbps_to_bps)
}

/// core `with_session_rate_limit` 的 provider：按（认证身份, token 哈希）给出会话限速（B/s）。
pub fn token_rate_limit_bps(identity: &AuthIdentity, token_hash: &str, db: &Database) -> Option<u64> {
    match identity {
        AuthIdentity::Node { .. } => relay_token_rate_limit_bps_by_hash(db, token_hash),
        AuthIdentity::Client { .. } => None, // 客户端账号不走 relay_token 配额
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sha256_hex;

    #[test]
    fn kbps_conversion() {
        assert_eq!(kbps_to_bps(1), Some(1024));
        assert_eq!(kbps_to_bps(10240), Some(10_485_760));
        // 非法值：负数与溢出均为 None（不限）
        assert_eq!(kbps_to_bps(-1), None);
        assert_eq!(kbps_to_bps(i64::MAX), None);
    }

    #[test]
    fn rate_limit_by_hash() {
        let db = Database::in_memory().unwrap();
        let hash = sha256_hex(b"tok-rl");
        db.create_relay_token_with_quota(&hash, "psk_rl", "", false, "full", None, Some(10240))
            .unwrap();
        // 10240 KB/s = 10 MiB/s
        assert_eq!(relay_token_rate_limit_bps_by_hash(&db, &hash), Some(10_485_760));

        // 未设配额 / 不存在的哈希：None（不限）
        let hash2 = sha256_hex(b"tok-free");
        db.create_relay_token_with_quota(&hash2, "psk_f", "", false, "full", None, None)
            .unwrap();
        assert_eq!(relay_token_rate_limit_bps_by_hash(&db, &hash2), None);
        assert_eq!(relay_token_rate_limit_bps_by_hash(&db, "no-such"), None);
    }

    #[test]
    fn provider_identity_mapping() {
        let db = Database::in_memory().unwrap();
        // Client 变体：恒 None
        let client = AuthIdentity::Client {
            account_id: "acc-1".into(),
            acl: vec![],
        };
        assert_eq!(token_rate_limit_bps(&client, "any-hash", &db), None);
        // Node 变体：按 token 哈希映射 relay_token 行
        let node = AuthIdentity::Node {
            node_id: "n-1".into(),
            advertise: vec![],
            control: None,
            acl: None,
        };
        let hash = sha256_hex(b"tok-map");
        db.create_relay_token_with_quota(&hash, "psk_m", "", false, "full", None, Some(2048))
            .unwrap();
        assert_eq!(token_rate_limit_bps(&node, &hash, &db), Some(2048 * 1024));
        assert_eq!(token_rate_limit_bps(&node, "no-such", &db), None);
    }
}
