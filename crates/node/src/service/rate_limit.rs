//! Relay session rate-limit quota provider: relay_token.rate_limit_kbps (KB/s) -> core TokenBucket (B/s).
//!
//! Quotas are configured per relay_token row (fan-in peer dimension); client accounts
//! (AuthIdentity::Client) authenticate against the account table and always get None here.

use crate::db::Database;
use agile_net_core::relay::listener::AuthIdentity;

/// KB/s -> B/s conversion (1024-based, matching the quota column unit).
fn kbps_to_bps(kbps: i64) -> Option<u64> {
    u64::try_from(kbps).ok()?.checked_mul(1024)
}

/// Look up the quota by token hash and convert to bytes/sec (None = unlimited: no row / no quota / invalid value).
pub fn relay_token_rate_limit_bps_by_hash(db: &Database, token_hash: &str) -> Option<u64> {
    db.get_relay_token_rate_limit(token_hash)
        .ok()
        .flatten()
        .filter(|v| *v > 0)
        .and_then(kbps_to_bps)
}

/// Provider for core `with_session_rate_limit`: session rate limit (B/s) by (auth identity, token hash).
pub fn token_rate_limit_bps(identity: &AuthIdentity, token_hash: &str, db: &Database) -> Option<u64> {
    match identity {
        AuthIdentity::Node { .. } => relay_token_rate_limit_bps_by_hash(db, token_hash),
        AuthIdentity::Client { .. } => None, // client accounts bypass relay_token quotas
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
        // invalid values: negatives and overflow yield None (unlimited)
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

        // no quota set / unknown hash: None (unlimited)
        let hash2 = sha256_hex(b"tok-free");
        db.create_relay_token_with_quota(&hash2, "psk_f", "", false, "full", None, None)
            .unwrap();
        assert_eq!(relay_token_rate_limit_bps_by_hash(&db, &hash2), None);
        assert_eq!(relay_token_rate_limit_bps_by_hash(&db, "no-such"), None);
    }

    #[test]
    fn provider_identity_mapping() {
        let db = Database::in_memory().unwrap();
        // Client variant: always None
        let client = AuthIdentity::Client {
            account_id: "acc-1".into(),
            acl: vec![],
            delegated: None,
        };
        assert_eq!(token_rate_limit_bps(&client, "any-hash", &db), None);
        // Node variant: maps to a relay_token row by token hash
        let node = AuthIdentity::Node {
            node_id: "n-1".into(),
            advertise: vec![],
            groups: vec![],
            control: None,
            acl: None,
            display: None,
        };
        let hash = sha256_hex(b"tok-map");
        db.create_relay_token_with_quota(&hash, "psk_m", "", false, "full", None, Some(2048))
            .unwrap();
        assert_eq!(token_rate_limit_bps(&node, &hash, &db), Some(2048 * 1024));
        assert_eq!(token_rate_limit_bps(&node, "no-such", &db), None);
    }
}
