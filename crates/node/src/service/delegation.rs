//! Delegated token issuance and fan-out session registration (federation P2, issuer side).
//!
//! Storage discipline mirrors relay tokens: the plaintext (`psk_` + 48 chars) is returned once
//! at issuance; the DB holds the SHA-256 hash only. The E2E master key (federation P3,
//! HKDF(token)) is derived at issuance and stored AES-256-GCM encrypted — the second and last
//! reversible-storage exception, same machine key as connector tokens (never logged/audited).

use crate::db::models::DelegatedTokenRecord;
use crate::db::{Database, generate_relay_token, sha256_hex};
use agile_net_core::proto::message::{CtrlMessage, HintEntry};
use anyhow::{Result, bail};
use std::net::IpAddr;

/// Issue a delegated token and set its disaster set (one row per upstream connector).
/// Returns the record and the plaintext (shown once, inside the share link).
pub fn issue_token(
    db: &Database,
    label: &str,
    group_ids: &[String],
    hint_map: &[HintEntry],
    regs: &[(String, bool)],
) -> Result<(DelegatedTokenRecord, String)> {
    if label.len() > 128 {
        bail!("备注过长（≤128 字符）");
    }
    if regs.is_empty() {
        bail!("容灾集合不能为空（至少选择一个扇出上游）");
    }
    if !regs.iter().any(|r| r.1) {
        bail!("必须指定一个主入口");
    }
    for gid in group_ids {
        if db.get_group(gid)?.is_none() {
            bail!("权限组不存在: {gid}");
        }
        // every referenced connector must exist as well (a dangling row would silently
        // never register); the FK would catch it at insert time, but with a clearer error here
    }
    for (cid, _) in regs {
        if db.get_connector(cid)?.is_none() {
            bail!("扇出连接不存在: {cid}");
        }
    }

    let plaintext = generate_relay_token(); // same entropy as relay tokens (psk_ + 48)
    let token_hash = sha256_hex(plaintext.as_bytes());
    let e2e_key = agile_net_core::relay::e2e::derive_key(&plaintext);
    let e2e_key_enc = db.encrypt_secret(&agile_net_core::util::base64_encode(&e2e_key))?;
    let groups_json = serde_json::to_string(group_ids)?;
    let hint_json = serde_json::to_string(hint_map)?;
    let prefix: String = plaintext.chars().take(8).collect();

    let rec = db.create_delegated_token(
        &token_hash,
        &prefix,
        label,
        &groups_json,
        &hint_json,
        &e2e_key_enc,
    )?;
    db.set_delegated_token_regs(&rec.id, regs)?;
    let rec = db.get_delegated_token(&rec.id)?.expect("just created");
    Ok((rec, plaintext))
}

/// Delete a delegated token; returns the record (with regs) so the caller can send the
/// revocation frame to every online upstream of the disaster set.
pub fn revoke_token(db: &Database, id: &str) -> Result<Option<DelegatedTokenRecord>> {
    let Some(rec) = db.get_delegated_token(id)? else {
        return Ok(None);
    };
    db.delete_delegated_token(id)?;
    Ok(Some(rec))
}

/// Build the registration frame for one token: local group IDs resolve to names (the relay
/// only ever sees names — namespaces are per-issuer), dangling groups are skipped with a warn.
pub fn build_register_msg(db: &Database, rec: &DelegatedTokenRecord) -> CtrlMessage {    let group_ids: Vec<String> = serde_json::from_str(&rec.groups).unwrap_or_default();
    let mut names = Vec::with_capacity(group_ids.len());
    for gid in &group_ids {
        match db.get_group(gid) {
            Ok(Some(g)) => names.push(g.name),
            _ => tracing::warn!(group_id = %gid, token = %rec.id, "delegated token references a missing group (skipped)"),
        }
    }
    CtrlMessage::TokenRegister {
        token_hash: rec.token_hash.clone(),
        label: rec.label.clone(),
        groups: names,
        hint_map: serde_json::from_str(&rec.hint_map).unwrap_or_default(),
    }
}

/// Derive a placeholder routing hint from the issuer's advertised routes (federation P3).
///
/// The hint is a literal address that must resolve back to this issuer on the relay's route
/// table — CIDR -> network address + 1, `*.suffix` wildcard -> `relay<suffix>`, exact host ->
/// itself. One shared hint covers every E2E group (the coarsest vocabulary: the relay learns
/// nothing about which group a connection belongs to). None when nothing is advertised.
pub fn derive_hint(advertise: &[String]) -> Option<String> {
    for entry in advertise {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        if let Ok(net) = entry.parse::<ip_network::IpNetwork>() {
            let host = match net.network_address() {
                IpAddr::V4(v4) => IpAddr::V4(std::net::Ipv4Addr::from(u32::from(v4).wrapping_add(1))),
                IpAddr::V6(v6) => IpAddr::V6(std::net::Ipv6Addr::from(u128::from(v6).wrapping_add(1))),
            };
            return Some(host.to_string());
        }
        if entry.contains('*') {
            let suffix = entry.trim_start_matches('*');
            if !suffix.is_empty() {
                return Some(format!("relay{suffix}"));
            }
            continue;
        }
        return Some(entry.to_string());
    }
    None
}

/// Recover the E2E master key of a token (issuer side, E2E unwrap path; never expose via API).
pub fn e2e_key_of(db: &Database, rec: &DelegatedTokenRecord) -> Result<[u8; 32]> {
    let b64 = db.decrypt_secret(&rec.e2e_key_enc)?;
    let raw = agile_net_core::util::base64_decode(&b64).ok_or_else(|| anyhow::anyhow!("e2e key corrupt"))?;
    let len = raw.len();
    let key: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("e2e key length invalid: {len}"))?;
    Ok(key)
}

// ==================== DelegationEngine (data-plane hooks, issuer endpoint) ====================

/// One local group in the enforcement cache.
struct GroupEntry {
    /// Compiled rule set (route hit = allow)
    router: std::sync::Arc<agile_net_core::proxy::router::ProxyRouter>,
    e2e_required: bool,
}

/// In-memory delegation enforcement engine (federation P2/P3, issuer side).
///
/// Two hot-swappable caches, rebuilt from the DB on every relevant change (issue/revoke,
/// group/rule edit) — the data plane never touches the database on the Open hot path:
/// - `keys`: kid -> E2E master key of every issued delegated token (E2E unwrap);
/// - `groups`: local group name -> compiled rules + e2e_required flag (per-open enforcement
///   and the fail-close check).
#[derive(Default)]
pub struct DelegationEngine {
    keys: arc_swap::ArcSwap<std::collections::HashMap<String, [u8; 32]>>,
    groups: arc_swap::ArcSwap<std::collections::HashMap<String, std::sync::Arc<GroupEntry>>>,
}

impl DelegationEngine {
    /// Empty engine (nothing unwraps, nothing enforces, nothing fails closed).
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::default())
    }

    /// Rebuild the kid -> E2E key cache from the DB (call on issue/revoke and at startup).
    pub fn refresh_keys(&self, db: &Database) {
        let mut map = std::collections::HashMap::new();
        for rec in db.list_delegated_tokens().unwrap_or_default() {
            match e2e_key_of(db, &rec) {
                Ok(key) => {
                    map.insert(
                        agile_net_core::relay::e2e::kid_of(&rec.token_hash).to_string(),
                        key,
                    );
                }
                Err(e) => {
                    tracing::error!(token = %rec.id, error = %e, "delegated token e2e key corrupt (skipped)")
                }
            }
        }
        self.keys.store(std::sync::Arc::new(map));
    }

    /// Rebuild the group enforcement cache from the DB (call on group/rule changes and at startup).
    pub fn refresh_groups(&self, db: &Database) {
        let mut map = std::collections::HashMap::new();
        // list_groups is paged; local group counts are small, pull one generous page
        let (groups, _) = db.list_groups(1, 10000, None).unwrap_or_default();
        for g in groups {
            let rules: Vec<String> = db
                .rules_of_group(&g.id)
                .map(|rs| rs.into_iter().map(|r| r.value).collect())
                .unwrap_or_default();
            map.insert(
                g.name,
                std::sync::Arc::new(GroupEntry {
                    router: agile_net_core::relay::build_acl_router(&rules),
                    e2e_required: g.e2e_required,
                }),
            );
        }
        self.groups.store(std::sync::Arc::new(map));
    }
}

impl agile_net_core::relay::DelegationHooks for DelegationEngine {
    fn group_acl_allows(&self, groups: &[String], target: &str) -> Option<bool> {
        let cache = self.groups.load();
        let mut any_known = false;
        for name in groups {
            if let Some(entry) = cache.get(name) {
                any_known = true;
                if entry.router.matches(target) {
                    return Some(true);
                }
            }
        }
        // every group unknown -> None (caller rejects + audits); known but no hit -> deny
        any_known.then_some(false)
    }

    fn e2e_required_hit(&self, target: &str) -> bool {
        let cache = self.groups.load();
        cache
            .values()
            .any(|entry| entry.e2e_required && entry.router.matches(target))
    }

    fn e2e_unwrap(
        &self,
        e2e: &agile_net_core::proto::message::E2eOpen,
    ) -> agile_net_core::error::Result<
        Option<(
            agile_net_core::relay::e2e::E2eOpenPayload,
            agile_net_core::relay::e2e::ChannelCipher,
        )>,
    > {
        let cache = self.keys.load();
        let Some(key) = cache.get(&e2e.kid) else {
            return Ok(None); // transit role: not our token
        };
        let (payload, cipher) = agile_net_core::relay::e2e::open_open(key, e2e)?;
        Ok(Some((payload, cipher)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_group(db: &Database, name: &str) -> String {
        db.create_group(name, "").expect("group").id
    }

    fn mk_connector(db: &Database, name: &str) -> String {
        db.create_connector(name, "1.2.3.4:54430", "psk_x", "", true, "", "", "", "", None, "")
            .expect("connector")
            .id
    }

    #[test]
    fn issue_stores_hash_and_recoverable_e2e_key() {
        let db = Database::in_memory().unwrap();
        let gid = mk_group(&db, "git");
        let cid = mk_connector(&db, "up-1");

        let (rec, plaintext) = issue_token(&db, "alice", std::slice::from_ref(&gid), &[], &[(cid.clone(), true)]).unwrap();
        assert!(plaintext.starts_with("psk_"));
        assert_eq!(plaintext.len(), 4 + 48);
        assert_eq!(rec.token_prefix, plaintext[..8]);
        // DB holds the hash, never the plaintext
        assert_eq!(rec.token_hash, sha256_hex(plaintext.as_bytes()));
        assert_ne!(rec.e2e_key_enc, plaintext);
        // E2E key recovers to HKDF(plaintext)
        let key = e2e_key_of(&db, &rec).unwrap();
        assert_eq!(key, agile_net_core::relay::e2e::derive_key(&plaintext));
        // disaster set persisted with the primary flag
        assert_eq!(rec.regs.len(), 1);
        assert_eq!(rec.regs[0].connector_id, cid);
        assert!(rec.regs[0].is_primary);
    }

    #[test]
    fn issue_validates_inputs() {
        let db = Database::in_memory().unwrap();
        let gid = mk_group(&db, "git");
        let cid = mk_connector(&db, "up-1");

        // empty disaster set
        assert!(issue_token(&db, "a", &[gid.clone()], &[], &[]).is_err());
        // no primary entry
        assert!(issue_token(&db, "a", &[gid.clone()], &[], &[(cid.clone(), false)]).is_err());
        // missing group
        assert!(issue_token(&db, "a", &["no-such-group".into()], &[], &[(cid.clone(), true)]).is_err());
        // missing connector
        assert!(issue_token(&db, "a", &[gid.clone()], &[], &[("no-such-conn".into(), true)]).is_err());
        // oversized label
        assert!(issue_token(&db, &"x".repeat(200), &[gid], &[], &[(cid, true)]).is_err());
    }

    #[test]
    fn register_msg_resolves_group_names_and_skips_dangling() {
        let db = Database::in_memory().unwrap();
        let g1 = mk_group(&db, "git");
        let g2 = mk_group(&db, "ops");
        let cid = mk_connector(&db, "up-1");
        let (rec, _) = issue_token(&db, "alice", &[g1.clone(), g2.clone()], &[], &[(cid, true)]).unwrap();

        let msg = build_register_msg(&db, &rec);
        let CtrlMessage::TokenRegister { token_hash, label, groups, hint_map } = msg else {
            panic!("expected TokenRegister");
        };
        assert_eq!(token_hash, rec.token_hash);
        assert_eq!(label, "alice");
        assert_eq!(groups, vec!["git".to_string(), "ops".to_string()]);
        assert!(hint_map.is_empty());

        // delete one group: it is skipped (warn only), the registration still goes out
        db.delete_group(&g1, false).unwrap();
        let rec = db.get_delegated_token(&rec.id).unwrap().unwrap();
        let CtrlMessage::TokenRegister { groups, .. } = build_register_msg(&db, &rec) else {
            panic!("expected TokenRegister");
        };
        assert_eq!(groups, vec!["ops".to_string()]);
    }

    #[test]
    fn revoke_returns_record_for_frames() {
        let db = Database::in_memory().unwrap();
        let gid = mk_group(&db, "git");
        let cid = mk_connector(&db, "up-1");
        let (rec, _) = issue_token(&db, "alice", &[gid], &[], &[(cid, true)]).unwrap();

        let revoked = revoke_token(&db, &rec.id).unwrap().expect("existed");
        assert_eq!(revoked.token_hash, rec.token_hash);
        assert_eq!(revoked.regs.len(), 1);
        assert!(db.get_delegated_token(&rec.id).unwrap().is_none());
        assert!(db.delegated_regs_of(&rec.id).unwrap().is_empty());
        // second revoke is a no-op
        assert!(revoke_token(&db, &rec.id).unwrap().is_none());
    }

    // ==================== DelegationEngine ====================

    fn mk_group_with_rule(db: &Database, name: &str, cidr: &str, e2e: bool) -> String {
        let gid = db.create_group(name, "").unwrap().id;
        let rid = db.create_rule("ip-cidr", cidr, false, "").unwrap().id;
        db.set_group_rules(&gid, &[rid]).unwrap();
        if e2e {
            db.set_group_e2e_required(&gid, true).unwrap();
        }
        gid
    }

    #[test]
    fn engine_group_acl_and_fail_close() {
        use agile_net_core::relay::DelegationHooks;

        let db = Database::in_memory().unwrap();
        mk_group_with_rule(&db, "git", "10.1.0.0/16", false);
        mk_group_with_rule(&db, "db-prod", "10.2.0.0/16", true);
        let engine = DelegationEngine::new();
        engine.refresh_groups(&db);

        // transparent tier: hit allowed, miss denied, unknown group -> None
        assert_eq!(
            engine.group_acl_allows(&["git".to_string()], "10.1.2.3:22"),
            Some(true)
        );
        assert_eq!(
            engine.group_acl_allows(&["git".to_string()], "8.8.8.8:443"),
            Some(false)
        );
        assert_eq!(engine.group_acl_allows(&["nope".to_string()], "10.1.2.3:22"), None);
        // union semantics: one known hit among several names passes
        assert_eq!(
            engine.group_acl_allows(&["nope".to_string(), "git".to_string()], "10.1.2.3:22"),
            Some(true)
        );

        // fail-close: targets under the e2e_required group must never go plaintext
        assert!(engine.e2e_required_hit("10.2.9.9:5432"));
        assert!(!engine.e2e_required_hit("10.1.2.3:22"));
    }

    #[test]
    fn engine_e2e_unwrap_three_roles() {
        use agile_net_core::relay::DelegationHooks;
        use agile_net_core::relay::e2e::{derive_key, kid_of, seal_open};

        let db = Database::in_memory().unwrap();
        let gid = mk_group(&db, "db-prod");
        let cid = mk_connector(&db, "up-1");
        let (rec, plaintext) = issue_token(&db, "alice", &[gid], &[], &[(cid, true)]).unwrap();

        let engine = DelegationEngine::new();
        engine.refresh_keys(&db);

        let key = derive_key(&plaintext);
        let (env, cipher) = seal_open(
            &key,
            kid_of(&rec.token_hash),
            "relay.internal",
            "10.2.0.5",
            5432,
            &["db-prod".to_string()],
        );

        // endpoint role: our kid unwraps
        let (payload, _cipher) = engine.e2e_unwrap(&env).unwrap().expect("endpoint role");
        assert_eq!(payload.target_addr, "10.2.0.5");
        assert_eq!(payload.target_port, 5432);
        drop(cipher);

        // transit role: unknown kid passes through (None, never an error)
        let foreign = agile_net_core::proto::message::E2eOpen {
            kid: "ffffffff".into(),
            ..env.clone()
        };
        assert!(engine.e2e_unwrap(&foreign).unwrap().is_none());

        // forged envelope (right kid, wrong key material) -> hard error
        let other_key = derive_key("psk_someone-else");
        let (forged, _) = seal_open(&other_key, kid_of(&rec.token_hash), "h", "a", 1, &[]);
        assert!(engine.e2e_unwrap(&forged).is_err());

        // after revoke + refresh, the endpoint role is gone (transit/None)
        revoke_token(&db, &rec.id).unwrap();
        engine.refresh_keys(&db);
        assert!(engine.e2e_unwrap(&env).unwrap().is_none());
    }
}
