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
    mode: &str,
    admin_scope: &str,
) -> Result<(DelegatedTokenRecord, String)> {
    if label.len() > 128 {
        bail!("备注过长（≤128 字符）");
    }
    if mode != "dedicated" && mode != "split" {
        bail!("未知的接入模式: {mode}");
    }
    if !["", "ro", "rules", "full"].contains(&admin_scope) {
        bail!("未知的管理授权档位: {admin_scope}");
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

    // federation P3 entrust mode: every E2E token carries its opaque entrust word as the FIRST
    // hint (en_<12 hex of token_hash>) — routing without rule disclosure; the issuer no longer
    // needs push_groups or advertise to serve E2E delegation. A caller-supplied or
    // advertise-derived legacy hint stays behind it as the old-client / old-relay fallback.
    let e2e_names: Vec<String> = group_ids
        .iter()
        .filter_map(|gid| db.get_group(gid).ok().flatten())
        .filter(|g| g.e2e_required)
        .map(|g| g.name)
        .collect();
    let mut hint_map = hint_map.to_vec();
    if !e2e_names.is_empty()
        && !hint_map
            .iter()
            .any(|h| h.hint.starts_with(agile_net_core::relay::e2e::ENTRUST_PREFIX))
    {
        hint_map.insert(
            0,
            HintEntry {
                hint: agile_net_core::relay::e2e::entrust_id_of(&token_hash),
                groups: e2e_names,
            },
        );
    }
    // a bootstrap ticket must never cross a relay in plaintext — admin requires the E2E channel
    // (evaluated after the entrust prepend: any e2e_required group satisfies it)
    if !admin_scope.is_empty() && hint_map.is_empty() {
        bail!("授权管理要求引用组含端到端加密组（票据经 E2E 通道下发）");
    }

    let e2e_key = agile_net_core::relay::e2e::derive_key(&plaintext);
    let e2e_key_enc = db.encrypt_secret(&agile_net_core::util::base64_encode(&e2e_key))?;
    let groups_json = serde_json::to_string(group_ids)?;
    let hint_json = serde_json::to_string(&hint_map)?;
    let prefix: String = plaintext.chars().take(8).collect();

    let rec = db.create_delegated_token(
        &token_hash,
        &prefix,
        label,
        &groups_json,
        &hint_json,
        &e2e_key_enc,
        mode,
        admin_scope,
        None,
        None,
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
    /// Raw rule strings (the split-tier delivery vocabulary)
    rules: Vec<String>,
    e2e_required: bool,
}

/// One issued token in the E2E key cache.
struct KeyEntry {
    key: [u8; 32],
    /// Local group names the token may use (empty-sealed blobs inherit this set — a consumer
    /// client knows no group names and seals "all groups of my token")
    groups: Vec<String>,
    /// Admin capability ('' = data-plane only; ro/rules/full)
    admin_scope: String,
    /// Token label (ticket subject attribution)
    label: String,
    /// Token row id (usage flush back to the DB on cache rebuild)
    token_id: String,
    /// Token lifecycle (docs/todo/e2e.md §8): None = never expires / unlimited
    expires_at: Option<String>,
    max_uses: Option<i64>,
    /// Opens served (seeded from the DB on refresh, incremented in memory on the hot path)
    used_count: std::sync::Arc<std::sync::atomic::AtomicI64>,
}

impl KeyEntry {
    /// Lifecycle gate: an expired or exhausted token is refused on every enforcement path
    /// (registration sync also stops offering it upstream — this is the in-session backstop).
    fn alive(&self) -> bool {
        crate::db::expiry_active(self.expires_at.as_deref())
            && !crate::db::uses_exhausted(self.max_uses, self.used_count.load(std::sync::atomic::Ordering::Relaxed))
    }
}

/// Runtime wiring for admin-capable tokens (issuer API endpoint + upstream registry + ticket minter).
struct AdminRuntime {
    db: Database,
    control_api: std::sync::Arc<arc_swap::ArcSwapOption<(String, u16)>>,
    manageable: crate::relay_auth::ManageableRegistry,
}

/// In-memory delegation enforcement engine (federation P2/P3, issuer side).
///
/// Two hot-swappable caches, rebuilt from the DB on every relevant change (issue/revoke,
/// group/rule edit) — the data plane never touches the database on the Open hot path:
/// - `keys`: kid -> E2E master key + group set of every issued delegated token (E2E unwrap);
/// - `groups`: local group name -> compiled rules + e2e_required flag (per-open enforcement
///   and the fail-close check).
#[derive(Default)]
pub struct DelegationEngine {
    keys: arc_swap::ArcSwap<std::collections::HashMap<String, KeyEntry>>,
    groups: arc_swap::ArcSwap<std::collections::HashMap<String, std::sync::Arc<GroupEntry>>>,
    admin_runtime: arc_swap::ArcSwapOption<AdminRuntime>,
}

impl DelegationEngine {
    /// Empty engine (nothing unwraps, nothing enforces, nothing fails closed).
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::default())
    }

    /// Wire the admin runtime (issuer API endpoint + upstream registry + ticket minter);
    /// called once at service assembly. Without it, admin-capable tokens stay data-plane only.
    pub fn set_admin_runtime(
        &self,
        db: Database,
        control_api: std::sync::Arc<arc_swap::ArcSwapOption<(String, u16)>>,
        manageable: crate::relay_auth::ManageableRegistry,
    ) {
        self.admin_runtime.store(Some(std::sync::Arc::new(AdminRuntime {
            db,
            control_api,
            manageable,
        })));
    }

    /// Rebuild the kid -> E2E key cache from the DB (call on issue/revoke and at startup).
    pub fn refresh_keys(&self, db: &Database) {
        // persist the current usage counters before swapping the map (best-effort restart
        // continuity for max_uses — the in-memory counter is authoritative during runtime)
        {
            let old = self.keys.load();
            for entry in old.values() {
                let n = entry.used_count.load(std::sync::atomic::Ordering::Relaxed);
                let _ = db.set_delegated_token_used(&entry.token_id, n);
            }
        }
        let mut map = std::collections::HashMap::new();
        for rec in db.list_delegated_tokens().unwrap_or_default() {
            match e2e_key_of(db, &rec) {
                Ok(key) => {
                    // resolve the token's group IDs to names once (empty-sealed blobs inherit them)
                    let group_ids: Vec<String> = serde_json::from_str(&rec.groups).unwrap_or_default();
                    let groups = group_ids
                        .iter()
                        .filter_map(|gid| db.get_group(gid).ok().flatten().map(|g| g.name))
                        .collect();
                    map.insert(
                        agile_net_core::relay::e2e::kid_of(&rec.token_hash).to_string(),
                        KeyEntry {
                            key,
                            groups,
                            admin_scope: rec.admin_scope.clone(),
                            label: rec.label.clone(),
                            token_id: rec.id.clone(),
                            expires_at: rec.expires_at.clone(),
                            max_uses: rec.max_uses,
                            used_count: std::sync::Arc::new(std::sync::atomic::AtomicI64::new(rec.used_count)),
                        },
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
                    rules,
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
        let Some(entry) = cache.get(&e2e.kid) else {
            return Ok(None); // transit role: not our token
        };
        // token lifecycle gate (expired / usage cap reached — the in-session backstop of the
        // registration sync's dead-token skip)
        if !entry.alive() {
            return Err(agile_net_core::error::Error::Other(
                "delegated token expired or exhausted".into(),
            ));
        }
        let (mut payload, cipher) = agile_net_core::relay::e2e::open_open(&entry.key, e2e)?;
        entry
            .used_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // an empty sealed group set means "all groups of my token" — the consumer client
        // knows no group names; inherit the token's set for local enforcement
        if payload.groups.is_empty() {
            payload.groups = entry.groups.clone();
        }
        Ok(Some((payload, cipher)))
    }

    fn delegation_config(&self, kid: &str) -> Option<agile_net_core::relay::DelegationConfig> {
        use agile_net_core::relay::{DelegationAdmin, DelegationConfig, DelegationUpstream};
        let keys = self.keys.load();
        let entry = keys.get(kid)?;
        if !entry.alive() {
            return None; // dead tokens pull no vocabulary / tickets
        }
        let groups = self.groups.load();
        let mut rules: Vec<String> = Vec::new();
        for name in &entry.groups {
            if let Some(g) = groups.get(name) {
                for r in &g.rules {
                    if !rules.contains(r) {
                        rules.push(r.clone());
                    }
                }
            }
        }
        let mut cfg = DelegationConfig {
            rules,
            ..Default::default()
        };
        if !entry.admin_scope.is_empty()
            && let Some(rt) = self.admin_runtime.load_full()
        {
            if let Some(port) = rt.control_api.load().as_ref().map(|a| a.1) {
                // a fresh bootstrap ticket per config pull (per fan-out session); the exchange
                // on the issuer API attributes the session to deleg:<label>@<kid>
                // (kind stays 'relay' — the admin_ticket CHECK constraint only allows account/relay;
                // the deleg: subject prefix carries the attribution)
                let subject = format!("deleg:{}@{}", entry.label, &kid[..8.min(kid.len())]);
                if let Ok(ticket) = rt.db.create_admin_ticket(
                    "relay",
                    &subject,
                    &entry.admin_scope,
                    crate::relay_auth::RELAY_TICKET_MAX_USES,
                    crate::relay_auth::RELAY_TICKET_TTL_SECS,
                ) {
                    cfg.admin = Some(DelegationAdmin { ticket, port });
                } else {
                    tracing::warn!(kid, "delegated admin ticket mint failed");
                }
            }
            // transit management: full-scope tokens additionally receive the discovered
            // upstream offers (tickets rotate with the issuer's own fan-out handshakes)
            if entry.admin_scope == "full" {
                cfg.upstreams = rt
                    .manageable
                    .iter()
                    .map(|o| {
                        let v = o.value();
                        DelegationUpstream {
                            node_name: v.node_name.clone(),
                            ticket: v.ticket.clone(),
                            api_host: v.api_host.clone().unwrap_or_default(),
                            api_port: v.api_port,
                            scope: v.scope.clone(),
                        }
                    })
                    .collect();
            }
        }
        Some(cfg)
    }

    fn delegation_admin_port(&self, kid: &str) -> Option<u16> {
        let keys = self.keys.load();
        let entry = keys.get(kid)?;
        if entry.admin_scope.is_empty() || !entry.alive() {
            return None;
        }
        let rt = self.admin_runtime.load_full()?;
        rt.control_api.load().as_ref().map(|a| a.1)
    }

    fn delegation_upstream(
        &self,
        kid: &str,
        node_name: &str,
    ) -> Option<agile_net_core::relay::DelegationUpstream> {
        let keys = self.keys.load();
        let entry = keys.get(kid)?;
        if entry.admin_scope != "full" || !entry.alive() {
            return None;
        }
        let rt = self.admin_runtime.load_full()?;
        let o = rt.manageable.get(node_name)?;
        let v = o.value();
        Some(agile_net_core::relay::DelegationUpstream {
            node_name: v.node_name.clone(),
            ticket: v.ticket.clone(),
            api_host: v.api_host.clone().unwrap_or_default(),
            api_port: v.api_port,
            scope: v.scope.clone(),
        })
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

        let (rec, plaintext) = issue_token(&db, "alice", std::slice::from_ref(&gid), &[], &[(cid.clone(), true)], "dedicated", "").unwrap();
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
        assert!(issue_token(&db, "a", &[gid.clone()], &[], &[], "dedicated", "").is_err());
        // no primary entry
        assert!(issue_token(&db, "a", &[gid.clone()], &[], &[(cid.clone(), false)], "dedicated", "").is_err());
        // missing group
        assert!(issue_token(&db, "a", &["no-such-group".into()], &[], &[(cid.clone(), true)], "dedicated", "").is_err());
        // missing connector
        assert!(issue_token(&db, "a", &[gid.clone()], &[], &[("no-such-conn".into(), true)], "dedicated", "").is_err());
        // oversized label
        assert!(issue_token(&db, &"x".repeat(200), &[gid], &[], &[(cid, true)], "dedicated", "").is_err());
    }

    #[test]
    fn engine_delegation_rules_unions_token_vocabulary() {
        let db = Database::in_memory().unwrap();
        let g1 = mk_group(&db, "git");
        let g2 = mk_group(&db, "ops");
        let r1 = db.create_rule("ip-cidr", "10.12.0.0/16", false, "").unwrap().id;
        let r2 = db.create_rule("host", "*.internal", false, "").unwrap().id;
        db.set_group_rules(&g1, &[r1.clone(), r2]).unwrap();
        db.set_group_rules(&g2, &[r1]).unwrap(); // same value bound to both groups -> dedup
        let cid = mk_connector(&db, "up-1");
        let (rec, _) = issue_token(&db, "alice", &[g1, g2], &[], &[(cid, true)], "dedicated", "").unwrap();

        let engine = DelegationEngine::new();
        engine.refresh_keys(&db);
        engine.refresh_groups(&db);
        use agile_net_core::relay::DelegationHooks;
        let kid = agile_net_core::relay::e2e::kid_of(&rec.token_hash).to_string();
        let rules = engine.delegation_config(&kid).expect("known kid").rules;
        assert!(rules.contains(&"10.12.0.0/16".to_string()));
        assert!(rules.contains(&"*.internal".to_string()));
        assert_eq!(rules.len(), 2, "values deduped: {rules:?}");
        assert!(engine.delegation_config("deadbeef").is_none());
    }

    #[test]
    fn engine_admin_config_ticket_and_scope() {
        let db = Database::in_memory().unwrap();
        let gid = mk_group(&db, "db-fine");
        let cid = mk_connector(&db, "up-1");
        let (rec, _) = issue_token(
            &db,
            "root-laptop",
            &[gid],
            &[HintEntry { hint: "relay.internal".into(), groups: vec!["db-fine".into()] }],
            &[(cid, true)],
            "dedicated",
            "full",
        )
        .unwrap();
        let engine = DelegationEngine::new();
        engine.refresh_keys(&db);
        engine.refresh_groups(&db);
        let slot = std::sync::Arc::new(arc_swap::ArcSwapOption::from_pointee(Some((
            "127.0.0.1".to_string(),
            59999u16,
        ))));
        engine.set_admin_runtime(db.clone(), slot, Default::default());
        use agile_net_core::relay::DelegationHooks;
        let kid = agile_net_core::relay::e2e::kid_of(&rec.token_hash).to_string();
        let cfg = engine.delegation_config(&kid).expect("config");
        let admin = cfg.admin.expect("admin capability");
        assert_eq!(admin.port, 59999);
        assert!(admin.ticket.starts_with("adt_"));
        assert_eq!(engine.delegation_admin_port(&kid), Some(59999));
    }

    #[test]
    fn register_msg_resolves_group_names_and_skips_dangling() {
        let db = Database::in_memory().unwrap();
        let g1 = mk_group(&db, "git");
        let g2 = mk_group(&db, "ops");
        let cid = mk_connector(&db, "up-1");
        let (rec, _) = issue_token(&db, "alice", &[g1.clone(), g2.clone()], &[], &[(cid, true)], "dedicated", "").unwrap();

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
        let (rec, _) = issue_token(&db, "alice", &[gid], &[], &[(cid, true)], "dedicated", "").unwrap();

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
        let (rec, plaintext) = issue_token(&db, "alice", &[gid], &[], &[(cid, true)], "dedicated", "").unwrap();

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

    #[test]
    fn engine_token_lifecycle_gate() {
        use agile_net_core::relay::DelegationHooks;
        use agile_net_core::relay::e2e::{derive_key, kid_of, seal_open};

        let db = Database::in_memory().unwrap();
        let gid = mk_group(&db, "db-prod");
        let cid = mk_connector(&db, "up-1");
        let (rec, plaintext) = issue_token(&db, "alice", &[gid], &[], &[(cid, true)], "dedicated", "").unwrap();
        let key = derive_key(&plaintext);
        let seal = || {
            seal_open(&key, kid_of(&rec.token_hash), "h", "10.2.0.5", 5432, &[]).0
        };

        // expired token: unwrap hard-rejects (OpenFail), config channel closed
        db.set_delegated_token_lifecycle(&rec.id, Some("2020-01-01T00:00:00Z"), None).unwrap();
        let engine = DelegationEngine::new();
        engine.refresh_keys(&db);
        assert!(engine.e2e_unwrap(&seal()).is_err());
        assert!(engine.delegation_config(kid_of(&rec.token_hash)).is_none());

        // future window: alive
        let future = (chrono::Utc::now() + chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        db.set_delegated_token_lifecycle(&rec.id, Some(&future), None).unwrap();
        engine.refresh_keys(&db);
        assert!(engine.e2e_unwrap(&seal()).unwrap().is_some());

        // usage cap 2: one use was already counted above (flushed on refresh) — one open
        // passes, the next is rejected (in-memory counting on the hot path)
        db.set_delegated_token_lifecycle(&rec.id, None, Some(2)).unwrap();
        engine.refresh_keys(&db);
        assert!(engine.e2e_unwrap(&seal()).unwrap().is_some());
        assert!(engine.e2e_unwrap(&seal()).is_err());

        // the refresh flushes counters back to the DB (restart continuity)
        engine.refresh_keys(&db);
        let rec2 = db.get_delegated_token(&rec.id).unwrap().unwrap();
        assert_eq!(rec2.used_count, 2, "usage flushed to the DB on refresh");
    }
}
