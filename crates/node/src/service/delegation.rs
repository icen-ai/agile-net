//! Delegated token issuance and fan-out session registration (unified issuance, issuer side).
//!
//! Storage discipline mirrors relay tokens: the plaintext (`psk_` + 48 chars) is returned once
//! at issuance; the DB holds the SHA-256 hash only. The E2E master key (federation P3,
//! HKDF(token)) is derived at issuance and stored AES-256-GCM encrypted — the second and last
//! reversible-storage exception, same machine key as connector tokens (never logged/audited).
//!
//! Entry modes: `relay` tokens ride the disaster set (registered upstream over each fan-out
//! session, revoke-by-disconnect); `direct` tokens are dialed at this issuer's own listener and
//! self-registered into the listener's delegated registry (see `sync_local_direct`).

use crate::db::models::DelegatedTokenRecord;
use crate::db::{Database, generate_relay_token, sha256_hex};
use agile_net_core::proto::message::{Concurrency, CtrlMessage, HintEntry};
use agile_net_core::relay::{DelegatedRegistry, DelegatedToken};
use anyhow::{Result, bail};

/// DB string -> wire enum (unknown values fail closed to the stricter `Single` tier).
pub(crate) fn concurrency_of(s: &str) -> Concurrency {
    match s {
        "multi" => Concurrency::Multi,
        _ => Concurrency::Single,
    }
}

/// Issue a delegated token and set its disaster set (one row per upstream connector).
/// Returns the record, the plaintext (shown once, inside the share link), and the E2E master key
/// (base64; carried in the share link's `ek` word — never sent through the relay).
///
/// `entry_mode`: `relay` = registered upstream via the disaster set (`regs` must be non-empty
/// with exactly one primary); `direct` = the consumer dials this issuer's own listener (`regs`
/// may be empty). `concurrency`: `single` (a new session kicks the old) / `multi` (bounded by
/// `max_sessions`, snapshotted by the caller from node_config.delegation_max_sessions).
#[allow(clippy::too_many_arguments)]
pub fn issue_token(
    db: &Database,
    label: &str,
    group_ids: &[String],
    regs: &[(String, bool)],
    mode: &str,
    admin_scope: &str,
    entry_mode: &str,
    concurrency: &str,
    max_sessions: i64,
) -> Result<(DelegatedTokenRecord, String, String)> {
    if label.len() > 128 {
        bail!("备注过长（≤128 字符）");
    }
    if mode != "dedicated" && mode != "split" {
        bail!("未知的接入模式: {mode}");
    }
    if !["", "ro", "rules", "full"].contains(&admin_scope) {
        bail!("未知的管理授权档位: {admin_scope}");
    }
    if entry_mode != "direct" && entry_mode != "relay" {
        bail!("未知的入口模式: {entry_mode}");
    }
    if concurrency != "single" && concurrency != "multi" {
        bail!("未知的并发档位: {concurrency}");
    }
    if max_sessions < 1 {
        bail!("并发上限必须 ≥ 1");
    }
    if entry_mode == "relay" {
        if regs.is_empty() {
            bail!("容灾集合不能为空（至少选择一个扇出上游）");
        }
        if !regs.iter().any(|r| r.1) {
            bail!("必须指定一个主入口");
        }
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

    // federation P3 entrust mode: an E2E token carries exactly one hint — its opaque entrust
    // word (en_<12 hex of token_hash>), routing without rule disclosure; the issuer needs no
    // push_groups or advertise to serve E2E delegation. The transparent tier (no e2e_required
    // group) carries no routing vocabulary at all.
    let e2e_names: Vec<String> = group_ids
        .iter()
        .filter_map(|gid| db.get_group(gid).ok().flatten())
        .filter(|g| g.e2e_required)
        .map(|g| g.name)
        .collect();
    let hint_map: Vec<HintEntry> = if e2e_names.is_empty() {
        Vec::new()
    } else {
        vec![HintEntry {
            hint: agile_net_core::relay::e2e::entrust_id_of(&token_hash),
            groups: e2e_names,
        }]
    };
    // a bootstrap ticket must never cross a relay in plaintext — admin requires the E2E channel
    if !admin_scope.is_empty() && hint_map.is_empty() {
        bail!("授权管理要求引用组含端到端加密组（票据经 E2E 通道下发）");
    }
    // audit F15: the E2E envelope terminates on the fan-out session (DelegationHooks live on
    // the connector); a direct-entry consumer's sealed Open would dead-end at this issuer's
    // own listener (no keys there) — reject at issuance instead of issuing a broken token
    if entry_mode == "direct" && !hint_map.is_empty() {
        bail!("直连入口不支持端到端组（E2E 信封终结于扇出会话；如需 E2E/管理档请选 relay 入口）");
    }

    // The E2E master key is random and independent of the auth token: a relay authenticates the
    // consumer with the token plaintext, so deriving the E2E key from it would let the relay
    // decrypt every envelope it forwards. The key reaches the consumer only via the share link.
    let e2e_key = agile_net_core::relay::e2e::random_key();
    let e2e_key_b64 = agile_net_core::util::base64_encode(&e2e_key);
    let e2e_key_enc = db.encrypt_secret(&e2e_key_b64)?;
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
        entry_mode,
        concurrency,
        max_sessions,
        None,
        None,
    )?;
    db.set_delegated_token_regs(&rec.id, regs)?;
    let rec = db.get_delegated_token(&rec.id)?.expect("just created");
    Ok((rec, plaintext, e2e_key_b64))
}

/// Delete a delegated token; returns the record (with regs) so the caller can send the
/// revocation frame to every online upstream of the disaster set (relay mode) or drop the
/// local registration (direct mode).
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
        concurrency: concurrency_of(&rec.concurrency),
        max_sessions: rec.max_sessions.clamp(1, u32::MAX as i64) as u32,
    }
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

// ==================== Direct-entry local self-registration ====================

/// Reconcile the direct-entry tokens of this issuer into the listener's persistent local
/// delegated registry (idempotent full sync: startup warm-up plus the incremental
/// issue/revoke path).
///
/// The local registry (`RelayListener::local_delegated_registry()`) is owned exclusively by
/// this node layer — entries never die with any session and the listener consults it before
/// the session-scoped registry at auth and route resolution. The sync therefore converges the
/// whole map to the live direct-entry set: expired/exhausted tokens and revoked rows drop out,
/// group/rule edits re-enter with a fresh ACL snapshot.
pub fn sync_local_direct(registry: &DelegatedRegistry, node_id: &str, db: &Database) {
    let mut desired = std::collections::HashSet::new();
    for rec in db.list_delegated_tokens().unwrap_or_default() {
        if rec.entry_mode != "direct" {
            continue;
        }
        // token lifecycle: a dead token is never registered (the engine's in-session gate
        // refuses its opens as the backstop)
        if !crate::db::expiry_active(rec.expires_at.as_deref())
            || crate::db::uses_exhausted(rec.max_uses, rec.used_count)
        {
            continue;
        }
        desired.insert(rec.token_hash.clone());
        registry.insert(rec.token_hash.clone(), local_entry(node_id, &rec, db));
    }
    // drop stale entries (revoked / expired / switched entry mode)
    let stale: Vec<String> = registry
        .iter()
        .filter(|e| !desired.contains(e.key()))
        .map(|e| e.key().clone())
        .collect();
    for hash in stale {
        registry.remove(&hash);
    }
}

/// One local registry entry for a direct-entry token: group IDs resolve to names, the
/// transparent-tier ACL snapshot is the union of the token's group rules (mirroring the
/// relay-side registration semantics); the concurrency policy is enforced by the listener
/// at consumer-session auth.
fn local_entry(node_id: &str, rec: &DelegatedTokenRecord, db: &Database) -> DelegatedToken {
    let group_ids: Vec<String> = serde_json::from_str(&rec.groups).unwrap_or_default();
    let mut groups = Vec::with_capacity(group_ids.len());
    let mut acl_rules: Vec<String> = Vec::new();
    for gid in &group_ids {
        match db.get_group(gid) {
            Ok(Some(g)) => groups.push(g.name),
            _ => tracing::warn!(group_id = %gid, token = %rec.id, "direct token references a missing group (skipped)"),
        }
        if let Ok(rs) = db.rules_of_group(gid) {
            for r in rs {
                if !acl_rules.contains(&r.value) {
                    acl_rules.push(r.value);
                }
            }
        }
    }
    DelegatedToken {
        issuer: node_id.to_string(),
        label: rec.label.clone(),
        groups,
        acl_rules,
        hint_map: serde_json::from_str(&rec.hint_map).unwrap_or_default(),
        concurrency: concurrency_of(&rec.concurrency),
        max_sessions: rec.max_sessions.clamp(1, u32::MAX as i64) as u32,
    }
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
    /// Anti cross-channel replay (audit F1): chan_salts already consumed by a successful
    /// unwrap. A sealed Open is one-shot — the same envelope forwarded again by a malicious
    /// relay would otherwise derive the same chan_key and accept a replayed record stream on
    /// a fresh channel whose sequence numbers start over. 128-bit random salts make legit
    /// collisions impossible; the cap bounds memory and fails closed.
    seen_salts: std::sync::Mutex<std::collections::HashSet<[u8; agile_net_core::relay::e2e::CHAN_SALT_LEN]>>,
    /// Anti-correlation padding grain (trust profile G1②): delegated_token.anti_correlate →
    /// PAD_BUCKET on the unwrap cipher (both ends derive the grain from the same flag).
    bucket: usize,
}

/// Per-token consumed-salt cap (audit F1): a token can never legitimately approach this many
/// distinct channels (sessions ≤ max_sessions ≤ 1024 × channels ≤ 1024/session is the absolute
/// theoretical ceiling; practical use is orders of magnitude below). Overflow fails closed.
const MAX_E2E_CHANNEL_SALTS: usize = 65536;

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
    /// Device certification gate cache (node.md M3-T2; wired at service assembly)
    device_gate: arc_swap::ArcSwapOption<super::device_gate::DeviceGateCache>,
    /// Relay-entry consumer sessions reported upstream by relays (federation P2 visibility):
    /// token_hash -> live consumer sessions as seen by the relay. Event-driven upsert/remove +
    /// periodic full-snapshot reconciliation. Surfaced to the issuance panel + /admin/sessions so
    /// the issuer sees who is connected through a relay it does not terminate locally.
    reported_sessions:
        arc_swap::ArcSwap<std::collections::HashMap<String, Vec<agile_net_core::proto::message::ConsumerSessionInfo>>>,
    /// The issuer's own node name (node_config.node_name), surfaced to consumers over the config
    /// channel as a "source" hint so they know which node a link terminates at.
    node_name: arc_swap::ArcSwapOption<String>,
}

impl DelegationEngine {
    /// Empty engine (nothing unwraps, nothing enforces, nothing fails closed).
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::default())
    }

    /// kid lookup: cache keys are exactly the 12-hex kid of the token hash (protocol v4);
    /// anything else (including legacy 8-char prefixes) fails closed.
    fn key_entry<'a>(
        cache: &'a std::collections::HashMap<String, KeyEntry>,
        kid: &str,
    ) -> Option<&'a KeyEntry> {
        if kid.len() != 12 || !kid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        cache.get(kid)
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

    /// Wire the device certification gate (node.md M3-T2): the issuer-side enforcement for
    /// relay-entry consumer opens (direct-entry opens are gated at the listener).
    pub fn set_device_gate(&self, gate: std::sync::Arc<super::device_gate::DeviceGateCache>) {
        self.device_gate.store(Some(gate));
    }

    /// Wire the issuer's own node name (surfaced to consumers over the config channel).
    pub fn set_node_name(&self, name: String) {
        self.node_name.store(Some(std::sync::Arc::new(name)));
    }

    /// Snapshot of relay-reported consumer sessions keyed by token_hash (federation P2 visibility).
    /// Used by the session inventory API to show relay-entry consumers on the issuance panel.
    pub fn reported_sessions(
        &self,
    ) -> std::sync::Arc<
        std::collections::HashMap<String, Vec<agile_net_core::proto::message::ConsumerSessionInfo>>,
    > {
        self.reported_sessions.load_full()
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
        let names_by_id = db.group_names_by_id().unwrap_or_default();
        for rec in db.list_delegated_tokens().unwrap_or_default() {
            match e2e_key_of(db, &rec) {
                Ok(key) => {
                    // resolve the token's group IDs to names once (empty-sealed blobs inherit them)
                    let group_ids: Vec<String> = serde_json::from_str(&rec.groups).unwrap_or_default();
                    let groups = group_ids
                        .iter()
                        .filter_map(|gid| names_by_id.get(gid).cloned())
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
                            seen_salts: std::sync::Mutex::new(std::collections::HashSet::new()),
                            bucket: if rec.anti_correlate {
                                agile_net_core::relay::e2e::PAD_BUCKET
                            } else {
                                0
                            },
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
        let (groups, _) = db.list_groups(1, 10000, None, None).unwrap_or_default();
        // One bulk fetch for all group→rules bindings (avoids an N+1 per-group query).
        let rules_by_group = db.rules_by_group_all().unwrap_or_default();
        for g in groups {
            let rules: Vec<String> = rules_by_group.get(&g.id).cloned().unwrap_or_default();
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
    /// Device certification gate (node.md M3-T2): relay-entry consumer opens arrive with the
    /// relay-stamped proven device_fp; answer from the local device registry (fail closed).
    fn device_open_gate(
        &self,
        _kid: Option<&str>,
        device_fp: &str,
    ) -> agile_net_core::relay::listener::DeviceGate {
        let Some(cache) = self.device_gate.load_full() else {
            return agile_net_core::relay::listener::DeviceGate::Allow;
        };
        cache.gate()(device_fp).0
    }

    /// Pending-session appeal forwarded by a relay: file onto the device's certification
    /// approval item (created on demand; the DB enforces the ≤3 cap).
    fn pending_note(&self, device_fp: &str, _session_key: &str, body: &str) {
        let Some(rt) = self.admin_runtime.load_full() else {
            return;
        };
        if let Some(id) = super::approvals::ensure_device_certify_approval(&rt.db, device_fp) {
            let _ = rt.db.add_approval_message(&id, "appeal", body);
        }
    }

    /// Relay-side consumer session state report (federation P2 visibility): maintain the
    /// `reported_sessions` cache so the issuance panel + /admin/sessions show relay-entry
    /// consumers. Event-driven online/offline upsert/remove + periodic snapshot reconciliation.
    fn consumer_session_report(
        &self,
        kind: &str,
        token_hash: &str,
        info: &agile_net_core::proto::message::ConsumerSessionInfo,
        sessions: &[agile_net_core::proto::message::ConsumerSessionInfo],
    ) {
        match kind {
            "online" => {
                let cur = self.reported_sessions.load();
                let mut map: std::collections::HashMap<_, _> = (**cur).clone();
                let entry = map.entry(token_hash.to_string()).or_default();
                // upsert by session_id (stable across reports)
                if let Some(existing) = entry.iter_mut().find(|s| s.session_id == info.session_id) {
                    *existing = info.clone();
                } else {
                    entry.push(info.clone());
                }
                self.reported_sessions.store(std::sync::Arc::new(map));
            }
            "offline" => {
                let cur = self.reported_sessions.load();
                let mut map: std::collections::HashMap<_, _> = (**cur).clone();
                if let Some(entry) = map.get_mut(token_hash) {
                    entry.retain(|s| s.session_id != info.session_id);
                    if entry.is_empty() {
                        map.remove(token_hash);
                    }
                }
                self.reported_sessions.store(std::sync::Arc::new(map));
            }
            "snapshot" => {
                let cur = self.reported_sessions.load();
                let mut map: std::collections::HashMap<_, _> = (**cur).clone();
                if sessions.is_empty() {
                    map.remove(token_hash);
                } else {
                    map.insert(token_hash.to_string(), sessions.to_vec());
                }
                self.reported_sessions.store(std::sync::Arc::new(map));
            }
            _ => {}
        }
    }

    /// One-time admin notice for a gated device (reject/decision note; take-on-read).
    fn device_notice(&self, _kid: Option<&str>, device_fp: &str) -> Option<String> {
        let rt = self.admin_runtime.load_full()?;
        rt.db.take_device_notice(device_fp).ok().flatten()
    }

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
        let Some(entry) = Self::key_entry(&cache, &e2e.kid) else {
            return Ok(None); // transit role: not our token
        };
        // token lifecycle gate (expired / usage cap reached — the in-session backstop of the
        // registration sync's dead-token skip)
        if !entry.alive() {
            return Err(agile_net_core::error::Error::Other(
                "delegated token expired or exhausted".into(),
            ));
        }
        let (mut payload, cipher) =
            agile_net_core::relay::e2e::open_open(&entry.key, e2e, entry.bucket)?;
        // one-shot envelope (audit F1): consume the chan_salt before anything else — a
        // replayed Open (same sealed blob) or a salt-window overflow rejects hard, so a
        // malicious relay can never re-derive a live chan_key from captured ciphertext
        {
            let Some(salt) = agile_net_core::util::base64_decode(&payload.chan_salt)
                .and_then(|raw| <[u8; agile_net_core::relay::e2e::CHAN_SALT_LEN]>::try_from(raw.as_slice()).ok())
            else {
                return Err(agile_net_core::error::Error::Protocol("invalid chan_salt".into()));
            };
            let mut seen = entry.seen_salts.lock().unwrap_or_else(|e| e.into_inner());
            if seen.len() >= MAX_E2E_CHANNEL_SALTS {
                return Err(agile_net_core::error::Error::Other(
                    "e2e channel-salt window exhausted".into(),
                ));
            }
            if !seen.insert(salt) {
                return Err(agile_net_core::error::Error::Auth(
                    "e2e envelope replayed (chan_salt reuse)".into(),
                ));
            }
        }
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
        let entry = Self::key_entry(&keys, kid)?;
        if !entry.alive() {
            return None; // dead tokens pull no vocabulary / tickets
        }
        let groups = self.groups.load();
        let mut rules: Vec<String> = Vec::new();
        let mut group_entries: Vec<agile_net_core::relay::DelegationGroupEntry> = Vec::new();
        for name in &entry.groups {
            if let Some(g) = groups.get(name) {
                // named breakdown (§7.2.1): the consumer seals per-target group identities
                group_entries.push(agile_net_core::relay::DelegationGroupEntry {
                    name: name.clone(),
                    rules: g.rules.clone(),
                });
                for r in &g.rules {
                    if !rules.contains(r) {
                        rules.push(r.clone());
                    }
                }
            }
        }
        let mut cfg = DelegationConfig {
            rules,
            groups: group_entries,
            issuer_node_name: self
                .node_name
                .load()
                .as_ref()
                .map(|s| (**s).clone())
                .unwrap_or_default(),
            ..Default::default()
        };
        if !entry.admin_scope.is_empty()
            && let Some(rt) = self.admin_runtime.load_full()
        {
            if let Some(port) = rt.control_api.load().as_ref().map(|a| a.1) {
                // a fresh bootstrap ticket per config pull (per fan-out session); the exchange
                // on the issuer API attributes the session to deleg:<label>@<kid>
                // (kind stays 'relay' — the admin_ticket CHECK constraint only allows relay;
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
        let entry = Self::key_entry(&keys, kid)?;
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
        let entry = Self::key_entry(&keys, kid)?;
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

    fn mk_e2e_group(db: &Database, name: &str) -> String {
        let gid = mk_group(db, name);
        db.set_group_e2e_required(&gid, true).expect("mark e2e");
        gid
    }

    fn mk_connector(db: &Database, name: &str) -> String {
        db.create_connector(name, "", "1.2.3.4:54430", "psk_x", "", true, "", "", "", "", None, "")
            .expect("connector")
            .id
    }

    /// Issue a relay-mode token with a single-entry disaster set.
    fn issue_relay(db: &Database, label: &str, group_ids: &[String], admin_scope: &str) -> (DelegatedTokenRecord, String, String) {
        let cid = mk_connector(db, &format!("up-{label}"));
        issue_token(db, label, group_ids, &[(cid, true)], "dedicated", admin_scope, "relay", "single", 8)
            .expect("issue relay token")
    }

    #[test]
    fn issue_stores_hash_and_recoverable_e2e_key() {
        let db = Database::in_memory().unwrap();
        let gid = mk_group(&db, "git");

        let (rec, plaintext, ek_b64) = issue_relay(&db, "alice", std::slice::from_ref(&gid), "");
        assert!(plaintext.starts_with("psk_"));
        assert_eq!(plaintext.len(), 4 + 48);
        assert_eq!(rec.token_prefix, plaintext[..8]);
        // DB holds the hash, never the plaintext
        assert_eq!(rec.token_hash, sha256_hex(plaintext.as_bytes()));
        assert_ne!(rec.e2e_key_enc, plaintext);
        // The E2E key is random (NOT derivable from the token) and round-trips through the link's base64 word
        let key = e2e_key_of(&db, &rec).unwrap();
        assert_eq!(
            agile_net_core::relay::e2e::key_from_b64(&ek_b64),
            Some(key)
        );
        assert_ne!(key, agile_net_core::util::sha256_hex(plaintext.as_bytes()).as_bytes()[..32]);
        // disaster set persisted with the primary flag
        assert_eq!(rec.regs.len(), 1);
        assert!(rec.regs[0].is_primary);
        // unified-issuance fields
        assert_eq!(rec.entry_mode, "relay");
        assert_eq!(rec.concurrency, "single");
        assert_eq!(rec.max_sessions, 8);
        // transparent tier (no e2e group): no routing vocabulary at all
        assert_eq!(rec.hint_map, "[]");
    }

    #[test]
    fn issue_validates_inputs() {
        let db = Database::in_memory().unwrap();
        let gid = mk_group(&db, "git");
        let cid = mk_connector(&db, "up-1");

        // relay mode: empty disaster set
        assert!(issue_token(&db, "a", std::slice::from_ref(&gid), &[], "dedicated", "", "relay", "single", 8).is_err());
        // relay mode: no primary entry
        assert!(issue_token(&db, "a", std::slice::from_ref(&gid), &[(cid.clone(), false)], "dedicated", "", "relay", "single", 8).is_err());
        // missing group
        assert!(issue_token(&db, "a", &["no-such-group".into()], &[(cid.clone(), true)], "dedicated", "", "relay", "single", 8).is_err());
        // missing connector
        assert!(issue_token(&db, "a", std::slice::from_ref(&gid), &[("no-such-conn".into(), true)], "dedicated", "", "relay", "single", 8).is_err());
        // oversized label
        assert!(issue_token(&db, &"x".repeat(200), std::slice::from_ref(&gid), &[(cid.clone(), true)], "dedicated", "", "relay", "single", 8).is_err());
        // unknown entry mode / concurrency / bad cap
        assert!(issue_token(&db, "a", std::slice::from_ref(&gid), &[(cid.clone(), true)], "dedicated", "", "wormhole", "single", 8).is_err());
        assert!(issue_token(&db, "a", std::slice::from_ref(&gid), &[(cid.clone(), true)], "dedicated", "", "relay", "plenty", 8).is_err());
        assert!(issue_token(&db, "a", std::slice::from_ref(&gid), &[(cid, true)], "dedicated", "", "relay", "single", 0).is_err());
        // admin without an e2e group
        assert!(issue_token(&db, "a", &[gid], &[], "dedicated", "ro", "direct", "single", 8).is_err());
    }

    #[test]
    fn issue_direct_allows_empty_regs() {
        let db = Database::in_memory().unwrap();
        let gid = mk_group(&db, "git");

        // direct mode: no disaster set needed
        let (rec, _, _) = issue_token(&db, "local-alice", &[gid], &[], "dedicated", "", "direct", "multi", 4)
            .expect("direct issue with empty regs");
        assert_eq!(rec.entry_mode, "direct");
        assert_eq!(rec.concurrency, "multi");
        assert_eq!(rec.max_sessions, 4);
        assert!(rec.regs.is_empty());
    }

    #[test]
    fn issue_e2e_group_carries_entrust_word_only() {
        let db = Database::in_memory().unwrap();
        let gid = mk_e2e_group(&db, "db-prod");

        let (rec, _, _) = issue_relay(&db, "e2e-alice", &[gid], "");
        let hints: Vec<HintEntry> = serde_json::from_str(&rec.hint_map).unwrap();
        assert_eq!(hints.len(), 1);
        assert_eq!(
            hints[0].hint,
            agile_net_core::relay::e2e::entrust_id_of(&rec.token_hash),
            "exactly the opaque entrust word, no legacy fallback hints"
        );
        assert_eq!(hints[0].groups, vec!["db-prod".to_string()]);
    }

    /// Audit F15: direct entry cannot serve E2E envelopes (termination lives on the fan-out
    /// session) — issuance must reject the combination instead of minting a dead token.
    #[test]
    fn issue_rejects_direct_entry_with_e2e_group() {
        let db = Database::in_memory().unwrap();
        let e2e_gid = mk_e2e_group(&db, "db-prod");

        // direct + an e2e_required group: rejected
        assert!(
            issue_token(&db, "bad", &[e2e_gid.clone()], &[], "dedicated", "", "direct", "single", 8).is_err(),
            "direct entry + e2e_required group must be rejected at issuance"
        );
        // direct + admin scope (implies an e2e group via the earlier check): rejected too
        assert!(
            issue_token(&db, "bad", &[e2e_gid], &[], "dedicated", "full", "direct", "single", 8).is_err()
        );
        // direct + transparent-only group stays legal
        let plain = mk_group(&db, "git");
        assert!(
            issue_token(&db, "ok", &[plain], &[], "dedicated", "", "direct", "single", 8).is_ok()
        );
    }

    /// Audit F1: a sealed E2E Open is one-shot — replaying the same envelope (identical
    /// chan_salt) must hard-fail at the issuer, while a freshly sealed open (new salt) passes.
    #[test]
    fn engine_e2e_envelope_is_one_shot() {
        use agile_net_core::relay::DelegationHooks;
        use agile_net_core::relay::e2e::{kid_of, seal_open};

        let db = Database::in_memory().unwrap();
        let gid = mk_group(&db, "db-prod");
        let (rec, _, _) = issue_relay(&db, "alice", &[gid], "");
        let key = e2e_key_of(&db, &rec).unwrap();
        let kid = kid_of(&rec.token_hash).to_string();

        let engine = DelegationEngine::new();
        engine.refresh_keys(&db);

        // first unwrap consumes the salt
        let (env, _) = seal_open(&key, &kid, "h", "10.2.0.5", 5432, &[], 0);
        assert!(engine.e2e_unwrap(&env).unwrap().is_some());

        // replaying the SAME sealed envelope (what a malicious relay captured) must fail
        let err = match engine.e2e_unwrap(&env) {
            Err(e) => e,
            Ok(_) => panic!("replayed envelope must be rejected"),
        };
        assert!(
            err.to_string().contains("replay"),
            "replayed envelope must be rejected as replay, got: {err}"
        );

        // a fresh open (client sealed a new channel with a new random salt) still passes
        let (env2, _) = seal_open(&key, &kid, "h", "10.2.0.5", 5432, &[], 0);
        assert!(engine.e2e_unwrap(&env2).unwrap().is_some());
    }

    #[test]
    fn sync_local_direct_reconciles_registry() {
        let db = Database::in_memory().unwrap();
        let gid = mk_group(&db, "git");
        let rid = db.create_rule("ip-cidr", "10.9.0.0/16", false, "").unwrap().id;
        db.set_group_rules(&gid, std::slice::from_ref(&rid)).unwrap();
        let registry: DelegatedRegistry = Default::default();

        // one direct token + one relay token: only the direct one self-registers
        let (direct, _, _) = issue_token(&db, "d1", std::slice::from_ref(&gid), &[], "dedicated", "", "direct", "single", 8).unwrap();
        let (_relay, _, _) = issue_relay(&db, "r1", std::slice::from_ref(&gid), "");
        sync_local_direct(&registry, "node-a", &db);
        assert!(registry.contains_key(&direct.token_hash));
        assert_eq!(registry.len(), 1);
        let entry = registry.get(&direct.token_hash).unwrap();
        assert_eq!(entry.issuer, "node-a");
        assert_eq!(entry.groups, vec!["git".to_string()]);
        assert_eq!(entry.acl_rules, vec!["10.9.0.0/16".to_string()]);
        drop(entry);

        // re-sync is idempotent; the map converges to the desired set (the local registry is
        // exclusively node-owned — anything not in the DB direct set drops out)
        registry.insert("ff".repeat(32), DelegatedToken {
            issuer: "other-node".into(),
            label: "foreign".into(),
            groups: vec![],
            acl_rules: vec![],
            hint_map: vec![],
            concurrency: Concurrency::Single,
            max_sessions: 8,
        });
        sync_local_direct(&registry, "node-a", &db);
        assert_eq!(registry.len(), 1);
        assert!(registry.contains_key(&direct.token_hash));

        // revoke the direct token -> the local entry drops out on the next sync
        revoke_token(&db, &direct.id).unwrap();
        sync_local_direct(&registry, "node-a", &db);
        assert!(registry.is_empty());

        // an expired direct token is never registered
        let (dead, _, _) = issue_token(&db, "d2", &[gid], &[], "dedicated", "", "direct", "single", 8).unwrap();
        db.set_delegated_token_lifecycle(&dead.id, Some("2020-01-01T00:00:00Z"), None).unwrap();
        sync_local_direct(&registry, "node-a", &db);
        assert!(!registry.contains_key(&dead.token_hash));
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
        let (rec, _, _) = issue_relay(&db, "alice", &[g1, g2], "");

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
        let gid = mk_e2e_group(&db, "db-fine");
        let (rec, _, _) = issue_relay(&db, "root-laptop", &[gid], "full");
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

    /// Trust profile G1②: anti_correlate makes the issuer unwrap with the padding bucket — a
    /// consumer sealing with PAD_BUCKET round-trips, a mismatched plain seal fails closed.
    #[test]
    fn engine_unwrap_pads_when_anti_correlate() {
        use agile_net_core::relay::DelegationHooks;
        use agile_net_core::relay::e2e::{PAD_BUCKET, kid_of, seal_open};

        let db = Database::in_memory().unwrap();
        let gid = mk_e2e_group(&db, "db-pad");
        let (rec, _, _) = issue_relay(&db, "padded-laptop", &[gid], "");
        // the API layer applies the tier right after issuance (same write path)
        db.set_delegated_token_anti_correlate(&rec.id, true).unwrap();

        let engine = DelegationEngine::new();
        engine.refresh_keys(&db);

        let key = e2e_key_of(&db, &rec).unwrap();
        // consumer seals with the bucket grain (Credential.padding -> PAD_BUCKET)
        let (env, mut sender) =
            seal_open(&key, kid_of(&rec.token_hash), "relay.internal", "10.2.0.5", 5432, &[], PAD_BUCKET);
        let (_, mut receiver) = engine.e2e_unwrap(&env).unwrap().expect("endpoint role");
        let rec_data = sender.seal(b"SELECT 1 FROM pad").unwrap();
        assert_eq!(
            (rec_data.len() - 4 - 16) % PAD_BUCKET,
            0,
            "issuer-side bucket mirrors the token flag (sealed body is bucket-aligned)"
        );
        assert_eq!(receiver.open(&rec_data[4..]).unwrap(), b"SELECT 1 FROM pad");

        // a plain (unpadded) consumer against the padded issuer fails closed on alignment
        let (plain_env, mut plain_sender) =
            seal_open(&key, kid_of(&rec.token_hash), "relay.internal", "10.2.0.5", 5432, &[], 0);
        let (_, mut padded_receiver) = engine.e2e_unwrap(&plain_env).unwrap().expect("unwrap");
        let plain_rec = plain_sender.seal(b"mismatch").unwrap();
        assert!(padded_receiver.open(&plain_rec[4..]).is_err(),
            "grain mismatch fails closed — both ends derive the grain from the same token flag");
    }

    #[test]
    fn register_msg_resolves_group_names_and_skips_dangling() {
        let db = Database::in_memory().unwrap();
        let g1 = mk_group(&db, "git");
        let g2 = mk_group(&db, "ops");
        let (rec, _, _) = issue_relay(&db, "alice", &[g1.clone(), g2.clone()], "");

        let msg = build_register_msg(&db, &rec);
        let CtrlMessage::TokenRegister { token_hash, label, groups, hint_map, concurrency, max_sessions } = msg else {
            panic!("expected TokenRegister");
        };
        assert_eq!(token_hash, rec.token_hash);
        assert_eq!(label, "alice");
        assert_eq!(groups, vec!["git".to_string(), "ops".to_string()]);
        assert!(hint_map.is_empty());
        assert_eq!(concurrency, Concurrency::Single);
        assert_eq!(max_sessions, 8);

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
        let (rec, _, _) = issue_relay(&db, "alice", &[gid], "");

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
        use agile_net_core::relay::e2e::{kid_of, random_key, seal_open};

        let db = Database::in_memory().unwrap();
        let gid = mk_group(&db, "db-prod");
        let (rec, _, _) = issue_relay(&db, "alice", &[gid], "");

        let engine = DelegationEngine::new();
        engine.refresh_keys(&db);

        let key = e2e_key_of(&db, &rec).unwrap();
        let (env, _cipher) = seal_open(
            &key,
            kid_of(&rec.token_hash),
            "relay.internal",
            "10.2.0.5",
            5432,
            &["db-prod".to_string()],
            0,
        );

        // endpoint role: our kid unwraps
        let (payload, _cipher) = engine.e2e_unwrap(&env).unwrap().expect("endpoint role");
        assert_eq!(payload.target_addr, "10.2.0.5");
        assert_eq!(payload.target_port, 5432);

        // transit role: unknown kid passes through (None, never an error)
        let foreign = agile_net_core::proto::message::E2eOpen {
            kid: "ffffffffffff".into(),
            ..env.clone()
        };
        assert!(engine.e2e_unwrap(&foreign).unwrap().is_none());

        // forged envelope (right kid, wrong key material) -> hard error
        let other_key = random_key();
        let (forged, _) = seal_open(&other_key, kid_of(&rec.token_hash), "h", "a", 1, &[], 0);
        assert!(engine.e2e_unwrap(&forged).is_err());

        // after revoke + refresh, the endpoint role is gone (transit/None)
        revoke_token(&db, &rec.id).unwrap();
        engine.refresh_keys(&db);
        assert!(engine.e2e_unwrap(&env).unwrap().is_none());
    }

    #[test]
    fn engine_token_lifecycle_gate() {
        use agile_net_core::relay::DelegationHooks;
        use agile_net_core::relay::e2e::{kid_of, seal_open};

        let db = Database::in_memory().unwrap();
        let gid = mk_group(&db, "db-prod");
        let (rec, _, _) = issue_relay(&db, "alice", &[gid], "");
        let key = e2e_key_of(&db, &rec).unwrap();
        let seal = || {
            seal_open(&key, kid_of(&rec.token_hash), "h", "10.2.0.5", 5432, &[], 0).0
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
