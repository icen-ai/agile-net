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
pub fn build_register_msg(db: &Database, rec: &DelegatedTokenRecord) -> CtrlMessage {
    let group_ids: Vec<String> = serde_json::from_str(&rec.groups).unwrap_or_default();
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

/// Recover the E2E master key of a token (issuer side, E2E unwrap path; never expose via API).
pub fn e2e_key_of(db: &Database, rec: &DelegatedTokenRecord) -> Result<[u8; 32]> {
    let b64 = db.decrypt_secret(&rec.e2e_key_enc)?;
    let raw = agile_net_core::util::base64_decode(&b64).map_err(|_| anyhow::anyhow!("e2e key corrupt"))?;
    let len = raw.len();
    let key: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("e2e key length invalid: {len}"))?;
    Ok(key)
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
}
