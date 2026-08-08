//! Transitive certification (node.md M6): origin-signed certification records propagate over
//! the federation control plane. The origin signs with its DEVICE key (the stable node identity
//! since M2 — relay certs rotate, the device key does not). Receivers verify the origin
//! signature and apply their own trust list: trusted origins adopt directly; anything else
//! degrades to a reference certification (一键采纳 via the approval center). Local
//! certifications always win over propagated ones; local revokes stay independent.

use agile_net_core::device::DeviceIdentity;
use agile_net_core::proto::message::{CertRecord, cert_record_verify};
use agile_net_core::util::{base64_decode, base64_encode};

use crate::db::Database;

const TRUST_LIST_KEY: &str = "cert_trust_list";
const RELAY_IN_KEY: &str = "cert_relay_in";

/// Trusted origin fingerprints (node_config JSON array).
pub fn trust_list(db: &Database) -> Vec<String> {
    db.get_config(TRUST_LIST_KEY)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_str::<Vec<String>>(&v).ok())
        .unwrap_or_default()
}

pub fn set_trust_list(db: &Database, list: &[String]) -> agile_net_core::error::Result<()> {
    db.set_config(TRUST_LIST_KEY, &serde_json::to_string(list).unwrap_or_else(|_| "[]".into()))
}

/// Inbound propagation switch (双向 opt-in: this node's listener accepts CertPush).
pub fn cert_relay_in_enabled(db: &Database) -> bool {
    db.get_config(RELAY_IN_KEY)
        .ok()
        .flatten()
        .map(|v| v == "1")
        .unwrap_or(false)
}

pub fn set_cert_relay_in(db: &Database, on: bool) -> agile_net_core::error::Result<()> {
    db.set_config(RELAY_IN_KEY, if on { "1" } else { "0" })
}

/// Build origin-signed records for every LOCAL certification/revocation (certified_by == ''),
/// signed with this node's device key.
pub fn origin_records(db: &Database, device: &DeviceIdentity, node_name: &str) -> Vec<CertRecord> {
    let origin_fp = device.device_fp();
    let origin_pubkey = base64_encode(device.pubkey());
    let Ok(rows) = db.list_devices(None, None) else {
        return Vec::new();
    };
    rows.into_iter()
        .filter(|d| d.certified_by.is_empty() && (d.state == "certified" || d.state == "revoked"))
        .map(|d| {
            let mut rec = CertRecord {
                device_fp: d.device_fp.clone(),
                pubkey: d.pubkey.clone(),
                subject: d.subject.clone(),
                remark: d.remark.clone(),
                origin_fp: origin_fp.clone(),
                origin_pubkey: origin_pubkey.clone(),
                origin_name: node_name.to_string(),
                ts: d.certified_at.clone().unwrap_or_else(|| d.last_seen.clone()),
                revoked: d.state == "revoked",
                sig: String::new(),
            };
            let bytes = agile_net_core::proto::message::cert_sign_bytes(&rec);
            rec.sig = base64_encode(&device.sign(&bytes));
            rec
        })
        .collect()
}

/// Inbound adoption: verify signatures, apply the trust list, keep local priority.
/// Returns (adopted, reference, rejected).
pub fn adopt_records(db: &Database, records: &[CertRecord], own_fp: &str) -> (usize, usize, usize) {
    let trust = trust_list(db);
    let (mut adopted, mut reference, mut rejected) = (0usize, 0usize, 0usize);
    for rec in records {
        // own-origin echoes and bad signatures are dropped outright
        if rec.origin_fp == own_fp {
            continue;
        }
        if !cert_record_verify(rec) {
            rejected += 1;
            continue;
        }
        let existing = db.get_device(&rec.device_fp).ok().flatten();
        // local certifications always win — a propagated record never overrides a local row
        if let Some(e) = &existing
            && e.certified_by.is_empty()
            && e.state != "pending"
        {
            continue;
        }
        if rec.revoked {
            // signed revocation propagation: only transitive rows of THIS origin follow;
            // the record's lineage is kept so a further hop forwards the ORIGINAL revocation
            if let Some(e) = &existing
                && e.certified_by == rec.origin_fp
                && e.state != "revoked"
            {
                let _ = db.revoke_device(&rec.device_fp);
                let _ = db.store_cert_lineage(&rec.device_fp, &rec.origin_pubkey, &rec.sig, &rec.ts);
            }
            continue;
        }
        // monotonicity guard: a revoked device from this origin cannot be re-certified by a
        // STALE (older-ts) record — this closes the "zombie cert" replay window where a middle
        // hop replays an old un-revoked record after the origin's revocation has propagated.
        // Only a genuinely newer certification (ts > the revocation's lineage ts) may revive.
        if let Some(e) = &existing
            && e.certified_by == rec.origin_fp
            && e.state == "revoked"
            && !rec.ts.is_empty()
            && e.cert_ts.as_str() >= rec.ts.as_str()
        {
            continue; // stale replay — keep the revoked state
        }
        // idempotency: an already-adopted row from this origin is current
        if let Some(e) = &existing
            && e.certified_by == rec.origin_fp
            && e.state == "certified"
            && e.subject == rec.subject
            && e.remark == rec.remark
        {
            continue;
        }
        if trust.contains(&rec.origin_fp) {
            // trusted origin: adopt (device row upserted pending-first when unknown; lineage
            // stored verbatim for blind forwarding)
            let _ = db.touch_device(&rec.device_fp, &rec.pubkey, "", "");
            let _ = db.certify_device_transitive(
                &rec.device_fp, &rec.subject, &rec.remark, &rec.origin_fp,
                &rec.origin_pubkey, &rec.sig, &rec.ts,
            );
            adopted += 1;
        } else {
            // untrusted: reference tier — one pending ref_cert_adopt approval per device
            let detail = serde_json::json!({
                "device_fp": rec.device_fp,
                "pubkey": rec.pubkey,
                "subject": rec.subject,
                "remark": rec.remark,
                "origin_fp": rec.origin_fp,
                "origin_name": rec.origin_name,
                "origin_pubkey": rec.origin_pubkey,
                "sig": rec.sig,
                "ts": rec.ts,
            })
            .to_string();
            let already = db
                .list_approvals(Some("pending"))
                .unwrap_or_default()
                .into_iter()
                .any(|a| {
                    a.r#type == super::approvals::REF_CERT_ADOPT && a.object_ref == rec.device_fp
                });
            if !already {
                let _ = db.create_approval(
                    super::approvals::REF_CERT_ADOPT,
                    &rec.device_fp,
                    &rec.origin_name,
                    &detail,
                );
                reference += 1;
            }
        }
    }
    (adopted, reference, rejected)
}

/// Approve-tier hold (node.md M6-T3): a visibility=approve token registers upstream only after
/// an approved topo_approve item (object_ref = "<token_id>:<connector_id>").
pub fn topo_approved(db: &Database, token_id: &str, connector_id: &str) -> bool {
    let object_ref = format!("{token_id}:{connector_id}");
    db.list_approvals(None)
        .unwrap_or_default()
        .into_iter()
        .any(|a| a.r#type == super::approvals::TOPO_APPROVE && a.state == "approved" && a.object_ref == object_ref)
}

/// Ensure the pending topo_approve item exists (returns true when newly created).
pub fn ensure_topo_approval(
    db: &Database,
    token_id: &str,
    connector_id: &str,
    label: &str,
    upstream: &str,
) -> bool {
    let object_ref = format!("{token_id}:{connector_id}");
    let pending = db.list_approvals(Some("pending")).unwrap_or_default();
    if pending.iter().any(|a| a.r#type == super::approvals::TOPO_APPROVE && a.object_ref == object_ref) {
        return false;
    }
    let detail = serde_json::json!({
        "token_id": token_id,
        "connector_id": connector_id,
        "label": label,
        "upstream": upstream,
    })
    .to_string();
    db.create_approval(super::approvals::TOPO_APPROVE, &object_ref, "local", &detail)
        .is_ok()
}

/// Rebuild the stored transitive records verbatim (blind forwarding): every device row adopted
/// from an origin (certified_by != '') carries its origin lineage for exactly this purpose.
pub fn transitive_records(db: &Database) -> Vec<CertRecord> {
    let Ok(rows) = db.list_devices(None, None) else {
        return Vec::new();
    };
    rows.into_iter()
        .filter(|d| {
            !d.certified_by.is_empty()
                && (d.state == "certified" || d.state == "revoked")
                && !d.cert_sig.is_empty()
        })
        .map(|d| CertRecord {
            device_fp: d.device_fp.clone(),
            pubkey: d.pubkey.clone(),
            subject: d.subject.clone(),
            remark: d.remark.clone(),
            origin_fp: d.certified_by.clone(),
            origin_pubkey: d.origin_pubkey.clone(),
            origin_name: String::new(), // display-only; unknown beyond the first hop
            ts: d.cert_ts.clone(),
            revoked: d.state == "revoked",
            sig: d.cert_sig.clone(),
        })
        .collect()
}

/// Adopt a reference certification (approval approve path): certify with the origin lineage.
pub fn adopt_reference(db: &Database, approval_id: &str) -> Result<(), String> {
    let item = db
        .list_approvals(None)
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|a| a.id == approval_id)
        .ok_or_else(|| "approval not found".to_string())?;
    if item.r#type != super::approvals::REF_CERT_ADOPT {
        return Err("not a reference-cert approval".into());
    }
    let detail: serde_json::Value = serde_json::from_str(&item.detail).map_err(|e| e.to_string())?;
    let fp = detail["device_fp"].as_str().ok_or("bad detail")?;
    let pubkey = detail["pubkey"].as_str().unwrap_or("");
    let subject = detail["subject"].as_str().unwrap_or("");
    let remark = detail["remark"].as_str().unwrap_or("");
    let origin = detail["origin_fp"].as_str().unwrap_or("");
    // sanity: the pubkey must derive the fingerprint (never trust the claimed fp)
    let matches = base64_decode(pubkey)
        .map(|raw| agile_net_core::device::fp_of(&raw) == fp)
        .unwrap_or(false);
    if !matches {
        return Err("pubkey/fingerprint mismatch".into());
    }
    let origin_pubkey = detail["origin_pubkey"].as_str().unwrap_or("");
    let sig = detail["sig"].as_str().unwrap_or("");
    let ts = detail["ts"].as_str().unwrap_or("");
    let _ = db.touch_device(fp, pubkey, "", "");
    db.certify_device_transitive(fp, subject, remark, origin, origin_pubkey, sig, ts)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certified_device(db: &Database, fp: &str, subject: &str) {
        db.touch_device(fp, "", "", "").unwrap();
        db.certify_device(fp, subject, "备注", "").unwrap();
    }

    #[test]
    fn origin_sign_and_adopt_roundtrip() {
        let origin_db = Database::in_memory().unwrap();
        let receiver_db = Database::in_memory().unwrap();
        let origin_key = DeviceIdentity::ephemeral();
        let dev = DeviceIdentity::ephemeral();
        certified_device(&origin_db, &dev.device_fp(), "小明");

        let records = origin_records(&origin_db, &origin_key, "origin-node");
        assert_eq!(records.len(), 1);
        assert!(cert_record_verify(&records[0]));

        // untrusted by default -> reference approval, no adoption
        let (a, r, rej) = adopt_records(&receiver_db, &records, "own-fp");
        assert_eq!((a, r, rej), (0, 1, 0));
        assert_eq!(
            receiver_db.get_device(&dev.device_fp()).unwrap().map(|d| d.state),
            None
        );

        // trust the origin -> adopt; a second push is idempotent
        set_trust_list(&receiver_db, &[origin_key.device_fp()]).unwrap();
        let (a, _, _) = adopt_records(&receiver_db, &records, "own-fp");
        assert_eq!(a, 1);
        let d = receiver_db.get_device(&dev.device_fp()).unwrap().unwrap();
        assert_eq!(d.state, "certified");
        assert_eq!(d.certified_by, origin_key.device_fp());
        assert_eq!(adopt_records(&receiver_db, &records, "own-fp").0, 0);

        // origin revokes -> signed revocation propagates to the transitive row
        origin_db.revoke_device(&dev.device_fp()).unwrap();
        let records = origin_records(&origin_db, &origin_key, "origin-node");
        assert!(records[0].revoked);
        adopt_records(&receiver_db, &records, "own-fp");
        assert_eq!(
            receiver_db.get_device(&dev.device_fp()).unwrap().unwrap().state,
            "revoked"
        );
    }

    #[test]
    fn local_row_wins_over_propagation() {
        let receiver_db = Database::in_memory().unwrap();
        let origin_key = DeviceIdentity::ephemeral();
        let dev = DeviceIdentity::ephemeral();
        // local certification of the same device
        certified_device(&receiver_db, &dev.device_fp(), "本地认证名");
        // origin pushes its own certification of it
        let origin_db = Database::in_memory().unwrap();
        origin_db.touch_device(&dev.device_fp(), "", "", "").unwrap();
        origin_db
            .certify_device(&dev.device_fp(), "对端名字", "", "")
            .unwrap();
        let records = origin_records(&origin_db, &origin_key, "origin");
        set_trust_list(&receiver_db, &[origin_key.device_fp()]).unwrap();
        adopt_records(&receiver_db, &records, "own-fp");
        let d = receiver_db.get_device(&dev.device_fp()).unwrap().unwrap();
        assert_eq!(d.subject, "本地认证名");
        assert_eq!(d.certified_by, "");
    }

    #[test]
    fn forged_signature_rejected() {
        let origin_db = Database::in_memory().unwrap();
        let origin_key = DeviceIdentity::ephemeral();
        let dev = DeviceIdentity::ephemeral();
        certified_device(&origin_db, &dev.device_fp(), "小明");
        let mut records = origin_records(&origin_db, &origin_key, "origin");
        records[0].remark = "tampered".into();
        let receiver_db = Database::in_memory().unwrap();
        set_trust_list(&receiver_db, &[origin_key.device_fp()]).unwrap();
        let (a, r, rej) = adopt_records(&receiver_db, &records, "own-fp");
        assert_eq!((a, r, rej), (0, 0, 1));
    }
}
