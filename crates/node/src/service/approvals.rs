//! Approval center plumbing (node.md M3-T4): pluggable adjudication event types, appeal
//! filing, and the WS fan-out for new items. The DB layer (`db/devices.rs`) owns storage.

use agile_net_core::relay::listener::SessionMeta;

use crate::db::Database;

/// A device awaits certification (first sight or pending-policy blocked).
pub const DEVICE_CERTIFY: &str = "device_certify";
/// Device replacement approval (rebind: certify new + migrate holder + revoke old).
pub const DEVICE_REBIND: &str = "device_rebind";
/// Adopt a transitive (reference) certification received over federation (M6).
pub const REF_CERT_ADOPT: &str = "ref_cert_adopt";
/// Topology-visibility approval (M6, visibility=approve).
pub const TOPO_APPROVE: &str = "topo_approve";

/// Find-or-create the pending `device_certify` approval for a device; returns the approval id.
pub fn ensure_device_certify_approval(db: &Database, device_fp: &str) -> Option<String> {
    if let Ok(pending) = db.list_approvals(Some("pending"))
        && let Some(a) = pending
            .into_iter()
            .find(|a| a.r#type == DEVICE_CERTIFY && a.object_ref == device_fp)
    {
        return Some(a.id);
    }
    let detail = serde_json::json!({ "device_fp": device_fp }).to_string();
    db.create_approval(DEVICE_CERTIFY, device_fp, device_fp, &detail)
        .ok()
        .map(|a| a.id)
}

/// Pending-session appeal (Ctrl PendingNote uplink): attach the note to the device's
/// certification approval item (created on demand; the ≤3 cap is enforced by the DB layer).
pub fn file_pending_note(db: &Database, meta: &SessionMeta, body: &str) {
    let Some(approval_id) = ensure_device_certify_approval(db, &meta.device_fp) else {
        return;
    };
    let _ = db.add_approval_message(&approval_id, "appeal", body);
}
