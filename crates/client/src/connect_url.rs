//! Delegated connect-link parsing for the client engine (fan-in side).
//!
//! The unified link primitives (`anet://` scheme, connect/fanout roles, parse + build) live in
//! `agile_net_core::link` — THE single Rust base, shared by the node (link generation at
//! issuance) and the client (import). This module only maps the core `ConnectLink` onto the
//! client-side `ParsedConnect` shape (extra fields: manage_hosts / save_credential) and adapts
//! saved credentials. The client consumes delegated credentials only — a connect link without
//! the `d:<label>` account mark is rejected.

use serde::{Deserialize, Serialize};

use crate::credential::Credential;

/// Parsed delegated connect parameters (desktop IPC and Web REST share the same shape).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedConnect {
    /// Primary relay entry (host:port)
    pub addr: String,
    /// Delegated token label (the `d:` mark stripped)
    pub label: String,
    /// Delegated token plaintext
    pub token: String,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub pinned_fingerprint: Option<String>,
    #[serde(default)]
    pub manage_hosts: bool,
    /// Whether to save the credential after a successful connect
    #[serde(default)]
    pub save_credential: bool,
    /// Disaster-set relay entries (failover order; empty = single entry)
    #[serde(default)]
    pub entries: Vec<String>,
    /// Per-entry relay cert fingerprints (parallel to `entries`; "" = TOFU)
    #[serde(default)]
    pub entry_fps: Vec<String>,
    /// Entrust word (en_xxx opaque routing ID; every Open is E2E-sealed when set)
    #[serde(default)]
    pub en: Option<String>,
    /// Consumer mode (`split` = E2E rule delivery; None = dedicated 专线)
    #[serde(default)]
    pub emode: Option<String>,
    /// Delegated admin capability hint (ticket pull via the E2E config channel)
    #[serde(default)]
    pub eadmin: bool,
    /// Self-declared display name suggestion from the link ("我的名称", node.md M2)
    #[serde(default)]
    pub myname: Option<String>,
}

/// Parse an `anet://connect?...` URL (delegated credentials only).
pub fn parse_connect_url(url: &str) -> std::result::Result<ParsedConnect, String> {
    let link = agile_net_core::link::parse_connect_url(url)?;
    let Some(label) = link.delegated_label().map(|s| s.to_string()) else {
        return Err("仅支持委托凭据链接（缺少 d:<label> 标记）".to_string());
    };
    Ok(ParsedConnect {
        addr: link.addr,
        label,
        token: link.password,
        insecure: link.insecure,
        pinned_fingerprint: link.pinned_fingerprint,
        manage_hosts: false,
        save_credential: true,
        entries: link.entries,
        entry_fps: link.entry_fps,
        en: link.en,
        emode: link.emode,
        eadmin: link.eadmin,
        myname: link.myname,
    })
}

/// Generate an anet://connect delegated URL from a saved credential (contains the token plaintext; share with care).
pub fn connect_url_of(c: &Credential) -> String {
    // Keep the failover set and every E2E field on re-export.
    let mut entries: Vec<(String, String)> = if c.entries.is_empty() {
        vec![(c.addr.clone(), c.pinned_fingerprint.clone().unwrap_or_default())]
    } else {
        c.entries
            .iter()
            .enumerate()
            .map(|(i, a)| (a.clone(), c.entry_fps.get(i).cloned().unwrap_or_default()))
            .collect()
    };
    if !entries.iter().any(|(a, _)| *a == c.addr) {
        entries.insert(0, (c.addr.clone(), c.pinned_fingerprint.clone().unwrap_or_default()));
    }
    agile_net_core::link::build_delegate_url(
        &c.addr,
        &c.label,
        &c.token,
        &entries,
        c.en.as_deref(),
        c.emode.as_deref(),
        c.eadmin,
        // myname is the importer-side "我的名称" suggestion; re-export keeps whatever the
        // original link carried (Credential.myname, wired by the client form in M4-T6)
        c.myname.as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_maps_core_link_shape() {
        let p = parse_connect_url(
            "anet://connect?server=anet.example.com&port=54430&account=d:alice&password=psk_x&fp=ab12",
        )
        .expect("parse");
        assert_eq!(p.addr, "anet.example.com:54430");
        assert_eq!(p.label, "alice");
        assert_eq!(p.token, "psk_x");
        assert_eq!(p.pinned_fingerprint.as_deref(), Some("ab12"));
        assert!(p.save_credential);
    }

    #[test]
    fn parse_rejects_non_delegated_link() {
        assert!(
            parse_connect_url("anet://connect?server=h:1&account=alice&password=sk-x").is_err()
        );
        assert!(
            parse_connect_url("agilenet://connect?server=h:1&account=d:alice&password=psk_x").is_err()
        );
    }

    #[test]
    fn connect_url_of_roundtrips() {
        let c = Credential {
            addr: "1.2.3.4:54430".into(),
            label: "alice".into(),
            token: "psk_p".into(),
            name: None,
            insecure: false,
            pinned_fingerprint: Some("ab".into()),
            entries: vec!["1.2.3.4:54430".into(), "5.6.7.8:54430".into()],
            entry_fps: vec!["ab".into(), "".into()],
            en: Some("en_a1b2c3d4e5f6".into()),
            emode: Some("split".into()),
            eadmin: true,
            myname: Some("小明".into()),
        };
        let url = connect_url_of(&c);
        assert!(url.starts_with("anet://connect?"));
        let p = parse_connect_url(&url).expect("roundtrip");
        assert_eq!(p.label, "alice");
        assert_eq!(p.token, "psk_p");
        assert_eq!(p.pinned_fingerprint.as_deref(), Some("ab"));
        assert_eq!(p.entries, vec!["1.2.3.4:54430".to_string(), "5.6.7.8:54430".to_string()]);
        assert_eq!(p.en.as_deref(), Some("en_a1b2c3d4e5f6"));
        assert_eq!(p.emode.as_deref(), Some("split"));
        assert!(p.eadmin);
        assert_eq!(p.myname.as_deref(), Some("小明"));
    }
}
