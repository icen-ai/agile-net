//! Connect-link parsing for the client engine (fan-in account side).
//!
//! The unified link primitives (`anet://` scheme, connect/fanout roles, parse + build) live in
//! `agile_net_core::link` — THE single Rust base, shared by the node (link generation at
//! issuance) and the client (import). This module only maps the core `ConnectLink` onto the
//! client-side `ParsedConnect` shape (extra fields: pinned_cert_path / manage_hosts /
//! save_credential / admin flag as a display string) and adapts saved credentials.

use serde::{Deserialize, Serialize};

use crate::credential::Credential;

/// Parsed connect parameters (desktop IPC and Web REST share the same shape).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedConnect {
    pub addr: String,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub pinned_cert_path: Option<String>,
    #[serde(default)]
    pub pinned_fingerprint: Option<String>,
    #[serde(default)]
    pub manage_hosts: bool,
    /// Whether to save the credential after a successful connect
    #[serde(default)]
    pub save_credential: bool,
    /// Admin connect URL flag (admin=1: the holder can manage this node; strong warning on import)
    #[serde(default)]
    pub admin: Option<String>,
    /// Federation P2: delegated credential mark (d: account prefix)
    #[serde(default)]
    pub delegated: bool,
    /// Disaster-set relay entries (failover order; empty = single entry)
    #[serde(default)]
    pub entries: Vec<String>,
    /// Per-entry relay cert fingerprints (parallel to `entries`; "" = TOFU)
    #[serde(default)]
    pub entry_fps: Vec<String>,
    /// Federation P3: E2E routing hint
    #[serde(default)]
    pub ehint: Option<String>,
    /// Federation P3 consumer mode (`split` = E2E rule delivery; None = dedicated 专线)
    #[serde(default)]
    pub emode: Option<String>,
}

/// Parse an `anet://connect?...` URL (legacy `agilenet://` accepted).
pub fn parse_connect_url(url: &str) -> std::result::Result<ParsedConnect, String> {
    let link = agile_net_core::link::parse_connect_url(url)?;
    let delegated = link.is_delegated();
    Ok(ParsedConnect {
        addr: link.addr,
        username: link.account,
        password: link.password,
        insecure: link.insecure,
        pinned_cert_path: None,
        pinned_fingerprint: link.pinned_fingerprint,
        manage_hosts: false,
        save_credential: true,
        admin: link.admin.then(|| "1".to_string()),
        delegated,
        entries: link.entries,
        entry_fps: link.entry_fps,
        ehint: link.ehint,
        emode: link.emode,
    })
}

/// Generate an anet://connect URL from a saved credential (contains plaintext password; share with care).
pub fn connect_url_of(c: &Credential) -> String {
    agile_net_core::link::build_connect_url(
        &c.addr,
        &c.username,
        &c.password,
        c.pinned_fingerprint.as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_maps_core_link_shape() {
        let p = parse_connect_url(
            "anet://connect?server=anet.example.com&port=59090&account=alice&password=sk-x&fp=ab12&admin=1",
        )
        .expect("parse");
        assert_eq!(p.addr, "anet.example.com:59090");
        assert_eq!(p.username, "alice");
        assert_eq!(p.password, "sk-x");
        assert_eq!(p.pinned_fingerprint.as_deref(), Some("ab12"));
        assert_eq!(p.admin.as_deref(), Some("1"));
        assert!(p.save_credential);
    }

    #[test]
    fn parse_legacy_scheme_still_works() {
        let p = parse_connect_url("agilenet://connect?server=1.2.3.4&port=59090&account=a&password=b")
            .expect("legacy parse");
        assert_eq!(p.addr, "1.2.3.4:59090");
        assert_eq!(p.admin, None);
    }

    #[test]
    fn connect_url_of_roundtrips() {
        let c = Credential {
            addr: "1.2.3.4:59090".into(),
            username: "u".into(),
            password: "p".into(),
            insecure: false,
            pinned_fingerprint: Some("ab".into()),
            delegated: false,
            entries: Vec::new(),
            entry_fps: Vec::new(),
            ehint: None,
            emode: None,
        };
        let url = connect_url_of(&c);
        assert!(url.starts_with("anet://connect?"));
        let p = parse_connect_url(&url).expect("roundtrip");
        assert_eq!(p.username, "u");
        assert_eq!(p.password, "p");
        assert_eq!(p.pinned_fingerprint.as_deref(), Some("ab"));
    }
}
