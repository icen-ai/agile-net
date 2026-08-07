//! Credential store: local persistence of delegated credentials (0600 JSON file).
//!
//! A credential is a pure data-plane key (delegated token): the token plaintext must stay
//! recoverable to dial the relay, so the file is the single storage tier (permissions 0600).

use anyhow::Result;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Saved delegated credential (fan-in endpoint).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    /// Primary relay entry address (host:port)
    pub addr: String,
    /// Delegated token label (the `d:` mark stripped)
    pub label: String,
    /// Delegated token plaintext (pure data-plane key; also the E2E key material)
    pub token: String,
    /// User-assigned display alias (fan-in list / rules page / admin menu). None = derive from node_id.
    /// The far side's self-reported node name is decorative; the user's own label wins everywhere.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub pinned_fingerprint: Option<String>,
    /// Disaster-set entry list (failover order; empty = single entry `addr`)
    #[serde(default)]
    pub entries: Vec<String>,
    /// Per-entry relay cert fingerprints (parallel to `entries`; "" = TOFU)
    #[serde(default)]
    pub entry_fps: Vec<String>,
    /// Entrust word (en_xxx opaque routing ID; every Open is E2E-sealed when set)
    #[serde(default)]
    pub en: Option<String>,
    /// Consumer mode: `split` = pull the rule vocabulary (E2E) and route
    /// selectively; None = `dedicated` (专线 — whole machine captured)
    #[serde(default)]
    pub emode: Option<String>,
    /// Delegated admin capability hint
    #[serde(default)]
    pub eadmin: bool,
    /// Self-declared display name uploaded to the issuer ("我的名称"; link-suggested, editable
    /// in the credential form — M4-T6 three-field naming)
    #[serde(default)]
    pub myname: Option<String>,
}

pub struct CredentialStore {
    path: PathBuf,
    credentials: DashMap<String, Credential>,
}

impl CredentialStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let store = Self {
            path: path.clone(),
            credentials: DashMap::new(),
        };
        if path.exists() {
            let data = std::fs::read_to_string(&path)?;
            if let Ok(map) =
                serde_json::from_str::<std::collections::HashMap<String, Credential>>(&data)
            {
                for (k, v) in map {
                    store.credentials.insert(k, v);
                }
            }
        }
        Ok(store)
    }

    pub fn open_temp() -> Result<Self> {
        let temp =
            std::env::temp_dir().join(format!("agile-net-cred-{}.json", uuid::Uuid::new_v4()));
        Self::open(temp)
    }

    /// Default store path (~/.anet/credentials.json — shared with the CLI `anet client` subcommand)
    pub fn open_default() -> Result<Self> {
        let dir = agile_net_core::util::brand_root();
        std::fs::create_dir_all(&dir)?;
        Self::open(dir.join("credentials.json"))
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub async fn save(&self, key: &str, cred: &Credential) {
        self.credentials.insert(key.to_string(), cred.clone());
        self.persist();
    }

    pub async fn get(&self, key: &str) -> Option<Credential> {
        self.credentials.get(key).map(|r| r.value().clone())
    }

    pub async fn remove(&self, key: &str) {
        self.credentials.remove(key);
        self.persist();
    }

    pub async fn keys(&self) -> Vec<String> {
        self.credentials.iter().map(|r| r.key().clone()).collect()
    }

    fn persist(&self) {
        let map: std::collections::HashMap<String, Credential> = self
            .credentials
            .iter()
            .map(|r| (r.key().clone(), r.value().clone()))
            .collect();
        if let Ok(data) = serde_json::to_string_pretty(&map) {
            let _ = std::fs::write(&self.path, data);
            // Tighten credential file permissions (Unix 0600)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(token: &str) -> Credential {
        Credential {
            addr: "node.example.com:54430".into(),
            label: "alice".into(),
            token: token.into(),
            name: None,
            insecure: false,
            pinned_fingerprint: None,
            entries: Vec::new(),
            entry_fps: Vec::new(),
            en: None,
            emode: None,
            eadmin: false,
            myname: None,
        }
    }

    fn temp_path() -> PathBuf {
        std::env::temp_dir().join(format!("agile-net-cred-test-{}.json", uuid::Uuid::new_v4()))
    }

    #[tokio::test]
    async fn file_backend_roundtrip() {
        let path = temp_path();
        let store = CredentialStore::open(path.clone()).unwrap();
        store.save("n1", &cred("psk_secret-1")).await;
        store.save("n2", &cred("psk_secret-2")).await;

        // Token plaintext persisted in the file (0600)
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("psk_secret-1"));

        // Reopen and read everything back
        let store2 = CredentialStore::open(path.clone()).unwrap();
        assert_eq!(store2.get("n1").await.unwrap().token, "psk_secret-1");
        assert_eq!(store2.get("n2").await.unwrap().label, "alice");
        let mut keys = store2.keys().await;
        keys.sort();
        assert_eq!(keys, vec!["n1".to_string(), "n2".to_string()]);

        store2.remove("n1").await;
        assert!(store2.get("n1").await.is_none());
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("psk_secret-1"));

        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn file_backend_perm_0600() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_path();
        let store = CredentialStore::open(path.clone()).unwrap();
        store.save("n1", &cred("psk_secret-1")).await;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_file(&path);
    }
}
