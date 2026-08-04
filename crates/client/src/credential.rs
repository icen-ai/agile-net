//! Credential store: local persistence of account passwords.
//!
//! Security tiers (P2 hardening):
//! - On desktop platforms (Windows/macOS) passwords go to the OS keyring; the file keeps only metadata (password field emptied);
//! - When keyring is unavailable (e.g. a Linux server without a desktop keyring), fall back to the legacy 0600 plaintext file;
//! - On first launch with a legacy plaintext file, auto-migrate into the keyring and scrub the password field from the file.

use anyhow::Result;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub addr: String,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub pinned_fingerprint: Option<String>,
    /// Federation P2: delegated credential mark (`d:` account prefix in the link) — pure
    /// data-plane key, dials the relay directly without any API roundtrip
    #[serde(default)]
    pub delegated: bool,
    /// Disaster-set entry list (failover order; empty = single entry `addr`)
    #[serde(default)]
    pub entries: Vec<String>,
    /// Per-entry relay cert fingerprints (parallel to `entries`; "" = TOFU)
    #[serde(default)]
    pub entry_fps: Vec<String>,
    /// Federation P3: E2E routing hint (every Open is sealed when set)
    #[serde(default)]
    pub ehint: Option<String>,
    /// Federation P3 consumer mode: `split` = pull the rule vocabulary (E2E) and route
    /// selectively; None = `dedicated` (专线 — whole machine captured)
    #[serde(default)]
    pub emode: Option<String>,
}

/// Service name in the OS keyring (shared by Windows Credential Manager / macOS Keychain).
const KEYRING_SERVICE: &str = "agile-net";

pub struct CredentialStore {
    path: PathBuf,
    credentials: DashMap<String, Credential>,
    /// Whether the keyring backend is enabled (probe failure or write error downgrades to plaintext file, same as legacy behavior)
    use_keyring: AtomicBool,
    /// keyring service name (tests use isolated service names to avoid polluting the real credential store)
    service: String,
}

/// OS keyring wrapper: real implementation only on desktop platforms (Windows/macOS);
/// always unavailable elsewhere (auto-fallback to the 0600 file scheme).
///
/// Note: the keyring crate silently degrades to an in-memory mock store (lost on process exit)
/// without any platform store feature, so this must be cfg-gated per platform, not its default build.
#[cfg(any(windows, target_os = "macos"))]
mod os_keyring {
    /// Probe whether the keyring is usable (returns false when the credential store is locked / permission-restricted, etc.).
    pub fn available(service: &str) -> bool {
        match keyring::Entry::new(service, "agile-net-probe") {
            Ok(entry) => matches!(
                entry.get_password(),
                Ok(_) | Err(keyring::Error::NoEntry)
            ),
            Err(_) => false,
        }
    }

    pub fn get(service: &str, key: &str) -> Option<String> {
        keyring::Entry::new(service, key).ok()?.get_password().ok()
    }

    pub fn set(service: &str, key: &str, secret: &str) -> Result<(), keyring::Error> {
        keyring::Entry::new(service, key)?.set_password(secret)
    }

    pub fn delete(service: &str, key: &str) {
        if let Ok(entry) = keyring::Entry::new(service, key) {
            let _ = entry.delete_credential();
        }
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
mod os_keyring {
    pub fn available(_service: &str) -> bool {
        false
    }

    pub fn get(_service: &str, _key: &str) -> Option<String> {
        None
    }

    pub fn set(_service: &str, _key: &str, _secret: &str) -> Result<(), ()> {
        Err(())
    }

    pub fn delete(_service: &str, _key: &str) {}
}

impl CredentialStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        Self::open_inner(path.into(), KEYRING_SERVICE.to_string(), true)
    }

    pub fn open_temp() -> Result<Self> {
        let temp =
            std::env::temp_dir().join(format!("agile-net-cred-{}.json", uuid::Uuid::new_v4()));
        // Temp store is for tests and one-shot scenarios only: force the file backend to keep tests hermetic (never touch the real keyring)
        Self::open_inner(temp, KEYRING_SERVICE.to_string(), false)
    }

    /// Default store path (~/.agile-net/credentials.json)
    pub fn open_default() -> Result<Self> {
        let dir = crate::home_dir().join(".agile-net");
        std::fs::create_dir_all(&dir)?;
        Self::open(dir.join("credentials.json"))
    }

    /// Unified constructor: read file → probe keyring → migrate legacy plaintext if needed.
    fn open_inner(path: PathBuf, service: String, allow_keyring: bool) -> Result<Self> {
        let store = Self {
            path: path.clone(),
            credentials: DashMap::new(),
            use_keyring: AtomicBool::new(false),
            service,
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

        let keyring_ok = allow_keyring && os_keyring::available(&store.service);
        store.use_keyring.store(keyring_ok, Ordering::Relaxed);
        if keyring_ok {
            store.load_passwords_from_keyring();
        } else if allow_keyring {
            // Diagnostics only on desktop platforms (always unavailable on Linux servers; expected fallback)
            #[cfg(any(windows, target_os = "macos"))]
            warn!("OS keyring 不可用，凭据密码将回退为 0600 文件明文存储");
        }
        Ok(store)
    }

    /// Load passwords in keyring mode: empty passwords in the file are fetched back from the keyring;
    /// legacy plaintext passwords in the file are migrated into the keyring and scrubbed on disk (automatic on first upgrade).
    fn load_passwords_from_keyring(&self) {
        let mut migrated = false;
        let mut downgrade = false;
        for mut item in self.credentials.iter_mut() {
            let key = item.key().clone();
            let cred = item.value_mut();
            if cred.password.is_empty() {
                // Migrated entry: fetch the plaintext back from the keyring into memory (if lost, keep it empty; reconnect then fails auth)
                match os_keyring::get(&self.service, &key) {
                    Some(pw) => cred.password = pw,
                    None => warn!(key = %key, "keyring 中未找到凭据密码，需重新保存"),
                }
            } else if os_keyring::set(&self.service, &key, &cred.password).is_ok() {
                migrated = true;
            } else {
                // Migration write failed: downgrade the whole store back to plaintext file, avoiding a half-migrated state
                warn!(key = %key, "keyring 写入失败，凭据存储降级为文件明文");
                downgrade = true;
                break;
            }
        }
        if downgrade {
            self.use_keyring.store(false, Ordering::Relaxed);
            self.persist();
            return;
        }
        if migrated {
            // All plaintext is now in the keyring: rewrite the file with the password field scrubbed
            self.persist();
        }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub async fn save(&self, key: &str, cred: &Credential) {
        if self.use_keyring.load(Ordering::Relaxed)
            && !cred.password.is_empty()
            && os_keyring::set(&self.service, key, &cred.password).is_err()
        {
            // keyring write failed: downgrade the whole store back to plaintext file (same as legacy behavior; no password loss)
            warn!(key = %key, "keyring 写入失败，凭据存储降级为文件明文");
            self.use_keyring.store(false, Ordering::Relaxed);
        }
        self.credentials.insert(key.to_string(), cred.clone());
        self.persist();
    }

    pub async fn get(&self, key: &str) -> Option<Credential> {
        self.credentials.get(key).map(|r| r.value().clone())
    }

    pub async fn remove(&self, key: &str) {
        self.credentials.remove(key);
        if self.use_keyring.load(Ordering::Relaxed) {
            os_keyring::delete(&self.service, key);
        }
        self.persist();
    }

    pub async fn keys(&self) -> Vec<String> {
        self.credentials.iter().map(|r| r.key().clone()).collect()
    }

    fn persist(&self) {
        let use_keyring = self.use_keyring.load(Ordering::Relaxed);
        let map: std::collections::HashMap<String, Credential> = self
            .credentials
            .iter()
            .map(|r| {
                let mut cred = r.value().clone();
                if use_keyring {
                    // keyring mode never writes plaintext to the file: scrub the password field, keep only metadata
                    cred.password.clear();
                }
                (r.key().clone(), cred)
            })
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

    fn cred(password: &str) -> Credential {
        Credential {
            addr: "node.example.com:59090".into(),
            username: "alice".into(),
            password: password.into(),
            insecure: false,
            pinned_fingerprint: None,
            delegated: false,
            entries: Vec::new(),
            entry_fps: Vec::new(),
            ehint: None,
            emode: None,
        }
    }

    fn temp_path() -> PathBuf {
        std::env::temp_dir().join(format!("agile-net-cred-test-{}.json", uuid::Uuid::new_v4()))
    }

    /// Test constructor with an isolated service name + explicit backend (keyring cases use isolated service names and clean up afterwards).
    fn open_with(path: PathBuf, service: &str, allow_keyring: bool) -> CredentialStore {
        CredentialStore::open_inner(path, service.to_string(), allow_keyring).unwrap()
    }

    // ==================== file fallback path ====================

    #[tokio::test]
    async fn file_backend_roundtrip() {
        let path = temp_path();
        let store = open_with(path.clone(), "agile-net-test", false);
        store.save("n1", &cred("secret-1")).await;
        store.save("n2", &cred("secret-2")).await;

        // File backend: plaintext persisted in the file (legacy behavior, 0600)
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("secret-1"));

        // Reopen and read everything back
        let store2 = open_with(path.clone(), "agile-net-test", false);
        assert_eq!(store2.get("n1").await.unwrap().password, "secret-1");
        assert_eq!(store2.get("n2").await.unwrap().username, "alice");
        let mut keys = store2.keys().await;
        keys.sort();
        assert_eq!(keys, vec!["n1".to_string(), "n2".to_string()]);

        store2.remove("n1").await;
        assert!(store2.get("n1").await.is_none());
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("secret-1"));

        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn file_backend_perm_0600() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_path();
        let store = open_with(path.clone(), "agile-net-test", false);
        store.save("n1", &cred("secret-1")).await;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_file(&path);
    }

    // ==================== keyring path (runs only when keyring is available) ====================

    /// Isolated service name for keyring tests; entries are deleted afterwards to avoid polluting the real credential store.
    fn test_service() -> Option<String> {
        let service = format!("agile-net-test-{}", uuid::Uuid::new_v4());
        os_keyring::available(&service).then_some(service)
    }

    /// keyring cases run serialized: the OS credential store is a shared out-of-process resource; concurrent reads/writes race transiently
    fn keyring_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[tokio::test]
    // The serialization lock is held across await on purpose (a test-only sync primitive; no production-code contention)
    #[allow(clippy::await_holding_lock)]
    async fn keyring_backend_scrubs_file() {
        let _guard = keyring_lock();
        let Some(service) = test_service() else {
            return; // No keyring on this platform/environment; skip
        };
        let path = temp_path();
        let store = open_with(path.clone(), &service, true);
        store.save("n1", &cred("secret-1")).await;

        // File has no plaintext; keyring holds the password; the read API behaves unchanged
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("secret-1"));
        assert_eq!(store.get("n1").await.unwrap().password, "secret-1");

        // Reopen (new-process semantics): fetch the password from the keyring
        let store2 = open_with(path.clone(), &service, true);
        assert_eq!(store2.get("n1").await.unwrap().password, "secret-1");

        store2.remove("n1").await;
        assert!(os_keyring::get(&service, "n1").is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    // The serialization lock is held across await on purpose (a test-only sync primitive; no production-code contention)
    #[allow(clippy::await_holding_lock)]
    async fn keyring_migration_from_legacy_plaintext() {
        let _guard = keyring_lock();
        let Some(service) = test_service() else {
            return; // No keyring on this platform/environment; skip
        };
        // First write legacy plaintext credentials with the file backend
        let path = temp_path();
        let legacy = open_with(path.clone(), &service, false);
        legacy.save("n1", &cred("legacy-secret")).await;
        assert!(std::fs::read_to_string(&path).unwrap().contains("legacy-secret"));
        drop(legacy);

        // Opening the same file with the keyring backend: auto-migration (file scrubbed + keyring holds the plaintext)
        let store = open_with(path.clone(), &service, true);
        assert!(!std::fs::read_to_string(&path).unwrap().contains("legacy-secret"));
        assert_eq!(store.get("n1").await.unwrap().password, "legacy-secret");
        assert_eq!(
            os_keyring::get(&service, "n1").as_deref(),
            Some("legacy-secret")
        );

        store.remove("n1").await;
        let _ = std::fs::remove_file(&path);
    }
}
