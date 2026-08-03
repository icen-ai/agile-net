//! 凭据存储：账号密码的本地持久化。
//!
//! 安全分层（P2 加固）：
//! - 桌面平台（Windows/macOS）优先使用 OS keyring 存密码，文件只留元数据（密码字段置空）；
//! - keyring 不可用（如无桌面密钥环的 Linux 服务器）时回退旧的 0600 明文文件方案；
//! - 首次启动发现旧明文文件时自动迁移到 keyring 并把文件中的密码字段清空。

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
}

/// OS keyring 中的服务名（Windows 凭据管理器 / macOS 钥匙串共用此标识）。
const KEYRING_SERVICE: &str = "agile-net";

pub struct CredentialStore {
    path: PathBuf,
    credentials: DashMap<String, Credential>,
    /// keyring 后端是否启用（探测失败或写入出错时降级为文件明文，与旧行为一致）
    use_keyring: AtomicBool,
    /// keyring 服务名（测试用独立服务名隔离，避免污染真实凭据库）
    service: String,
}

/// OS 密钥环封装：仅桌面平台（Windows/macOS）编译真实实现，
/// 其余平台一律不可用（自动回退 0600 文件方案）。
///
/// 注意：keyring crate 在无任何平台 store feature 时会静默退化为内存 mock store
/// （进程退出即丢），因此这里必须按平台 cfg 门控，而不是依赖其默认构建。
#[cfg(any(windows, target_os = "macos"))]
mod os_keyring {
    /// 探测 keyring 是否可用（凭据库被锁定/权限受限等场景返回 false）。
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
        // 临时存储仅用于测试与一次性场景：强制文件后端，保持测试密闭（不触碰真实 keyring）
        Self::open_inner(temp, KEYRING_SERVICE.to_string(), false)
    }

    /// 默认存储路径（~/.agile-net/credentials.json）
    pub fn open_default() -> Result<Self> {
        let dir = crate::home_dir().join(".agile-net");
        std::fs::create_dir_all(&dir)?;
        Self::open(dir.join("credentials.json"))
    }

    /// 统一构造：读取文件 → 探测 keyring → 必要时迁移旧明文。
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
            // 仅在桌面平台打出诊断（Linux 服务器恒不可用，属预期回退）
            #[cfg(any(windows, target_os = "macos"))]
            warn!("OS keyring 不可用，凭据密码将回退为 0600 文件明文存储");
        }
        Ok(store)
    }

    /// keyring 模式下装载密码：文件中的空密码从 keyring 取回内存；
    /// 文件中的旧明文密码迁移进 keyring 并落盘擦除（首次升级自动发生）。
    fn load_passwords_from_keyring(&self) {
        let mut migrated = false;
        let mut downgrade = false;
        for mut item in self.credentials.iter_mut() {
            let key = item.key().clone();
            let cred = item.value_mut();
            if cred.password.is_empty() {
                // 已迁移条目：从 keyring 取回明文到内存（丢失则保持空，重连时按认证失败处理）
                match os_keyring::get(&self.service, &key) {
                    Some(pw) => cred.password = pw,
                    None => warn!(key = %key, "keyring 中未找到凭据密码，需重新保存"),
                }
            } else if os_keyring::set(&self.service, &key, &cred.password).is_ok() {
                migrated = true;
            } else {
                // 迁移写入失败：整体降级回文件明文，避免半迁移状态
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
            // 全部明文已进 keyring：重写文件擦除密码字段
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
            // keyring 写入失败：整体降级回文件明文（与旧行为一致，不丢密码）
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
                    // keyring 模式下文件不落明文：密码字段擦除，仅存元数据
                    cred.password.clear();
                }
                (r.key().clone(), cred)
            })
            .collect();
        if let Ok(data) = serde_json::to_string_pretty(&map) {
            let _ = std::fs::write(&self.path, data);
            // 凭据文件权限收紧（Unix 0600）
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
        }
    }

    fn temp_path() -> PathBuf {
        std::env::temp_dir().join(format!("agile-net-cred-test-{}.json", uuid::Uuid::new_v4()))
    }

    /// 独立服务名 + 指定后端的测试构造（keyring 用例用独立服务名隔离，跑完清理）。
    fn open_with(path: PathBuf, service: &str, allow_keyring: bool) -> CredentialStore {
        CredentialStore::open_inner(path, service.to_string(), allow_keyring).unwrap()
    }

    // ==================== 文件回退路径 ====================

    #[tokio::test]
    async fn file_backend_roundtrip() {
        let path = temp_path();
        let store = open_with(path.clone(), "agile-net-test", false);
        store.save("n1", &cred("secret-1")).await;
        store.save("n2", &cred("secret-2")).await;

        // 文件后端：明文随文件落盘（旧行为，0600）
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("secret-1"));

        // 重开后完整读回
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

    // ==================== keyring 路径（仅 keyring 可用时执行） ====================

    /// keyring 测试隔离服务名；跑完删除条目，避免污染真实凭据库。
    fn test_service() -> Option<String> {
        let service = format!("agile-net-test-{}", uuid::Uuid::new_v4());
        os_keyring::available(&service).then_some(service)
    }

    /// keyring 用例串行执行：OS 凭据库是进程外共享资源，并行读写存在瞬时竞争
    fn keyring_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[tokio::test]
    // 串行锁有意跨 await 持有（测试内同步原语，无生产代码竞争）
    #[allow(clippy::await_holding_lock)]
    async fn keyring_backend_scrubs_file() {
        let _guard = keyring_lock();
        let Some(service) = test_service() else {
            return; // 当前平台/环境无 keyring，跳过
        };
        let path = temp_path();
        let store = open_with(path.clone(), &service, true);
        store.save("n1", &cred("secret-1")).await;

        // 文件不含明文，keyring 持有密码，读取接口行为不变
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("secret-1"));
        assert_eq!(store.get("n1").await.unwrap().password, "secret-1");

        // 重开（新进程语义）：从 keyring 取回密码
        let store2 = open_with(path.clone(), &service, true);
        assert_eq!(store2.get("n1").await.unwrap().password, "secret-1");

        store2.remove("n1").await;
        assert!(os_keyring::get(&service, "n1").is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    // 串行锁有意跨 await 持有（测试内同步原语，无生产代码竞争）
    #[allow(clippy::await_holding_lock)]
    async fn keyring_migration_from_legacy_plaintext() {
        let _guard = keyring_lock();
        let Some(service) = test_service() else {
            return; // 当前平台/环境无 keyring，跳过
        };
        // 先以文件后端写入旧版明文凭据
        let path = temp_path();
        let legacy = open_with(path.clone(), &service, false);
        legacy.save("n1", &cred("legacy-secret")).await;
        assert!(std::fs::read_to_string(&path).unwrap().contains("legacy-secret"));
        drop(legacy);

        // keyring 后端打开同一文件：自动迁移（文件擦除 + keyring 持有明文）
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
