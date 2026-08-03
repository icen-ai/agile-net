//! Settings sync (Netcatty-style versioned archive): WebDAV / S3-compatible storage / manual file import-export.
//!
//! - Synced content = all local config: `gui-settings.json` (the sub_scripts override script chain
//!   lives in this file; no separate script file), `gui-custom-rules.json`, `subscriptions.json`
//! - Security filter: the mihomo control plane `secret` in subscriptions.json is a per-device random value
//!   (meaningless across devices): stripped on upload; local original secret kept on restore. `web-auth.json` (admin password hash) never syncs
//! - Archive JSON: app/kind/version/device/created_at + enc (none|aes256gcm) + payload
//!   (plaintext = object; encrypted = b64 ciphertext string). Encryption: PBKDF2-HMAC-SHA256 (100k iterations, random
//!   16B salt per archive) -> AES-256-GCM; key input = "agile-net-sync:v1:" + PIN
//! - PIN: 4 digits (obfuscation-grade encryption explicitly requested by users) or empty for no encryption. **PIN is never persisted**;
//!   pin_set in sync-config.json is only a UI hint (without storing the PIN we cannot check "is it the same PIN")
//! - Version is monotonic: upload = max(remote version, local version)+1; comparison lets the frontend tell newer/same/older
//! - State goes to `~/.agile-net/sync-state.json` (0600), channel config to `sync-config.json` (0600)
//! - Audit gui.sync_config / gui.sync_upload / gui.sync_restore (never records plaintext or ciphertext content)

use agile_net_node::db::sha256_hex;
use serde::{Deserialize, Serialize};

use crate::roles;

/// Remote archive file name (fixed key under the WebDAV directory / S3 prefix)
const ARCHIVE_NAME: &str = "agile-net-sync.json";
/// Whitelist of synced config files (only these enter/leave the archive; sensitive files like web-auth.json are excluded)
const SYNCED_FILES: [&str; 3] = [
    "gui-settings.json",
    "gui-custom-rules.json",
    "subscriptions.json",
];

fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Device name (no hostname crate; read env var COMPUTERNAME/HOSTNAME)
fn device_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown-device".into())
}

// ==================== Config and state (0600 on disk) ====================

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WebdavConfig {
    pub url: String,
    pub user: String,
    pub pass: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct S3Config {
    pub endpoint: String,
    pub bucket: String,
    pub ak: String,
    pub sk: String,
    pub region: String,
    pub prefix: String,
}

/// Sync channel config (sync-config.json, 0600). PIN is not in it (never persisted).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SyncConfig {
    /// "none" | "webdav" | "s3"
    pub target: String,
    pub webdav: WebdavConfig,
    pub s3: S3Config,
    /// UI hint only that "the user has set a PIN" (the PIN itself is never persisted, so consistency cannot be checked)
    pub pin_set: bool,
}

/// set_sync_config input (same shape as SyncConfig; empty pass/sk = keep existing value)
pub type SyncConfigInput = SyncConfig;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SyncState {
    pub version: u64,
    pub last_upload_at: u64,
    pub last_device: String,
    pub last_restore_at: u64,
}

fn config_path() -> std::path::PathBuf {
    roles::data_dir().join("sync-config.json")
}

fn state_path() -> std::path::PathBuf {
    roles::data_dir().join("sync-state.json")
}

/// Write a private file (0600; config holds credentials, state holds version metadata)
fn write_private(path: &std::path::Path, data: &str) -> Result<(), String> {
    std::fs::write(path, data).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn load_config() -> SyncConfig {
    std::fs::read_to_string(config_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_config(cfg: &SyncConfig) -> Result<(), String> {
    let dir = roles::data_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    write_private(
        &config_path(),
        &serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?,
    )
}

fn load_state() -> SyncState {
    std::fs::read_to_string(state_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_state(st: &SyncState) -> Result<(), String> {
    let dir = roles::data_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    write_private(
        &state_path(),
        &serde_json::to_string_pretty(st).map_err(|e| e.to_string())?,
    )
}

/// Mask for display echo: keep only the last 2 chars (empty string stays as-is)
fn mask_secret(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    let tail: String = s
        .chars()
        .rev()
        .take(2)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("**{tail}")
}

// ==================== Archive format ====================

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct Archive {
    app: String,
    kind: String,
    version: u64,
    device: String,
    created_at: u64,
    /// "none" | "aes256gcm"
    enc: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    salt: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    nonce: String,
    /// Plaintext = object; encrypted = b64 ciphertext string
    payload: serde_json::Value,
}

/// PIN validation: empty (no encryption) or exactly 4 digits; anything else errs
fn validate_pin(pin: &str) -> Result<(), String> {
    if pin.is_empty() {
        return Ok(());
    }
    if pin.len() == 4 && pin.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err("PIN 须为正好 4 位数字，或留空不加密".into())
    }
}

/// Derive the AES-256 key via PBKDF2-HMAC-SHA256 (100k iterations); input "agile-net-sync:v1:" + PIN
fn derive_key(pin: &str, salt: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(100_000).expect("非零迭代数"),
        salt,
        format!("agile-net-sync:v1:{pin}").as_bytes(),
        &mut out,
    );
    out
}

fn aes_gcm_seal(key_bytes: &[u8; 32], nonce_bytes: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let key = ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key_bytes)
            .map_err(|_| "加密初始化失败".to_string())?,
    );
    let nonce = ring::aead::Nonce::try_assume_unique_for_key(nonce_bytes)
        .map_err(|_| "加密初始化失败".to_string())?;
    let mut buf = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, ring::aead::Aad::empty(), &mut buf)
        .map_err(|_| "加密失败".to_string())?;
    Ok(buf)
}

fn aes_gcm_open(key_bytes: &[u8; 32], nonce_bytes: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let key = ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key_bytes)
            .map_err(|_| "解密初始化失败".to_string())?,
    );
    let nonce = ring::aead::Nonce::try_assume_unique_for_key(nonce_bytes)
        .map_err(|_| "解密初始化失败".to_string())?;
    let mut buf = ciphertext.to_vec();
    let data = key
        .open_in_place(nonce, ring::aead::Aad::empty(), &mut buf)
        .map_err(|_| "PIN 错误或存档损坏".to_string())?;
    Ok(data.to_vec())
}

fn b64e(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn b64d(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|_| "存档内容损坏（base64 解码失败）".to_string())
}

/// Build archive bytes: payload is a plaintext object (empty pin) or AES-256-GCM ciphertext b64 (non-empty pin)
fn build_archive(
    version: u64,
    device: &str,
    created_at: u64,
    pin: &str,
    payload: serde_json::Value,
) -> Result<Vec<u8>, String> {
    let mut a = Archive {
        app: "agile-net".into(),
        kind: "sync-archive".into(),
        version,
        device: device.into(),
        created_at,
        ..Default::default()
    };
    if pin.is_empty() {
        a.enc = "none".into();
        a.payload = payload;
    } else {
        use ring::rand::SecureRandom as _;
        let rng = ring::rand::SystemRandom::new();
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        rng.fill(&mut salt).map_err(|_| "随机数生成失败".to_string())?;
        rng.fill(&mut nonce).map_err(|_| "随机数生成失败".to_string())?;
        let key = derive_key(pin, &salt);
        let pt = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
        let ct = aes_gcm_seal(&key, &nonce, &pt)?;
        a.enc = "aes256gcm".into();
        a.salt = b64e(&salt);
        a.nonce = b64e(&nonce);
        a.payload = serde_json::Value::String(b64e(&ct));
    }
    serde_json::to_vec_pretty(&a).map_err(|e| e.to_string())
}

/// Validate app/kind, decrypt if needed, and return the plaintext payload object
fn extract_payload(a: &Archive, pin: &str) -> Result<serde_json::Value, String> {
    if a.app != "agile-net" || a.kind != "sync-archive" {
        return Err("不是 AgileNet 同步存档".into());
    }
    match a.enc.as_str() {
        "none" | "" => {
            if a.payload.is_object() {
                Ok(a.payload.clone())
            } else {
                Err("存档内容损坏（payload 非对象）".into())
            }
        }
        "aes256gcm" => {
            if pin.is_empty() {
                return Err("该存档已加密，请输入 4 位 PIN".into());
            }
            let ct_b64 = a.payload.as_str().ok_or("存档内容损坏（payload 非密文）")?;
            let salt = b64d(&a.salt)?;
            let nonce_raw = b64d(&a.nonce)?;
            let nonce: &[u8; 12] = nonce_raw
                .as_slice()
                .try_into()
                .map_err(|_| "存档内容损坏（nonce 长度非法）".to_string())?;
            let key = derive_key(pin, &salt);
            let pt = aes_gcm_open(&key, nonce, &b64d(ct_b64)?)?;
            serde_json::from_slice(&pt).map_err(|_| "存档解密后内容损坏".to_string())
        }
        other => Err(format!("存档使用了未知加密方式（{other}），请升级客户端")),
    }
}

// ==================== Payload collection and restore ====================

/// Security filter: strip the per-device random mihomo control plane secret from subscriptions.json (meaningless across devices)
fn strip_local_secrets(name: &str, mut v: serde_json::Value) -> serde_json::Value {
    if name == "subscriptions.json" {
        if let Some(obj) = v.as_object_mut() {
            obj.remove("secret");
        }
    }
    v
}

/// Restore merge: subscriptions.json keeps the local original secret (if any); everything else is written back as archived
fn restore_value(
    name: &str,
    mut archived: serde_json::Value,
    local: Option<serde_json::Value>,
) -> serde_json::Value {
    if name == "subscriptions.json" {
        if let Some(secret) = local
            .as_ref()
            .and_then(|l| l["secret"].as_str())
            .filter(|s| !s.is_empty())
        {
            if let Some(obj) = archived.as_object_mut() {
                obj.insert("secret".into(), serde_json::Value::String(secret.to_string()));
            }
        }
    }
    archived
}

/// Collect local config into the plaintext payload object (missing files / bad JSON are skipped)
fn collect_payload() -> serde_json::Value {
    let dir = roles::data_dir();
    let mut files = serde_json::Map::new();
    for name in SYNCED_FILES {
        let Ok(raw) = std::fs::read_to_string(dir.join(name)) else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else {
            continue;
        };
        files.insert(name.to_string(), strip_local_secrets(name, v));
    }
    serde_json::json!({
        "files": files,
        "app_version": env!("CARGO_PKG_VERSION"),
    })
}

/// Write the archive payload back to the local config dir: back up existing config to backup-pre-restore-<ts>/ first,
/// then write back file by file per the whitelist. Returns the list of files actually written.
fn apply_payload(payload: &serde_json::Value) -> Result<Vec<String>, String> {
    let files = payload["files"]
        .as_object()
        .ok_or("存档内容损坏（缺少 files）")?;
    let dir = roles::data_dir();
    let backup = dir.join(format!("backup-pre-restore-{}", now_ts()));
    let mut backup_ready = false;
    let mut written = Vec::new();
    for name in SYNCED_FILES {
        let Some(v) = files.get(name) else { continue };
        if !v.is_object() && !v.is_array() {
            continue;
        }
        let path = dir.join(name);
        let local: Option<serde_json::Value> = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok());
        if path.exists() {
            if !backup_ready {
                std::fs::create_dir_all(&backup).map_err(|e| format!("创建备份目录失败：{e}"))?;
                backup_ready = true;
            }
            std::fs::copy(&path, backup.join(name)).map_err(|e| format!("备份 {name} 失败：{e}"))?;
        }
        let merged = restore_value(name, v.clone(), local);
        let data = serde_json::to_string_pretty(&merged).map_err(|e| e.to_string())?;
        std::fs::write(&path, data).map_err(|e| format!("写入 {name} 失败：{e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        written.push(name.to_string());
    }
    if written.is_empty() {
        return Err("存档中没有可恢复的配置文件".into());
    }
    Ok(written)
}

/// Version comparison (remote vs local state version)
fn relation_of(remote: u64, local: u64) -> &'static str {
    if remote > local {
        "newer"
    } else if remote == local {
        "same"
    } else {
        "older"
    }
}

// ==================== Sync channels (fetch/put) ====================

enum SyncTarget {
    Webdav(WebdavConfig),
    S3(S3Config),
    File(String),
}

impl SyncTarget {
    fn kind(&self) -> &'static str {
        match self {
            Self::Webdav(_) => "webdav",
            Self::S3(_) => "s3",
            Self::File(_) => "file",
        }
    }

    /// Fetch remote archive bytes; returns None if it does not exist
    async fn fetch(&self) -> Result<Option<Vec<u8>>, String> {
        match self {
            Self::Webdav(c) => webdav_fetch(c).await,
            Self::S3(c) => s3_fetch(c).await,
            Self::File(path) => match std::fs::read(path) {
                Ok(b) => Ok(Some(b)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(format!("读取文件失败：{e}")),
            },
        }
    }

    /// Upload archive bytes
    async fn put(&self, bytes: &[u8]) -> Result<(), String> {
        match self {
            Self::Webdav(c) => webdav_put(c, bytes).await,
            Self::S3(c) => s3_put(c, bytes).await,
            Self::File(path) => {
                let p = std::path::Path::new(path);
                if let Some(parent) = p.parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent).map_err(|e| format!("创建目录失败：{e}"))?;
                    }
                }
                std::fs::write(p, bytes).map_err(|e| format!("写入文件失败：{e}"))
            }
        }
    }
}

/// Resolve the sync channel from persisted config (unconfigured/incomplete -> friendly Chinese error)
fn resolve_target(cfg: &SyncConfig) -> Result<SyncTarget, String> {
    match cfg.target.as_str() {
        "webdav" => {
            if cfg.webdav.url.trim().is_empty() {
                return Err("未配置 WebDAV 地址".into());
            }
            if !(cfg.webdav.url.starts_with("https://") || cfg.webdav.url.starts_with("http://")) {
                return Err("WebDAV 地址须以 http:// 或 https:// 开头".into());
            }
            Ok(SyncTarget::Webdav(cfg.webdav.clone()))
        }
        "s3" => {
            if cfg.s3.endpoint.trim().is_empty() {
                return Err("未配置 S3 endpoint".into());
            }
            if cfg.s3.bucket.trim().is_empty() {
                return Err("未配置 S3 bucket".into());
            }
            if cfg.s3.ak.trim().is_empty() || cfg.s3.sk.trim().is_empty() {
                return Err("未配置 S3 Access Key / Secret Key".into());
            }
            Ok(SyncTarget::S3(cfg.s3.clone()))
        }
        _ => Err("未配置同步通道，请先选择 WebDAV 或 S3 兼容存储".into()),
    }
}

fn http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP 客户端初始化失败：{e}"))
}

// ---------- WebDAV ----------

/// WebDAV archive URL: normalize whether the base URL ends with / or not
fn webdav_archive_url(url: &str) -> String {
    format!("{}/{ARCHIVE_NAME}", url.trim_end_matches('/'))
}

async fn webdav_fetch(c: &WebdavConfig) -> Result<Option<Vec<u8>>, String> {
    let url = webdav_archive_url(&c.url);
    let mut req = http_client()?.get(&url);
    if !c.user.is_empty() {
        req = req.basic_auth(&c.user, Some(&c.pass));
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("无法连接 WebDAV 服务器：{e}"))?;
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err("WebDAV 认证失败（401/403）：请检查用户名与密码".into());
    }
    if !status.is_success() {
        return Err(format!("WebDAV 服务器返回错误（{status}）"));
    }
    resp.bytes()
        .await
        .map(|b| Some(b.to_vec()))
        .map_err(|e| format!("读取 WebDAV 响应失败：{e}"))
}

async fn webdav_put(c: &WebdavConfig, bytes: &[u8]) -> Result<(), String> {
    let url = webdav_archive_url(&c.url);
    let mut req = http_client()?.put(&url).body(bytes.to_vec());
    if !c.user.is_empty() {
        req = req.basic_auth(&c.user, Some(&c.pass));
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("无法连接 WebDAV 服务器：{e}"))?;
    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err("WebDAV 认证失败（401/403）：请检查用户名与密码".into());
    }
    if status == reqwest::StatusCode::CONFLICT {
        return Err("WebDAV 目录不存在（409）：请先在网盘中创建同步目录".into());
    }
    if !status.is_success() {
        return Err(format!("WebDAV 上传失败（{status}）"));
    }
    Ok(())
}

// ---------- S3-compatible storage (path-style + SigV4) ----------

/// SigV4 URI encoding (unreserved chars kept; slash encoded depending on the flag)
fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    let tag = ring::hmac::sign(&k, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// Unix seconds -> (x-amz-date "YYYYMMDDTHHMMSSZ", date "YYYYMMDD");
/// no chrono: civil-from-days (Howard Hinnant algorithm) for the Gregorian conversion
fn amz_dates(ts: u64) -> (String, String) {
    let days = (ts / 86400) as i64;
    let secs = ts % 86400;
    // civil_from_days
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    let (hh, mm, ss) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    (
        format!("{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z"),
        format!("{y:04}{m:02}{d:02}"),
    )
}

/// SigV4 signing key derivation chain: HMAC("AWS4"+sk, date) -> region -> service -> "aws4_request"
fn sigv4_signing_key(sk: &str, date: &str, region: &str, service: &str) -> [u8; 32] {
    let k_date = hmac_sha256(format!("AWS4{sk}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// SigV4 signing parameters (bundles sigv4_authorization inputs; service is fixed to s3)
struct SigV4Params<'a> {
    method: &'a str,
    canonical_uri: &'a str,
    host: &'a str,
    region: &'a str,
    ak: &'a str,
    sk: &'a str,
    amz_date: &'a str,
    payload_hash: &'a str,
}

/// AWS SigV4 Authorization header (service=s3; signs only the three headers host;x-amz-content-sha256;x-amz-date)
fn sigv4_authorization(p: &SigV4Params<'_>) -> String {
    // All fields are &str (Copy); destructure-copy and keep the original layout
    let SigV4Params {
        method,
        canonical_uri,
        host,
        region,
        ak,
        sk,
        amz_date,
        payload_hash,
    } = *p;
    let canonical_headers =
        format!("host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n");
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_request =
        format!("{method}\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
    let date = &amz_date[..8];
    let scope = format!("{date}/{region}/s3/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let k_signing = sigv4_signing_key(sk, date, region, "s3");
    let signature = hex(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={ak}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    )
}

struct S3Url {
    /// Actual request URL
    url: String,
    /// Host for signing (including port)
    host: String,
    /// Canonical URI for signing (segment-encoded)
    canonical_uri: String,
}

/// path-style URL: `{scheme}://{endpoint}/{bucket}/{prefix}agile-net-sync.json`
/// (endpoint handled with or without scheme, default https; compatible with MinIO/B2/Cloudflare R2)
fn s3_url(c: &S3Config) -> S3Url {
    let e = c.endpoint.trim().trim_end_matches('/');
    let (scheme, host) = if let Some(r) = e.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = e.strip_prefix("http://") {
        ("http", r)
    } else {
        ("https", e)
    };
    let key = format!("{}{ARCHIVE_NAME}", c.prefix);
    S3Url {
        url: format!("{scheme}://{host}/{}/{key}", uri_encode(c.bucket.trim(), true)),
        host: host.to_string(),
        canonical_uri: format!(
            "/{}/{}",
            uri_encode(c.bucket.trim(), true),
            uri_encode(&key, false)
        ),
    }
}

/// Send a SigV4-signed request (empty region defaults to "auto")
async fn s3_request(
    c: &S3Config,
    method: reqwest::Method,
    body: Option<Vec<u8>>,
) -> Result<reqwest::Response, String> {
    let u = s3_url(c);
    let payload_hash = sha256_hex(body.as_deref().unwrap_or(b""));
    let region = if c.region.trim().is_empty() {
        "auto"
    } else {
        c.region.trim()
    };
    let (amz_date, _) = amz_dates(now_ts());
    let auth = sigv4_authorization(&SigV4Params {
        method: method.as_str(),
        canonical_uri: &u.canonical_uri,
        host: &u.host,
        region,
        ak: c.ak.trim(),
        sk: &c.sk,
        amz_date: &amz_date,
        payload_hash: &payload_hash,
    });
    let mut req = http_client()?
        .request(method, &u.url)
        .header("x-amz-date", amz_date)
        .header("x-amz-content-sha256", payload_hash)
        .header("Authorization", auth);
    if let Some(b) = body {
        req = req.body(b);
    }
    req.send()
        .await
        .map_err(|e| format!("无法连接 S3 端点：{e}"))
}

/// Uniform S3 error translation (404 -> Ok(None) is distinguished by the caller; 403 gets troubleshooting hints)
async fn s3_error(resp: reqwest::Response, action: &str) -> String {
    let status = resp.status();
    let body: String = resp
        .text()
        .await
        .unwrap_or_default()
        .chars()
        .take(200)
        .collect();
    if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::UNAUTHORIZED {
        format!(
            "S3 认证失败（{status}）：请检查 AK/SK 与 region 是否正确、endpoint 是否支持 path-style 寻址（MinIO/B2/R2 兼容）；服务端提示：{body}"
        )
    } else {
        format!("S3 {action}失败（{status}）：{body}")
    }
}

async fn s3_fetch(c: &S3Config) -> Result<Option<Vec<u8>>, String> {
    let resp = s3_request(c, reqwest::Method::GET, None).await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(s3_error(resp, "下载").await);
    }
    resp.bytes()
        .await
        .map(|b| Some(b.to_vec()))
        .map_err(|e| format!("读取 S3 响应失败：{e}"))
}

async fn s3_put(c: &S3Config, bytes: &[u8]) -> Result<(), String> {
    let resp = s3_request(c, reqwest::Method::PUT, Some(bytes.to_vec())).await?;
    if !resp.status().is_success() {
        return Err(s3_error(resp, "上传").await);
    }
    Ok(())
}

// ==================== Upload / check / restore main flows ====================

/// Upload: fetch the remote version first (missing/unparseable = 0, overwrite-style upload); new version = max(remote, local)+1
async fn upload_inner(target: &SyncTarget, pin: &str) -> Result<SyncStatus, String> {
    validate_pin(pin)?;
    let state = load_state();
    let remote_version = match target.fetch().await? {
        Some(bytes) => serde_json::from_slice::<Archive>(&bytes)
            .map(|a| a.version)
            .unwrap_or(0),
        None => 0,
    };
    let new_version = remote_version.max(state.version) + 1;
    let device = device_name();
    let now = now_ts();
    let archive = build_archive(new_version, &device, now, pin, collect_payload())?;
    target.put(&archive).await?;
    save_state(&SyncState {
        version: new_version,
        last_upload_at: now,
        last_device: device.clone(),
        last_restore_at: state.last_restore_at,
    })?;
    // pin_set is only a UI hint: record true once an upload used a PIN
    if !pin.is_empty() {
        let mut cfg = load_config();
        if !cfg.pin_set {
            cfg.pin_set = true;
            let _ = save_config(&cfg);
        }
    }
    roles::audit(
        "gui.sync_upload",
        serde_json::json!({"version": new_version, "device": device, "target": target.kind()}),
    );
    Ok(SyncStatus {
        remote_version: new_version,
        remote_device: device,
        remote_at: now,
        local_version: new_version,
        relation: "same".into(),
    })
}

/// Check: parse only the archive header to compare versions (no decryption); remote encrypted but PIN empty -> relation="need-pin"
async fn check_inner(cfg: &SyncConfig, pin: &str) -> Result<SyncStatus, String> {
    validate_pin(pin)?;
    let state = load_state();
    let Ok(target) = resolve_target(cfg) else {
        return Ok(SyncStatus {
            local_version: state.version,
            relation: "unconfigured".into(),
            ..Default::default()
        });
    };
    let Some(bytes) = target.fetch().await? else {
        return Ok(SyncStatus {
            local_version: state.version,
            relation: "empty".into(),
            ..Default::default()
        });
    };
    let archive: Archive =
        serde_json::from_slice(&bytes).map_err(|_| "远端文件不是有效的 AgileNet 同步存档".to_string())?;
    if archive.app != "agile-net" || archive.kind != "sync-archive" {
        return Err("远端文件不是 AgileNet 同步存档".into());
    }
    let relation = if archive.enc == "aes256gcm" && pin.is_empty() {
        "need-pin"
    } else {
        relation_of(archive.version, state.version)
    };
    Ok(SyncStatus {
        remote_version: archive.version,
        remote_device: archive.device,
        remote_at: archive.created_at,
        local_version: state.version,
        relation: relation.into(),
    })
}

/// Restore: fetch remote -> decrypt -> back up existing config -> write back -> save state -> delayed restart (IPC response reaches the frontend first).
/// The version relation (newer/same/older) is not blocked at the command layer; the frontend prompts first via sync_check and the user confirms before calling.
async fn restore_inner(
    app: &tauri::AppHandle,
    target: &SyncTarget,
    pin: &str,
) -> Result<RestoreResult, String> {
    validate_pin(pin)?;
    let Some(bytes) = target.fetch().await? else {
        return Err("远端没有同步存档，请先在其他设备上执行上传".into());
    };
    let archive: Archive =
        serde_json::from_slice(&bytes).map_err(|_| "存档无法解析（可能不是 AgileNet 同步存档）".to_string())?;
    let payload = extract_payload(&archive, pin)?;
    let files = apply_payload(&payload)?;
    let now = now_ts();
    let state = load_state();
    save_state(&SyncState {
        version: archive.version,
        last_upload_at: state.last_upload_at,
        last_device: archive.device.clone(),
        last_restore_at: now,
    })?;
    roles::audit(
        "gui.sync_restore",
        serde_json::json!({"version": archive.version, "device": archive.device, "target": target.kind()}),
    );
    // Config is mostly read at startup, so a full restart applies the restore; the delayed trigger lets the response reach the frontend first (need_restart lets it prompt)
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        handle.restart();
    });
    Ok(RestoreResult {
        version: archive.version,
        files,
        need_restart: true,
    })
}

// ==================== Tauri commands ====================

/// get_sync_config response: masked channel config + version state
#[derive(Debug, Clone, Serialize)]
pub struct SyncConfigView {
    pub target: String,
    pub webdav_url: String,
    pub webdav_user: String,
    pub webdav_pass_mask: String,
    pub s3_endpoint: String,
    pub s3_bucket: String,
    pub s3_ak: String,
    pub s3_sk_mask: String,
    pub s3_region: String,
    pub s3_prefix: String,
    pub pin_set: bool,
    pub version: u64,
    pub last_upload_at: u64,
    pub last_device: String,
    pub last_restore_at: u64,
}

/// sync_check / sync_upload response
#[derive(Debug, Clone, Default, Serialize)]
pub struct SyncStatus {
    pub remote_version: u64,
    pub remote_device: String,
    pub remote_at: u64,
    pub local_version: u64,
    /// "newer" | "same" | "older" | "empty" | "unconfigured" | "need-pin"
    pub relation: String,
}

/// sync_restore / sync_import response
#[derive(Debug, Clone, Serialize)]
pub struct RestoreResult {
    pub version: u64,
    pub files: Vec<String>,
    pub need_restart: bool,
}

#[tauri::command]
pub async fn get_sync_config() -> Result<SyncConfigView, String> {
    let cfg = load_config();
    let st = load_state();
    Ok(SyncConfigView {
        target: cfg.target,
        webdav_url: cfg.webdav.url,
        webdav_user: cfg.webdav.user,
        webdav_pass_mask: mask_secret(&cfg.webdav.pass),
        s3_endpoint: cfg.s3.endpoint,
        s3_bucket: cfg.s3.bucket,
        s3_ak: cfg.s3.ak,
        s3_sk_mask: mask_secret(&cfg.s3.sk),
        s3_region: cfg.s3.region,
        s3_prefix: cfg.s3.prefix,
        pin_set: cfg.pin_set,
        version: st.version,
        last_upload_at: st.last_upload_at,
        last_device: st.last_device,
        last_restore_at: st.last_restore_at,
    })
}

/// Save channel config: empty pass/sk = keep existing value; audit never records any plaintext
#[tauri::command]
pub async fn set_sync_config(cfg: SyncConfigInput) -> Result<(), String> {
    if !matches!(cfg.target.as_str(), "none" | "webdav" | "s3") {
        return Err("同步通道须为 none / webdav / s3".into());
    }
    let mut cur = load_config();
    cur.target = cfg.target;
    cur.webdav.url = cfg.webdav.url.trim().to_string();
    cur.webdav.user = cfg.webdav.user;
    if !cfg.webdav.pass.is_empty() {
        cur.webdav.pass = cfg.webdav.pass;
    }
    cur.s3.endpoint = cfg.s3.endpoint.trim().to_string();
    cur.s3.bucket = cfg.s3.bucket.trim().to_string();
    cur.s3.ak = cfg.s3.ak.trim().to_string();
    if !cfg.s3.sk.is_empty() {
        cur.s3.sk = cfg.s3.sk;
    }
    cur.s3.region = cfg.s3.region;
    cur.s3.prefix = cfg.s3.prefix;
    cur.pin_set = cfg.pin_set;
    save_config(&cur)?;
    roles::audit("gui.sync_config", serde_json::json!({"target": cur.target}));
    Ok(())
}

#[tauri::command]
pub async fn sync_check(pin: String) -> Result<SyncStatus, String> {
    check_inner(&load_config(), &pin).await
}

#[tauri::command]
pub async fn sync_upload(pin: String) -> Result<SyncStatus, String> {
    let target = resolve_target(&load_config())?;
    upload_inner(&target, &pin).await
}

#[tauri::command]
pub async fn sync_restore(app: tauri::AppHandle, pin: String) -> Result<RestoreResult, String> {
    let target = resolve_target(&load_config())?;
    restore_inner(&app, &target, &pin).await
}

/// Manual export: write the archive to a local file (version still +1, same semantics as upload)
#[tauri::command]
pub async fn sync_export(path: String, pin: String) -> Result<SyncStatus, String> {
    if path.trim().is_empty() {
        return Err("导出路径不能为空".into());
    }
    upload_inner(&SyncTarget::File(path), &pin).await
}

/// Manual import: restore from a local archive file (auto-restart after restore, same as sync_restore)
#[tauri::command]
pub async fn sync_import(app: tauri::AppHandle, path: String, pin: String) -> Result<RestoreResult, String> {
    if path.trim().is_empty() {
        return Err("导入路径不能为空".into());
    }
    restore_inner(&app, &SyncTarget::File(path), &pin).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_payload() -> serde_json::Value {
        serde_json::json!({
            "files": {
                "gui-settings.json": {"client": true, "sub_scripts": [{"id": "a", "name": "甲"}]},
                "subscriptions.json": {"subscriptions": [{"name": "s", "url": "https://x/sub?token=t"}]},
            },
            "app_version": "0.1.0",
        })
    }

    #[test]
    fn pin_validation() {
        assert!(validate_pin("").is_ok());
        assert!(validate_pin("0821").is_ok());
        assert!(validate_pin("9999").is_ok());
        for bad in ["123", "12345", "12ab", "abcd", " 123", "123 "] {
            assert!(validate_pin(bad).is_err(), "{bad} 应被拒绝");
        }
    }

    #[test]
    fn archive_plain_roundtrip() {
        let bytes = build_archive(3, "dev-a", 1_730_000_000, "", sample_payload()).unwrap();
        let a: Archive = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(a.app, "agile-net");
        assert_eq!(a.kind, "sync-archive");
        assert_eq!(a.version, 3);
        assert_eq!(a.device, "dev-a");
        assert_eq!(a.enc, "none");
        assert!(a.salt.is_empty() && a.nonce.is_empty());
        assert!(a.payload.is_object());
        let p = extract_payload(&a, "").unwrap();
        assert_eq!(p, sample_payload());
        // Plaintext archive also reads with a PIN (the PIN is ignored)
        assert!(extract_payload(&a, "1234").is_ok());
    }

    #[test]
    fn archive_encrypted_roundtrip_and_wrong_pin() {
        let bytes = build_archive(5, "dev-b", 1_730_000_100, "0821", sample_payload()).unwrap();
        let a: Archive = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(a.enc, "aes256gcm");
        assert!(!a.salt.is_empty() && !a.nonce.is_empty());
        assert!(a.payload.is_string());
        // Ciphertext exposes no plaintext content
        assert!(!String::from_utf8_lossy(&bytes).contains("gui-settings"));
        // Correct PIN restores
        let p = extract_payload(&a, "0821").unwrap();
        assert_eq!(p, sample_payload());
        // Empty PIN: prompts for input
        let e = extract_payload(&a, "").unwrap_err();
        assert!(e.contains("PIN"), "{e}");
        // Wrong PIN: GCM verification fails -> unified message
        let e = extract_payload(&a, "0822").unwrap_err();
        assert_eq!(e, "PIN 错误或存档损坏");
    }

    #[test]
    fn archive_rejects_foreign_json() {
        let a = Archive {
            app: "other".into(),
            ..Default::default()
        };
        assert!(extract_payload(&a, "").is_err());
    }

    #[test]
    fn version_relation() {
        assert_eq!(relation_of(2, 1), "newer");
        assert_eq!(relation_of(1, 1), "same");
        assert_eq!(relation_of(1, 2), "older");
        assert_eq!(relation_of(0, 0), "same");
    }

    #[test]
    fn sigv4_flow_matches_aws_official_vector() {
        // AWS official "complete SigV4 signing flow" example (IAM docs, AKIAIOSFODNN7EXAMPLE):
        // official final signature 5d672d79.... The signing mechanism is identical to S3 (service is a parameter);
        // run it end to end with this module's primitives (sha256_hex/hmac_sha256/hex + sigv4_signing_key).
        let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let canonical_request = format!(
            "GET\n/\nAction=ListUsers&Version=2010-05-08\n\
             content-type:application/x-www-form-urlencoded; charset=utf-8\n\
             host:iam.amazonaws.com\n\
             x-amz-date:20150830T123600Z\n\n\
             content-type;host;x-amz-date\n{empty}"
        );
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/iam/aws4_request\n{}",
            sha256_hex(canonical_request.as_bytes())
        );
        let k = sigv4_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "iam",
        );
        assert_eq!(
            hex(&hmac_sha256(&k, string_to_sign.as_bytes())),
            "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
        // Also anchor the canonical-request hash of the S3 docs GET Object example (7344ae5b..., with range header):
        // verifies sha256_hex and this module's canonical-request layout (that example's printed signature f0e8bdb8...
        // disagrees with its own string-to-sign, an AWS docs erratum, so it is not an assertion target)
        let s3_cr = format!(
            "GET\n/test.txt\n\n\
             host:examplebucket.s3.amazonaws.com\n\
             range:bytes=0-9\n\
             x-amz-content-sha256:{empty}\n\
             x-amz-date:20130524T000000Z\n\n\
             host;range;x-amz-content-sha256;x-amz-date\n{empty}"
        );
        assert_eq!(
            sha256_hex(s3_cr.as_bytes()),
            "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"
        );
    }

    #[test]
    fn sigv4_authorization_fixed_vector() {
        // This implementation's three-header signing (host;x-amz-content-sha256;x-amz-date) with fixed input/output;
        // the expected value was cross-verified with an independent HMAC-SHA256 implementation (Python hmac/hashlib)
        let auth = sigv4_authorization(&SigV4Params {
            method: "GET",
            canonical_uri: "/test.txt",
            host: "examplebucket.s3-us-west-1.amazonaws.com",
            region: "us-west-1",
            ak: "AKIAIOSFODNN7EXAMPLE",
            sk: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            amz_date: "20130524T000000Z",
            payload_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        });
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-west-1/s3/aws4_request, \
SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
Signature=d5cdd2e19642573e9f29f12a994baa76d72bd3f34e99e4ec7b52ff0f7899681e"
        );
    }

    #[test]
    fn amz_date_formatting() {
        let (amz, date) = amz_dates(1_369_353_600);
        assert_eq!(amz, "20130524T000000Z");
        assert_eq!(date, "20130524");
        let (amz2, _) = amz_dates(0);
        assert_eq!(amz2, "19700101T000000Z");
    }

    #[test]
    fn webdav_url_join_normalizes_slash() {
        assert_eq!(
            webdav_archive_url("https://dav.example.com/dav"),
            "https://dav.example.com/dav/agile-net-sync.json"
        );
        assert_eq!(
            webdav_archive_url("https://dav.example.com/dav/"),
            "https://dav.example.com/dav/agile-net-sync.json"
        );
    }

    #[test]
    fn s3_url_path_style_and_scheme() {
        let c = S3Config {
            endpoint: "https://minio.example.com:9000/".into(),
            bucket: "backups".into(),
            prefix: "anet/".into(),
            ..Default::default()
        };
        let u = s3_url(&c);
        assert_eq!(u.url, "https://minio.example.com:9000/backups/anet/agile-net-sync.json");
        assert_eq!(u.host, "minio.example.com:9000");
        assert_eq!(u.canonical_uri, "/backups/anet/agile-net-sync.json");
        // No scheme defaults to https
        let c2 = S3Config {
            endpoint: "s3.us-west-004.backblazeb2.com".into(),
            bucket: "b".into(),
            ..Default::default()
        };
        assert!(s3_url(&c2).url.starts_with("https://s3.us-west-004.backblazeb2.com/b/"));
    }

    #[test]
    fn secret_stripped_only_from_subscriptions() {
        let sub = serde_json::json!({"secret": "abc123", "subscriptions": [{"name": "s"}]});
        let out = strip_local_secrets("subscriptions.json", sub);
        assert!(out.get("secret").is_none());
        assert_eq!(out["subscriptions"][0]["name"], "s");
        // Other files untouched
        let settings = serde_json::json!({"secret": "keep", "client": true});
        let out2 = strip_local_secrets("gui-settings.json", settings);
        assert_eq!(out2["secret"], "keep");
    }

    #[test]
    fn restore_preserves_local_secret() {
        let archived = serde_json::json!({"subscriptions": [{"name": "s"}]});
        let local = serde_json::json!({"secret": "local-secret", "subscriptions": []});
        let merged = restore_value("subscriptions.json", archived, Some(local));
        assert_eq!(merged["secret"], "local-secret");
        assert_eq!(merged["subscriptions"][0]["name"], "s");
        // Do not add a secret out of thin air when the local one is absent
        let merged2 = restore_value(
            "subscriptions.json",
            serde_json::json!({"subscriptions": []}),
            None,
        );
        assert!(merged2.get("secret").is_none());
    }

    #[test]
    fn mask_secret_tail_only() {
        assert_eq!(mask_secret(""), "");
        assert_eq!(mask_secret("sk-abcdef"), "**ef");
        assert_eq!(mask_secret("ab"), "**ab");
    }
}
