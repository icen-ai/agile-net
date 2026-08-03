//! SQLite 数据库模块（对应 docs/database/schema.md）
//!
//! 基于 rusqlite，启动时执行版本化迁移；全部敏感字段（密码、Token）
//! 以 Argon2id / SHA-256 哈希存储，严禁明文落库。
//!
//! 按域拆分子模块（纯搬运，零逻辑变更）：pool（连接池与共享基础）/
//! migrations（版本化迁移）/ admin / rules / accounts / connectors / logs；
//! 对外路径 `db::xxx` 全部不变。

pub mod models;

mod accounts;
mod admin;
mod connectors;
mod logs;
mod migrations;
mod pool;
mod rules;

pub use pool::Database;

use agile_net_core::error::{Error, Result};
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};

// ==================== 密码与令牌 ====================

/// Argon2id 密码哈希（OWASP 推荐参数：64MB / t=3 / p=4）
pub fn hash_password(password: &str) -> Result<String> {
    let random_bytes: [u8; 16] = rand::random();
    let salt = SaltString::encode_b64(&random_bytes).map_err(|e| Error::Other(e.to_string()))?;
    let params = Params::new(65536, 3, 4, None).map_err(|e| Error::Other(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| Error::Other(e.to_string()))?
        .to_string();
    Ok(hash)
}

/// 验证密码（Argon2id）
pub fn verify_password(password: &str, password_hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(password_hash).map_err(|e| Error::Other(e.to_string()))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// 生成强密码（sk 风格：`sk-` + 48 位混合字符，约 286 bits 熵）
pub fn generate_password() -> String {
    format!("sk-{}", random_alnum(48))
}

/// 生成 Relay PSK Token（`psk_` + 48 位）
pub fn generate_relay_token() -> String {
    format!("psk_{}", random_alnum(48))
}

/// 生成 Tunnel Token（`tun_` + 48 位）
pub fn generate_tunnel_token() -> String {
    format!("tun_{}", random_alnum(48))
}

/// 生成随机密钥（hex 64 字符，用于 JWT secret 等）
pub fn generate_secret_hex() -> String {
    let bytes: [u8; 32] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 hex（Token 落库哈希）
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn random_alnum(len: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::rng();
    (0..len)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}
