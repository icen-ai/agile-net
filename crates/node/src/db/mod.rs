//! SQLite database module (see docs/database/schema.md)
//!
//! Built on rusqlite; versioned migrations run at startup. All sensitive fields
//! (passwords, tokens) are stored as Argon2id / SHA-256 hashes; plaintext is forbidden.
//!
//! Submodules split by domain (pure move, no logic change): pool (connection pool and
//! shared helpers) / migrations (versioned migrations) / paginate (shared paged-query helper) /
//! admin / rules / accounts / connectors / logs.
//! Public paths `db::xxx` are unchanged.

pub mod models;

mod accounts;
mod admin;
mod connectors;
mod logs;
mod migrations;
mod paginate;
mod pool;
mod rules;

pub use pool::Database;

use agile_net_core::error::{Error, Result};
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};

// ==================== Passwords & Tokens ====================

/// Argon2id password hash (OWASP-recommended params: 64MB / t=3 / p=4)
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

/// Verify password (Argon2id)
pub fn verify_password(password: &str, password_hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(password_hash).map_err(|e| Error::Other(e.to_string()))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// Generate a strong password (sk style: `sk-` + 48 mixed chars, ~286 bits entropy)
pub fn generate_password() -> String {
    format!("sk-{}", random_alnum(48))
}

/// Generate a Relay PSK token (`psk_` + 48 chars)
pub fn generate_relay_token() -> String {
    format!("psk_{}", random_alnum(48))
}

/// Generate a Tunnel token (`tun_` + 48 chars)
pub fn generate_tunnel_token() -> String {
    format!("tun_{}", random_alnum(48))
}

/// Generate a random secret (hex, 64 chars; for JWT secret etc.)
pub fn generate_secret_hex() -> String {
    let bytes: [u8; 32] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 hex (token storage hash): re-export of the shared core impl (keeps the `db::sha256_hex` path)
pub use agile_net_core::util::sha256_hex;

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
