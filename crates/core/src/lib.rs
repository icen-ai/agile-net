//! AgileNet Core — core network library
//!
//! Provides five submodules: relay, local proxy, TLS connection pool (tunnel),
//! wire protocol (proto) and config model (config).

pub mod config;
pub mod error;
pub mod proto;
pub mod proxy;
pub mod relay;
pub mod tunnel;
pub mod util;

/// Install the rustls default CryptoProvider (ring).
pub fn init_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
