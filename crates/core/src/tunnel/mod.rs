//! TLS tunnel module: connection pool, TLS config and client tunnel.

pub mod client_tunnel;
pub mod opener;
pub mod pool;
pub mod tls;

pub use client_tunnel::ClientTunnel;
pub use opener::ChannelOpener;
pub use pool::{TunnelPool, TunnelPoolConfig};
pub use tls::TlsConfigBuilder;
