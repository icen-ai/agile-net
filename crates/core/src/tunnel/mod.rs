//! TLS 隧道连接模块：连接池、TLS 配置与客户端隧道。

pub mod client_tunnel;
pub mod opener;
pub mod pool;
pub mod tls;

pub use client_tunnel::ClientTunnel;
pub use opener::ChannelOpener;
pub use pool::{TunnelPool, TunnelPoolConfig};
pub use tls::TlsConfigBuilder;
