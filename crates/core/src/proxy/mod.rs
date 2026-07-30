//! Proxy 本地代理模块
//!
//! SOCKS5/HTTP 入站 + CIDR/HOST 路由 + 出站策略。

pub mod inbound;
pub mod outbound;
pub mod router;

pub use inbound::{ProxyInbound, ProxyStats};
pub use outbound::{DirectOutbound, TunnelOutbound};
pub use router::{Outbound, ProxyRouter};
