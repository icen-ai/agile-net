//! Local proxy module
//!
//! SOCKS5/HTTP inbound + CIDR/HOST routing + outbound policy.

pub mod inbound;
pub mod outbound;
pub mod router;

pub use inbound::{ProxyInbound, ProxyStats};
pub use outbound::{DirectOutbound, TunnelOutbound};
pub use router::{Outbound, ProxyRouter};
