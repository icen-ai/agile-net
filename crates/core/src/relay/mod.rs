//! Relay 穿透隧道模块
//!
//! 节点间建立 TLS 1.3 加密隧道，多路复用 TCP 连接。

pub mod acl;
pub mod bandwidth;
pub mod bridge;
pub mod connector;
pub mod limit;
pub mod listener;
pub mod mux;
pub mod transit;

pub use acl::PeerAcl;
pub use bridge::bridge;
pub use connector::{ConnectionState, RelayConnector};
pub use limit::TokenBucket;
pub use listener::{
    AuthIdentity, PeerEvent, RelayListener, StaticTokenValidator, TokenValidator, build_acl_router,
    constant_time_eq,
};
pub use mux::{MuxChannel, MuxSession};
pub use transit::{FROM_PROXY, TO_LOCAL, TransitMeter, TransitPair};
