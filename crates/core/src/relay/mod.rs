//! Relay 穿透隧道模块
//!
//! 节点间建立 TLS 1.3 加密隧道，多路复用 TCP 连接。

pub mod bridge;
pub mod connector;
pub mod listener;
pub mod mux;

pub use bridge::bridge;
pub use connector::{ConnectionState, RelayConnector};
pub use listener::{
    AuthIdentity, PeerEvent, RelayListener, StaticTokenValidator, TokenValidator, build_acl_router,
    constant_time_eq,
};
pub use mux::{MuxChannel, MuxSession};
