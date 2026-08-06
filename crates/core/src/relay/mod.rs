//! Relay tunnel module
//!
//! TLS 1.3 encrypted tunnels between endpoints, multiplexing TCP connections.

pub mod acl;
pub mod bandwidth;
pub mod bridge;
pub mod connector;
pub mod e2e;
pub mod limit;
pub mod listener;
pub mod mux;
pub mod transit;

pub use acl::PeerAcl;
pub use bridge::bridge;
pub use connector::{
    ConnectionState, DelegationAdmin, DelegationConfig, DelegationGroupEntry, DelegationHooks,
    DelegationUpstream, RelayConnector,
};
pub use limit::TokenBucket;
pub use listener::{
    AuthIdentity, DelegatedIdentity, DelegatedRegistry, DelegatedToken, PeerEvent,
    RelayListener, StaticTokenValidator, TokenValidator, build_acl_router, constant_time_eq,
    delegated_session_key,
};
pub use mux::{MuxChannel, MuxSession, SessionEvents};
pub use transit::{FROM_PROXY, TO_LOCAL, TransitMeter, TransitPair};
