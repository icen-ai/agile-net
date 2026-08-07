//! AgileNet Client core engine
//!
//! Full data plane implementation (delegated credentials only):
//! 1. Parse a delegated connect link (anet://connect?...&account=d:<label>&password=psk_...)
//! 2. Dial the relay entries directly (TLS 1.3 + token data plane auth; failover across the disaster set)
//! 3. Multi-node route merging + local SOCKS5/HTTP proxy inbound
//! 4. Split tier: pull the token's rule vocabulary over the E2E config channel
//! 5. Optional system hosts maintenance from resolve rules
//!
//! Modules:
//! - `client`: multi-node engine (connection lifecycle / route merging / background tasks / local proxy inbound)
//! - `credential`: credential store (0600 JSON file)
//! - `connect_url`: anet://connect URL parse & generate (thin wrapper over `agile_net_core::link`)
//! - `custom_rules`: custom rules (GUI bypass / hosts mapping)
//! - `hosts`: system hosts file management

pub mod api;
pub mod daemon;

mod client;
mod connect_url;
mod credential;
mod custom_rules;
mod hosts;
mod notify;

pub use client::{
    AgileNetClient, ClientRule, ConnectParams, ManageableNode, NodeState, NodeStatus,
};
pub use agile_net_core::link::{FanoutLink, LINK_SCHEME, build_fanout_url, parse_fanout_url};
pub use connect_url::{ParsedConnect, connect_url_of, parse_connect_url};
pub use credential::{Credential, CredentialStore};
pub use custom_rules::{CustomBypassRule, CustomRules};
pub use hosts::HostsManager;
pub use notify::{Notification, NotificationCenter};

pub use agile_net_core::proxy::router::wildcard_match;
