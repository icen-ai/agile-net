//! AgileNet Client core engine
//!
//! Full data plane implementation:
//! 1. Log in to the node API (access + refresh + tunnel_token)
//! 2. Pull route config and establish ClientTunnel (TLS 1.3 + tunnel_token data plane auth)
//! 3. Multi-node route merging + local SOCKS5/HTTP proxy inbound
//! 4. Long-poll config hot reload + heartbeat report + auto reconnect
//! 5. Optional system hosts maintenance from resolve rules
//!
//! Modules:
//! - `client`: multi-node engine (connection lifecycle / route merging / background tasks / local proxy inbound)
//! - `credential`: credential store (OS keyring preferred, 0600 file fallback, legacy plaintext auto-migration)
//! - `config_cache`: offline node config cache
//! - `connect_url`: agilenet://connect URL parse & generate
//! - `custom_rules`: custom rules (GUI bypass / hosts mapping)
//! - `hosts`: system hosts file management

use std::path::PathBuf;

pub mod api;
pub mod daemon;

mod client;
mod config_cache;
mod connect_url;
mod credential;
mod custom_rules;
mod hosts;

pub use client::{
    AgileNetClient, ClientRule, ConnectParams, ManageableNode, NodeState, NodeStatus,
};
pub use config_cache::{CachedNodeConfig, ConfigCache};
pub use agile_net_core::link::{FanoutLink, LINK_SCHEME, build_fanout_url, parse_fanout_url};
pub use connect_url::{ParsedConnect, connect_url_of, parse_connect_url};
pub use credential::{Credential, CredentialStore};
pub use custom_rules::{CustomBypassRule, CustomRules};
pub use hosts::HostsManager;

pub use agile_net_core::proxy::router::wildcard_match;

fn home_dir() -> PathBuf {
    std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}
