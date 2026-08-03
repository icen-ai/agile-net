//! Tunnel channel acquisition (TunnelPool)
//!
//! Manages channel acquisition to fan-out relay nodes.
//!
//! Design note: a channel (MuxChannel) is bound 1:1 to a target address; reusing an
//! established channel would send traffic to the wrong target, so **every acquire opens
//! a new channel**. Session-level reuse comes for free from MuxSession multiplexing
//! (a single TLS connection carries all channels).

use crate::error::Result;
use crate::relay::listener::RelayListener;
use crate::relay::mux::MuxChannel;

use std::sync::Arc;
use std::time::Duration;

/// Tunnel pool config
#[derive(Debug, Clone)]
pub struct TunnelPoolConfig {
    pub pool_size: usize,
    pub idle_timeout: Duration,
    pub max_lifetime: Duration,
}

impl Default for TunnelPoolConfig {
    fn default() -> Self {
        Self {
            pool_size: 5,
            idle_timeout: Duration::from_secs(300),
            max_lifetime: Duration::from_secs(1800),
        }
    }
}

/// Tunnel channel acquire handle (thin wrapper, keeps the backwards-compatible API).
pub struct TunnelPool {
    listener: Arc<RelayListener>,
    node_id: String,
}

impl TunnelPool {
    /// Create a new TunnelPool
    pub fn new(
        listener: Arc<RelayListener>,
        node_id: impl Into<String>,
        _config: TunnelPoolConfig,
    ) -> Self {
        Self {
            listener,
            node_id: node_id.into(),
        }
    }

    /// Pre-built channels currently available (no channel caching, always 0)
    pub async fn available(&self) -> usize {
        0
    }

    /// Open a new channel to the target.
    pub async fn acquire(&self, target_host: &str, target_port: u16) -> Result<MuxChannel> {
        self.listener
            .open_channel(&self.node_id, target_host, target_port)
            .await
    }

    /// Return a channel: channels are bound to a concrete target and cannot be reused; dropped (drop = close).
    pub async fn release(&self, channel: MuxChannel) {
        drop(channel);
    }

    /// Idle eviction: no cache, no-op (kept for API compatibility).
    pub async fn evict_expired(&self) {}
}
