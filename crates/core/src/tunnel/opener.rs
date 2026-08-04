//! Channel opener abstraction (ChannelOpener)
//!
//! Unifies "open a data channel to some node":
//! - `RelayListener`: open a channel to a given fan-out peer on the fan-in node
//! - `ClientTunnel`: open a channel inside the client-to-node tunnel (node_id ignored, single fan-in side)
//!
//! The proxy inbound resolves Tunnel outbounds to a concrete channel source through this abstraction.

use crate::error::Result;
use crate::relay::listener::RelayListener;
use crate::tunnel::client_tunnel::ClientTunnel;

use std::future::Future;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};

/// Any bidirectional async stream usable as a data channel.
pub trait AsyncChannel: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncChannel for T {}

/// Boxed data channel (consumers only need AsyncRead + AsyncWrite + Send + Unpin).
///
/// The opener returns boxed streams rather than concrete `MuxChannel`s, so implementations may
/// wrap the raw channel — federation P3's delegated opener seals E2E record encryption around
/// it (`E2eStream`) transparently to every consumer.
pub type BoxedChannel = Box<dyn AsyncChannel + Send + Unpin>;

/// Open a logical channel to a target address.
///
/// `node_id` is the target node from the routing rule:
/// - for `RelayListener`: the fan-out peer's node_id
/// - for `ClientTunnel`: ignored (the tunnel itself leads to that node)
pub trait ChannelOpener: Send + Sync {
    fn open<'a>(
        &'a self,
        node_id: &'a str,
        target_host: &'a str,
        target_port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<BoxedChannel>> + Send + 'a>>;

    /// Destination label for transit accounting (defaults to the rule's node_id; auto-routing openers override with the actual peer).
    fn transit_label<'a>(&'a self, node_id: &'a str, _target_host: &'a str) -> String {
        node_id.to_string()
    }
}

impl ChannelOpener for RelayListener {
    fn open<'a>(
        &'a self,
        node_id: &'a str,
        target_host: &'a str,
        target_port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<BoxedChannel>> + Send + 'a>> {
        Box::pin(async move {
            let ch = self.open_channel(node_id, target_host, target_port).await?;
            Ok(Box::new(ch) as BoxedChannel)
        })
    }
}

impl ChannelOpener for ClientTunnel {
    fn open<'a>(
        &'a self,
        _node_id: &'a str,
        target_host: &'a str,
        target_port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<BoxedChannel>> + Send + 'a>> {
        Box::pin(async move {
            let ch = self.open_channel(target_host, target_port).await?;
            Ok(Box::new(ch) as BoxedChannel)
        })
    }
}

/// Opener that auto-selects a fan-out peer from the advertised routing table (for the node's local proxy).
pub struct PeerAutoOpener {
    listener: std::sync::Arc<RelayListener>,
}

impl PeerAutoOpener {
    pub fn new(listener: std::sync::Arc<RelayListener>) -> Self {
        Self { listener }
    }
}

impl ChannelOpener for PeerAutoOpener {
    fn open<'a>(
        &'a self,
        node_id: &'a str,
        target_host: &'a str,
        target_port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<BoxedChannel>> + Send + 'a>> {
        Box::pin(async move {
            // prefer the rule-specified node, otherwise auto-resolve via advertised routes
            let peer = if !node_id.is_empty() {
                node_id.to_string()
            } else {
                self.listener.resolve_peer(target_host).ok_or_else(|| {
                    crate::error::Error::NotFound(format!(
                        "no downstream peer serves {target_host}"
                    ))
                })?
            };
            let ch = self
                .listener
                .open_channel(&peer, target_host, target_port)
                .await?;
            Ok(Box::new(ch) as BoxedChannel)
        })
    }

    fn transit_label<'a>(&'a self, node_id: &'a str, target_host: &'a str) -> String {
        // same resolution as open: rule-specified first, else auto-resolve via advertised routes
        if !node_id.is_empty() {
            node_id.to_string()
        } else {
            self.listener
                .resolve_peer(target_host)
                .unwrap_or_else(|| "?".to_string())
        }
    }
}
