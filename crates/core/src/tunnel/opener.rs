//! 通道开启抽象 (ChannelOpener)
//!
//! 统一「向某个节点打开数据通道」的动作：
//! - `RelayListener`：在上游节点上向指定下游 peer 打开通道
//! - `ClientTunnel`：在客户端到节点的隧道里打开通道（忽略 node_id，单上游）
//!
//! Proxy 入站通过该抽象把 Tunnel 出站解析到具体的通道来源。

use crate::error::Result;
use crate::relay::listener::RelayListener;
use crate::relay::mux::MuxChannel;
use crate::tunnel::client_tunnel::ClientTunnel;

use std::future::Future;
use std::pin::Pin;

/// 打开一条到目标地址的逻辑通道。
///
/// `node_id` 为路由规则中指定的目标节点标识：
/// - 对 `RelayListener`：下游 peer 的 node_id
/// - 对 `ClientTunnel`：忽略（隧道本身即通往该节点）
pub trait ChannelOpener: Send + Sync {
    fn open<'a>(
        &'a self,
        node_id: &'a str,
        target_host: &'a str,
        target_port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<MuxChannel>> + Send + 'a>>;

    /// 途径核算用的去向标识（默认取规则 node_id；自动选路的开启器覆盖为实际对端）。
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
    ) -> Pin<Box<dyn Future<Output = Result<MuxChannel>> + Send + 'a>> {
        Box::pin(async move { self.open_channel(node_id, target_host, target_port).await })
    }
}

impl ChannelOpener for ClientTunnel {
    fn open<'a>(
        &'a self,
        _node_id: &'a str,
        target_host: &'a str,
        target_port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<MuxChannel>> + Send + 'a>> {
        Box::pin(async move { self.open_channel(target_host, target_port).await })
    }
}

/// 按通告路由表自动选择下游 peer 的开启器（节点本地代理用）。
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
    ) -> Pin<Box<dyn Future<Output = Result<MuxChannel>> + Send + 'a>> {
        Box::pin(async move {
            // 优先使用规则指定的节点，其次按通告路由自动解析
            let peer = if !node_id.is_empty() {
                node_id.to_string()
            } else {
                self.listener.resolve_peer(target_host).ok_or_else(|| {
                    crate::error::Error::NotFound(format!(
                        "no downstream peer serves {target_host}"
                    ))
                })?
            };
            self.listener
                .open_channel(&peer, target_host, target_port)
                .await
        })
    }

    fn transit_label<'a>(&'a self, node_id: &'a str, target_host: &'a str) -> String {
        // 与 open 同一解析口径：规则指定优先，否则按通告路由自动解析
        if !node_id.is_empty() {
            node_id.to_string()
        } else {
            self.listener
                .resolve_peer(target_host)
                .unwrap_or_else(|| "?".to_string())
        }
    }
}
