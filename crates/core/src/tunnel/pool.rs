//! 隧道通道获取 (TunnelPool)
//!
//! 管理到下游 Relay Node 的通道获取。
//!
//! 设计说明：通道 (MuxChannel) 与目标地址一一绑定，复用已建立的通道
//! 会把流量发往错误目标，因此本实现**每次 acquire 都新建通道**。
//! 会话级复用由 MuxSession 的多路复用天然提供（单条 TLS 连接承载全部通道）。

use crate::error::Result;
use crate::relay::listener::RelayListener;
use crate::relay::mux::MuxChannel;

use std::sync::Arc;
use std::time::Duration;

/// 隧道连接池配置
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

/// 隧道通道获取器（薄封装，保留向后兼容 API）。
pub struct TunnelPool {
    listener: Arc<RelayListener>,
    node_id: String,
}

impl TunnelPool {
    /// 创建新的 TunnelPool
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

    /// 当前可用预建通道数（不做通道缓存，恒为 0）
    pub async fn available(&self) -> usize {
        0
    }

    /// 向目标打开一条新通道。
    pub async fn acquire(&self, target_host: &str, target_port: u16) -> Result<MuxChannel> {
        self.listener
            .open_channel(&self.node_id, target_host, target_port)
            .await
    }

    /// 归还通道：通道绑定具体目标不可复用，直接丢弃（drop 即关闭）。
    pub async fn release(&self, channel: MuxChannel) {
        drop(channel);
    }

    /// 空闲清理：无缓存，空操作（保留 API 兼容）。
    pub async fn evict_expired(&self) {}
}
