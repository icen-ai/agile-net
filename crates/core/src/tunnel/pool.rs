//! 隧道连接池 (TunnelPool)
//!
//! 管理 Client / Node 到上游 Relay Node 的 TLS 长连接与通道池。
//! 支持连接复用、空闲回收与自动重连补满。

use crate::error::Result;
use crate::relay::listener::RelayListener;
use crate::relay::mux::MuxChannel;

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::debug;

/// 池化的通道条目
struct PooledItem {
    channel: MuxChannel,
    created_at: Instant,
    last_used: Instant,
}

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

/// 隧道连接池
pub struct TunnelPool {
    listener: Arc<RelayListener>,
    node_id: String,
    config: TunnelPoolConfig,
    pool: Mutex<Vec<PooledItem>>,
}

impl TunnelPool {
    /// 创建新的 TunnelPool
    pub fn new(
        listener: Arc<RelayListener>,
        node_id: impl Into<String>,
        config: TunnelPoolConfig,
    ) -> Self {
        Self {
            listener,
            node_id: node_id.into(),
            config,
            pool: Mutex::new(Vec::new()),
        }
    }

    /// 当前可用预建通道数
    pub async fn available(&self) -> usize {
        let pool = self.pool.lock().await;
        pool.len()
    }

    /// 从池中获取或在 RelayListener 上直接打开新通道
    pub async fn acquire(&self, target_host: &str, target_port: u16) -> Result<MuxChannel> {
        let mut pool = self.pool.lock().await;

        // 1. 寻找未过期的空闲通道
        let now = Instant::now();
        while let Some(item) = pool.pop() {
            if now.duration_since(item.created_at) < self.config.max_lifetime
                && now.duration_since(item.last_used) < self.config.idle_timeout
            {
                debug!("reusing pooled mux channel");
                return Ok(item.channel);
            }
        }
        drop(pool);

        // 2. 如果无可用缓存，向 Listener 打开新通道
        self.listener
            .open_channel(&self.node_id, target_host, target_port)
            .await
    }

    /// 归还未关闭的通道回池中
    pub async fn release(&self, channel: MuxChannel) {
        let mut pool = self.pool.lock().await;
        if pool.len() < self.config.pool_size {
            pool.push(PooledItem {
                channel,
                created_at: Instant::now(),
                last_used: Instant::now(),
            });
        }
    }

    /// 定理空闲与超时的通道
    pub async fn evict_expired(&self) {
        let mut pool = self.pool.lock().await;
        let now = Instant::now();
        let idle_timeout = self.config.idle_timeout;
        let max_lifetime = self.config.max_lifetime;

        pool.retain(|item| {
            now.duration_since(item.created_at) < max_lifetime
                && now.duration_since(item.last_used) < idle_timeout
        });
    }
}
