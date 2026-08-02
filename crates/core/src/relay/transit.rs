//! 中继途径流量核算（TransitMeter）
//!
//! 在流转发路径上按「来源 × 去向」累计字节（本节点可见的相邻两跳）：
//! - 来源（from）：扇入对端 node_id / 本地代理入站 "proxy" / 扇出 connector 名（上游反向来流）
//! - 去向（to）：下游对端 node_id / 本机终结 "local"（代理 Forward 出站亦按本机终结计）
//!
//! 热路径零侵入：不做逐字节计数，桥接关闭时按 `bridge()` 返回的总量一次性入账
//!（一次 DashMap 查找 + 两次原子加；长连接的字节在其关闭时才入途径对账，
//! 实时会话级流量另见 `MuxSession::traffic()`）。

use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// 途径对数量上限（防异常标签组合无界增长；正常规模约为 对端数 × 去向数）。
const MAX_PAIRS: usize = 4096;

/// 本地代理入站的来源标识（契约固定值）。
pub const FROM_PROXY: &str = "proxy";
/// 本机终结的去向标识（契约固定值）。
pub const TO_LOCAL: &str = "local";

/// 单条途径对计数。
#[derive(Default)]
struct PairBytes {
    up: AtomicU64,
    down: AtomicU64,
}

/// 途径对快照（up = from→to 方向字节，down = to→from 方向字节）。
#[derive(Debug, Clone)]
pub struct TransitPair {
    pub from: String,
    pub to: String,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

/// 中继途径核算表（全节点共享一份，listener / connector / proxy 三处打点）。
#[derive(Default)]
pub struct TransitMeter {
    pairs: DashMap<(String, String), PairBytes>,
}

impl TransitMeter {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// 入账一条已关闭桥接的字节量（up = from→to 方向，down = to→from 方向）。
    pub fn record(&self, from: &str, to: &str, up: u64, down: u64) {
        if up == 0 && down == 0 {
            return;
        }
        let key = (from.to_string(), to.to_string());
        if !self.pairs.contains_key(&key) && self.pairs.len() >= MAX_PAIRS {
            return;
        }
        let entry = self.pairs.entry(key).or_default();
        entry.up.fetch_add(up, Ordering::Relaxed);
        entry.down.fetch_add(down, Ordering::Relaxed);
    }

    /// 快照：(汇总 up, 汇总 down, 全部途径对)（按总字节降序，稳定次序）。
    pub fn snapshot(&self) -> (u64, u64, Vec<TransitPair>) {
        let mut pairs: Vec<TransitPair> = self
            .pairs
            .iter()
            .map(|p| TransitPair {
                from: p.key().0.clone(),
                to: p.key().1.clone(),
                bytes_up: p.up.load(Ordering::Relaxed),
                bytes_down: p.down.load(Ordering::Relaxed),
            })
            .collect();
        pairs.sort_by(|a, b| {
            (b.bytes_up + b.bytes_down)
                .cmp(&(a.bytes_up + a.bytes_down))
                .then_with(|| a.from.cmp(&b.from))
                .then_with(|| a.to.cmp(&b.to))
        });
        let up = pairs.iter().map(|p| p.bytes_up).sum();
        let down = pairs.iter().map(|p| p.bytes_down).sum();
        (up, down, pairs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_snapshot() {
        let meter = TransitMeter::new();
        meter.record("peer-a", "peer-b", 100, 200);
        meter.record("peer-a", "peer-b", 1, 2);
        meter.record(FROM_PROXY, TO_LOCAL, 50, 60);
        meter.record("zero", "ignored", 0, 0);

        let (up, down, pairs) = meter.snapshot();
        assert_eq!(up, 151);
        assert_eq!(down, 262);
        assert_eq!(pairs.len(), 2);
        // 降序：proxy→local (110) 在前，peer-a→peer-b (303) 实际更大应在最前
        assert_eq!(pairs[0].from, "peer-a");
        assert_eq!(pairs[0].to, "peer-b");
        assert_eq!(pairs[0].bytes_up, 101);
        assert_eq!(pairs[0].bytes_down, 202);
        assert_eq!(pairs[1].from, FROM_PROXY);
        assert_eq!(pairs[1].to, TO_LOCAL);
    }
}
