//! Relay transit traffic accounting (TransitMeter)
//!
//! Accumulates bytes on the forwarding path by "source x destination" (the two adjacent
//! hops visible to this node):
//! - source (from): fan-in peer node_id / local proxy inbound "proxy" / fan-out connector name (reverse flow from upstream)
//! - destination (to): fan-out peer node_id / locally terminated "local" (proxy Forward outbound also counts as local)
//!
//! Zero hot-path intrusion: no per-byte counting; when a bridge closes, the totals from
//! `bridge()` are booked in one shot (one DashMap lookup + two atomic adds; long-lived
//! connections only enter the transit ledger on close — see `MuxSession::traffic()` for
//! real-time per-session traffic).

use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Cap on transit pairs (guards against unbounded growth from abnormal label combos;
/// normal scale is about peers x destinations).
const MAX_PAIRS: usize = 4096;

/// Source label for the local proxy inbound (fixed contract value).
pub const FROM_PROXY: &str = "proxy";
/// Destination label for locally terminated traffic (fixed contract value).
pub const TO_LOCAL: &str = "local";

/// Counters for a single transit pair.
#[derive(Default)]
struct PairBytes {
    up: AtomicU64,
    down: AtomicU64,
}

/// Transit pair snapshot (up = from->to bytes, down = to->from bytes).
#[derive(Debug, Clone)]
pub struct TransitPair {
    pub from: String,
    pub to: String,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

/// Relay transit accounting table (one per node, metered from listener / connector / proxy).
#[derive(Default)]
pub struct TransitMeter {
    pairs: DashMap<(String, String), PairBytes>,
}

impl TransitMeter {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Book the bytes of a closed bridge (up = from->to, down = to->from).
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

    /// Snapshot: (total up, total down, all transit pairs) (sorted by total bytes desc, stable order).
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
        // descending: proxy->local (110) would come first, but peer-a->peer-b (303) is larger and leads
        assert_eq!(pairs[0].from, "peer-a");
        assert_eq!(pairs[0].to, "peer-b");
        assert_eq!(pairs[0].bytes_up, 101);
        assert_eq!(pairs[0].bytes_down, 202);
        assert_eq!(pairs[1].from, FROM_PROXY);
        assert_eq!(pairs[1].to, TO_LOCAL);
    }
}
