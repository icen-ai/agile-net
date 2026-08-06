//! Connection log (per-connection records at the local proxy inbound; design: docs/todo/conn-log.md).
//!
//! One record per inbound connection across all three outbound arms (Direct / Tunnel / Forward),
//! with the precedence layer that produced the decision (`HitLayer`). Disabled by default — every
//! path short-circuits on the enabled flag, so an off logger costs one atomic load per connection.
//! Storage is an in-memory ring (closed records) plus a live active table; persistence is the
//! caller's job via batched `take_unflushed` snapshots (smart flush, never per-record writes).

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Ring capacity for closed records (oldest evicted).
pub const CONLOG_CAPACITY: usize = 5000;
/// Unflushed batch threshold hint for the persistence task (it also flushes on an idle timer).
pub const CONLOG_FLUSH_BATCH: usize = 200;

/// Inbound protocol.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Socks5,
    Http,
}

/// Record source: plain local-proxy inbound vs. TUN-relayed (mihomo `MATCH,ANET-IN` loopback).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Proxy,
    TunRelay,
}

/// Outbound kind of a record (mirrors `router::Outbound` without borrowing the router).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum OutboundKind {
    Direct,
    Tunnel { node: String },
    Forward,
}

/// Precedence layer that produced the inbound decision (see ProxyRouter::decide_inbound_hit).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum HitLayer {
    /// User custom rule (GUI bypass / via-subscription bypass)
    UserBypass,
    /// Explicit route narrower than catch-all
    ExplicitRoute,
    /// Built-in preset bypass (LAN/loopback direct defaults)
    PresetBypass,
    /// Catch-all route / default outbound
    Default,
}

/// Record lifecycle state.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum RecState {
    Active,
    Closed,
    Failed { reason: String },
}

/// One connection record (row of the 连接记录 tab).
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ConnRec {
    pub id: u64,
    pub start_ms: i64,
    /// 0 while active
    pub end_ms: i64,
    pub host: String,
    pub port: u16,
    /// hosts-mapping rewrite target (None = not rewritten)
    pub mapped_to: Option<String>,
    pub proto: Proto,
    pub source: Source,
    pub outbound: OutboundKind,
    pub hit: HitLayer,
    pub up: u64,
    pub down: u64,
    pub state: RecState,
}

/// Live byte counters of an active connection (shared with the CountingIo wrapper on the client stream).
#[derive(Default)]
pub struct ActiveCounters {
    /// Bytes read from the client (uplink)
    pub up: AtomicU64,
    /// Bytes written to the client (downlink)
    pub down: AtomicU64,
}

/// Query filter (all fields optional; offset/limit drive the 50-row pages).
#[derive(Default, Debug)]
pub struct ConnFilter {
    /// Case-insensitive substring on host (and mapped_to)
    pub keyword: Option<String>,
    /// "direct" | "tunnel" | "forward"
    pub outbound: Option<String>,
    /// "active" | "closed" | "failed"
    pub state: Option<String>,
    /// TunRelay rows are hidden unless source=Some("tun_relay")/"all" is requested
    pub source: Option<String>,
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
    pub offset: usize,
    pub limit: usize,
}

/// Query result page.
#[derive(Serialize)]
pub struct QueryOut {
    pub total: usize,
    pub items: Vec<ConnRec>,
}

/// Session totals for the toolbar (live: active rows contribute current counter values).
#[derive(Serialize)]
pub struct Totals {
    pub active: usize,
    pub closed: usize,
    pub up: u64,
    pub down: u64,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Kill switch of an active connection (oneshot fired into the inbound task's select).
type KillTx = tokio::sync::oneshot::Sender<()>;

/// Active table entry: the record template, live counters, optional kill switch.
type ActiveEntry = (ConnRec, Arc<ActiveCounters>, Option<KillTx>);

/// The connection logger. Handle shared via Arc; all hot paths lock-free except the
/// closed/unflushed VecDeques (short Mutex, only on finalize).
pub struct ConnLog {
    enabled: AtomicBool,
    tun_relay: AtomicBool,
    next_id: AtomicU64,
    closed: Mutex<VecDeque<ConnRec>>,
    active: DashMap<u64, ActiveEntry>,
    unflushed: Mutex<Vec<ConnRec>>,
}

impl Default for ConnLog {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnLog {
    pub fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            tun_relay: AtomicBool::new(false),
            next_id: AtomicU64::new(1),
            closed: Mutex::new(VecDeque::new()),
            active: DashMap::new(),
            unflushed: Mutex::new(Vec::new()),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Toggle logging. Disabling finalizes in-flight rows as Closed (bytes so far), so history stays coherent.
    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
        if !on {
            let now = now_ms();
            let drained: Vec<u64> = self.active.iter().map(|e| *e.key()).collect();
            for id in drained {
                if let Some((_, (mut rec, ctr, _))) = self.active.remove(&id) {
                    rec.up = ctr.up.load(Ordering::Relaxed);
                    rec.down = ctr.down.load(Ordering::Relaxed);
                    rec.end_ms = now;
                    rec.state = RecState::Closed;
                    self.push_closed(rec);
                }
            }
        }
    }

    /// TUN relay marking (desktop sets it with tun_mode; records begun while on carry Source::TunRelay).
    pub fn set_tun_relay(&self, on: bool) {
        self.tun_relay.store(on, Ordering::Relaxed);
    }

    fn push_closed(&self, rec: ConnRec) {
        let mut q = self.closed.lock().unwrap();
        q.push_back(rec.clone());
        while q.len() > CONLOG_CAPACITY {
            q.pop_front();
        }
        drop(q);
        self.unflushed.lock().unwrap().push(rec);
    }

    /// Begin an Active record; None when disabled (callers then skip stream wrapping).
    #[allow(clippy::too_many_arguments)]
    pub fn begin(
        self: &Arc<Self>,
        proto: Proto,
        host: &str,
        port: u16,
        mapped_to: Option<String>,
        outbound: OutboundKind,
        hit: HitLayer,
    ) -> Option<(u64, Arc<ActiveCounters>)> {
        if !self.is_enabled() {
            return None;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let ctr = Arc::new(ActiveCounters::default());
        let rec = ConnRec {
            id,
            start_ms: now_ms(),
            end_ms: 0,
            host: host.to_string(),
            port,
            mapped_to,
            proto,
            source: if self.tun_relay.load(Ordering::Relaxed) {
                Source::TunRelay
            } else {
                Source::Proxy
            },
            outbound,
            hit,
            up: 0,
            down: 0,
            state: RecState::Active,
        };
        self.active.insert(id, (rec, ctr.clone(), None));
        Some((id, ctr))
    }

    /// Register the kill switch of an in-flight record (called right after begin by the inbound guard).
    pub fn attach_kill(&self, id: u64, tx: KillTx) {
        if let Some(mut e) = self.active.get_mut(&id) {
            e.value_mut().2 = Some(tx);
        }
    }

    /// Force-close an active connection (row right-click 「强制打断」): fires the kill switch into the
    /// inbound task's select; the task then unwinds and the guard finalizes the row as Closed.
    pub fn kill(&self, id: u64) -> bool {
        let tx = self
            .active
            .get_mut(&id)
            .and_then(|mut e| e.value_mut().2.take());
        match tx {
            Some(tx) => {
                let _ = tx.send(());
                true
            }
            None => false,
        }
    }

    /// Finalize an Active record as Closed (counter values become final).
    pub fn end(&self, id: u64) {
        if let Some((_, (mut rec, ctr, _))) = self.active.remove(&id) {
            rec.up = ctr.up.load(Ordering::Relaxed);
            rec.down = ctr.down.load(Ordering::Relaxed);
            rec.end_ms = now_ms();
            rec.state = RecState::Closed;
            self.push_closed(rec);
        }
    }

    /// Finalize an Active record as Failed (dial/handshake error).
    pub fn end_failed(&self, id: u64, reason: String) {
        if let Some((_, (mut rec, ctr, _))) = self.active.remove(&id) {
            rec.up = ctr.up.load(Ordering::Relaxed);
            rec.down = ctr.down.load(Ordering::Relaxed);
            rec.end_ms = now_ms();
            rec.state = RecState::Failed { reason };
            self.push_closed(rec);
        }
    }

    /// One-shot Failed record helper for failures before/without a begin (no-op when disabled).
    #[allow(clippy::too_many_arguments)]
    pub fn fail(
        self: &Arc<Self>,
        proto: Proto,
        host: &str,
        port: u16,
        mapped_to: Option<String>,
        outbound: OutboundKind,
        hit: HitLayer,
        reason: String,
    ) {
        if let Some((id, _)) = self.begin(proto, host, port, mapped_to, outbound, hit) {
            self.end_failed(id, reason);
        }
    }

    /// Newest-first filtered page (active rows merged in with live counter values).
    pub fn query(&self, f: &ConnFilter) -> QueryOut {
        let kw = f.keyword.as_ref().map(|k| k.to_lowercase());
        let mut rows: Vec<ConnRec> = Vec::new();
        for e in self.active.iter() {
            let (rec, ctr, _) = e.value();
            let mut r = rec.clone();
            r.up = ctr.up.load(Ordering::Relaxed);
            r.down = ctr.down.load(Ordering::Relaxed);
            rows.push(r);
        }
        rows.extend(self.closed.lock().unwrap().iter().cloned());
        rows.sort_by(|a, b| b.id.cmp(&a.id));
        let want_tun = matches!(f.source.as_deref(), Some("tun_relay") | Some("all"));
        let matches = |r: &&ConnRec| {
            if !want_tun && r.source == Source::TunRelay {
                return false;
            }
            if let Some(k) = &kw {
                let in_host = r.host.to_lowercase().contains(k);
                let in_mapped = r
                    .mapped_to
                    .as_ref()
                    .is_some_and(|m| m.to_lowercase().contains(k));
                if !in_host && !in_mapped {
                    return false;
                }
            }
            if let Some(o) = &f.outbound {
                let kind = match &r.outbound {
                    OutboundKind::Direct => "direct",
                    OutboundKind::Tunnel { .. } => "tunnel",
                    OutboundKind::Forward => "forward",
                };
                if o != kind {
                    return false;
                }
            }
            if let Some(s) = &f.state {
                let st = match &r.state {
                    RecState::Active => "active",
                    RecState::Closed => "closed",
                    RecState::Failed { .. } => "failed",
                };
                if s != st {
                    return false;
                }
            }
            if f.from_ms.is_some_and(|from| r.start_ms < from) {
                return false;
            }
            if f.to_ms.is_some_and(|to| r.start_ms > to) {
                return false;
            }
            true
        };
        let iter_rows: Vec<&ConnRec> = rows.iter().filter(&matches).collect();
        let total = iter_rows.len();
        let items = if f.limit == 0 {
            Vec::new()
        } else {
            iter_rows
                .into_iter()
                .skip(f.offset)
                .take(f.limit)
                .cloned()
                .collect()
        };
        QueryOut { total, items }
    }

    /// Session totals (live values for active rows).
    pub fn totals(&self) -> Totals {
        let mut t = Totals {
            active: 0,
            closed: 0,
            up: 0,
            down: 0,
        };
        for e in self.active.iter() {
            t.active += 1;
            t.up += e.value().1.up.load(Ordering::Relaxed);
            t.down += e.value().1.down.load(Ordering::Relaxed);
        }
        for r in self.closed.lock().unwrap().iter() {
            t.closed += 1;
            t.up += r.up;
            t.down += r.down;
        }
        t
    }

    /// One-click clear (in-memory rows + pending flush buffer; the persistence file is the caller's job).
    pub fn clear(&self) {
        self.closed.lock().unwrap().clear();
        self.unflushed.lock().unwrap().clear();
        self.active.clear();
    }

    /// Pending rows for the persistence task (takes the buffer).
    pub fn take_unflushed(&self) -> Vec<ConnRec> {
        std::mem::take(&mut *self.unflushed.lock().unwrap())
    }

    pub fn unflushed_len(&self) -> usize {
        self.unflushed.lock().unwrap().len()
    }

    /// Restore replayed rows at startup (all must be closed/failed; not marked unflushed).
    /// Ring keeps the newest CONLOG_CAPACITY rows; id sequence resumes beyond the max seen.
    pub fn restore(&self, recs: Vec<ConnRec>) {
        let mut max_id = 0;
        let mut q = self.closed.lock().unwrap();
        for rec in recs {
            if rec.state == RecState::Active {
                continue; // a stale active row from a crash means the connection died; skip it
            }
            max_id = max_id.max(rec.id);
            q.push_back(rec);
        }
        while q.len() > CONLOG_CAPACITY {
            q.pop_front();
        }
        drop(q);
        if max_id > 0 {
            self.next_id.store(max_id + 1, Ordering::Relaxed);
        }
    }
}

/// Client-stream wrapper that feeds the live counters of an active record.
/// `None` counters (logging disabled) degrade to a pass-through with one Option check per poll.
pub struct CountingIo<T> {
    inner: T,
    ctr: Option<Arc<ActiveCounters>>,
}

impl<T> CountingIo<T> {
    pub fn new(inner: T, ctr: Option<Arc<ActiveCounters>>) -> Self {
        Self { inner, ctr }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for CountingIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let (Poll::Ready(Ok(())), Some(c)) = (&r, &self.ctr) {
            let n = buf.filled().len() - before;
            if n > 0 {
                c.up.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
        r
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for CountingIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let (Poll::Ready(Ok(n)), Some(c)) = (&r, &self.ctr) {
            c.down.fetch_add(*n as u64, Ordering::Relaxed);
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log() -> Arc<ConnLog> {
        Arc::new(ConnLog::new())
    }

    fn begin_one(l: &Arc<ConnLog>, host: &str) -> (u64, Arc<ActiveCounters>) {
        l.begin(Proto::Socks5, host, 443, None, OutboundKind::Direct, HitLayer::UserBypass)
            .expect("enabled")
    }

    #[test]
    fn disabled_by_default_and_short_circuits() {
        let l = log();
        assert!(!l.is_enabled());
        assert!(l
            .begin(Proto::Socks5, "a.com", 443, None, OutboundKind::Direct, HitLayer::Default)
            .is_none());
        l.fail(Proto::Http, "a.com", 80, None, OutboundKind::Direct, HitLayer::Default, "x".into());
        assert_eq!(l.totals().closed, 0);
    }

    #[test]
    fn begin_end_cycle_and_unflushed() {
        let l = log();
        l.set_enabled(true);
        let (id, ctr) = begin_one(&l, "a.com");
        ctr.up.fetch_add(100, Ordering::Relaxed);
        ctr.down.fetch_add(250, Ordering::Relaxed);
        // active row visible with live counters
        let q = l.query(&ConnFilter { limit: 50, ..Default::default() });
        assert_eq!(q.total, 1);
        assert_eq!(q.items[0].state, RecState::Active);
        assert_eq!(q.items[0].up, 100);
        l.end(id);
        let q = l.query(&ConnFilter { limit: 50, ..Default::default() });
        assert_eq!(q.items[0].state, RecState::Closed);
        assert_eq!(q.items[0].down, 250);
        assert!(q.items[0].end_ms > 0);
        assert_eq!(l.unflushed_len(), 1);
        assert_eq!(l.take_unflushed().len(), 1);
        assert_eq!(l.unflushed_len(), 0);
    }

    #[test]
    fn failed_records_and_disable_finalizes_inflight() {
        let l = log();
        l.set_enabled(true);
        l.fail(Proto::Socks5, "b.com", 443, None, OutboundKind::Forward, HitLayer::Default, "dial refused".into());
        let (id, _) = begin_one(&l, "c.com");
        l.set_enabled(false);
        let q = l.query(&ConnFilter { limit: 50, ..Default::default() });
        assert_eq!(q.total, 2);
        assert!(matches!(q.items.iter().find(|r| r.host == "b.com").unwrap().state, RecState::Failed { .. }));
        let c = q.items.iter().find(|r| r.id == id).unwrap();
        assert_eq!(c.state, RecState::Closed);
    }

    #[test]
    fn filters_and_pagination() {
        let l = log();
        l.set_enabled(true);
        for i in 0..120u64 {
            let kind = if i % 2 == 0 { OutboundKind::Direct } else { OutboundKind::Tunnel { node: "n".into() } };
            let (id, _) = l.begin(Proto::Socks5, &format!("h{i}.com"), 443, None, kind, HitLayer::Default).unwrap();
            l.end(id);
        }
        let page1 = l.query(&ConnFilter { limit: 50, ..Default::default() });
        assert_eq!(page1.total, 120);
        assert_eq!(page1.items.len(), 50);
        assert_eq!(page1.items[0].id, 120); // newest first
        let page3 = l.query(&ConnFilter { offset: 100, limit: 50, ..Default::default() });
        assert_eq!(page3.items.len(), 20);
        let kw = l.query(&ConnFilter { keyword: Some("h1.".into()), limit: 50, ..Default::default() });
        assert_eq!(kw.total, 1);
        let tunnel = l.query(&ConnFilter { outbound: Some("tunnel".into()), limit: 50, ..Default::default() });
        assert_eq!(tunnel.total, 60);
        let closed = l.query(&ConnFilter { state: Some("closed".into()), limit: 200, ..Default::default() });
        assert_eq!(closed.total, 120);
    }

    #[test]
    fn ring_capacity_and_restore() {
        let l = log();
        l.set_enabled(true);
        for i in 0..(CONLOG_CAPACITY + 10) as u64 {
            let (id, _) = begin_one(&l, &format!("x{i}"));
            l.end(id);
        }
        assert_eq!(l.totals().closed, CONLOG_CAPACITY);

        let l2 = log();
        let rows = l.query(&ConnFilter { limit: 6000, ..Default::default() }).items;
        l2.restore(rows);
        assert_eq!(l2.totals().closed, CONLOG_CAPACITY);
        // id sequence resumes beyond the restored max
        l2.set_enabled(true);
        let (id, _) = begin_one(&l2, "new");
        assert_eq!(id, (CONLOG_CAPACITY + 10 + 1) as u64);
    }

    #[test]
    fn tun_relay_marking_and_visibility() {
        let l = log();
        l.set_enabled(true);
        l.set_tun_relay(true);
        let (id, _) = begin_one(&l, "relay.com");
        l.end(id);
        // hidden by default
        assert_eq!(l.query(&ConnFilter { limit: 50, ..Default::default() }).total, 0);
        let all = l.query(&ConnFilter { source: Some("all".into()), limit: 50, ..Default::default() });
        assert_eq!(all.total, 1);
        assert_eq!(all.items[0].source, Source::TunRelay);
    }

    #[test]
    fn kill_fires_the_switch_once() {
        let l = log();
        l.set_enabled(true);
        let (id, _) = begin_one(&l, "k.com");
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        l.attach_kill(id, tx);
        assert!(l.kill(id));
        assert!(rx.blocking_recv().is_ok()); // fired
        assert!(!l.kill(id)); // second kill: switch already taken
    }

    #[tokio::test]
    async fn counting_io_counts_both_directions() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let ctr = Arc::new(ActiveCounters::default());
        let (a, mut b) = tokio::io::duplex(64);
        let mut w = CountingIo::new(a, Some(ctr.clone()));
        w.write_all(b"hello").await.unwrap();
        b.write_all(b"world!").await.unwrap();
        let mut buf = [0u8; 6];
        w.read_exact(&mut buf).await.unwrap();
        assert_eq!(ctr.down.load(Ordering::Relaxed), 5); // written to client
        assert_eq!(ctr.up.load(Ordering::Relaxed), 6); // read from client
    }
}
