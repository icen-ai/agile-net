//! Connection log (per-target aggregated connection records at the local proxy inbound; docs/todo/conn-log.md).
//!
//! Two layers:
//! - **Per-connection ring** (`ConnRec`, capacity-capped): the raw evidence — one row per inbound connection
//!   across all three outbound arms (Direct / Tunnel / Forward) with the precedence layer (`HitLayer`).
//! - **Per-target aggregation** (`hosts` map keyed by host:port): the 连接记录 tab's primary view — one row per
//!   target with live counters, session totals, and a persisted historical baseline (conn-stats.json snapshot;
//!   smart flush, never per-connection writes).
//!
//! Disabled by default — every path short-circuits on the enabled flag, so an off logger costs one atomic
//! load per connection.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Ring capacity for closed per-connection records (oldest evicted).
/// (The dirty-flag flush cadence is driven by the desktop task: 5s tick / 30s idle sweep.)
pub const CONLOG_CAPACITY: usize = 5000;

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

/// One per-connection record (ring layer; detail expand / agent evidence source).
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

/// Live byte counters (shared with the CountingIo wrapper on the client stream; also the per-target cell's).
#[derive(Default)]
pub struct ActiveCounters {
    /// Bytes read from the client (uplink)
    pub up: AtomicU64,
    /// Bytes written to the client (downlink)
    pub down: AtomicU64,
}

/// Query filter (all fields optional; offset/limit drive the 50-row pages).
/// `outbound` / `state` / `hit` accept comma-separated multi-values (OR) — the header funnel
/// popovers are multi-select by design.
#[derive(Default, Debug)]
pub struct ConnFilter {
    /// Case-insensitive substring on host (and mapped_to)
    pub keyword: Option<String>,
    /// "direct" | "tunnel" | "forward" (comma-separated OR set)
    pub outbound: Option<String>,
    /// per-conn query: "active"|"closed"|"failed"; per-target query: active = has live conns, closed = none, failed = has failures (comma-separated OR set)
    pub state: Option<String>,
    /// HitLayer snake_case set (user_bypass / explicit_route / preset_bypass / default; comma-separated OR)
    pub hit: Option<String>,
    /// TunRelay rows are hidden unless source=Some("tun_relay")/"all" is requested
    pub source: Option<String>,
    /// Per-target sort "col:dir" (col = last|conns|target, dir = asc|desc; default last:desc).
    /// Live targets always pin to the top regardless (operator attention first).
    pub sort: Option<String>,
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

/// One aggregated target row (the 连接记录 tab's primary view).
#[derive(Clone, Serialize)]
pub struct HostStat {
    pub key: String,
    pub host: String,
    pub port: u16,
    /// connection counts (this session)
    pub conns: u64,
    pub fails: u64,
    /// currently open connections
    pub active: u64,
    /// this-session cumulative bytes (live-inclusive)
    pub sess_up: u64,
    pub sess_down: u64,
    /// historical cumulative bytes (persisted baseline, excludes this session)
    pub hist_up: u64,
    pub hist_down: u64,
    pub first_ms: i64,
    pub last_ms: i64,
    /// last connection's outbound / hit layer / source
    pub outbound: OutboundKind,
    pub hit: HitLayer,
    pub source: Source,
}

#[derive(Serialize)]
pub struct HostQueryOut {
    pub total: usize,
    pub items: Vec<HostStat>,
}

/// Persisted per-target cumulative (conn-stats.json snapshot).
#[derive(Clone, Serialize, Deserialize)]
pub struct HostDiskStat {
    pub host: String,
    pub port: u16,
    pub up: u64,
    pub down: u64,
}

/// Session totals for the toolbar (target-aggregated; live values included).
#[derive(Serialize)]
pub struct Totals {
    pub active: usize,
    pub hosts: usize,
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

/// Per-target aggregation cell (live counters are shared with the CountingIo wrappers of its connections).
struct HostAgg {
    host: String,
    port: u16,
    first_ms: i64,
    last_ms: AtomicI64,
    conns: AtomicU64,
    fails: AtomicU64,
    active: AtomicU64,
    live: Arc<ActiveCounters>,
    hist_up: u64,
    hist_down: u64,
    meta: Mutex<(OutboundKind, HitLayer, Source)>,
}

impl HostAgg {
    fn new(host: &str, port: u16, hist_up: u64, hist_down: u64) -> Self {
        Self {
            host: host.to_string(),
            port,
            first_ms: now_ms(),
            last_ms: AtomicI64::new(now_ms()),
            conns: AtomicU64::new(0),
            fails: AtomicU64::new(0),
            active: AtomicU64::new(0),
            live: Arc::new(ActiveCounters::default()),
            hist_up,
            hist_down,
            meta: Mutex::new((OutboundKind::Direct, HitLayer::Default, Source::Proxy)),
        }
    }
}

/// What begin() hands back to the inbound guard: the record id plus the two counter targets
/// (per-connection for the ring row, per-target for the aggregated cell).
pub struct BeginHandle {
    pub id: u64,
    pub conn: Arc<ActiveCounters>,
    pub agg: Arc<ActiveCounters>,
}

/// The connection logger. Handle shared via Arc; hot paths lock-free except the closed VecDeque
/// (short Mutex, only on finalize) and the per-target meta Mutex.
pub struct ConnLog {
    enabled: AtomicBool,
    tun_relay: AtomicBool,
    next_id: AtomicU64,
    closed: Mutex<VecDeque<ConnRec>>,
    active: DashMap<u64, ActiveEntry>,
    hosts: DashMap<String, Arc<HostAgg>>,
    dirty: AtomicBool,
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
            hosts: DashMap::new(),
            dirty: AtomicBool::new(false),
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
            let had_inflight = !drained.is_empty();
            for id in drained {
                if let Some((_, (mut rec, ctr, _))) = self.active.remove(&id) {
                    self.agg_of(&rec.host, rec.port).map(|a| a.active.fetch_sub(1, Ordering::Relaxed));
                    rec.up = ctr.up.load(Ordering::Relaxed);
                    rec.down = ctr.down.load(Ordering::Relaxed);
                    rec.end_ms = now;
                    rec.state = RecState::Closed;
                    self.push_closed(rec);
                }
            }
            if had_inflight {
                self.dirty.store(true, Ordering::Relaxed);
            }
        }
    }

    /// TUN relay marking (desktop sets it with tun_mode; records begun while on carry Source::TunRelay).
    pub fn set_tun_relay(&self, on: bool) {
        self.tun_relay.store(on, Ordering::Relaxed);
    }

    fn agg_of(&self, host: &str, port: u16) -> Option<Arc<HostAgg>> {
        self.hosts
            .get(&format!("{}:{}", host.to_lowercase(), port))
            .map(|r| r.value().clone())
    }

    fn push_closed(&self, rec: ConnRec) {
        let mut q = self.closed.lock().unwrap();
        q.push_back(rec);
        while q.len() > CONLOG_CAPACITY {
            q.pop_front();
        }
        self.dirty.store(true, Ordering::Relaxed);
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
    ) -> Option<BeginHandle> {
        if !self.is_enabled() {
            return None;
        }
        let now = now_ms();
        let source = if self.tun_relay.load(Ordering::Relaxed) {
            Source::TunRelay
        } else {
            Source::Proxy
        };
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let ctr = Arc::new(ActiveCounters::default());
        let rec = ConnRec {
            id,
            start_ms: now,
            end_ms: 0,
            host: host.to_string(),
            port,
            mapped_to,
            proto,
            source,
            outbound: outbound.clone(),
            hit,
            up: 0,
            down: 0,
            state: RecState::Active,
        };
        // per-target aggregation cell (created with zero baseline; restore_stats primes historical baselines)
        let agg = self
            .hosts
            .entry(format!("{}:{}", host.to_lowercase(), port))
            .or_insert_with(|| Arc::new(HostAgg::new(host, port, 0, 0)))
            .value()
            .clone();
        agg.conns.fetch_add(1, Ordering::Relaxed);
        agg.active.fetch_add(1, Ordering::Relaxed);
        agg.last_ms.store(now, Ordering::Relaxed);
        *agg.meta.lock().unwrap() = (outbound, hit, source);
        self.active.insert(id, (rec, ctr.clone(), None));
        self.dirty.store(true, Ordering::Relaxed);
        Some(BeginHandle { id, conn: ctr, agg: agg.live.clone() })
    }

    /// Register the kill switch of an in-flight record (called right after begin by the inbound guard).
    pub fn attach_kill(&self, id: u64, tx: KillTx) {
        if let Some(mut e) = self.active.get_mut(&id) {
            e.value_mut().2 = Some(tx);
        }
    }

    /// Force-close an active connection (「强制打断」): fires the kill switch into the inbound task's
    /// select; the task then unwinds and the guard finalizes the row as Closed.
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

    /// Force-close every active connection to a target (aggregated row's 强制打断); returns how many fired.
    pub fn kill_target(&self, host: &str, port: u16) -> u32 {
        let host_lc = host.to_lowercase();
        let ids: Vec<u64> = self
            .active
            .iter()
            .filter(|e| e.value().0.host.to_lowercase() == host_lc && e.value().0.port == port)
            .map(|e| *e.key())
            .collect();
        let mut n = 0;
        for id in ids {
            if self.kill(id) {
                n += 1;
            }
        }
        n
    }

    fn finalize(&self, id: u64, failed: Option<String>) {
        if let Some((_, (mut rec, ctr, _))) = self.active.remove(&id) {
            if let Some(a) = self.agg_of(&rec.host, rec.port) {
                a.active.fetch_sub(1, Ordering::Relaxed);
                a.last_ms.store(now_ms(), Ordering::Relaxed);
                if failed.is_some() {
                    a.fails.fetch_add(1, Ordering::Relaxed);
                }
            }
            rec.up = ctr.up.load(Ordering::Relaxed);
            rec.down = ctr.down.load(Ordering::Relaxed);
            rec.end_ms = now_ms();
            rec.state = match failed {
                Some(r) => RecState::Failed { reason: r },
                None => RecState::Closed,
            };
            self.push_closed(rec);
        }
    }

    /// Finalize an Active record as Closed (counter values become final).
    pub fn end(&self, id: u64) {
        self.finalize(id, None);
    }

    /// Finalize an Active record as Failed (dial/handshake error).
    pub fn end_failed(&self, id: u64, reason: String) {
        self.finalize(id, Some(reason));
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
        if let Some(h) = self.begin(proto, host, port, mapped_to, outbound, hit) {
            self.end_failed(h.id, reason);
        }
    }

    /// Newest-first filtered page of per-connection records (ring layer; active rows merge live counters).
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
                if !o.split(',').any(|x| x == kind) {
                    return false;
                }
            }
            if let Some(s) = &f.state {
                let st = match &r.state {
                    RecState::Active => "active",
                    RecState::Closed => "closed",
                    RecState::Failed { .. } => "failed",
                };
                if !s.split(',').any(|x| x == st) {
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

    /// Aggregated per-target page (primary view of the 连接记录 tab), most-recent-activity first.
    pub fn query_hosts(&self, f: &ConnFilter) -> HostQueryOut {
        let kw = f.keyword.as_ref().map(|k| k.to_lowercase());
        let want_tun = matches!(f.source.as_deref(), Some("tun_relay") | Some("all"));
        let mut rows: Vec<HostStat> = self
            .hosts
            .iter()
            .map(|e| {
                let key = e.key().clone();
                let a = e.value();
                let (outbound, hit, source) = a.meta.lock().unwrap().clone();
                HostStat {
                    key,
                    host: a.host.clone(),
                    port: a.port,
                    conns: a.conns.load(Ordering::Relaxed),
                    fails: a.fails.load(Ordering::Relaxed),
                    active: a.active.load(Ordering::Relaxed),
                    sess_up: a.live.up.load(Ordering::Relaxed),
                    sess_down: a.live.down.load(Ordering::Relaxed),
                    hist_up: a.hist_up,
                    hist_down: a.hist_down,
                    first_ms: a.first_ms,
                    last_ms: a.last_ms.load(Ordering::Relaxed),
                    outbound,
                    hit,
                    source,
                }
            })
            .collect();
        rows.sort_by(|a, b| {
            // Live targets pin to the top (operator attention); the chosen column sorts within each tier
            let (col, desc) = f
                .sort
                .as_deref()
                .and_then(|s| s.split_once(':'))
                .map(|(c, d)| (c, d != "asc"))
                .unwrap_or(("last", true));
            (b.active > 0).cmp(&(a.active > 0)).then_with(|| {
                let ord = match col {
                    "conns" => a.conns.cmp(&b.conns),
                    "target" => a.host.to_lowercase().cmp(&b.host.to_lowercase()).then(a.port.cmp(&b.port)),
                    _ => a.last_ms.cmp(&b.last_ms),
                };
                if desc { ord.reverse() } else { ord }
            })
        });
        let matches = |r: &&HostStat| {
            if !want_tun && r.source == Source::TunRelay {
                return false;
            }
            if kw.as_ref().is_some_and(|k| !r.host.to_lowercase().contains(k)) {
                return false;
            }
            if let Some(o) = &f.outbound {
                let kind = match &r.outbound {
                    OutboundKind::Direct => "direct",
                    OutboundKind::Tunnel { .. } => "tunnel",
                    OutboundKind::Forward => "forward",
                };
                if !o.split(',').any(|x| x == kind) {
                    return false;
                }
            }
            if let Some(s) = &f.state {
                // OR over the comma-separated set (unknown values match nothing — fail-closed)
                let ok = s.split(',').any(|x| match x {
                    "active" => r.active > 0,
                    "closed" => r.active == 0,
                    "failed" => r.fails > 0,
                    _ => false,
                });
                if !ok {
                    return false;
                }
            }
            if let Some(h) = &f.hit {
                let layer = match r.hit {
                    HitLayer::UserBypass => "user_bypass",
                    HitLayer::ExplicitRoute => "explicit_route",
                    HitLayer::PresetBypass => "preset_bypass",
                    HitLayer::Default => "default",
                };
                if !h.split(',').any(|x| x == layer) {
                    return false;
                }
            }
            if f.from_ms.is_some_and(|from| r.last_ms < from) {
                return false;
            }
            if f.to_ms.is_some_and(|to| r.last_ms > to) {
                return false;
            }
            true
        };
        let iter_rows: Vec<&HostStat> = rows.iter().filter(&matches).collect();
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
        HostQueryOut { total, items }
    }

    /// Session totals for the toolbar (target-aggregated; live values included).
    pub fn totals(&self) -> Totals {
        let mut t = Totals {
            active: 0,
            hosts: 0,
            up: 0,
            down: 0,
        };
        for e in self.hosts.iter() {
            let a = e.value();
            t.hosts += 1;
            t.active += a.active.load(Ordering::Relaxed) as usize;
            t.up += a.live.up.load(Ordering::Relaxed);
            t.down += a.live.down.load(Ordering::Relaxed);
        }
        t
    }

    /// One-click clear (in-memory rows + aggregation map; the persistence file is the caller's job).
    pub fn clear(&self) {
        self.closed.lock().unwrap().clear();
        self.active.clear();
        self.hosts.clear();
        self.dirty.store(true, Ordering::Relaxed);
    }

    /// Dirty flag for the smart-flush task (set on begin/finalize/clear; taken = flushed).
    pub fn take_dirty(&self) -> bool {
        self.dirty.swap(false, Ordering::Relaxed)
    }

    pub fn has_active(&self) -> bool {
        !self.active.is_empty()
    }

    /// Persistence snapshot: per-target cumulative totals (historical baseline + live session bytes).
    pub fn stats_snapshot(&self) -> Vec<HostDiskStat> {
        self.hosts
            .iter()
            .map(|e| {
                let a = e.value();
                HostDiskStat {
                    host: a.host.clone(),
                    port: a.port,
                    up: a.hist_up + a.live.up.load(Ordering::Relaxed),
                    down: a.hist_down + a.live.down.load(Ordering::Relaxed),
                }
            })
            .collect()
    }

    /// Load the persisted baselines at startup (historical cumulative columns).
    pub fn restore_stats(&self, rows: Vec<HostDiskStat>) {
        for r in rows {
            let key = format!("{}:{}", r.host.to_lowercase(), r.port);
            self.hosts
                .entry(key)
                .or_insert_with(|| Arc::new(HostAgg::new(&r.host, r.port, r.up, r.down)));
        }
    }

    /// Restore replayed per-connection rows at startup (ring layer only; not marked dirty).
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

/// Client-stream wrapper feeding live counters (per-connection and/or per-target).
/// Both `None` (logging disabled) degrades to a pass-through with one Option check per poll.
pub struct CountingIo<T> {
    inner: T,
    conn: Option<Arc<ActiveCounters>>,
    agg: Option<Arc<ActiveCounters>>,
}

impl<T> CountingIo<T> {
    pub fn new(inner: T, conn: Option<Arc<ActiveCounters>>, agg: Option<Arc<ActiveCounters>>) -> Self {
        Self { inner, conn, agg }
    }

    #[inline]
    fn count(&self, up: u64, down: u64) {
        if let Some(c) = &self.conn {
            c.up.fetch_add(up, Ordering::Relaxed);
            c.down.fetch_add(down, Ordering::Relaxed);
        }
        if let Some(a) = &self.agg {
            a.up.fetch_add(up, Ordering::Relaxed);
            a.down.fetch_add(down, Ordering::Relaxed);
        }
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
        if let Poll::Ready(Ok(())) = &r {
            let n = (buf.filled().len() - before) as u64;
            if n > 0 {
                self.count(n, 0);
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
        if let Poll::Ready(Ok(n)) = &r {
            self.count(0, *n as u64);
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

    fn begin_one(l: &Arc<ConnLog>, host: &str) -> BeginHandle {
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
        assert_eq!(l.totals().hosts, 0);
    }

    #[test]
    fn per_target_aggregation_and_live_counters() {
        let l = log();
        l.set_enabled(true);
        // two connections to the same target, one to another
        let h1 = begin_one(&l, "A.com"); // case-insensitive key
        let h2 = begin_one(&l, "a.com");
        let h3 = begin_one(&l, "b.com");
        h1.agg.up.fetch_add(100, Ordering::Relaxed);
        h2.agg.up.fetch_add(50, Ordering::Relaxed);
        h3.agg.down.fetch_add(7, Ordering::Relaxed);
        let out = l.query_hosts(&ConnFilter { limit: 50, ..Default::default() });
        assert_eq!(out.total, 2); // A.com/a.com deduped
        let a = out.items.iter().find(|r| r.host == "A.com").unwrap();
        assert_eq!(a.conns, 2);
        assert_eq!(a.active, 2);
        assert_eq!(a.sess_up, 150);
        l.end(h1.id);
        let out = l.query_hosts(&ConnFilter { limit: 50, ..Default::default() });
        let a = out.items.iter().find(|r| r.host == "A.com").unwrap();
        assert_eq!(a.active, 1);
        // failed filter + kill_target
        l.end_failed(h2.id, "refused".into());
        let failed = l.query_hosts(&ConnFilter { state: Some("failed".into()), limit: 50, ..Default::default() });
        assert_eq!(failed.total, 1);
        l.end(h3.id);
    }

    #[test]
    fn live_targets_pin_first_and_sort_param() {
        let l = log();
        l.set_enabled(true);
        // three connections to zeta.com (one stays live), one to alpha.com (closed)
        let z1 = begin_one(&l, "zeta.com");
        let z2 = begin_one(&l, "zeta.com");
        let z3 = begin_one(&l, "zeta.com");
        let a1 = begin_one(&l, "alpha.com");
        l.end(a1.id);
        l.end(z2.id);
        l.end(z3.id);
        // alpha.com wears the newest timestamp — plain recency order would lead with it
        l.agg_of("zeta.com", 443).unwrap().last_ms.store(1_000, Ordering::Relaxed);
        l.agg_of("alpha.com", 443).unwrap().last_ms.store(9_999_999, Ordering::Relaxed);
        let out = l.query_hosts(&ConnFilter { limit: 50, ..Default::default() });
        assert_eq!(out.items[0].host, "zeta.com", "live targets pin above more-recent closed ones");
        // all closed now: the chosen column sorts within the tier
        l.end(z1.id);
        l.agg_of("zeta.com", 443).unwrap().last_ms.store(1_000, Ordering::Relaxed);
        l.agg_of("alpha.com", 443).unwrap().last_ms.store(9_999_999, Ordering::Relaxed);
        let recent = l.query_hosts(&ConnFilter { limit: 50, ..Default::default() });
        assert_eq!(recent.items[0].host, "alpha.com");
        let by_conns = l.query_hosts(&ConnFilter { sort: Some("conns:desc".into()), limit: 50, ..Default::default() });
        assert_eq!(by_conns.items[0].host, "zeta.com");
        let by_target = l.query_hosts(&ConnFilter { sort: Some("target:asc".into()), limit: 50, ..Default::default() });
        assert_eq!(by_target.items[0].host, "alpha.com");
    }

    #[test]
    fn kill_target_fires_all_matching() {
        let l = log();
        l.set_enabled(true);
        let h1 = begin_one(&l, "k.com");
        let h2 = begin_one(&l, "k.com");
        let (tx1, rx1) = tokio::sync::oneshot::channel::<()>();
        let (tx2, rx2) = tokio::sync::oneshot::channel::<()>();
        l.attach_kill(h1.id, tx1);
        l.attach_kill(h2.id, tx2);
        assert_eq!(l.kill_target("K.com", 443), 2);
        assert!(rx1.blocking_recv().is_ok());
        assert!(rx2.blocking_recv().is_ok());
    }

    #[test]
    fn snapshot_and_restore_baselines() {
        let l = log();
        l.set_enabled(true);
        let h = begin_one(&l, "s.com");
        h.agg.up.fetch_add(300, Ordering::Relaxed);
        l.end(h.id);
        let snap = l.stats_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].up, 300);

        let l2 = log();
        l2.restore_stats(snap);
        let out = l2.query_hosts(&ConnFilter { limit: 50, ..Default::default() });
        assert_eq!(out.items[0].hist_up, 300);
        assert_eq!(out.items[0].sess_up, 0);
        // new session bytes add on top of the baseline
        l2.set_enabled(true);
        let h2 = begin_one(&l2, "s.com");
        h2.agg.up.fetch_add(20, Ordering::Relaxed);
        let out = l2.query_hosts(&ConnFilter { limit: 50, ..Default::default() });
        assert_eq!(out.items[0].hist_up, 300);
        assert_eq!(out.items[0].sess_up, 20);
        assert_eq!(l2.stats_snapshot()[0].up, 320);
    }

    #[test]
    fn per_conn_ring_still_works() {
        let l = log();
        l.set_enabled(true);
        let h = begin_one(&l, "a.com");
        h.conn.up.fetch_add(100, Ordering::Relaxed);
        let q = l.query(&ConnFilter { limit: 50, ..Default::default() });
        assert_eq!(q.items[0].state, RecState::Active);
        assert_eq!(q.items[0].up, 100);
        l.end(h.id);
        let q = l.query(&ConnFilter { limit: 50, ..Default::default() });
        assert_eq!(q.items[0].state, RecState::Closed);
        assert_eq!(q.items[0].up, 100);
        assert!(l.take_dirty());
        assert!(!l.take_dirty());
    }

    #[test]
    fn tun_relay_marking_and_visibility() {
        let l = log();
        l.set_enabled(true);
        l.set_tun_relay(true);
        let h = begin_one(&l, "relay.com");
        l.end(h.id);
        assert_eq!(l.query(&ConnFilter { limit: 50, ..Default::default() }).total, 0);
        assert_eq!(l.query_hosts(&ConnFilter { limit: 50, ..Default::default() }).total, 0);
        let all = l.query_hosts(&ConnFilter { source: Some("all".into()), limit: 50, ..Default::default() });
        assert_eq!(all.total, 1);
        assert_eq!(all.items[0].source, Source::TunRelay);
    }

    #[tokio::test]
    async fn counting_io_counts_both_targets() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let conn = Arc::new(ActiveCounters::default());
        let agg = Arc::new(ActiveCounters::default());
        let (a, mut b) = tokio::io::duplex(64);
        let mut w = CountingIo::new(a, Some(conn.clone()), Some(agg.clone()));
        w.write_all(b"hello").await.unwrap();
        b.write_all(b"world!").await.unwrap();
        let mut buf = [0u8; 6];
        w.read_exact(&mut buf).await.unwrap();
        for c in [&conn, &agg] {
            assert_eq!(c.down.load(Ordering::Relaxed), 5);
            assert_eq!(c.up.load(Ordering::Relaxed), 6);
        }
    }
}
