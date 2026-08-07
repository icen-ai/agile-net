//! Split out of subscription.rs: WS collection and aggregation (pure move, zero logic change)

use serde::Serialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::config::MIHOMO_CTRL_PORT;
use super::store::now_ts;

// ==================== Traffic stats (/traffic WS accumulation) ====================

/// Kernel traffic accumulator: /traffic WS pushes {up,down} (bytes for that second) each second;
/// session totals and latest per-second rates are recorded here. All-atomic, lock-free; zeroed on kernel stop (single reset at task exit).
#[derive(Debug, Default)]
pub struct TrafficStats {
    up_total: AtomicU64,
    down_total: AtomicU64,
    up_rate: AtomicU64,
    down_rate: AtomicU64,
}

/// Traffic snapshot (sub_traffic command response body)
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct TrafficSnapshot {
    pub up_total: u64,
    pub down_total: u64,
    pub up_rate: u64,
    pub down_rate: u64,
}

impl TrafficStats {
    fn add(&self, up: u64, down: u64) {
        self.up_total.fetch_add(up, Ordering::Relaxed);
        self.down_total.fetch_add(down, Ordering::Relaxed);
        self.up_rate.store(up, Ordering::Relaxed);
        self.down_rate.store(down, Ordering::Relaxed);
    }
    fn clear_rates(&self) {
        self.up_rate.store(0, Ordering::Relaxed);
        self.down_rate.store(0, Ordering::Relaxed);
    }
    pub(crate) fn reset(&self) {
        self.up_total.store(0, Ordering::Relaxed);
        self.down_total.store(0, Ordering::Relaxed);
        self.clear_rates();
    }
    pub fn snapshot(&self) -> TrafficSnapshot {
        TrafficSnapshot {
            up_total: self.up_total.load(Ordering::Relaxed),
            down_total: self.down_total.load(Ordering::Relaxed),
            up_rate: self.up_rate.load(Ordering::Relaxed),
            down_rate: self.down_rate.load(Ordering::Relaxed),
        }
    }
}

/// /traffic WS accumulation task: exponential backoff reconnect on drop (1s start, 30s cap;
/// backoff resets after a 10s-stable session); stop signal (incl. dropped sender) exits and zeroes counters.
pub(crate) async fn traffic_ws_loop(secret: String, stats: Arc<TrafficStats>, mut stop: tokio::sync::mpsc::Receiver<()>) {
    let mut backoff = 1u64;
    loop {
        let started = std::time::Instant::now();
        tokio::select! {
            _ = stop.recv() => break,
            _ = traffic_ws_session(&secret, &stats) => {}
        }
        // Disconnected: zero the rates (totals kept; resume accumulating after reconnect)
        stats.clear_rates();
        if started.elapsed() >= std::time::Duration::from_secs(10) {
            backoff = 1;
        }
        if tokio::time::timeout(std::time::Duration::from_secs(backoff), stop.recv())
            .await
            .is_ok()
        {
            break;
        }
        backoff = (backoff * 2).min(30);
    }
    stats.reset();
}

/// One /traffic WS session (semantics preserved: accumulate {up,down} text frames).
async fn traffic_ws_session(secret: &str, stats: &TrafficStats) -> Result<(), String> {
    traffic_ws_session_on(MIHOMO_CTRL_PORT, secret, stats).await
}

/// /traffic session with parameterized port (production uses the control plane port; tests inject a mock port).
async fn traffic_ws_session_on(port: u16, secret: &str, stats: &TrafficStats) -> Result<(), String> {
    ws_session_on(port, secret, "/traffic", &mut |payload| {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(payload) {
            stats.add(
                v["up"].as_u64().unwrap_or(0),
                v["down"].as_u64().unwrap_or(0),
            );
        }
    })
    .await
}

/// Generic collection reconnect loop (shared by /connections and /logs): exponential backoff
/// reconnect on drop (1s start, 30s cap; backoff resets after a 10s-stable session); stop signal (incl. dropped sender) exits.
pub(crate) async fn collect_ws_loop<F>(
    secret: String,
    path: &str,
    mut stop: tokio::sync::mpsc::Receiver<()>,
    mut handler: F,
) where
    F: FnMut(&[u8]) + Send,
{
    let mut backoff = 1u64;
    loop {
        let started = std::time::Instant::now();
        tokio::select! {
            _ = stop.recv() => break,
            _ = ws_session_on(MIHOMO_CTRL_PORT, &secret, path, &mut handler) => {}
        }
        if started.elapsed() >= std::time::Duration::from_secs(10) {
            backoff = 1;
        }
        if tokio::time::timeout(std::time::Duration::from_secs(backoff), stop.recv())
            .await
            .is_ok()
        {
            break;
        }
        backoff = (backoff * 2).min(30);
    }
}

/// Generic single WS session (handshake path parameterized): handshake → frame loop (text/binary
/// frames to handler / ping→pong / close ends normally). Minimal RFC 6455 client, only for the
/// loopback mihomo control plane; no extra dependencies.
async fn ws_session_on<F: FnMut(&[u8])>(
    port: u16,
    secret: &str,
    path: &str,
    handler: &mut F,
) -> Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|e| e.to_string())?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer {secret}\r\n\r\n",
        ws_key()
    );
    stream.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
    // HTTP 101 response headers (read up to \r\n\r\n)
    let mut head = Vec::with_capacity(256);
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut b).await.map_err(|e| e.to_string())?;
        head.push(b[0]);
        if head.len() > 8192 {
            return Err("WS 握手响应头过长".into());
        }
    }
    let head = String::from_utf8_lossy(&head);
    if !head.starts_with("HTTP/1.1 101") && !head.starts_with("HTTP/1.0 101") {
        return Err(format!(
            "WS 握手失败: {}",
            head.lines().next().unwrap_or("无状态行")
        ));
    }
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("WS 连接已关闭".into());
        }
        buf.extend_from_slice(&chunk[..n]);
        while let Some(frame) = parse_ws_frame(&buf)? {
            buf.drain(..frame.consumed);
            match frame.opcode {
                0x1 | 0x2 => {
                    if !frame.fin {
                        return Err("不支持分片帧".into());
                    }
                    handler(&frame.payload);
                }
                0x8 => return Ok(()), // close
                0x9 => {
                    // ping → pong (client frames must be masked)
                    let pong = build_ws_frame(0xA, &frame.payload);
                    stream.write_all(&pong).await.map_err(|e| e.to_string())?;
                }
                _ => {} // pong / others ignored
            }
        }
        if buf.len() > 1 << 20 {
            return Err("WS 帧缓冲超限".into());
        }
    }
}

struct WsFrame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
    consumed: usize,
}

/// Parse one server WS frame (RFC 6455): Ok(None) = insufficient data;
/// masked frames, reserved bits, and invalid control frames are protocol errors (server→client frames must not be masked).
fn parse_ws_frame(buf: &[u8]) -> Result<Option<WsFrame>, String> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let fin = buf[0] & 0x80 != 0;
    if buf[0] & 0x70 != 0 {
        return Err("WS 帧带保留位（不支持扩展）".into());
    }
    let opcode = buf[0] & 0x0f;
    if buf[1] & 0x80 != 0 {
        return Err("服务端帧不允许掩码".into());
    }
    let mut len = (buf[1] & 0x7f) as u64;
    let mut pos = 2;
    if len == 126 {
        if buf.len() < 4 {
            return Ok(None);
        }
        len = u16::from_be_bytes([buf[2], buf[3]]) as u64;
        pos = 4;
    } else if len == 127 {
        if buf.len() < 10 {
            return Ok(None);
        }
        len = u64::from_be_bytes(buf[2..10].try_into().unwrap());
        pos = 10;
    }
    if opcode >= 0x8 && (!fin || len > 125) {
        return Err("非法控制帧".into());
    }
    let total = pos + len as usize;
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some(WsFrame {
        fin,
        opcode,
        payload: buf[pos..total].to_vec(),
        consumed: total,
    }))
}

/// Build a client WS frame (FIN set; RFC 6455 requires client frames to be masked).
fn build_ws_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mask: [u8; 4] = uuid::Uuid::new_v4().as_bytes()[..4].try_into().unwrap();
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(0x80 | opcode);
    if payload.len() < 126 {
        out.push(0x80 | payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        out.push(0x80 | 126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        out.push(0x80 | 127);
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    out.extend_from_slice(&mask);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    out
}

/// Sec-WebSocket-Key (16 random bytes, base64)
fn ws_key() -> String {
    b64_encode(uuid::Uuid::new_v4().as_bytes())
}

fn b64_encode(data: &[u8]) -> String {
    const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let b0 = c[0] as u32;
        let b1 = *c.get(1).unwrap_or(&0) as u32;
        let b2 = *c.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TBL[(n >> 18) as usize & 63] as char);
        out.push(TBL[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { TBL[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { TBL[n as usize & 63] as char } else { '=' });
    }
    out
}

/// Rate formatting (B/KB/MB adaptive, base 1024; shared by tray tooltip and frontend display)
pub fn format_rate(bytes: u64) -> String {
    if bytes >= 1 << 20 {
        format!("{:.1} MB", bytes as f64 / 1048576.0)
    } else if bytes >= 1 << 10 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

// ==================== Connection/log collection (/connections, /logs WS) ====================

/// Connection record (shared by active and closed; rates diffed from adjacent snapshots)
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionInfo {
    pub id: String,
    /// Target host (metadata.host preferred, fallback destinationIP)
    pub host: String,
    /// Target port (metadata.destinationPort; mihomo emits it as a string — both shapes accepted)
    pub port: u16,
    /// Originating process (metadata.process; empty string if unknown)
    pub process: String,
    /// Outbound chain (last segment is the node name)
    pub chains: Vec<String>,
    pub rule: String,
    pub rule_payload: String,
    pub upload: u64,
    pub download: u64,
    /// Snapshot-diffed rates (bytes/sec; always 0 for closed connections)
    pub up_rate: u64,
    pub down_rate: u64,
    /// Establish time (second-precision timestamp)
    pub start: u64,
    /// Alive duration (seconds; active = up to now, closed = total lifetime)
    pub elapsed: u64,
}

/// Kernel log entry (pushed over /logs WS)
#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    /// Receive time (second-precision timestamp)
    pub time: u64,
    pub level: String,
    pub payload: String,
}

/// Rule hit aggregation (by rule+rule_payload)
#[derive(Debug, Clone, Serialize)]
pub struct RuleHit {
    pub rule: String,
    pub payload: String,
    pub count: u64,
    pub last_host: String,
    pub last_seen: u64,
}

/// Active connection internal state (ConnectionInfo + diff baseline)
#[derive(Debug)]
struct ConnState {
    info: ConnectionInfo,
    last_up: u64,
    last_down: u64,
    last_tick: std::time::Instant,
}

/// Connection/log/hit buffers (short Mutex critical sections — the accepted simple design,
/// parallel to TrafficStats' all-atomic style; cleared on kernel stop, so commands return empty sets)
#[derive(Debug, Default)]
pub struct ConnTracker {
    active: std::sync::Mutex<std::collections::HashMap<String, ConnState>>,
    /// Recently closed (newest first, cap 300)
    closed: std::sync::Mutex<std::collections::VecDeque<ConnectionInfo>>,
    /// Hit aggregation, key=(rule, rule_payload), keep top 100
    hits: std::sync::Mutex<std::collections::HashMap<(String, String), RuleHit>>,
    /// Log ring buffer (cap 500, ordered oldest→newest)
    logs: std::sync::Mutex<std::collections::VecDeque<LogEntry>>,
}

impl ConnTracker {
    /// /connections full snapshot: update the active table (diff rates), move vanished entries to the closed ring, register hits for new connections.
    pub(crate) fn apply_snapshot(&self, v: &serde_json::Value) {
        let now = now_ts();
        let Some(list) = v["connections"].as_array() else {
            return;
        };
        let mut active = self.active.lock().unwrap();
        let mut seen = std::collections::HashSet::new();
        for c in list {
            let Some(id) = c["id"].as_str() else { continue };
            seen.insert(id.to_string());
            let up = c["upload"].as_u64().unwrap_or(0);
            let down = c["download"].as_u64().unwrap_or(0);
            if let Some(st) = active.get_mut(id) {
                let dt = st.last_tick.elapsed().as_secs().max(1);
                st.info.up_rate = up.saturating_sub(st.last_up) / dt;
                st.info.down_rate = down.saturating_sub(st.last_down) / dt;
                st.info.upload = up;
                st.info.download = down;
                st.info.elapsed = now.saturating_sub(st.info.start);
                st.last_up = up;
                st.last_down = down;
                st.last_tick = std::time::Instant::now();
            } else {
                let md = &c["metadata"];
                let host = md["host"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .or_else(|| md["destinationIP"].as_str())
                    .unwrap_or_default()
                    .to_string();
                let info = ConnectionInfo {
                    id: id.to_string(),
                    host,
                    port: md["destinationPort"]
                        .as_str()
                        .and_then(|s| s.parse().ok())
                        .or_else(|| md["destinationPort"].as_u64().map(|n| n as u16))
                        .unwrap_or(0),
                    process: md["process"].as_str().unwrap_or_default().to_string(),
                    chains: c["chains"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default(),
                    rule: c["rule"].as_str().unwrap_or_default().to_string(),
                    rule_payload: c["rulePayload"].as_str().unwrap_or_default().to_string(),
                    upload: up,
                    download: down,
                    up_rate: 0,
                    down_rate: 0,
                    start: c["start"].as_str().and_then(parse_rfc3339_ts).unwrap_or(now),
                    elapsed: 0,
                };
                self.record_hit(&info);
                active.insert(
                    id.to_string(),
                    ConnState {
                        info,
                        last_up: up,
                        last_down: down,
                        last_tick: std::time::Instant::now(),
                    },
                );
            }
        }
        // Vanished from snapshot = closed: move to ring front (rates zeroed, elapsed frozen)
        let gone: Vec<String> = active.keys().filter(|k| !seen.contains(*k)).cloned().collect();
        if !gone.is_empty() {
            let mut closed = self.closed.lock().unwrap();
            for id in gone {
                if let Some(mut st) = active.remove(&id) {
                    st.info.up_rate = 0;
                    st.info.down_rate = 0;
                    closed.push_front(st.info);
                }
            }
            while closed.len() > 300 {
                closed.pop_back();
            }
        }
    }

    /// Hit registration for new connections (count increments; pruned to top 100 when over 128 keys)
    fn record_hit(&self, info: &ConnectionInfo) {
        if info.rule.is_empty() {
            return;
        }
        let mut hits = self.hits.lock().unwrap();
        let key = (info.rule.clone(), info.rule_payload.clone());
        let h = hits.entry(key).or_insert_with(|| RuleHit {
            rule: info.rule.clone(),
            payload: info.rule_payload.clone(),
            count: 0,
            last_host: String::new(),
            last_seen: 0,
        });
        h.count += 1;
        h.last_host = info.host.clone();
        h.last_seen = now_ts();
        if hits.len() > 128 {
            let mut all: Vec<(String, String)> = hits
                .values()
                .map(|x| (x.rule.clone(), x.payload.clone()))
                .collect();
            all.sort_by_key(|k| std::cmp::Reverse(hits[k].count));
            all.truncate(100);
            let keep: std::collections::HashSet<_> = all.into_iter().collect();
            hits.retain(|k, _| keep.contains(k));
        }
    }

    pub(crate) fn push_log(&self, v: &serde_json::Value) {
        let Some(payload) = v["payload"].as_str() else {
            return;
        };
        let mut logs = self.logs.lock().unwrap();
        logs.push_back(LogEntry {
            time: now_ts(),
            level: v["type"].as_str().unwrap_or("info").to_string(),
            payload: payload.to_string(),
        });
        while logs.len() > 500 {
            logs.pop_front();
        }
    }

    pub(crate) fn connections(&self) -> (Vec<ConnectionInfo>, Vec<ConnectionInfo>) {
        let active = self
            .active
            .lock()
            .unwrap()
            .values()
            .map(|st| st.info.clone())
            .collect();
        let closed = self.closed.lock().unwrap().iter().cloned().collect();
        (active, closed)
    }

    pub(crate) fn rule_hits(&self) -> Vec<RuleHit> {
        let mut v: Vec<RuleHit> = self.hits.lock().unwrap().values().cloned().collect();
        v.sort_by(|a, b| b.count.cmp(&a.count).then(b.last_seen.cmp(&a.last_seen)));
        v
    }

    pub(crate) fn logs(&self) -> Vec<LogEntry> {
        self.logs.lock().unwrap().iter().cloned().collect()
    }

    /// Clear log and hit buffers (sub_clear_logs command; connection state untouched)
    pub(crate) fn clear_logs(&self) {
        self.logs.lock().unwrap().clear();
        self.hits.lock().unwrap().clear();
    }

    /// Zeroed when collection tasks exit (aligned with traffic's clear-on-stop semantics)
    pub(crate) fn reset(&self) {
        self.active.lock().unwrap().clear();
        self.closed.lock().unwrap().clear();
        self.hits.lock().unwrap().clear();
        self.logs.lock().unwrap().clear();
    }
}

/// Minimal RFC3339 timestamp parser (mihomo start field; tolerates fractional seconds and Z/±HH:MM offsets, seconds only).
/// No chrono dependency — control plane data; callers fall back to current time on parse failure.
fn parse_rfc3339_ts(s: &str) -> Option<u64> {
    let (date, rest) = s.split_once('T')?;
    let mut it = date.split('-');
    let y: i64 = it.next()?.parse().ok()?;
    let mo: i64 = it.next()?.parse().ok()?;
    let d: i64 = it.next()?.parse().ok()?;
    // The timezone marker can only appear after byte 8 of "HH:MM:SS"
    let tz_at = rest
        .char_indices()
        .skip_while(|(i, _)| *i < 8)
        .find(|(_, c)| matches!(c, 'Z' | '+' | '-'))
        .map(|(i, _)| i);
    let (time_s, tz_s) = match tz_at {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "Z"),
    };
    let time_s = time_s.split('.').next()?;
    let mut it = time_s.split(':');
    let hh: i64 = it.next()?.parse().ok()?;
    let mm: i64 = it.next().unwrap_or("0").parse().ok()?;
    let ss: i64 = it.next().unwrap_or("0").parse().ok()?;
    let off: i64 = match tz_s {
        "" | "Z" => 0,
        t => {
            let sign = if t.starts_with('-') { -1 } else { 1 };
            let mut it = t[1..].split(':');
            let h: i64 = it.next()?.parse().ok()?;
            let m: i64 = it.next().unwrap_or("0").parse().ok()?;
            sign * (h * 3600 + m * 60)
        }
    };
    // days-from-civil (Howard Hinnant's algorithm)
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let ts = days * 86400 + hh * 3600 + mm * 60 + ss - off;
    u64::try_from(ts).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traffic_stats_accumulate_and_reset() {
        let st = TrafficStats::default();
        st.add(100, 200);
        st.add(50, 60);
        let snap = st.snapshot();
        assert_eq!((snap.up_total, snap.down_total), (150, 260));
        assert_eq!((snap.up_rate, snap.down_rate), (50, 60));
        st.clear_rates();
        let snap = st.snapshot();
        assert_eq!((snap.up_total, snap.down_total), (150, 260));
        assert_eq!((snap.up_rate, snap.down_rate), (0, 0));
        st.reset();
        let snap = st.snapshot();
        assert_eq!(
            (snap.up_total, snap.down_total, snap.up_rate, snap.down_rate),
            (0, 0, 0, 0)
        );
    }

    #[test]
    fn ws_frame_parse_text_and_close() {
        // Short text frame
        let payload = br#"{"up":3,"down":5}"#;
        let mut buf = vec![0x81, payload.len() as u8];
        buf.extend_from_slice(payload);
        let f = parse_ws_frame(&buf).unwrap().expect("应解析出完整帧");
        assert!(f.fin);
        assert_eq!(f.opcode, 0x1);
        assert_eq!(f.payload, payload);
        assert_eq!(f.consumed, buf.len());
        // close frame
        let f = parse_ws_frame(&[0x88, 0x00]).unwrap().unwrap();
        assert_eq!(f.opcode, 0x8);
        // Insufficient data → None
        assert!(parse_ws_frame(&[0x81]).unwrap().is_none());
        assert!(parse_ws_frame(&[0x81, 20, b'{']).unwrap().is_none());
    }

    #[test]
    fn ws_frame_parse_extended_len() {
        let payload = vec![7u8; 300];
        let mut buf = vec![0x82, 126];
        buf.extend_from_slice(&300u16.to_be_bytes());
        buf.extend_from_slice(&payload);
        let f = parse_ws_frame(&buf).unwrap().unwrap();
        assert_eq!(f.opcode, 0x2);
        assert_eq!(f.payload.len(), 300);
        assert_eq!(f.consumed, 304);
        // Incomplete 16-bit length header → None
        assert!(parse_ws_frame(&[0x82, 126, 0x01]).unwrap().is_none());
    }

    #[test]
    fn ws_frame_rejects_masked_and_bad_control() {
        // Masked server frame → protocol error
        assert!(parse_ws_frame(&[0x81, 0x80]).is_err());
        // Reserved bits → protocol error
        assert!(parse_ws_frame(&[0xC1, 0x00]).is_err());
        // Fragmented control frame → protocol error
        assert!(parse_ws_frame(&[0x08, 0x00]).is_err());
    }

    #[test]
    fn ws_client_frame_is_masked() {
        let out = build_ws_frame(0xA, b"hi");
        assert_eq!(out[0], 0x8A); // FIN + pong
        assert_eq!(out[1] & 0x80, 0x80); // mask bit
        assert_eq!(out[1] & 0x7f, 2);
        let mask = &out[2..6];
        assert_eq!(out[6] ^ mask[0], b'h');
        assert_eq!(out[7] ^ mask[1], b'i');
    }

    #[test]
    fn b64_vectors() {
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(ws_key().len(), 24);
    }

    #[test]
    fn format_rate_scales() {
        assert_eq!(format_rate(0), "0 B");
        assert_eq!(format_rate(512), "512 B");
        assert_eq!(format_rate(1024), "1.0 KB");
        assert_eq!(format_rate(1536), "1.5 KB");
        assert_eq!(format_rate(1048576), "1.0 MB");
        assert_eq!(format_rate(12 * 1048576 + 524288), "12.5 MB");
    }

    #[test]
    fn rfc3339_parse_variants() {
        assert_eq!(parse_rfc3339_ts("1970-01-01T00:00:00Z"), Some(0));
        // 08:00 at +08:00 = UTC 00:00
        assert_eq!(parse_rfc3339_ts("1970-01-01T08:00:00+08:00"), Some(0));
        assert_eq!(parse_rfc3339_ts("2024-01-01T00:00:00Z"), Some(1704067200));
        // Tolerate fractional seconds (mihomo's actual format)
        assert_eq!(parse_rfc3339_ts("2024-01-01T00:00:00.123456Z"), Some(1704067200));
        // Negative offset
        assert_eq!(parse_rfc3339_ts("2023-12-31T19:00:00-05:00"), Some(1704067200));
        // Invalid input
        assert!(parse_rfc3339_ts("not-a-time").is_none());
        assert!(parse_rfc3339_ts("").is_none());
    }

    #[test]
    fn conn_tracker_snapshot_lifecycle() {
        let t = ConnTracker::default();
        let snap = |conns: serde_json::Value| serde_json::json!({"connections": conns});
        let conn = |id: &str, up: u64, down: u64| {
            serde_json::json!({
                "id": id,
                "metadata": {"host": "example.com", "process": "chrome.exe", "destinationIP": "93.184.216.34"},
                "upload": up, "download": down,
                "start": "1970-01-01T00:00:00Z",
                "chains": ["AGILE-SUB", "节点A"],
                "rule": "DomainSuffix", "rulePayload": "example.com"
            })
        };
        // First snapshot: two active connections
        t.apply_snapshot(&snap(serde_json::json!([conn("c1", 100, 200), conn("c2", 0, 0)])));
        let (active, closed) = t.connections();
        assert_eq!(active.len(), 2);
        assert!(closed.is_empty());
        let c1 = active.iter().find(|c| c.id == "c1").unwrap();
        assert_eq!(c1.host, "example.com");
        assert_eq!(c1.process, "chrome.exe");
        assert_eq!(c1.chains, vec!["AGILE-SUB", "节点A"]);
        assert_eq!(c1.rule, "DomainSuffix");
        assert_eq!(c1.rule_payload, "example.com");
        assert_eq!((c1.upload, c1.download), (100, 200));
        // Hit aggregation
        let hits = t.rule_hits();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].count, 2);
        assert_eq!(hits[0].last_host, "example.com");
        // Second snapshot: c1 still present (counters grown), c2 gone → closed ring
        std::thread::sleep(std::time::Duration::from_millis(1100));
        t.apply_snapshot(&snap(serde_json::json!([conn("c1", 300, 500)])));
        let (active, closed) = t.connections();
        assert_eq!(active.len(), 1);
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].id, "c2");
        assert_eq!((closed[0].up_rate, closed[0].down_rate), (0, 0));
        let c1 = &active[0];
        assert_eq!((c1.upload, c1.download), (300, 500));
        assert!(c1.up_rate > 0 && c1.down_rate > 0, "差分速率应 > 0");
        assert!(c1.elapsed >= 1, "start=epoch，elapsed 须为大值");
        // host missing → fall back to destinationIP; empty rule records no hit
        let bare = serde_json::json!({
            "id": "c3", "metadata": {"destinationIP": "1.1.1.1"},
            "upload": 1, "download": 1, "start": "bad-start", "chains": []
        });
        t.apply_snapshot(&snap(serde_json::json!([conn("c1", 300, 500), bare])));
        let (active, _) = t.connections();
        let c3 = active.iter().find(|c| c.id == "c3").unwrap();
        assert_eq!(c3.host, "1.1.1.1");
        assert_eq!(t.rule_hits().len(), 1, "rule 缺失不记命中");
        // Everything empty after reset
        t.reset();
        let (active, closed) = t.connections();
        assert!(active.is_empty() && closed.is_empty());
        assert!(t.rule_hits().is_empty());
    }

    #[test]
    fn log_buffer_ring_and_clear() {
        let t = ConnTracker::default();
        for i in 0..505 {
            t.push_log(&serde_json::json!({"type": "info", "payload": format!("log-{i}")}));
        }
        let logs = t.logs();
        assert_eq!(logs.len(), 500, "ring 上限 500");
        assert_eq!(logs[0].payload, "log-5", "最旧的被挤出（旧→新排列）");
        assert_eq!(logs[499].payload, "log-504");
        // Non-log payload ignored
        t.push_log(&serde_json::json!({"type": "info"}));
        assert_eq!(t.logs().len(), 500);
        t.clear_logs();
        assert!(t.logs().is_empty());
    }

    /// Mock control plane: verify handshake request → push two /traffic frames → close; verify end-to-end accumulation
    #[tokio::test]
    async fn ws_session_accumulates_from_mock_server() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut b = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                s.read_exact(&mut b).await.unwrap();
                head.push(b[0]);
            }
            let head = String::from_utf8_lossy(&head);
            assert!(head.starts_with("GET /traffic HTTP/1.1\r\n"), "握手请求行: {head}");
            assert!(head.contains("Authorization: Bearer sek"), "缺鉴权头: {head}");
            assert!(head.contains("Sec-WebSocket-Key: "), "缺 WS Key: {head}");
            s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                .await
                .unwrap();
            for msg in [r#"{"up":10,"down":20}"#, r#"{"up":5,"down":7}"#] {
                let mut f = vec![0x81, msg.len() as u8];
                f.extend_from_slice(msg.as_bytes());
                s.write_all(&f).await.unwrap();
            }
            s.write_all(&[0x88, 0x00]).await.unwrap(); // close
        });
        let stats = TrafficStats::default();
        traffic_ws_session_on(port, "sek", &stats).await.unwrap();
        server.await.unwrap();
        let snap = stats.snapshot();
        assert_eq!((snap.up_total, snap.down_total), (15, 27));
        assert_eq!((snap.up_rate, snap.down_rate), (5, 7));
    }
}
