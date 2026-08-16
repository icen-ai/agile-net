//! Multi-hop & scale benchmarks (audit §2.5.2, `docs/audit/multihop-scale-report.md`).
//!
//! Run explicitly (kept out of CI rounds via #[ignore]) and read the printed numbers:
//! ```text
//! cargo test -p agile-net-core --test multihop_bench_test -- --ignored --nocapture
//! ```
//!
//! Measurements:
//! 1. Transparent chain of 1..=5 TLS legs: RTT (1 KiB echo) plus one-way up/down throughput
//!    (4 MiB) per hop count — verifies latency growth ~linear in hops and quantifies the
//!    per-hop cost. Up/down use dedicated sink/source targets (same semantics as the
//!    protocol's bandwidth-diagnostic plane) so the benchmark never depends on draining a
//!    bidirectional echo (a full-duplex echo backpressures the return path and would
//!    deadlock any write-then-read measurement larger than the buffered window).
//! 2. E2E endpoint overhead: E2eStream (AES-256-GCM record layer) vs raw copy over the same
//!    duplex for the same payload — E2E cost must sit at the endpoints only (relays stay
//!    byte-forwarders; verified by construction: the relay never sees plaintext keys).
//! 3. Mux fairness under a saturated bulk channel: a 1 KiB RTT probe on a second channel of
//!    the same session must not starve while the bulk channel saturates the session
//!    (per-channel window flow control + session mpsc backpressure — no head-of-line blocking).

use agile_net_core::error::Result;
use agile_net_core::proto::frame::{Frame, FrameType};
use agile_net_core::proto::message::AuthRequest;
use agile_net_core::relay::connector::RelayConnector;
use agile_net_core::relay::e2e::{E2eStream, open_open, seal_open};
use agile_net_core::relay::listener::RelayListener;
use agile_net_core::relay::mux::{MuxSession, SessionEvents};
use agile_net_core::tunnel::tls::TlsConfigBuilder;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn get_free_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

/// Small-payload TCP echo (RTT probing only; buffered window dwarfs the 1 KiB payload).
async fn start_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

/// Upload target: reads and discards; on EOF replies an 8-byte BE total count (no other
/// return traffic — the upload direction can never deadlock on backpressure).
async fn start_sink() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let mut total: u64 = 0;
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => total += n as u64,
                    }
                }
                let _ = s.write_all(&total.to_be_bytes()).await;
            });
        }
    });
    port
}

/// Download target: reads an 8-byte BE requested count, then streams that many bytes.
async fn start_source() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let Ok(count) = s.read_u64().await else { return };
                let chunk = vec![0u8; 64 * 1024];
                let mut remaining = count;
                while remaining > 0 {
                    let n = chunk.len().min(remaining as usize);
                    if s.write_all(&chunk[..n]).await.is_err() {
                        return;
                    }
                    remaining -= n as u64;
                }
            });
        }
    });
    port
}

/// A raw consumer endpoint: TLS + node auth + mux (client side, even channel ids).
async fn raw_consumer(entry: SocketAddr, node_id: &str, token: &str) -> Result<Arc<MuxSession>> {
    let tls = TlsConfigBuilder::new().allow_self_signed(true).build_client()?;
    let connector = tokio_rustls::TlsConnector::from(tls);
    let tcp = TcpStream::connect(entry).await?;
    let server_name = rustls::pki_types::ServerName::try_from("cdn.cloudflare.com".to_string()).unwrap();
    let mut stream = connector.connect(server_name, tcp).await?;
    let mut auth = AuthRequest {
        node_id: node_id.into(),
        token: token.into(),
        kind: agile_net_core::proto::message::AuthKind::Node,
        advertise: vec![],
        groups: Vec::new(),
        version: 4,
        my_name: String::new(),
        device_pubkey: String::new(),
        device_sig: String::new(),
    };
    let challenge = agile_net_core::device::session_challenge(stream.get_ref().1)?;
    auth.attach_device_proof(&challenge, &agile_net_core::device::DeviceIdentity::ephemeral());
    Frame::new(FrameType::Auth, 0, Bytes::from(serde_json::to_vec(&auth).unwrap()))
        .write_to(&mut stream)
        .await?;
    let f = Frame::read_from(&mut stream).await?;
    assert_eq!(f.frame_type, FrameType::AuthOk);
    let (mux, _h) = MuxSession::start(stream, 2, SessionEvents::default(), true, None);
    Ok(mux)
}

/// Build a transparent forwarding chain of `legs` TLS legs terminating at 127.0.0.1:
/// consumer -> L1 -> L2 -> ... -> L(legs); the last connector dials the target locally.
/// Returns the entry listener address. (All benchmark targets share 127.0.0.1; routing is
/// IP-based so the single /32 route covers every target port.)
async fn build_chain(legs: usize) -> SocketAddr {
    assert!(legs >= 1);
    let mut listeners = Vec::new();
    for _ in 0..legs {
        let addr = get_free_addr();
        let l = Arc::new(RelayListener::new(addr, "bench").unwrap());
        let lc = l.clone();
        tokio::spawn(async move {
            let _ = lc.start().await;
        });
        listeners.push(l);
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    // node i (1..=legs-1) fans out into L_i and forwards opens onward through its OWN
    // listener L_{i+1} (chained forwarding via peer_router); the terminal node dials locally
    let route = "127.0.0.1/32".to_string();
    for i in 1..legs {
        let c = RelayConnector::new(listeners[i - 1].listen_addr(), format!("node-{i}"), "bench")
            .unwrap()
            .with_advertise(vec![route.clone()])
            .with_peer_router(listeners[i].clone());
        c.connect().await.unwrap();
    }
    let term = RelayConnector::new(
        listeners[legs - 1].listen_addr(),
        format!("node-{legs}"),
        "bench",
    )
    .unwrap()
    .with_advertise(vec![route]);
    term.connect().await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    listeners[0].listen_addr()
}

fn stats(samples: &[Duration]) -> (Duration, Duration, Duration) {
    let mut s: Vec<_> = samples.iter().map(|d| d.as_micros() as u64).collect();
    s.sort_unstable();
    let min = Duration::from_micros(s[0]);
    let max = Duration::from_micros(*s.last().unwrap());
    let avg = Duration::from_micros(s.iter().sum::<u64>() / s.len() as u64);
    (min, avg, max)
}

fn open_payload(port: u16) -> Bytes {
    Bytes::from(
        serde_json::to_vec(&agile_net_core::proto::message::OpenChannel::new("127.0.0.1", port))
            .unwrap(),
    )
}

/// §2.5.2-1: transparent chain latency/throughput vs hop count.
#[tokio::test]
#[ignore = "benchmark — run with --ignored --nocapture"]
async fn bench_chain_latency_and_throughput() -> Result<()> {
    let echo_port = start_echo().await;
    let sink_port = start_sink().await;
    let source_port = start_source().await;
    const RTT_BYTES: usize = 1024;
    const BULK: u64 = 4 * 1024 * 1024;
    let payload = vec![b'x'; 64 * 1024];

    println!(
        "{:<6} {:>12} {:>12} {:>12} {:>14} {:>14}",
        "legs", "rtt_min", "rtt_avg", "rtt_max", "up_Mbps", "down_Mbps"
    );
    for legs in [1usize, 2, 3, 5] {
        let entry = build_chain(legs).await;
        let mux = raw_consumer(entry, "consumer", "bench").await?;

        // RTT: 1 KiB echo round trips
        let mut ch = mux.open_channel(open_payload(echo_port)).await?;
        let mut buf = vec![0u8; RTT_BYTES];
        ch.write_all(&vec![b'p'; RTT_BYTES]).await?;
        let _ = ch.read_exact(&mut buf).await?; // warm-up
        let mut samples = Vec::new();
        for _ in 0..50 {
            let t = Instant::now();
            ch.write_all(&vec![b'p'; RTT_BYTES]).await?;
            ch.read_exact(&mut buf).await?;
            samples.push(t.elapsed());
        }
        mux.close_channel(ch.channel_id);

        // upload: BULK bytes into the sink, until the EOF ack count arrives
        let mut ch = mux.open_channel(open_payload(sink_port)).await?;
        let t = Instant::now();
        let mut sent = 0u64;
        while sent < BULK {
            let n = payload.len().min((BULK - sent) as usize);
            ch.write_all(&payload[..n]).await?;
            sent += n as u64;
        }
        ch.shutdown().await?;
        let ack = ch.read_u64().await?;
        let up_secs = t.elapsed().as_secs_f64();
        mux.close_channel(ch.channel_id);
        assert_eq!(ack, BULK, "sink must ack the exact upload volume ({legs} legs)");

        // download: BULK bytes out of the source
        let mut ch = mux.open_channel(open_payload(source_port)).await?;
        let t = Instant::now();
        ch.write_u64(BULK).await?;
        let mut got = 0u64;
        let mut rbuf = vec![0u8; 64 * 1024];
        while got < BULK {
            let n = ch.read(&mut rbuf).await?;
            if n == 0 {
                break;
            }
            got += n as u64;
        }
        let down_secs = t.elapsed().as_secs_f64();
        mux.close_channel(ch.channel_id);
        assert_eq!(got, BULK, "source must stream the exact volume ({legs} legs)");

        let (mn, av, mx) = stats(&samples);
        let mbps = |s: f64| (BULK as f64 * 8.0 / s) / 1_000_000.0;
        println!(
            "{:<6} {:>12} {:>12} {:>12} {:>14.1} {:>14.1}",
            legs,
            format!("{mn:?}"),
            format!("{av:?}"),
            format!("{mx:?}"),
            mbps(up_secs),
            mbps(down_secs)
        );
    }
    Ok(())
}

/// §2.5.2-1 (E2E leg): endpoint-only record-layer cost vs raw copy — the relays in an E2E
/// chain forward sealed bytes untouched, so total E2E cost = this endpoint delta + relay
/// byte-forwarding cost measured above.
#[tokio::test]
#[ignore = "benchmark — run with --ignored --nocapture"]
async fn bench_e2e_endpoint_overhead() -> Result<()> {
    use tokio::io::duplex;
    const BULK: usize = 8 * 1024 * 1024;
    let key = agile_net_core::relay::e2e::random_key();
    let hash = agile_net_core::util::sha256_hex(b"bench-e2e-token");
    let (env, client_cipher) = seal_open(&key, agile_net_core::relay::e2e::kid_of(&hash), "h", "10.0.0.9", 7, &[]);
    let (_, issuer_cipher) = open_open(&key, &env)?;

    // sealed one-way transfer over duplex
    let (s1, s2) = duplex(256 * 1024);
    let mut a = E2eStream::new(s1, client_cipher);
    let mut b = E2eStream::new(s2, issuer_cipher);
    let data = vec![b'e'; BULK];
    let t = Instant::now();
    let writer = tokio::spawn(async move {
        a.write_all(&data).await.unwrap();
        a.shutdown().await.unwrap();
    });
    let mut got = Vec::new();
    b.read_to_end(&mut got).await?;
    writer.await.unwrap();
    let e2e_secs = t.elapsed().as_secs_f64();
    assert_eq!(got.len(), BULK);

    // raw copy baseline over the same duplex size
    let (r1, r2) = duplex(256 * 1024);
    let mut ra = r1;
    let mut rb = r2;
    let data = vec![b'r'; BULK];
    let t = Instant::now();
    let writer = tokio::spawn(async move {
        ra.write_all(&data).await.unwrap();
        ra.shutdown().await.unwrap();
    });
    let mut got = Vec::new();
    rb.read_to_end(&mut got).await?;
    writer.await.unwrap();
    let raw_secs = t.elapsed().as_secs_f64();
    assert_eq!(got.len(), BULK);

    let mbps = |s: f64| (BULK as f64 * 8.0 / s) / 1_000_000.0;
    println!(
        "e2e endpoint: {:.1} Mbps ({:.0} ms) | raw: {:.1} Mbps ({:.0} ms) | delta/byte = {:.1} ns",
        mbps(e2e_secs),
        e2e_secs * 1000.0,
        mbps(raw_secs),
        raw_secs * 1000.0,
        (e2e_secs - raw_secs) * 1e9 / BULK as f64
    );
    Ok(())
}

/// §2.5.2-2: mux fairness — a small RTT probe on a second channel of one session while a
/// bulk upload saturates the same session. Probe RTT inflation bounds head-of-line blocking.
#[tokio::test]
#[ignore = "benchmark — run with --ignored --nocapture"]
async fn bench_mux_fairness_under_bulk() -> Result<()> {
    let echo_port = start_echo().await;
    let sink_port = start_sink().await;
    let entry = build_chain(2).await;
    let mux = raw_consumer(entry, "consumer", "bench").await?;

    // idle baseline on the probe channel
    let mut probe = mux.open_channel(open_payload(echo_port)).await?;
    let mut buf = vec![0u8; 1024];
    let mut idle = Vec::new();
    for _ in 0..20 {
        let t = Instant::now();
        probe.write_all(&vec![b'q'; 1024]).await?;
        probe.read_exact(&mut buf).await?;
        idle.push(t.elapsed());
    }
    let idle_avg = stats(&idle).1;

    // saturate the session with a 16 MiB bulk upload while probing
    const BULK: u64 = 16 * 1024 * 1024;
    let bulk_mux = mux.clone();
    let bulk = tokio::spawn(async move {
        let mut ch = bulk_mux.open_channel(open_payload(sink_port)).await.unwrap();
        let payload = vec![b'b'; 64 * 1024];
        let mut sent = 0u64;
        while sent < BULK {
            ch.write_all(&payload).await.unwrap();
            sent += payload.len() as u64;
        }
        ch.shutdown().await.unwrap();
        assert_eq!(ch.read_u64().await.unwrap(), BULK);
    });
    tokio::time::sleep(Duration::from_millis(200)).await; // let the bulk channel spin up
    let mut busy = Vec::new();
    for _ in 0..20 {
        let t = Instant::now();
        probe.write_all(&vec![b'q'; 1024]).await?;
        probe.read_exact(&mut buf).await?;
        busy.push(t.elapsed());
    }
    bulk.await.unwrap();
    let busy_avg = stats(&busy).1;
    println!(
        "probe RTT idle: {idle_avg:?} | under bulk: {busy_avg:?} | inflation: {:.1}x",
        busy_avg.as_secs_f64() / idle_avg.as_secs_f64()
    );
    // fairness contract: the probe must complete at all and stay within a sane factor —
    // a starved channel would time out (read_exact pending) rather than inflate moderately
    assert!(
        busy_avg < idle_avg.mul_f32(20.0),
        "probe channel starved under bulk load: idle {idle_avg:?} vs busy {busy_avg:?}"
    );
    Ok(())
}
