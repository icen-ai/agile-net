//! Multi-hop & scale benchmarks (audit §2.5.2, `docs/audit/multihop-scale-report.md`).
//!
//! Run explicitly (kept out of CI rounds via #[ignore]) and read the printed numbers:
//! ```text
//! cargo test -p agile-net-core --test multihop_bench_test -- --ignored --nocapture
//! ```
//!
//! Measurements:
//! 1. Transparent chain of 1..=5 TLS legs: RTT (1 KiB echo) and throughput (4 MiB echo) per
//!    hop count — verifies latency growth ~linear in hops and quantifies per-hop cost.
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

/// Plain TCP echo server (the guarded-segment stand-in at the end of the chain).
async fn start_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
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
    addr
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

/// Build a transparent forwarding chain of `legs` TLS legs ending at `target`:
/// consumer -> L1 -> L2 -> ... -> L(legs); the last connector dials the target locally.
/// Returns the entry listener address.
async fn build_chain(legs: usize, target: SocketAddr) -> SocketAddr {
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
    // node i (2..=legs) fans out into listener i-1, advertising the echo /32
    let route = format!("{}/32", target.ip());
    for i in 1..legs {
        let c = RelayConnector::new(listeners[i - 1].listen_addr(), format!("node-{i}"), "bench")
            .unwrap()
            .with_advertise(vec![route.clone()]);
        c.connect().await.unwrap();
    }
    // the terminal node dials the echo locally (no further routing)
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

/// §2.5.2-1: transparent chain latency/throughput vs hop count.
#[tokio::test]
#[ignore = "benchmark — run with --ignored --nocapture"]
async fn bench_chain_latency_and_throughput() -> Result<()> {
    let echo = start_echo().await;
    const RTT_BYTES: usize = 1024;
    const BULK: usize = 4 * 1024 * 1024;
    let payload = vec![b'x'; 64 * 1024];

    println!("{:<8} {:>14} {:>14} {:>14} {:>14}", "legs", "rtt_min", "rtt_avg", "rtt_max", "tput_Mbps");
    for legs in [1usize, 2, 3, 5] {
        let entry = build_chain(legs, echo).await;
        let mux = raw_consumer(entry, "consumer", "bench").await?;

        // warm-up + RTT samples
        let mut ch = mux.open_channel(open_payload(echo)).await?;
        let mut buf = vec![0u8; RTT_BYTES];
        ch.write_all(&vec![b'p'; RTT_BYTES]).await?;
        let _ = ch.read_exact(&mut buf).await?;
        let mut samples = Vec::new();
        for _ in 0..50 {
            let t = Instant::now();
            ch.write_all(&vec![b'p'; RTT_BYTES]).await?;
            ch.read_exact(&mut buf).await?;
            samples.push(t.elapsed());
        }
        mux.close_channel(ch.channel_id);

        // throughput: push BULK through the chain and read the echo back
        let mut ch = mux.open_channel(open_payload(echo)).await?;
        let t = Instant::now();
        let mut sent = 0usize;
        while sent < BULK {
            let n = payload.len().min(BULK - sent);
            ch.write_all(&payload[..n]).await?;
            sent += n;
        }
        let mut got = 0usize;
        let mut rbuf = vec![0u8; 64 * 1024];
        while got < BULK {
            let n = ch.read(&mut rbuf).await?;
            if n == 0 {
                break;
            }
            got += n;
        }
        let secs = t.elapsed().as_secs_f64();
        mux.close_channel(ch.channel_id);
        assert_eq!(got, BULK, "echo must return the full bulk payload ({legs} legs)");
        let mbps = (BULK as f64 * 2.0 * 8.0 / secs) / 1_000_000.0; // x2: there and back
        let (mn, av, mx) = stats(&samples);
        println!("{:<8} {:>14} {:>14} {:>14} {:>14.1}", legs, format!("{mn:?}"), format!("{av:?}"), format!("{mx:?}"), mbps);
    }
    Ok(())
}

fn open_payload(target: SocketAddr) -> Bytes {
    Bytes::from(
        serde_json::to_vec(&agile_net_core::proto::message::OpenChannel::new(
            target.ip().to_string(),
            target.port(),
        ))
        .unwrap(),
    )
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

    // sealed transfer over duplex
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
    writer.await?;
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
    writer.await?;
    let raw_secs = t.elapsed().as_secs_f64();
    assert_eq!(got.len(), BULK);

    let mbps = |s: f64| (BULK as f64 * 8.0 / s) / 1_000_000.0;
    println!("e2e endpoint: {:.1} Mbps ({:.0} ms) | raw: {:.1} Mbps ({:.0} ms) | delta/byte = {:.1} ns",
        mbps(e2e_secs), e2e_secs * 1000.0, mbps(raw_secs), raw_secs * 1000.0,
        (e2e_secs - raw_secs) * 1e9 / BULK as f64);
    Ok(())
}

/// §2.5.2-2: mux fairness — a small RTT probe on a second channel of one session while a bulk
/// channel saturates the same session. Probe RTT inflation bounds head-of-line blocking.
#[tokio::test]
#[ignore = "benchmark — run with --ignored --nocapture"]
async fn bench_mux_fairness_under_bulk() -> Result<()> {
    let echo = start_echo().await;
    let entry = build_chain(2, echo).await;
    let mux = raw_consumer(entry, "consumer", "bench").await?;

    // idle baseline on the probe channel
    let mut probe = mux.open_channel(open_payload(echo)).await?;
    let mut buf = vec![0u8; 1024];
    let mut idle = Vec::new();
    for _ in 0..20 {
        let t = Instant::now();
        probe.write_all(&vec![b'q'; 1024]).await?;
        probe.read_exact(&mut buf).await?;
        idle.push(t.elapsed());
    }
    let idle_avg = stats(&idle).1;

    // saturate with a bulk channel while probing
    let bulk_mux = mux.clone();
    let bulk_echo = echo;
    let bulk = tokio::spawn(async move {
        let mut ch = bulk_mux.open_channel(open_payload(bulk_echo)).await.unwrap();
        let payload = vec![b'b'; 64 * 1024];
        for _ in 0..256 {
            // 16 MiB total upload; echo backpressure keeps the session genuinely busy
            ch.write_all(&payload).await.unwrap();
        }
        ch.shutdown().await.unwrap();
        let mut sink = vec![0u8; 64 * 1024];
        let mut got = 0usize;
        while got < 16 * 1024 * 1024 {
            let n = ch.read(&mut sink).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            got += n;
        }
    });
    tokio::time::sleep(Duration::from_millis(200)).await; // let the bulk channel spin up
    let mut busy = Vec::new();
    for _ in 0..20 {
        let t = Instant::now();
        probe.write_all(&vec![b'q'; 1024]).await?;
        probe.read_exact(&mut buf).await?;
        busy.push(t.elapsed());
    }
    bulk.await?;
    let busy_avg = stats(&busy).1;
    println!("probe RTT idle: {idle_avg:?} | under bulk: {busy_avg:?} | inflation: {:.1}x",
        busy_avg.as_secs_f64() / idle_avg.as_secs_f64());
    // fairness contract: the probe must complete at all and stay within a sane factor —
    // a starved channel would time out (read_exact pending) rather than inflate moderately
    assert!(
        busy_avg < idle_avg.mul_f32(20.0),
        "probe channel starved under bulk load: idle {idle_avg:?} vs busy {busy_avg:?}"
    );
    Ok(())
}
