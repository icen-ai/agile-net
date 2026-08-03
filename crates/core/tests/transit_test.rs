//! Relay transit traffic accounting integration tests (TransitMeter + RelayConnector::traffic)
//!
//! Covers:
//! - connector current-session traffic accessor (zeroes on disconnect)
//! - fan-in peer originated: transit pair classification to downstream peer / to local termination
//! - fan-out connector reverse flow: transit pair classification chained to downstream peer / local direct
//! - local proxy inbound: transit pair classification tunnel egress / direct egress

use agile_net_core::error::Result;
use agile_net_core::proxy::inbound::ProxyInbound;
use agile_net_core::proxy::router::{Outbound, ProxyRouter};
use agile_net_core::relay::transit::{FROM_PROXY, TO_LOCAL, TransitMeter, TransitPair};
use agile_net_core::relay::{RelayConnector, RelayListener};
use agile_net_core::tunnel::opener::PeerAutoOpener;
use arc_swap::ArcSwap;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn get_free_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

/// Get a free port on the given loopback address (127.0.0.2 avoids the 127.0.0.1/32 route rule).
fn get_free_addr_on(ip: &str) -> SocketAddr {
    let listener = std::net::TcpListener::bind(format!("{ip}:0")).unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

/// Start an echo TCP service (echoes once per connection, then serves the next).
async fn spawn_echo(addr: SocketAddr) {
    let listener = TcpListener::bind(addr).await.unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
}

/// Find the given transit pair in a snapshot.
fn find_pair<'a>(pairs: &'a [TransitPair], from: &str, to: &str) -> Option<&'a TransitPair> {
    pairs.iter().find(|p| p.from == from && p.to == to)
}

/// Wait for the given transit pair to appear (accounting lags behind bridge teardown), up to 3s.
async fn wait_pair(meter: &TransitMeter, from: &str, to: &str) -> TransitPair {
    for _ in 0..30 {
        let (_, _, pairs) = meter.snapshot();
        if let Some(p) = find_pair(&pairs, from, to) {
            return p.clone();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("transit pair {from} -> {to} not recorded in time");
}

/// Write over the channel and read back the echo, then shutdown to trigger the bridge close cascade.
async fn roundtrip<C>(ch: &mut C, msg: &[u8])
where
    C: AsyncReadExt + AsyncWriteExt + Unpin,
{
    ch.write_all(msg).await.unwrap();
    let mut buf = vec![0u8; msg.len()];
    ch.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, msg);
    ch.shutdown().await.unwrap();
}

/// Connector current-session traffic accessor: non-zero after transfer, zeroed after disconnect.
#[tokio::test]
async fn connector_traffic_accessor() -> Result<()> {
    let relay_addr = get_free_addr();
    let echo_addr = get_free_addr();
    let token = "traffic_token";
    spawn_echo(echo_addr).await;

    let listener = Arc::new(RelayListener::new(relay_addr, token)?);
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.start().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let connector = RelayConnector::new(relay_addr, "node-b", token)?;
    connector.connect().await?;
    assert_eq!(connector.traffic(), (0, 0));

    // listener → connector stream (connector dials echo locally), data in both directions
    let mut ch = listener
        .open_channel("node-b", &echo_addr.ip().to_string(), echo_addr.port())
        .await?;
    roundtrip(&mut ch, b"connector-traffic-probe").await;
    drop(ch);

    // counters accumulate asynchronously in the read/write tasks; poll until non-zero
    let mut traffic = (0u64, 0u64);
    for _ in 0..30 {
        traffic = connector.traffic();
        if traffic.0 > 0 && traffic.1 > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        traffic.0 >= 22 && traffic.1 >= 22,
        "connector traffic should count both directions, got {traffic:?}"
    );

    // current-session handle cleared after disconnect → (0, 0)
    connector.disconnect().await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(connector.traffic(), (0, 0));
    Ok(())
}

/// Fan-in peer originated forwarding: classified by from=peer node_id (to downstream peer / to local termination).
#[tokio::test]
async fn listener_transit_classification() -> Result<()> {
    let relay_addr = get_free_addr();
    let echo_local = get_free_addr(); // B local termination target
    let echo_peer = get_free_addr(); // C-side service target (127.0.0.1 advertised by C)
    let token = "transit_listener_token";
    spawn_echo(echo_local).await;
    spawn_echo(echo_peer).await;

    let meter = TransitMeter::new();
    let listener = Arc::new(RelayListener::new(relay_addr, token)?.with_transit_meter(meter.clone()));
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.start().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // downstream peer C: advertises 127.0.0.1 (/32), runs echo_peer locally
    let peer_c = RelayConnector::new(relay_addr, "node-c", token)?
        .with_advertise(vec!["127.0.0.1/32".to_string()]);
    peer_c.connect().await?;
    // downstream peer A: traffic source
    let peer_a = RelayConnector::new(relay_addr, "node-a", token)?;
    peer_a.connect().await?;

    // A → 127.0.0.1:echo_peer (hits C's advertised route → chained to C → C's local echo)
    let mut ch = peer_a.open_stream("127.0.0.1", echo_peer.port()).await?;
    roundtrip(&mut ch, b"via-peer-c").await;
    drop(ch);

    // A → localhost:echo_local (no route hit → B dials directly)
    let mut ch2 = peer_a.open_stream("localhost", echo_local.port()).await?;
    roundtrip(&mut ch2, b"to-local-end").await;
    drop(ch2);

    let p1 = wait_pair(&meter, "node-a", "node-c").await;
    assert!(p1.bytes_up >= 10 && p1.bytes_down >= 10, "pair node-a->node-c: {p1:?}");
    let p2 = wait_pair(&meter, "node-a", TO_LOCAL).await;
    assert!(p2.bytes_up >= 11 && p2.bytes_down >= 11, "pair node-a->local: {p2:?}");

    // aggregate = sum of transit pairs
    let (up, down, _) = meter.snapshot();
    assert_eq!(up, p1.bytes_up + p2.bytes_up);
    assert_eq!(down, p1.bytes_down + p2.bytes_down);
    Ok(())
}

/// Fan-out connector reverse flow: classified by from=connector name (chained to downstream peer / local direct).
#[tokio::test]
async fn connector_transit_classification() -> Result<()> {
    let upstream_addr = get_free_addr(); // upstream U's listener
    let mid_addr = get_free_addr(); // middle node B's listener
    let echo_local = get_free_addr(); // B local termination target
    let echo_peer = get_free_addr(); // C-side service target
    let token = "transit_connector_token";
    spawn_echo(echo_local).await;
    spawn_echo(echo_peer).await;

    // upstream U
    let upstream = Arc::new(RelayListener::new(upstream_addr, token)?);
    let u = upstream.clone();
    tokio::spawn(async move {
        let _ = u.start().await;
    });

    // middle node B: listener serves C + connector out to U (with transit accounting, source label "b-up")
    let meter = TransitMeter::new();
    let mid_listener = Arc::new(RelayListener::new(mid_addr, token)?);
    let m = mid_listener.clone();
    tokio::spawn(async move {
        let _ = m.start().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mid_connector = RelayConnector::new(upstream_addr, "node-b", token)?
        .with_peer_router(mid_listener.clone())
        .with_transit_meter(meter.clone(), "b-up".to_string());
    mid_connector.connect().await?;

    // downstream C: joins B's listener and advertises 127.0.0.1
    let peer_c = RelayConnector::new(mid_addr, "node-c", token)?
        .with_advertise(vec!["127.0.0.1/32".to_string()]);
    peer_c.connect().await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // U → B (via connector) → 127.0.0.1:echo_peer (B chains to C → C's local echo)
    let mut ch = upstream
        .open_channel("node-b", "127.0.0.1", echo_peer.port())
        .await?;
    roundtrip(&mut ch, b"chain-to-c").await;
    drop(ch);

    // U → B → localhost:echo_local (B dials directly)
    let mut ch2 = upstream
        .open_channel("node-b", "localhost", echo_local.port())
        .await?;
    roundtrip(&mut ch2, b"up-to-local").await;
    drop(ch2);

    let p1 = wait_pair(&meter, "b-up", "node-c").await;
    assert!(p1.bytes_up >= 10 && p1.bytes_down >= 10, "pair b-up->node-c: {p1:?}");
    let p2 = wait_pair(&meter, "b-up", TO_LOCAL).await;
    assert!(p2.bytes_up >= 11 && p2.bytes_down >= 11, "pair b-up->local: {p2:?}");
    Ok(())
}

/// Local proxy inbound: from="proxy" (tunnel egress to downstream peer / direct local termination).
#[tokio::test]
async fn proxy_transit_classification() -> Result<()> {
    let relay_addr = get_free_addr();
    let proxy_addr = get_free_addr();
    let echo_local = get_free_addr_on("127.0.0.2"); // direct local target (avoids the 127.0.0.1/32 rule)
    let echo_peer = get_free_addr(); // C-side service target
    let token = "transit_proxy_token";
    spawn_echo(echo_local).await;
    spawn_echo(echo_peer).await;

    // node listener + downstream C (advertises 127.0.0.1)
    let listener = Arc::new(RelayListener::new(relay_addr, token)?);
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.start().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let peer_c = RelayConnector::new(relay_addr, "node-c", token)?
        .with_advertise(vec!["127.0.0.1/32".to_string()]);
    peer_c.connect().await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // proxy routing: 127.0.0.1/32 goes via tunnel (auto peer pick), rest direct; ProxyInbound carries transit accounting
    let mut router = ProxyRouter::new();
    router.add_cidr("127.0.0.1/32", Outbound::tunnel("")).unwrap();
    let meter = TransitMeter::new();
    let inbound = ProxyInbound::new(proxy_addr, Arc::new(ArcSwap::from_pointee(router)))
        .with_default_opener(Arc::new(PeerAutoOpener::new(listener.clone())))
        .with_transit_meter(meter.clone());
    tokio::spawn(async move {
        let _ = inbound.start().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // socks5 request 127.0.0.1:echo_peer → tunnel → C
    let mut c1 = socks5_connect_ipv4(proxy_addr, echo_peer).await?;
    roundtrip(&mut c1, b"proxy-via-tunnel").await;
    drop(c1);

    // socks5 request 127.0.0.2:echo_local (no route hit → direct local)
    let mut c2 = socks5_connect_ipv4(proxy_addr, echo_local).await?;
    roundtrip(&mut c2, b"proxy-direct").await;
    drop(c2);

    let p1 = wait_pair(&meter, FROM_PROXY, "node-c").await;
    assert!(p1.bytes_up >= 16 && p1.bytes_down >= 16, "pair proxy->node-c: {p1:?}");
    let p2 = wait_pair(&meter, FROM_PROXY, TO_LOCAL).await;
    assert!(p2.bytes_up >= 12 && p2.bytes_down >= 12, "pair proxy->local: {p2:?}");
    Ok(())
}

/// SOCKS5 CONNECT (IPv4 form) to the target, returning the ready stream.
async fn socks5_connect_ipv4(
    proxy_addr: SocketAddr,
    target: SocketAddr,
) -> Result<tokio::net::TcpStream> {
    let mut client = tokio::net::TcpStream::connect(proxy_addr).await?;
    client.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).await?;
    assert_eq!(greeting, [0x05, 0x00]);

    let ip = match target.ip() {
        std::net::IpAddr::V4(ip4) => ip4.octets(),
        _ => panic!("expected ipv4"),
    };
    let port = target.port().to_be_bytes();
    client
        .write_all(&[0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], port[0], port[1]])
        .await?;
    let mut resp = [0u8; 10];
    client.read_exact(&mut resp).await?;
    assert_eq!(resp[1], 0x00, "socks5 connect failed");
    Ok(client)
}
