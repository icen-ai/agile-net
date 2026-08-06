//! Delegated consumer data-plane E2E tests (M4 full path)
//!
//! Path: consumer(SOCKS5) → ClientTunnel → Node-A(listener, delegated registry ACL) → Node-B(connector) → Echo Server

use agile_net_core::error::Result;
use agile_net_core::proto::message::{AuthRequest, Concurrency};
use agile_net_core::proxy::ProxyInbound;
use agile_net_core::proxy::router::{Outbound, ProxyRouter};
use agile_net_core::relay::listener::{
    AuthIdentity, DelegatedRegistry, DelegatedToken, RelayListener, TokenValidator,
    delegated_session_key,
};
use agile_net_core::relay::{RelayConnector, constant_time_eq};
use agile_net_core::tunnel::client_tunnel::ClientTunnel;
use agile_net_core::tunnel::opener::ChannelOpener;
use agile_net_core::util::sha256_hex;
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

/// Test validator: node PSK only (consumer auth is resolved by the listener itself against the
/// delegated token registry)
struct TestValidator;

impl TokenValidator for TestValidator {
    fn validate(&self, auth: &AuthRequest) -> Option<AuthIdentity> {
        if auth.kind != agile_net_core::proto::message::AuthKind::Node {
            return None;
        }
        if constant_time_eq(auth.token.as_bytes(), b"node-psk") {
            Some(AuthIdentity::Node {
                node_id: auth.node_id.clone(),
                advertise: auth.advertise.clone(),
                groups: auth.groups.clone(),
                control: None,
                acl: None,
                display: None,
            })
        } else {
            None
        }
    }
}

/// Delegated token registry holding one token ("tun_secret", loopback-only ACL, multi sessions).
fn test_delegated_registry() -> (DelegatedRegistry, String) {
    let hash = sha256_hex(b"tun_secret");
    let registry: DelegatedRegistry = Arc::new(dashmap::DashMap::new());
    registry.insert(
        hash.clone(),
        DelegatedToken {
            issuer: "issuer-x".into(),
            label: "test-consumer".into(),
            groups: vec![],
            acl_rules: vec!["127.0.0.0/8".to_string()],
            hint_map: vec![],
            concurrency: Concurrency::Multi,
            max_sessions: 8,
        },
    );
    (registry, hash)
}

async fn start_echo_server(addr: SocketAddr) {
    let echo = TcpListener::bind(addr).await.unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = echo.accept().await {
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

async fn start_listener(addr: SocketAddr) -> Arc<RelayListener> {
    let (registry, _) = test_delegated_registry();
    let listener = Arc::new(
        RelayListener::with_validator(
            addr,
            Arc::new(TestValidator),
            agile_net_core::tunnel::tls::TlsConfigBuilder::new()
                .build_server()
                .map(|(cfg, _)| tokio_rustls::TlsAcceptor::from(cfg))
                .unwrap(),
        )
        .with_delegated_registry(registry),
    );
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.start().await;
    });
    tokio::time::sleep(Duration::from_millis(80)).await;
    listener
}

/// Full path: consumer reaches the internal echo through a two-node tunnel chain
#[tokio::test]
async fn client_to_node_to_downstream_chain() -> Result<()> {
    let echo_addr = get_free_addr();
    let relay_addr = get_free_addr();

    start_echo_server(echo_addr).await;
    let listener = start_listener(relay_addr).await;

    // Node-B: downstream connector, advertises 127.0.0.0/8
    let connector = RelayConnector::new(relay_addr, "node-b", "node-psk")?
        .with_advertise(vec!["127.0.0.0/8".to_string()]);
    connector.connect().await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(listener.peer_count(), 1);
    assert_eq!(
        listener.resolve_peer("127.0.0.1"),
        Some("node-b".to_string())
    );

    // consumer client: tunnel + local SOCKS5 inbound
    let tunnel = Arc::new(ClientTunnel::new_insecure(
        relay_addr,
        "consumer-zhangsan",
        "tun_secret",
    )?);
    tunnel.connect().await?;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let hash = sha256_hex(b"tun_secret");
    assert!(listener.is_client_online(&delegated_session_key(&hash, "consumer-zhangsan")));

    let mut router = ProxyRouter::new();
    router
        .add_cidr("127.0.0.0/8", Outbound::tunnel("node-a"))
        .unwrap();
    let proxy_addr = get_free_addr();
    let inbound = ProxyInbound::new(proxy_addr, Arc::new(ArcSwap::from_pointee(router)))
        .with_default_opener(Arc::clone(&tunnel) as Arc<dyn ChannelOpener>);
    tokio::spawn(async move {
        let _ = inbound.start().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // SOCKS5 handshake + CONNECT echo
    let mut sock = tokio::net::TcpStream::connect(proxy_addr).await?;
    sock.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    sock.read_exact(&mut resp).await?;
    assert_eq!(resp, [0x05, 0x00]);

    let ip = echo_addr.ip().to_string();
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&[127, 0, 0, 1]);
    req.extend_from_slice(&echo_addr.port().to_be_bytes());
    let _ = ip; // use the 127.0.0.1 literal directly
    sock.write_all(&req).await?;
    let mut resp = [0u8; 10];
    sock.read_exact(&mut resp).await?;
    assert_eq!(resp[1], 0x00, "SOCKS5 connect should succeed");

    sock.write_all(b"ping-through-chain").await?;
    let mut buf = vec![0u8; 64];
    let n = sock.read(&mut buf).await?;
    assert_eq!(&buf[..n], b"ping-through-chain");

    Ok(())
}

/// ACL deny: target outside the delegated token's rule snapshot
#[tokio::test]
async fn client_acl_denied() -> Result<()> {
    let relay_addr = get_free_addr();
    let _listener = start_listener(relay_addr).await;

    let tunnel = ClientTunnel::new_insecure(relay_addr, "consumer-lisi", "tun_secret")?;
    tunnel.connect().await?;

    // 10.9.9.9 is outside the ACL (127.0.0.0/8) → Open must fail
    let res = tunnel.open_channel("10.9.9.9", 8080).await;
    assert!(res.is_err(), "ACL 之外的目标必须被拒绝");

    // unknown delegated token fails auth outright
    let bad = ClientTunnel::new_insecure(relay_addr, "consumer-lisi", "tun_wrong")?;
    assert!(bad.connect().await.is_err());

    Ok(())
}

/// Traffic counters: traffic() reflects current-session Data frame bytes (uplink/downlink, payload only)
#[tokio::test]
async fn client_tunnel_traffic_counters() -> Result<()> {
    let echo_addr = get_free_addr();
    let relay_addr = get_free_addr();

    start_echo_server(echo_addr).await;
    let _listener = start_listener(relay_addr).await;

    let tunnel = ClientTunnel::new_insecure(relay_addr, "consumer-wangwu", "tun_secret")?;
    // (0, 0) before connecting
    assert_eq!(tunnel.traffic().await, (0, 0));

    tunnel.connect().await?;
    tokio::time::sleep(Duration::from_millis(50)).await;
    // still (0, 0) when connected but idle (only Data frames count; auth/heartbeat do not)
    assert_eq!(tunnel.traffic().await, (0, 0));

    // open a channel and send fixed bytes; echo returns them as-is (256KiB fits the flow-control window, no stall)
    const PAYLOAD: usize = 256 * 1024;
    let data = vec![0x5Au8; PAYLOAD];
    let mut ch = tunnel.open_channel("127.0.0.1", echo_addr.port()).await?;
    ch.write_all(&data).await?;
    let mut received = vec![0u8; PAYLOAD];
    ch.read_exact(&mut received).await?;
    assert_eq!(received, data);

    // full downlink arrival implies the uplink was sent and counted; both sides equal the payload size exactly
    let (up, down) = tunnel.traffic().await;
    assert_eq!(up, PAYLOAD as u64, "上行字节应等于发送的 Data payload");
    assert_eq!(down, PAYLOAD as u64, "下行字节应等于回显的 Data payload");

    Ok(())
}
