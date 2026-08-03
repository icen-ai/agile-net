//! Peer ACL integration tests: fan-in / fan-out data-plane restriction points
//!
//! - fan-in: target connections opened by the listener-side peer (AuthKind::Node) session are restricted by AuthIdentity.acl
//! - fan-out: reverse target connections arriving over the connector tunnel are restricted by the ACL injected via with_acl
//! - `None` on both sides means no restriction (allow all); denials emit a subscribable AclDenied event

use agile_net_core::proto::frame::{Frame, FrameType};
use agile_net_core::proto::message::{
    AuthKind, AuthRequest, OpenChannel, PROTOCOL_VERSION, PROTOCOL_VERSION_FLOW_CONTROL,
};
use agile_net_core::proxy::router::{Outbound, ProxyRouter};
use agile_net_core::relay::listener::{AuthIdentity, TokenValidator};
use agile_net_core::relay::mux::MuxSession;
use agile_net_core::relay::{PeerAcl, PeerEvent, RelayConnector, RelayListener, constant_time_eq};
use agile_net_core::tunnel::tls::TlsConfigBuilder;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Helper: get a free port
fn get_free_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

/// Start a TCP echo server
async fn start_echo_server(addr: SocketAddr) {
    let echo = TcpListener::bind(addr).await.unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = echo.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 || stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
}

/// ACL allowing only 127.0.0.0/8
fn loopback_acl() -> Arc<PeerAcl> {
    let mut router = ProxyRouter::new();
    router.add_cidr("127.0.0.0/8", Outbound::Direct).unwrap();
    Arc::new(PeerAcl::new(router))
}

/// Test validator: static token + optional peer ACL
struct AclValidator {
    token: String,
    acl: Option<Arc<PeerAcl>>,
}

impl TokenValidator for AclValidator {
    fn validate(&self, auth: &AuthRequest) -> Option<AuthIdentity> {
        if auth.kind != AuthKind::Node {
            return None;
        }
        if constant_time_eq(auth.token.as_bytes(), self.token.as_bytes()) {
            Some(AuthIdentity::Node {
                node_id: auth.node_id.clone(),
                advertise: auth.advertise.clone(),
                control: None,
                acl: self.acl.clone(),
            })
        } else {
            None
        }
    }
}

/// Simulate a fan-in peer over a raw mux session (Node auth, may then open channels)
async fn connect_raw_peer(relay_addr: SocketAddr, node_id: &str, token: &str) -> Arc<MuxSession> {
    let tls_builder = TlsConfigBuilder::new().allow_self_signed(true);
    let server_name =
        rustls::pki_types::ServerName::try_from(tls_builder.sni_hostname.clone()).unwrap();
    let tls_connector = tokio_rustls::TlsConnector::from(tls_builder.build_client().unwrap());
    let tcp = TcpStream::connect(relay_addr).await.unwrap();
    let mut tls = tls_connector.connect(server_name, tcp).await.unwrap();

    let auth_req = AuthRequest {
        node_id: node_id.to_string(),
        token: token.to_string(),
        kind: AuthKind::Node,
        advertise: Vec::new(),
        version: PROTOCOL_VERSION,
    };
    let payload = serde_json::to_vec(&auth_req).unwrap();
    Frame::new(FrameType::Auth, 0, Bytes::from(payload))
        .write_to(&mut tls)
        .await
        .unwrap();
    let res = Frame::read_from(&mut tls).await.unwrap();
    assert_eq!(res.frame_type, FrameType::AuthOk);
    let mut server_version = 1u32;
    if !res.payload.is_empty()
        && let Ok(v) = serde_json::from_slice::<serde_json::Value>(&res.payload)
    {
        server_version = v["version"].as_u64().unwrap_or(1) as u32;
    }
    let flow_control = server_version >= PROTOCOL_VERSION_FLOW_CONTROL;
    let (mux, _reader) = MuxSession::start(tls, 2, None, flow_control, None);
    mux
}

/// Wait for the first AclDenied from the event stream (ignoring other events); panic on timeout
async fn expect_acl_denied(events: &mut tokio::sync::broadcast::Receiver<PeerEvent>) -> (String, String) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::time::timeout_at(deadline, events.recv()).await {
            Ok(Ok(PeerEvent::AclDenied { peer_label, target })) => return (peer_label, target),
            Ok(Ok(_)) => continue,
            other => panic!("expected AclDenied event, got {other:?}"),
        }
    }
}

/// Fan-in restriction: peer-opened target misses the ACL → OpenFail + AclDenied event
#[tokio::test]
async fn fanin_peer_open_denied_by_acl() {
    let relay_addr = get_free_addr();
    let token = "fanin-token";

    let (server_config, _) = TlsConfigBuilder::new().build_server().unwrap();
    let listener = Arc::new(RelayListener::with_validator(
        relay_addr,
        Arc::new(AclValidator {
            token: token.to_string(),
            acl: Some(loopback_acl()),
        }),
        tokio_rustls::TlsAcceptor::from(server_config),
    ));
    let mut events = listener.subscribe_events();
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.start().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mux = connect_raw_peer(relay_addr, "peer-a", token).await;

    let payload = serde_json::to_vec(&OpenChannel {
        target_addr: "8.8.8.8".to_string(),
        target_port: 443,
    })
    .unwrap();
    let res = mux.open_channel(Bytes::from(payload)).await;
    assert!(res.is_err(), "denied target must fail to open");

    let (peer_label, target) = expect_acl_denied(&mut events).await;
    assert_eq!(peer_label, "peer-a");
    assert_eq!(target, "8.8.8.8:443");
}

/// Fan-in restriction: target hits the ACL → normal bridging (echo roundtrip)
#[tokio::test]
async fn fanin_peer_open_allowed_by_acl() {
    let echo_addr = get_free_addr();
    let relay_addr = get_free_addr();
    let token = "fanin-token";
    start_echo_server(echo_addr).await;

    let (server_config, _) = TlsConfigBuilder::new().build_server().unwrap();
    let listener = Arc::new(RelayListener::with_validator(
        relay_addr,
        Arc::new(AclValidator {
            token: token.to_string(),
            acl: Some(loopback_acl()),
        }),
        tokio_rustls::TlsAcceptor::from(server_config),
    ));
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.start().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mux = connect_raw_peer(relay_addr, "peer-a", token).await;
    let payload = serde_json::to_vec(&OpenChannel {
        target_addr: echo_addr.ip().to_string(),
        target_port: echo_addr.port(),
    })
    .unwrap();
    let mut channel = mux.open_channel(Bytes::from(payload)).await.unwrap();

    channel.write_all(b"fanin-allow").await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = channel.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"fanin-allow");
}

/// Fan-in None semantics: peer carries no ACL → allow everything (echo roundtrip)
#[tokio::test]
async fn fanin_peer_open_none_acl_allows_all() {
    let echo_addr = get_free_addr();
    let relay_addr = get_free_addr();
    let token = "fanin-token";
    start_echo_server(echo_addr).await;

    // StaticTokenValidator yields acl=None
    let listener = Arc::new(RelayListener::new(relay_addr, token).unwrap());
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.start().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mux = connect_raw_peer(relay_addr, "peer-a", token).await;
    let payload = serde_json::to_vec(&OpenChannel {
        target_addr: echo_addr.ip().to_string(),
        target_port: echo_addr.port(),
    })
    .unwrap();
    let mut channel = mux.open_channel(Bytes::from(payload)).await.unwrap();

    channel.write_all(b"fanin-none").await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = channel.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"fanin-none");
}

/// Fan-out restriction: reverse-opened target misses the ACL → OpenFail + AclDenied event
#[tokio::test]
async fn fanout_reverse_open_denied_by_acl() {
    let relay_addr = get_free_addr();
    let token = "fanout-token";

    let listener = Arc::new(RelayListener::new(relay_addr, token).unwrap());
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.start().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let connector = RelayConnector::new(relay_addr, "node-b", token)
        .unwrap()
        .with_acl(Some(loopback_acl()));
    let mut events = connector.subscribe_events();
    connector.connect().await.unwrap();
    assert!(connector.is_connected());

    // upstream reverse-opens a target connection over the tunnel (misses the ACL)
    let res = listener.open_channel("node-b", "8.8.8.8", 443).await;
    assert!(res.is_err(), "denied target must fail to open");

    let (peer_label, target) = expect_acl_denied(&mut events).await;
    assert_eq!(peer_label, relay_addr.to_string());
    assert_eq!(target, "8.8.8.8:443");

    connector.disconnect().await;
}

/// Fan-out restriction: target hits the ACL → normal bridging (echo roundtrip)
#[tokio::test]
async fn fanout_reverse_open_allowed_by_acl() {
    let echo_addr = get_free_addr();
    let relay_addr = get_free_addr();
    let token = "fanout-token";
    start_echo_server(echo_addr).await;

    let listener = Arc::new(RelayListener::new(relay_addr, token).unwrap());
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.start().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let connector = RelayConnector::new(relay_addr, "node-b", token)
        .unwrap()
        .with_acl(Some(loopback_acl()));
    connector.connect().await.unwrap();

    let mut channel = listener
        .open_channel("node-b", &echo_addr.ip().to_string(), echo_addr.port())
        .await
        .unwrap();
    channel.write_all(b"fanout-allow").await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = channel.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"fanout-allow");

    connector.disconnect().await;
}

/// Fan-out None semantics: no ACL attached → allow everything (echo roundtrip)
#[tokio::test]
async fn fanout_reverse_open_none_acl_allows_all() {
    let echo_addr = get_free_addr();
    let relay_addr = get_free_addr();
    let token = "fanout-token";
    start_echo_server(echo_addr).await;

    let listener = Arc::new(RelayListener::new(relay_addr, token).unwrap());
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.start().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let connector = RelayConnector::new(relay_addr, "node-b", token).unwrap();
    connector.connect().await.unwrap();

    let mut channel = listener
        .open_channel("node-b", &echo_addr.ip().to_string(), echo_addr.port())
        .await
        .unwrap();
    channel.write_all(b"fanout-none").await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = channel.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"fanout-none");

    connector.disconnect().await;
}
