//! Protocol-level bandwidth diagnostics service integration tests (echo / sink / source, listener and connector sides)
//!
//! - verify RTT / up-down throughput over a loopback tunnel (order-of-magnitude asserts, loose floor against CI jitter)
//! - reserved addresses are intercepted before the ACL check: bandwidth streams still measure when both sides carry an ACL
//!   (no routing capability, not a bypass), and ACL decisions for normal targets stay unaffected with no AclDenied events
//! - unknown mode byte closes the channel silently

use agile_net_core::proto::frame::{Frame, FrameType};
use agile_net_core::proto::message::{
    AuthKind, AuthRequest, PROTOCOL_VERSION, PROTOCOL_VERSION_FLOW_CONTROL,
};
use agile_net_core::proxy::router::{Outbound, ProxyRouter};
use agile_net_core::relay::bandwidth::{
    self, MAGIC_HOST, MODE_ECHO, MODE_SINK, MODE_SOURCE,
};
use agile_net_core::relay::listener::{AuthIdentity, TokenValidator};
use agile_net_core::relay::mux::{MuxSession, SessionEvents};
use agile_net_core::relay::{PeerAcl, PeerEvent, RelayConnector, RelayListener, constant_time_eq};
use agile_net_core::tunnel::tls::TlsConfigBuilder;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Helper: get a free port
fn get_free_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

/// ACL allowing only 127.0.0.0/8 (the magic address is not an IP, never matches → being served proves pre-ACL interception)
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
                groups: auth.groups.clone(),
                control: None,
                acl: self.acl.clone(),
                display: None,
                guarded: false,
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

    let mut auth_req = AuthRequest {
        node_id: node_id.to_string(),
        token: token.to_string(),
        kind: AuthKind::Node,
        advertise: Vec::new(),
            groups: Vec::new(),
        version: PROTOCOL_VERSION,
        my_name: String::new(),
        device_pubkey: String::new(),
        device_sig: String::new(),
    };
    // device proof is mandatory (handshake v4): sign the TLS-exporter challenge (throwaway identity)
    let challenge = agile_net_core::device::session_challenge(tls.get_ref().1).unwrap();
    auth_req.attach_device_proof(&challenge, &agile_net_core::device::DeviceIdentity::ephemeral());
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
    let (mux, _reader) = MuxSession::start(tls, 2, SessionEvents::default(), flow_control, None);
    mux
}

/// Start a static-token listener in the background
async fn start_listener(relay_addr: SocketAddr, token: &str) -> Arc<RelayListener> {
    let listener = Arc::new(RelayListener::new(relay_addr, token).unwrap());
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.start().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    listener
}

/// Full initiator-side measurement: ordered RTT stats, exact up/down byte counts, throughput above a loose floor
#[tokio::test]
async fn bandwidth_full_measure_over_connector_tunnel() {
    let relay_addr = get_free_addr();
    let token = "bw-token";
    start_listener(relay_addr, token).await;

    let connector = RelayConnector::new(relay_addr, "node-b", token).unwrap();
    connector.connect().await.unwrap();
    assert!(connector.is_connected());
    let mux = connector.current_mux().expect("connected connector must expose mux");

    let sample = bandwidth::measure(&mux, 10, 4 * 1024 * 1024)
        .await
        .expect("bandwidth measure over loopback tunnel");

    assert!(sample.rtt.min_ms >= 0.0);
    assert!(sample.rtt.min_ms <= sample.rtt.avg_ms);
    assert!(sample.rtt.avg_ms <= sample.rtt.max_ms);
    assert_eq!(sample.up.bytes, 4 * 1024 * 1024);
    assert_eq!(sample.down.bytes, 4 * 1024 * 1024);
    // loose floor: a loopback tunnel (TLS+mux) should far exceed 10 MB/s (80 Mbps); no hard cap, CI jitter safe
    assert!(
        sample.up.mbps > 80.0,
        "upload throughput too low: {} Mbps",
        sample.up.mbps
    );
    assert!(
        sample.down.mbps > 80.0,
        "download throughput too low: {} Mbps",
        sample.down.mbps
    );

    connector.disconnect().await;
}

/// RelayConnector::open_stream straight to the reserved address + echo roundtrip
#[tokio::test]
async fn bandwidth_connector_open_stream_echo() {
    let relay_addr = get_free_addr();
    let token = "bw-token";
    start_listener(relay_addr, token).await;

    let connector = RelayConnector::new(relay_addr, "node-b", token).unwrap();
    connector.connect().await.unwrap();

    let mut ch = connector.open_stream(MAGIC_HOST, 0).await.unwrap();
    ch.write_u8(MODE_ECHO).await.unwrap();
    ch.write_all(b"ping-payload").await.unwrap();
    let mut buf = [0u8; 64];
    let n = ch.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"ping-payload");

    connector.disconnect().await;
}

/// Fan-in side (listener) with ACL: magic address still intercepted and served (before ACL),
/// normal missing targets still denied, and the magic address emits no AclDenied event
#[tokio::test]
async fn bandwidth_listener_side_serves_before_acl() {
    let relay_addr = get_free_addr();
    let token = "bw-token";

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

    // sink: 1 MiB upload, peer confirms the count (magic address is not an IP, never matches the loopback ACL → intercepted)
    let up = bandwidth::measure_upload(&mux, 1024 * 1024).await.unwrap();
    assert_eq!(up.bytes, 1024 * 1024);

    // source: 1 MiB download read in full
    let down = bandwidth::measure_download(&mux, 1024 * 1024).await.unwrap();
    assert_eq!(down.bytes, 1024 * 1024);

    // echo: small payload roundtrip
    let mut ch = bandwidth::open_stream(&mux).await.unwrap();
    ch.write_u8(MODE_ECHO).await.unwrap();
    ch.write_all(b"acl-before").await.unwrap();
    let mut buf = [0u8; 64];
    let n = ch.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"acl-before");
    drop(ch);

    // magic address emits no AclDenied (ignore online/offline etc. within a 300ms window)
    let deadline = tokio::time::Instant::now() + Duration::from_millis(300);
    loop {
        match tokio::time::timeout_at(deadline, events.recv()).await {
            Ok(Ok(PeerEvent::AclDenied { target, .. })) => {
                panic!("magic target must not emit AclDenied: {target}")
            }
            Ok(_) => continue,
            Err(_) => break, // no more events within the window
        }
    }

    // ACL decisions unaffected: a normal missing target from the fan-in peer still OpenFails
    let payload = serde_json::to_vec(&agile_net_core::proto::message::OpenChannel::new("8.8.8.8", 443)).unwrap();
    let denied = mux.open_channel(Bytes::from(payload)).await;
    assert!(denied.is_err(), "non-magic target must still be denied by ACL");
}

/// Fan-out side (connector) with ACL: upstream reverse traffic to the magic address still intercepted (before ACL),
/// normal missing targets still denied
#[tokio::test]
async fn bandwidth_connector_side_serves_before_acl() {
    let relay_addr = get_free_addr();
    let token = "bw-token";
    let listener = start_listener(relay_addr, token).await;

    let connector = RelayConnector::new(relay_addr, "node-b", token)
        .unwrap()
        .with_acl(Some(loopback_acl()));
    let mut events = connector.subscribe_events();
    connector.connect().await.unwrap();
    assert!(connector.is_connected());

    // echo roundtrip (reverse-opened by the upstream listener)
    let mut ch = listener
        .open_channel("node-b", MAGIC_HOST, 0)
        .await
        .expect("magic target must be served despite connector ACL");
    ch.write_u8(MODE_ECHO).await.unwrap();
    ch.write_all(b"fanout-magic").await.unwrap();
    let mut buf = [0u8; 64];
    let n = ch.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"fanout-magic");
    drop(ch);

    // sink: 1 MiB upload (peer connector confirms the received count)
    let mut ch = listener.open_channel("node-b", MAGIC_HOST, 0).await.unwrap();
    ch.write_u8(MODE_SINK).await.unwrap();
    let chunk = vec![0u8; 64 * 1024];
    for _ in 0..16 {
        ch.write_all(&chunk).await.unwrap();
    }
    ch.shutdown().await.unwrap();
    let acked = ch.read_u64().await.unwrap();
    assert_eq!(acked, 1024 * 1024);
    drop(ch);

    // source: 512 KiB download read in full
    let mut ch = listener.open_channel("node-b", MAGIC_HOST, 0).await.unwrap();
    ch.write_u8(MODE_SOURCE).await.unwrap();
    ch.write_u64(512 * 1024).await.unwrap();
    let mut got: u64 = 0;
    let mut buf = vec![0u8; 64 * 1024];
    while got < 512 * 1024 {
        let n = ch.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        got += n as u64;
    }
    assert_eq!(got, 512 * 1024);
    drop(ch);

    // ACL decisions unaffected: normal missing target still OpenFail + AclDenied event
    let denied = listener.open_channel("node-b", "8.8.8.8", 443).await;
    assert!(denied.is_err(), "non-magic target must still be denied by ACL");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::time::timeout_at(deadline, events.recv()).await {
            Ok(Ok(PeerEvent::AclDenied { target, .. })) => {
                assert_eq!(target, "8.8.8.8:443");
                break;
            }
            Ok(Ok(_)) => continue,
            other => panic!("expected AclDenied event, got {other:?}"),
        }
    }

    connector.disconnect().await;
}

/// Unknown mode byte: peer silently closes the channel (reads EOF), no panic, no hang
#[tokio::test]
async fn bandwidth_unknown_mode_closes_channel() {
    let relay_addr = get_free_addr();
    let token = "bw-token";
    start_listener(relay_addr, token).await;

    let connector = RelayConnector::new(relay_addr, "node-b", token).unwrap();
    connector.connect().await.unwrap();

    let mut ch = connector.open_stream(MAGIC_HOST, 0).await.unwrap();
    ch.write_u8(0x00).await.unwrap();
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(3), ch.read(&mut buf))
        .await
        .expect("channel must close promptly on unknown mode")
        .unwrap();
    assert_eq!(n, 0, "unknown mode must yield EOF");

    connector.disconnect().await;
}
