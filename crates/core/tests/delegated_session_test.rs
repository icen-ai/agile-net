//! Unified-issuance delegated consumer session tests:
//! - session key `delegated:<token_hash>:<node_id>` (multi-endpoint coexistence)
//! - concurrency policy enforced at auth: single kicks older sessions, multi caps at max_sessions
//! - persistent local registry (self-entry/direct mode): auth resolution order local -> session,
//!   entries never die with any session
//! - Ctrl token_register/revoke full path over a real issuer node session

use agile_net_core::proto::frame::{Frame, FrameType};
use agile_net_core::proto::message::{
    AuthKind, AuthRequest, Concurrency, CtrlMessage, HintEntry, PROTOCOL_VERSION,
};
use agile_net_core::relay::listener::{
    DelegatedRegistry, DelegatedToken, RelayListener, delegated_session_key,
};
use agile_net_core::relay::mux::{MuxSession, SessionEvents};
use agile_net_core::tunnel::tls::TlsConfigBuilder;
use agile_net_core::util::sha256_hex;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;

fn get_free_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

fn delegated_entry(concurrency: Concurrency, max_sessions: u32) -> DelegatedToken {
    DelegatedToken {
        issuer: "issuer-x".into(),
        label: "tok".into(),
        groups: vec![],
        acl_rules: vec!["127.0.0.0/8".into()],
        hint_map: vec![],
        concurrency,
        max_sessions,
    }
}

async fn start_listener(addr: SocketAddr) -> Arc<RelayListener> {
    let listener = Arc::new(RelayListener::new(addr, "node-psk").unwrap());
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.start().await;
    });
    tokio::time::sleep(Duration::from_millis(60)).await;
    listener
}

/// Consumer auth against the listener (kind = Client). Some(stream) on AuthOk — holding the
/// stream open keeps the session online; None on AuthFail.
async fn consumer_auth(
    addr: SocketAddr,
    node_id: &str,
    token: &str,
) -> Option<tokio_rustls::client::TlsStream<TcpStream>> {
    let tls = TlsConfigBuilder::new()
        .allow_self_signed(true)
        .build_client()
        .unwrap();
    let connector = tokio_rustls::TlsConnector::from(tls);
    let tcp = TcpStream::connect(addr).await.ok()?;
    let server_name =
        rustls::pki_types::ServerName::try_from("cdn.cloudflare.com".to_string()).unwrap();
    let mut stream = connector.connect(server_name, tcp).await.ok()?;
    let auth = AuthRequest {
        node_id: node_id.into(),
        token: token.into(),
        kind: AuthKind::Client,
        advertise: vec![],
        groups: vec![],
        version: PROTOCOL_VERSION,
    };
    let payload = serde_json::to_vec(&auth).unwrap();
    Frame::new(FrameType::Auth, 0, Bytes::from(payload))
        .write_to(&mut stream)
        .await
        .ok()?;
    let f = Frame::read_from(&mut stream).await.ok()?;
    if f.frame_type == FrameType::AuthOk {
        Some(stream)
    } else {
        None
    }
}

/// Issuer node peer with a Ctrl-plane subscription (for token_register/revoke + ack reads).
async fn issuer_peer(
    addr: SocketAddr,
    node_id: &str,
    token: &str,
) -> (Arc<MuxSession>, tokio::sync::mpsc::Receiver<Bytes>) {
    let tls = TlsConfigBuilder::new()
        .allow_self_signed(true)
        .build_client()
        .unwrap();
    let connector = tokio_rustls::TlsConnector::from(tls);
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name =
        rustls::pki_types::ServerName::try_from("cdn.cloudflare.com".to_string()).unwrap();
    let mut stream = connector.connect(server_name, tcp).await.unwrap();
    let auth = AuthRequest {
        node_id: node_id.into(),
        token: token.into(),
        kind: AuthKind::Node,
        advertise: vec![],
        groups: vec![],
        version: PROTOCOL_VERSION,
    };
    let payload = serde_json::to_vec(&auth).unwrap();
    Frame::new(FrameType::Auth, 0, Bytes::from(payload))
        .write_to(&mut stream)
        .await
        .unwrap();
    let res = Frame::read_from(&mut stream).await.unwrap();
    assert_eq!(res.frame_type, FrameType::AuthOk);
    let (ctrl_tx, ctrl_rx) = tokio::sync::mpsc::channel::<Bytes>(8);
    // both ends are v4: flow control negotiated on
    let (mux, _reader) = MuxSession::start(
        stream,
        2,
        SessionEvents {
            open_tx: None,
            ctrl_tx: Some(ctrl_tx),
        },
        true,
        None,
    );
    (mux, ctrl_rx)
}

async fn send_ctrl(mux: &MuxSession, msg: &CtrlMessage) {
    let payload = serde_json::to_vec(msg).unwrap();
    mux.send_frame(Frame::new(FrameType::Ctrl, 0, Bytes::from(payload)))
        .await
        .unwrap();
}

async fn recv_ack(rx: &mut tokio::sync::mpsc::Receiver<Bytes>) -> (bool, String) {
    let payload = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("ack delivered")
        .expect("payload");
    let CtrlMessage::TokenAck { ok, error, .. } = serde_json::from_slice(&payload).unwrap() else {
        panic!("expected TokenAck");
    };
    (ok, error)
}

#[test]
fn session_key_includes_node_id() {
    assert_eq!(delegated_session_key("hash64", "node-a"), "delegated:hash64:node-a");
}

/// multi: sessions of one token coexist across node_ids until max_sessions, then auth is refused;
/// a freed slot admits the next consumer again
#[tokio::test]
async fn multi_sessions_coexist_until_cap() {
    let addr = get_free_addr();
    let listener = start_listener(addr).await;
    let token = "psk_delegated-multi";
    let hash = sha256_hex(token.as_bytes());
    listener
        .delegated_registry()
        .insert(hash.clone(), delegated_entry(Concurrency::Multi, 2));

    let key_a = delegated_session_key(&hash, "consumer-a");
    let key_b = delegated_session_key(&hash, "consumer-b");
    let key_c = delegated_session_key(&hash, "consumer-c");

    let s_a = consumer_auth(addr, "consumer-a", token).await.expect("a online");
    let s_b = consumer_auth(addr, "consumer-b", token).await.expect("b online");
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(listener.is_client_online(&key_a));
    assert!(listener.is_client_online(&key_b));

    // cap reached: the third consumer's auth is rejected
    assert!(
        consumer_auth(addr, "consumer-c", token).await.is_none(),
        "max_sessions 达到后新会话认证必须被拒"
    );

    // freeing a slot admits the next consumer
    drop(s_a);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!listener.is_client_online(&key_a));
    let _s_c = consumer_auth(addr, "consumer-c", token).await.expect("c online after slot freed");
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(listener.is_client_online(&key_c));
    drop(s_b);
}

/// single: a new session of the same token kicks every older one (any node_id)
#[tokio::test]
async fn single_policy_kicks_previous() {
    let addr = get_free_addr();
    let listener = start_listener(addr).await;
    let token = "psk_delegated-single";
    let hash = sha256_hex(token.as_bytes());
    listener
        .delegated_registry()
        .insert(hash.clone(), delegated_entry(Concurrency::Single, 1));

    let key_a = delegated_session_key(&hash, "consumer-a");
    let key_b = delegated_session_key(&hash, "consumer-b");

    let _s_a = consumer_auth(addr, "consumer-a", token).await.expect("a online");
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(listener.is_client_online(&key_a));

    let _s_b = consumer_auth(addr, "consumer-b", token).await.expect("b online");
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(!listener.is_client_online(&key_a), "single 档旧会话必须被踢");
    assert!(listener.is_client_online(&key_b));
}

/// Local registry (self-entry/direct mode): auth resolves local before session-scoped, and the
/// entry never dies with any session.
#[tokio::test]
async fn local_registry_wins_and_persists() {
    let addr = get_free_addr();
    let base = RelayListener::new(addr, "node-psk").unwrap();
    let local: DelegatedRegistry = Arc::new(dashmap::DashMap::new());
    let session: DelegatedRegistry = Arc::new(dashmap::DashMap::new());
    let listener = Arc::new(
        base.with_local_delegated_registry(local.clone())
            .with_delegated_registry(session.clone()),
    );
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.start().await;
    });
    tokio::time::sleep(Duration::from_millis(60)).await;

    let token = "psk_delegated-local";
    let hash = sha256_hex(token.as_bytes());
    // same hash in both registries, distinguishable by policy: local multi/5, session single/1
    local.insert(hash.clone(), delegated_entry(Concurrency::Multi, 5));
    let mut session_entry = delegated_entry(Concurrency::Single, 1);
    session_entry.label = "session".into();
    session.insert(hash.clone(), session_entry);

    // two consumers of the same token coexist -> the local multi entry answered (precedence)
    let _s_a = consumer_auth(addr, "consumer-a", token).await.expect("a online");
    let s_b = consumer_auth(addr, "consumer-b", token).await.expect("b online");
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(listener.is_client_online(&delegated_session_key(&hash, "consumer-a")));
    assert!(
        listener.is_client_online(&delegated_session_key(&hash, "consumer-b")),
        "local 注册表优先（multi 并存），session 级 single 未生效"
    );

    // entries never die with a session: dropping the consumers keeps re-auth working
    drop(s_b);
    drop(_s_a);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(listener.online_client_count(), 0);
    assert!(local.contains_key(&hash), "本地注册表永不随会话清空");
    let _s_c = consumer_auth(addr, "consumer-c", token).await.expect("re-auth still works");
}

/// Full path: issuer registers/revokes over Ctrl frames (with the concurrency policy fields);
/// consumer sessions follow the registration lifecycle (revoke kicks every node_id's session).
#[tokio::test]
async fn ctrl_register_revoke_drives_consumer_sessions() {
    let addr = get_free_addr();
    let listener = start_listener(addr).await;
    let (issuer, mut acks) = issuer_peer(addr, "issuer-a", "node-psk").await;

    let token = "psk_delegated-ctrl";
    let hash = sha256_hex(token.as_bytes());

    // invalid max_sessions is rejected with an error ack
    send_ctrl(
        &issuer,
        &CtrlMessage::TokenRegister {
            token_hash: hash.clone(),
            label: "bad".into(),
            groups: vec![],
            hint_map: vec![HintEntry {
                hint: format!("en_{}", &hash[..12]),
                groups: vec![],
            }],
            concurrency: Concurrency::Multi,
            max_sessions: 0,
        },
    )
    .await;
    let (ok, error) = recv_ack(&mut acks).await;
    assert!(!ok);
    assert!(error.contains("max_sessions"), "实际错误: {error}");

    // valid registration (entrust hint: no pushed groups needed)
    send_ctrl(
        &issuer,
        &CtrlMessage::TokenRegister {
            token_hash: hash.clone(),
            label: "good".into(),
            groups: vec![],
            hint_map: vec![HintEntry {
                hint: format!("en_{}", &hash[..12]),
                groups: vec![],
            }],
            concurrency: Concurrency::Multi,
            max_sessions: 2,
        },
    )
    .await;
    let (ok, _) = recv_ack(&mut acks).await;
    assert!(ok, "注册必须成功");

    let key_a = delegated_session_key(&hash, "consumer-a");
    let key_b = delegated_session_key(&hash, "consumer-b");
    let _s_a = consumer_auth(addr, "consumer-a", token).await.expect("a online");
    let _s_b = consumer_auth(addr, "consumer-b", token).await.expect("b online");
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(listener.is_client_online(&key_a));
    assert!(listener.is_client_online(&key_b));
    assert!(
        consumer_auth(addr, "consumer-c", token).await.is_none(),
        "超过 max_sessions 必须被拒"
    );

    // revoke: every session of the token (any node_id) is kicked
    send_ctrl(
        &issuer,
        &CtrlMessage::TokenRevoke {
            token_hash: hash.clone(),
            concurrency: Concurrency::Multi,
            max_sessions: 2,
        },
    )
    .await;
    let (ok, _) = recv_ack(&mut acks).await;
    assert!(ok);
    assert!(!listener.is_client_online(&key_a));
    assert!(!listener.is_client_online(&key_b));

    // registration is gone: fresh auth fails closed
    assert!(consumer_auth(addr, "consumer-d", token).await.is_none());
}

/// Session-scoped registrations die with the issuer session (revoke-by-disconnect), and the
/// consumer sessions they authenticated are kicked; a local entry of the same shape survives.
#[tokio::test]
async fn issuer_disconnect_revokes_session_registrations() {
    let addr = get_free_addr();
    let base = RelayListener::new(addr, "node-psk").unwrap();
    let local: DelegatedRegistry = Arc::new(dashmap::DashMap::new());
    let listener = Arc::new(base.with_local_delegated_registry(local.clone()));
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.start().await;
    });
    tokio::time::sleep(Duration::from_millis(60)).await;

    let (issuer, mut acks) = issuer_peer(addr, "issuer-a", "node-psk").await;
    let token = "psk_delegated-lifecycle";
    let hash = sha256_hex(token.as_bytes());
    send_ctrl(
        &issuer,
        &CtrlMessage::TokenRegister {
            token_hash: hash.clone(),
            label: "lifecycle".into(),
            groups: vec![],
            hint_map: vec![HintEntry {
                hint: format!("en_{}", &hash[..12]),
                groups: vec![],
            }],
            concurrency: Concurrency::Multi,
            max_sessions: 4,
        },
    )
    .await;
    let (ok, _) = recv_ack(&mut acks).await;
    assert!(ok);

    let key = delegated_session_key(&hash, "consumer-a");
    let _s = consumer_auth(addr, "consumer-a", token).await.expect("consumer online");
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(listener.is_client_online(&key));

    // issuer session drops -> the registration and its consumer sessions die
    // (shutdown aborts the local reader; dropping the last mux ref closes the writer half,
    // so the listener sees EOF and runs its session teardown)
    issuer.shutdown();
    drop(issuer);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!listener.is_client_online(&key), "签发端断连必须吊销其委托会话");
    assert!(consumer_auth(addr, "consumer-b", token).await.is_none());

    // a local entry is unaffected by any session lifecycle
    local.insert(hash.clone(), delegated_entry(Concurrency::Multi, 4));
    let _s2 = consumer_auth(addr, "consumer-b", token)
        .await
        .expect("local entry keeps auth working");
}
