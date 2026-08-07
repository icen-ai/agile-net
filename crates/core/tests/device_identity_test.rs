//! Device identity (handshake v4, node.md M2) integration tests:
//! - proof mandatory: missing/invalid proof is rejected with `device_proof_invalid`
//! - device_fp is derived by the listener from the presented pubkey (never trusted from the wire)
//! - same fp reconnects fine; a forged fp (pubkey/sig mismatch) can never authenticate
//! - session notices: single-takeover and delegated-revoke ship a SessionNotice with reason +
//!   one-time message before the forced close

use agile_net_core::device::DeviceIdentity;
use agile_net_core::proto::frame::{Frame, FrameType};
use agile_net_core::proto::message::{
    AuthKind, AuthRequest, Concurrency, CtrlMessage, HintEntry, PROTOCOL_VERSION, reason,
};
use agile_net_core::relay::listener::RelayListener;
use agile_net_core::relay::mux::{MuxSession, SessionEvents};
use agile_net_core::tunnel::tls::TlsConfigBuilder;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

fn get_free_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
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

enum Proof {
    Valid,
    Missing,
    /// Sign with a DIFFERENT key than the declared pubkey (fp forgery attempt)
    Forged,
}

/// Open TLS + send Auth (kind=Node), returning (stream, AuthOk payload / AuthFail payload).
async fn node_auth(
    addr: SocketAddr,
    node_id: &str,
    identity: &DeviceIdentity,
    proof: Proof,
) -> (
    tokio_rustls::client::TlsStream<TcpStream>,
    Frame,
) {
    node_auth_adv(addr, node_id, identity, proof, vec![]).await
}

/// node_auth with an advertised route set (issuers need their hint vocabulary routed back).
async fn node_auth_adv(
    addr: SocketAddr,
    node_id: &str,
    identity: &DeviceIdentity,
    proof: Proof,
    advertise: Vec<&str>,
) -> (
    tokio_rustls::client::TlsStream<TcpStream>,
    Frame,
) {
    let tls = TlsConfigBuilder::new()
        .allow_self_signed(true)
        .build_client()
        .unwrap();
    let connector = tokio_rustls::TlsConnector::from(tls);
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name =
        rustls::pki_types::ServerName::try_from("cdn.cloudflare.com".to_string()).unwrap();
    let mut stream = connector.connect(server_name, tcp).await.unwrap();
    let mut auth = AuthRequest {
        node_id: node_id.into(),
        token: "node-psk".into(),
        kind: AuthKind::Node,
        advertise: advertise.iter().map(|s| s.to_string()).collect(),
        groups: vec![],
        version: PROTOCOL_VERSION,
        my_name: "测试机".into(),
        device_pubkey: String::new(),
        device_sig: String::new(),
    };
    let challenge = agile_net_core::device::session_challenge(stream.get_ref().1).unwrap();
    match proof {
        Proof::Valid => auth.attach_device_proof(&challenge, identity),
        Proof::Missing => {}
        Proof::Forged => {
            // declare OUR pubkey but sign with a DIFFERENT key — the listener's derived fp must
            // never match a claim, and verification must fail
            let other = DeviceIdentity::ephemeral();
            auth.device_pubkey = agile_net_core::util::base64_encode(identity.pubkey());
            auth.device_sig = agile_net_core::util::base64_encode(&other.sign(&challenge));
        }
    }
    let payload = serde_json::to_vec(&auth).unwrap();
    Frame::new(FrameType::Auth, 0, Bytes::from(payload))
        .write_to(&mut stream)
        .await
        .unwrap();
    let res = Frame::read_from(&mut stream).await.unwrap();
    (stream, res)
}

#[tokio::test]
async fn proof_binds_listener_derived_device_fp() {
    let addr = get_free_addr();
    let listener = start_listener(addr).await;
    let id = DeviceIdentity::ephemeral();

    let (stream, res) = node_auth(addr, "n1", &id, Proof::Valid).await;
    assert_eq!(res.frame_type, FrameType::AuthOk);
    // hold the session via a mux so the registry stays populated
    let (mux, _reader) = MuxSession::start(stream, 2, SessionEvents::default(), true, None);
    tokio::time::sleep(Duration::from_millis(80)).await;

    let metas = listener.session_metas();
    assert_eq!(metas.len(), 1);
    assert_eq!(metas[0].device_fp, id.device_fp());
    assert_eq!(metas[0].my_name, "测试机");
    assert!(metas[0].session_id.starts_with("sess_"));
    mux.shutdown();
}

#[tokio::test]
async fn missing_or_forged_proof_is_rejected() {
    let addr = get_free_addr();
    let listener = start_listener(addr).await;
    let id = DeviceIdentity::ephemeral();

    // missing proof
    let (_s, res) = node_auth(addr, "n1", &id, Proof::Missing).await;
    assert_eq!(res.frame_type, FrameType::AuthFail);
    let fail: agile_net_core::proto::message::FailReason =
        serde_json::from_slice(&res.payload).unwrap();
    assert_eq!(fail.reason_code, reason::DEVICE_PROOF_INVALID);

    // forged proof (pubkey/sig mismatch)
    let (_s, res) = node_auth(addr, "n1", &id, Proof::Forged).await;
    assert_eq!(res.frame_type, FrameType::AuthFail);

    // nothing registered
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(listener.session_metas().is_empty());

    // same device CAN reconnect (same fp passes again)
    let (stream, res) = node_auth(addr, "n1", &id, Proof::Valid).await;
    assert_eq!(res.frame_type, FrameType::AuthOk);
    let (mux, _r) = MuxSession::start(stream, 2, SessionEvents::default(), true, None);
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(listener.session_metas()[0].device_fp, id.device_fp());
    mux.shutdown();
}

#[tokio::test]
async fn stale_node_session_gets_takeover_notice() {
    let addr = get_free_addr();
    let _listener = start_listener(addr).await;
    let id = DeviceIdentity::ephemeral();

    // first session with a ctrl subscription
    let (stream, res) = node_auth(addr, "dup-node", &id, Proof::Valid).await;
    assert_eq!(res.frame_type, FrameType::AuthOk);
    let (ctrl_tx, mut ctrl_rx) = tokio::sync::mpsc::channel::<Bytes>(8);
    let (mux1, _r1) = MuxSession::start(
        stream,
        2,
        SessionEvents {
            open_tx: None,
            ctrl_tx: Some(ctrl_tx),
        },
        true,
        None,
    );
    tokio::time::sleep(Duration::from_millis(80)).await;

    // second session with the same node_id kicks the first
    let (stream2, res2) = node_auth(addr, "dup-node", &id, Proof::Valid).await;
    assert_eq!(res2.frame_type, FrameType::AuthOk);
    let (mux2, _r2) = MuxSession::start(stream2, 2, SessionEvents::default(), true, None);

    let notice = tokio::time::timeout(Duration::from_secs(3), ctrl_rx.recv())
        .await
        .expect("takeover notice")
        .expect("ctrl frame");
    let msg: CtrlMessage = serde_json::from_slice(&notice).unwrap();
    match msg {
        CtrlMessage::SessionNotice { reason_code, .. } => {
            assert_eq!(reason_code, reason::SESSION_TAKEOVER)
        }
        other => panic!("unexpected ctrl message: {other:?}"),
    }
    mux1.shutdown();
    mux2.shutdown();
}

#[tokio::test]
async fn device_gate_blocks_pending_and_rejects_revoked() {
    // gate state machine for the test: 0=pending 1=certified 2=revoked
    let gate_state = Arc::new(std::sync::atomic::AtomicU8::new(0));
    let gs = gate_state.clone();
    let gate: agile_net_core::relay::listener::DeviceGateHook = Arc::new(move |_fp| {
        match gs.load(std::sync::atomic::Ordering::Relaxed) {
            1 => agile_net_core::relay::listener::DeviceGate::Allow,
            2 => agile_net_core::relay::listener::DeviceGate::Deny,
            _ => agile_net_core::relay::listener::DeviceGate::Pending,
        }
    });

    let addr = get_free_addr();
    // direct-entry delegated token in the persistent local registry
    let registry: agile_net_core::relay::listener::DelegatedRegistry =
        Arc::new(dashmap::DashMap::new());
    let token_hash = agile_net_core::util::sha256_hex(b"gate-token");
    registry.insert(
        token_hash.clone(),
        agile_net_core::relay::listener::DelegatedToken {
            issuer: "self".into(),
            label: "gate-tok".into(),
            groups: vec![],
            acl_rules: vec!["127.0.0.0/8".into()],
            hint_map: vec![],
            concurrency: Concurrency::Multi,
            max_sessions: 4,
        },
    );
    let listener = RelayListener::new(addr, "node-psk").unwrap();
    let listener = Arc::new(
        listener
            .with_local_delegated_registry(registry)
            .with_device_gate(gate),
    );
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.start().await;
    });
    tokio::time::sleep(Duration::from_millis(60)).await;

    // dummy target for successful opens
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = target.local_addr().unwrap().port();
    tokio::spawn(async move { while target.accept().await.is_ok() {} });

    // helper: consumer connect + auth (kind=Client)
    async fn consumer_mux(addr: SocketAddr) -> Option<Arc<MuxSession>> {
        let tls = TlsConfigBuilder::new()
            .allow_self_signed(true)
            .build_client()
            .unwrap();
        let connector = tokio_rustls::TlsConnector::from(tls);
        let tcp = TcpStream::connect(addr).await.ok()?;
        let server_name =
            rustls::pki_types::ServerName::try_from("cdn.cloudflare.com".to_string()).unwrap();
        let mut stream = connector.connect(server_name, tcp).await.ok()?;
        let mut auth = AuthRequest {
            node_id: "gate-consumer".into(),
            token: "gate-token".into(),
            kind: AuthKind::Client,
            advertise: vec![],
            groups: vec![],
            version: PROTOCOL_VERSION,
            my_name: String::new(),
            device_pubkey: String::new(),
            device_sig: String::new(),
        };
        let challenge = agile_net_core::device::session_challenge(stream.get_ref().1).ok()?;
        auth.attach_device_proof(&challenge, &DeviceIdentity::ephemeral());
        Frame::new(FrameType::Auth, 0, Bytes::from(serde_json::to_vec(&auth).unwrap()))
            .write_to(&mut stream)
            .await
            .ok()?;
        let res = Frame::read_from(&mut stream).await.ok()?;
        if res.frame_type != FrameType::AuthOk {
            return None;
        }
        let (mux, _r) = MuxSession::start(stream, 2, SessionEvents::default(), true, None);
        Some(mux)
    }

    // pending: auth passes, opens are blocked with pending_approval
    let mux = consumer_mux(addr).await.expect("pending device still authenticates");
    let payload = serde_json::to_vec(&agile_net_core::proto::message::OpenChannel::new("127.0.0.1", target_port)).unwrap();
    let denied = mux.open_channel(Bytes::from(payload)).await;
    assert!(denied.is_err(), "pending device open must be blocked");
    mux.shutdown();

    // certified: opens flow
    gate_state.store(1, std::sync::atomic::Ordering::Relaxed);
    let mux = consumer_mux(addr).await.unwrap();
    let payload = serde_json::to_vec(&agile_net_core::proto::message::OpenChannel::new("127.0.0.1", target_port)).unwrap();
    let ch = mux.open_channel(Bytes::from(payload)).await;
    assert!(ch.is_ok(), "certified device open must pass: {:?}", ch.err());
    mux.shutdown();

    // revoked: auth itself rejected with device_revoked
    gate_state.store(2, std::sync::atomic::Ordering::Relaxed);
    assert!(consumer_mux(addr).await.is_none(), "revoked device must not authenticate");
}

#[tokio::test]
async fn delegated_revoke_notice_carries_reason_and_message() {
    let addr = get_free_addr();
    let listener = start_listener(addr).await;
    let id = DeviceIdentity::ephemeral();

    // issuer node session with ctrl plane (advertises the hint vocabulary so registration
    // route-checks pass)
    let (stream, res) = node_auth_adv(addr, "issuer-1", &id, Proof::Valid, vec!["127.0.0.0/8"]).await;
    assert_eq!(res.frame_type, FrameType::AuthOk);
    let (ctrl_tx, mut issuer_ctrl_rx) = tokio::sync::mpsc::channel::<Bytes>(8);
    let (issuer_mux, _r) = MuxSession::start(
        stream,
        2,
        SessionEvents {
            open_tx: None,
            ctrl_tx: Some(ctrl_tx),
        },
        true,
        None,
    );
    tokio::time::sleep(Duration::from_millis(80)).await;

    // register a delegated token on that session (entrust hint: no pushed groups needed — the
    // opaque-word path skips the route-table check and keeps the transparent ACL fail-closed)
    let token_hash = agile_net_core::util::sha256_hex(b"deleg-token-1");
    let register = CtrlMessage::TokenRegister {
        token_hash: token_hash.clone(),
        label: "tok".into(),
        groups: vec![],
        hint_map: vec![HintEntry {
            hint: "en_a1b2c3d4e5f6".into(),
            groups: vec![],
        }],
        concurrency: Concurrency::Multi,
        max_sessions: 4,
    };
    issuer_mux
        .send_frame(Frame::new(
            FrameType::Ctrl,
            0,
            Bytes::from(serde_json::to_vec(&register).unwrap()),
        ))
        .await
        .unwrap();
    // wait for the ack
    let ack = tokio::time::timeout(Duration::from_secs(3), issuer_ctrl_rx.recv())
        .await
        .expect("ack")
        .expect("ctrl frame");
    match serde_json::from_slice::<CtrlMessage>(&ack).unwrap() {
        CtrlMessage::TokenAck { ok, .. } => assert!(ok),
        other => panic!("unexpected: {other:?}"),
    }

    // consumer dials with the delegated token (kind=Client), ctrl subscription for notices
    let tls = TlsConfigBuilder::new()
        .allow_self_signed(true)
        .build_client()
        .unwrap();
    let connector = tokio_rustls::TlsConnector::from(tls);
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name =
        rustls::pki_types::ServerName::try_from("cdn.cloudflare.com".to_string()).unwrap();
    let mut cstream = connector.connect(server_name, tcp).await.unwrap();
    let mut cauth = AuthRequest {
        node_id: "consumer-1".into(),
        token: "deleg-token-1".into(),
        kind: AuthKind::Client,
        advertise: vec![],
        groups: vec![],
        version: PROTOCOL_VERSION,
        my_name: String::new(),
        device_pubkey: String::new(),
        device_sig: String::new(),
    };
    let challenge = agile_net_core::device::session_challenge(cstream.get_ref().1).unwrap();
    let consumer_id = DeviceIdentity::ephemeral();
    cauth.attach_device_proof(&challenge, &consumer_id);
    Frame::new(FrameType::Auth, 0, Bytes::from(serde_json::to_vec(&cauth).unwrap()))
        .write_to(&mut cstream)
        .await
        .unwrap();
    let cres = Frame::read_from(&mut cstream).await.unwrap();
    assert_eq!(cres.frame_type, FrameType::AuthOk);
    let (consumer_ctrl_tx, mut consumer_ctrl_rx) = tokio::sync::mpsc::channel::<Bytes>(8);
    let (consumer_mux, _r2) = MuxSession::start(
        cstream,
        2,
        SessionEvents {
            open_tx: None,
            ctrl_tx: Some(consumer_ctrl_tx),
        },
        true,
        None,
    );
    tokio::time::sleep(Duration::from_millis(80)).await;
    // the consumer session carries ITS device fp, distinct from the issuer's
    assert!(
        listener
            .session_metas()
            .iter()
            .any(|m| m.device_fp == consumer_id.device_fp())
    );

    // issuer revokes with reason + one-time message → consumer gets a SessionNotice first
    let revoke = CtrlMessage::TokenRevoke {
        token_hash: token_hash.clone(),
        concurrency: Concurrency::Multi,
        max_sessions: 4,
        reason_code: reason::REVOKED_BY_ADMIN.into(),
        message: "令牌已回收，联系管理员".into(),
    };
    issuer_mux
        .send_frame(Frame::new(
            FrameType::Ctrl,
            0,
            Bytes::from(serde_json::to_vec(&revoke).unwrap()),
        ))
        .await
        .unwrap();

    let notice = tokio::time::timeout(Duration::from_secs(3), consumer_ctrl_rx.recv())
        .await
        .expect("revoke notice")
        .expect("ctrl frame");
    match serde_json::from_slice::<CtrlMessage>(&notice).unwrap() {
        CtrlMessage::SessionNotice {
            reason_code,
            message,
        } => {
            assert_eq!(reason_code, reason::REVOKED_BY_ADMIN);
            assert_eq!(message, "令牌已回收，联系管理员");
        }
        other => panic!("unexpected: {other:?}"),
    }
    consumer_mux.shutdown();
    issuer_mux.shutdown();
}
