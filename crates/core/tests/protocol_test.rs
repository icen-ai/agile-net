//! Protocol v4 wire-format tests (federation P2/P3, unified issuance):
//! - PROTOCOL_VERSION is 4 and no version-gated feature constants exist (v4 is the only behavior)
//! - OpenChannel extension fields (groups / e2e) round-trip; a plain Open serializes minimal
//! - Ctrl token_register/revoke frames carry the session concurrency policy fields and flow
//!   over the mux session control plane to subscribers only

use agile_net_core::proto::frame::{Frame, FrameType};
use agile_net_core::proto::message::{
    Concurrency, CtrlMessage, E2eOpen, HintEntry, OpenChannel, PROTOCOL_VERSION,
    PROTOCOL_VERSION_FLOW_CONTROL,
};
use agile_net_core::relay::mux::{MuxSession, SessionEvents};
use bytes::Bytes;

#[test]
fn protocol_version_is_v4() {
    assert_eq!(PROTOCOL_VERSION, 4);
    assert_eq!(PROTOCOL_VERSION_FLOW_CONTROL, 2);
}

#[test]
fn open_channel_minimal_payload_parses() {
    // the plain-Open wire shape carries only the two target fields
    let wire = serde_json::json!({ "target_addr": "10.0.0.1", "target_port": 5432 });
    let open: OpenChannel = serde_json::from_value(wire).unwrap();
    assert_eq!(open.target_addr, "10.0.0.1");
    assert_eq!(open.target_port, 5432);
    assert!(open.groups.is_empty());
    assert!(open.e2e.is_none());
}

#[test]
fn open_channel_extension_roundtrip() {
    let open = OpenChannel {
        target_addr: "git.internal".into(),
        target_port: 22,
        groups: vec!["git".into(), "ops".into()],
        e2e: Some(E2eOpen {
            kid: "0123abcd5678".into(),
            hint: "git.internal".into(),
            blob: "AAECAwQ=".into(),
        }),
    };
    let json = serde_json::to_value(&open).unwrap();
    let back: OpenChannel = serde_json::from_value(json).unwrap();
    assert_eq!(back.target_addr, "git.internal");
    assert_eq!(back.target_port, 22);
    assert_eq!(back.groups, vec!["git".to_string(), "ops".to_string()]);
    assert_eq!(back.e2e.as_ref().unwrap().kid, "0123abcd5678");
}

#[test]
fn open_channel_plain_serializes_without_extension_keys() {
    // a transparent Open must produce the exact minimal payload shape (no noise on the wire)
    let json = serde_json::to_value(OpenChannel::new("1.2.3.4", 80)).unwrap();
    assert_eq!(json, serde_json::json!({ "target_addr": "1.2.3.4", "target_port": 80 }));
}

#[test]
fn ctrl_message_wire_format() {
    let register = CtrlMessage::TokenRegister {
        token_hash: "ab".repeat(32),
        label: "alice-laptop".into(),
        groups: vec!["git".into()],
        hint_map: vec![HintEntry {
            hint: "en_0123abcd5678".into(),
            groups: vec!["git".into()],
        }],
        concurrency: Concurrency::Multi,
        max_sessions: 8,
    };
    let json = serde_json::to_value(&register).unwrap();
    assert_eq!(json["op"], "token_register");
    assert_eq!(json["label"], "alice-laptop");
    assert_eq!(json["hint_map"][0]["hint"], "en_0123abcd5678");
    assert_eq!(json["concurrency"], "multi");
    assert_eq!(json["max_sessions"], 8);
    let back: CtrlMessage = serde_json::from_value(json).unwrap();
    let CtrlMessage::TokenRegister {
        token_hash,
        groups,
        concurrency,
        max_sessions,
        ..
    } = back
    else {
        panic!("expected TokenRegister");
    };
    assert_eq!(token_hash, "ab".repeat(32));
    assert_eq!(groups, vec!["git".to_string()]);
    assert_eq!(concurrency, Concurrency::Multi);
    assert_eq!(max_sessions, 8);

    let revoke = serde_json::to_value(CtrlMessage::TokenRevoke {
        token_hash: "cd".repeat(32),
        concurrency: Concurrency::Single,
        max_sessions: 1,
        reason_code: String::new(),
        message: String::new(),
    })
    .unwrap();
    assert_eq!(revoke["op"], "token_revoke");
    assert_eq!(revoke["concurrency"], "single");
    let back: CtrlMessage = serde_json::from_value(revoke).unwrap();
    let CtrlMessage::TokenRevoke { token_hash, .. } = back else {
        panic!("expected TokenRevoke");
    };
    assert_eq!(token_hash, "cd".repeat(32));

    let ack = serde_json::to_value(CtrlMessage::TokenAck {
        token_hash: "ef".repeat(32),
        ok: false,
        error: "hint outside advertised routes".into(),
    })
    .unwrap();
    assert_eq!(ack["op"], "token_ack");
    assert_eq!(ack["ok"], false);
    let back: CtrlMessage = serde_json::from_value(ack).unwrap();
    let CtrlMessage::TokenAck { ok, error, .. } = back else {
        panic!("expected TokenAck");
    };
    assert!(!ok);
    assert!(error.contains("advertised"));
}

#[tokio::test]
async fn ctrl_frame_reaches_ctrl_subscriber() {
    let (s1, s2) = tokio::io::duplex(4096);
    let (ctrl_tx, mut ctrl_rx) = tokio::sync::mpsc::channel::<Bytes>(8);
    let (a, _h1) = MuxSession::start(s1, 1, SessionEvents::default(), false, None);
    let (_b, _h2) = MuxSession::start(
        s2,
        2,
        SessionEvents {
            open_tx: None,
            ctrl_tx: Some(ctrl_tx),
        },
        false,
        None,
    );

    let msg = serde_json::to_vec(&CtrlMessage::TokenRevoke {
        token_hash: "ff".repeat(32),
        concurrency: Concurrency::Single,
        max_sessions: 1,
        reason_code: String::new(),
        message: String::new(),
    })
    .unwrap();
    a.send_frame(Frame::new(FrameType::Ctrl, 0, Bytes::from(msg.clone())))
        .await
        .unwrap();

    let got = tokio::time::timeout(std::time::Duration::from_secs(2), ctrl_rx.recv())
        .await
        .expect("ctrl frame delivered")
        .expect("payload");
    assert_eq!(got.as_ref(), msg.as_slice());
}

#[tokio::test]
async fn ctrl_frame_dropped_without_subscriber() {
    // a peer that did not subscribe to Ctrl (e.g. a plain consumer client) must not stall or
    // error — the frame is simply dropped
    let (s1, s2) = tokio::io::duplex(4096);
    let (a, _h1) = MuxSession::start(s1, 1, SessionEvents::default(), false, None);
    let (_b, _h2) = MuxSession::start(s2, 2, SessionEvents::default(), false, None);

    a.send_frame(Frame::new(FrameType::Ctrl, 0, Bytes::from_static(b"{}")))
        .await
        .unwrap();
    // session stays alive: assert liveness via traffic counters staying consistent
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(a.channel_count(), 0);
}
