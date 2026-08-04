//! M2 milestone relay traversal integration tests
//!
//! Full AT-M2-01 ~ AT-M2-07 test suite

use agile_net_core::error::Result;
use agile_net_core::proto::frame::{Frame, FrameType};
use agile_net_core::relay::{ConnectionState, RelayConnector, RelayListener};
use bytes::Bytes;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Helper: get a free port
fn get_free_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

/// Port-allocation race guard: get_free_addr releases the probe socket before rebinding, so
/// parallel tests can collide on the same port (TLS cross-talk: "got ClientHello"). Serialize
/// the network tests — the probe-bind/listen sequence stays fast enough for that.
static NET_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// AT-M2-01: frame encode/decode roundtrip
#[test]
fn frame_roundtrip_all_types() {
    let frame_types = vec![
        FrameType::Auth,
        FrameType::AuthOk,
        FrameType::AuthFail,
        FrameType::Open,
        FrameType::OpenOk,
        FrameType::OpenFail,
        FrameType::Data,
        FrameType::DataFin,
        FrameType::Ping,
        FrameType::Pong,
        FrameType::Close,
    ];

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    for ft in frame_types {
        let original = Frame::new(ft, 100, Bytes::from("payload-test"));
        let bytes = original.encode();
        let mut cursor = std::io::Cursor::new(bytes.to_vec());

        let decoded = rt.block_on(Frame::read_from(&mut cursor)).unwrap();
        assert_eq!(decoded.frame_type, ft);
        assert_eq!(decoded.channel_id, 100);
        assert_eq!(decoded.payload.as_ref(), b"payload-test");
    }
}

/// AT-M2-02: TLS tunnel establishment and bidirectional communication
#[tokio::test]
async fn tls_tunnel_established() -> Result<()> {
    let _net_guard = NET_TEST_LOCK.lock().unwrap();
    let addr = get_free_addr();
    let token = "secret_token_123";

    let listener = std::sync::Arc::new(RelayListener::new(addr, token)?);
    tokio::spawn(async move {
        let _ = listener.start().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let connector = RelayConnector::new(addr, "node-b", token)?;
    assert_eq!(connector.state(), ConnectionState::Disconnected);

    connector.connect().await?;
    assert!(connector.is_connected());

    connector.disconnect().await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(connector.state(), ConnectionState::Disconnected);

    Ok(())
}

/// AT-M2-04: auth failure rejected
#[tokio::test]
async fn auth_rejected_with_wrong_token() -> Result<()> {
    let _net_guard = NET_TEST_LOCK.lock().unwrap();
    let addr = get_free_addr();
    let listener = std::sync::Arc::new(RelayListener::new(addr, "correct_token")?);
    tokio::spawn(async move {
        let _ = listener.start().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let connector = RelayConnector::new(addr, "node-b", "wrong_token")?;
    let res = connector.connect().await;

    assert!(res.is_err());
    assert_eq!(connector.state(), ConnectionState::Disconnected);

    Ok(())
}

/// AT-M2-03: TCP passthrough E2E
#[tokio::test]
async fn tcp_passthrough() -> Result<()> {
    let _net_guard = NET_TEST_LOCK.lock().unwrap();
    let echo_addr = get_free_addr();
    let relay_addr = get_free_addr();
    let token = "passthrough_token";

    // 1. start echo TCP server
    let echo_server = TcpListener::bind(echo_addr).await?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = echo_server.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
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

    // 2. start listener & connector
    let listener = std::sync::Arc::new(RelayListener::new(relay_addr, token)?);
    let listener_clone = listener.clone();
    tokio::spawn(async move {
        let _ = listener_clone.start().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let connector = RelayConnector::new(relay_addr, "target-node", token)?;
    connector.connect().await?;
    assert!(connector.is_connected());

    // 3. listener opens a channel asking the connector to reach the echo server
    let mut mux_channel = listener
        .open_channel("target-node", &echo_addr.ip().to_string(), echo_addr.port())
        .await?;

    // 4. send data and receive the echo reply
    mux_channel.write_all(b"hello agile-net").await?;

    let mut buf = vec![0u8; 1024];
    let n = mux_channel.read(&mut buf).await?;
    assert_eq!(&buf[..n], b"hello agile-net");

    Ok(())
}

/// AT-M2-07: concurrent data channels
#[tokio::test]
async fn concurrent_data_channels() -> Result<()> {
    let _net_guard = NET_TEST_LOCK.lock().unwrap();
    let echo_addr = get_free_addr();
    let relay_addr = get_free_addr();
    let token = "concurrent_token";

    // 1. start echo TCP server
    let echo_server = TcpListener::bind(echo_addr).await?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = echo_server.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
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

    // 2. start relay node
    let listener = std::sync::Arc::new(RelayListener::new(relay_addr, token)?);
    let listener_clone = listener.clone();
    tokio::spawn(async move {
        let _ = listener_clone.start().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let connector = RelayConnector::new(relay_addr, "target-node", token)?;
    connector.connect().await?;

    // 3. issue 5 concurrent channel requests
    let mut handles = vec![];
    for i in 0..5 {
        let listener_inner = listener.clone();
        handles.push(tokio::spawn(async move {
            let mut channel = listener_inner
                .open_channel("target-node", &echo_addr.ip().to_string(), echo_addr.port())
                .await
                .unwrap();

            let msg = format!("msg-{i}");
            channel.write_all(msg.as_bytes()).await.unwrap();

            let mut buf = vec![0u8; 1024];
            let n = channel.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], msg.as_bytes());
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    Ok(())
}

/// Federation P1: pushed policy groups ride the fan-out handshake into the upstream
/// authorizable pool (peer_offers), and are cleared when the session drops.
#[tokio::test]
async fn pushed_groups_pool_and_disconnect_clear() -> Result<()> {
    let _net_guard = NET_TEST_LOCK.lock().unwrap();
    use agile_net_core::proto::message::PushedGroupMsg;
    let addr = get_free_addr();
    let token = "secret_token_123";

    let listener = std::sync::Arc::new(RelayListener::new(addr, token)?);
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.start().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let slot = std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(vec![
        PushedGroupMsg {
            name: "git".into(),
            remark: "代码组".into(),
            rules: vec!["git.internal".into(), "10.12.0.0/16".into()],
        },
    ]));
    let connector = RelayConnector::new(addr, "peer-c", token)?.with_push_groups(slot);
    connector.connect().await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let offers = listener.peer_offers();
    let o = offers.iter().find(|o| o.node_id == "peer-c").expect("peer offer");
    assert_eq!(o.groups.len(), 1);
    assert_eq!(o.groups[0].name, "git");
    assert_eq!(o.groups[0].remark, "代码组");
    assert_eq!(
        o.groups[0].rules,
        vec!["git.internal".to_string(), "10.12.0.0/16".to_string()]
    );

    connector.disconnect().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        listener
            .peer_offers()
            .iter()
            .all(|o| o.node_id != "peer-c"),
        "disconnect clears the pooled offer"
    );
    Ok(())
}

/// Federation P1: pushed-group sanitization drops offending entries (never rejects the session).
#[test]
fn sanitize_pushed_groups_caps() {
    use agile_net_core::proto::message::PushedGroupMsg;
    use agile_net_core::relay::listener::{
        MAX_PUSHED_GROUP_RULES, MAX_PUSHED_GROUPS, sanitize_pushed_groups,
    };
    let mk = |name: &str, rules: Vec<&str>| PushedGroupMsg {
        name: name.into(),
        remark: String::new(),
        rules: rules.into_iter().map(str::to_string).collect(),
    };
    let huge = (0..MAX_PUSHED_GROUP_RULES + 10)
        .map(|i| format!("10.0.{i}.0/24"))
        .collect::<Vec<_>>();
    let out = sanitize_pushed_groups(vec![
        mk("", vec!["a"]),                    // empty name dropped
        mk(&"x".repeat(200), vec!["a"]),      // overlong name dropped
        mk("ok", vec!["", "  ", "10.0.0.0/8", &"y".repeat(300)]), // blank/overlong rules dropped
        PushedGroupMsg {
            name: "big".into(),
            remark: String::new(),
            rules: huge,
        },
    ]);
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].name, "ok");
    assert_eq!(out[0].rules, vec!["10.0.0.0/8".to_string()]);
    assert_eq!(out[1].rules.len(), MAX_PUSHED_GROUP_RULES);
    // Group-count cap
    let many = (0..MAX_PUSHED_GROUPS + 5)
        .map(|i| mk(&format!("g{i}"), vec![]))
        .collect();
    assert_eq!(sanitize_pushed_groups(many).len(), MAX_PUSHED_GROUPS);
}
