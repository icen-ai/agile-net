//! 对端收敛（PeerAcl）集成测试：扇入 / 扇出两个数据面收敛点
//!
//! - 扇入：listener 侧对端（AuthKind::Node）会话发起的目标连接按 AuthIdentity.acl 收敛
//! - 扇出：connector 隧道反向来的目标连接按 with_acl 注入的收敛表收敛
//! - 两侧 `None` 语义均为不收敛（放行一切），拒绝时产生可订阅的 AclDenied 事件

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

/// 辅助函数：获取空闲端口
fn get_free_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

/// 启动 TCP echo server
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

/// 仅放行 127.0.0.0/8 的收敛表
fn loopback_acl() -> Arc<PeerAcl> {
    let mut router = ProxyRouter::new();
    router.add_cidr("127.0.0.0/8", Outbound::Direct).unwrap();
    Arc::new(PeerAcl::new(router))
}

/// 测试用校验器：静态 token + 可选的对端收敛表
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

/// 以原始 mux 会话模拟一个扇入对端（Node 认证，之后可主动发起 Open）
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

/// 从事件流中等待第一个 AclDenied（忽略其余事件），超时即 panic
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

/// 扇入收敛：对端发起的目标连接未命中收敛表 → OpenFail + AclDenied 事件
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

/// 扇入收敛：目标命中收敛表 → 正常桥接（echo 往返）
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

/// 扇入 None 语义：对端不带收敛表 → 放行一切（echo 往返）
#[tokio::test]
async fn fanin_peer_open_none_acl_allows_all() {
    let echo_addr = get_free_addr();
    let relay_addr = get_free_addr();
    let token = "fanin-token";
    start_echo_server(echo_addr).await;

    // StaticTokenValidator 产出 acl=None
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

/// 扇出收敛：对端反向发起的目标连接未命中收敛表 → OpenFail + AclDenied 事件
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

    // 上游经隧道反向发起目标连接（未命中收敛表）
    let res = listener.open_channel("node-b", "8.8.8.8", 443).await;
    assert!(res.is_err(), "denied target must fail to open");

    let (peer_label, target) = expect_acl_denied(&mut events).await;
    assert_eq!(peer_label, relay_addr.to_string());
    assert_eq!(target, "8.8.8.8:443");

    connector.disconnect().await;
}

/// 扇出收敛：目标命中收敛表 → 正常桥接（echo 往返）
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

/// 扇出 None 语义：不挂收敛表 → 放行一切（echo 往返）
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
