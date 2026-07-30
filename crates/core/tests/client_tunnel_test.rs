//! 客户端数据面 E2E 测试（M4 全链路）
//!
//! 链路：Client(SOCKS5) → ClientTunnel → Node-A(listener, ACL) → Node-B(connector) → Echo Server

use agile_net_core::error::Result;
use agile_net_core::proto::message::AuthRequest;
use agile_net_core::proxy::ProxyInbound;
use agile_net_core::proxy::router::{Outbound, ProxyRouter};
use agile_net_core::relay::listener::{AuthIdentity, RelayListener, TokenValidator};
use agile_net_core::relay::{RelayConnector, constant_time_eq};
use agile_net_core::tunnel::client_tunnel::ClientTunnel;
use agile_net_core::tunnel::opener::ChannelOpener;
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

/// 测试用校验器：节点 PSK + 客户端 tunnel_token（带 ACL）
struct TestValidator;

impl TokenValidator for TestValidator {
    fn validate(&self, auth: &AuthRequest) -> Option<AuthIdentity> {
        match auth.kind {
            agile_net_core::proto::message::AuthKind::Node => {
                if constant_time_eq(auth.token.as_bytes(), b"node-psk") {
                    Some(AuthIdentity::Node {
                        node_id: auth.node_id.clone(),
                        advertise: auth.advertise.clone(),
                    })
                } else {
                    None
                }
            }
            agile_net_core::proto::message::AuthKind::Client => {
                if constant_time_eq(auth.token.as_bytes(), b"tun_secret") {
                    Some(AuthIdentity::Client {
                        account_id: auth.node_id.clone(),
                        acl: vec!["127.0.0.0/8".to_string()],
                    })
                } else {
                    None
                }
            }
        }
    }
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

/// 全链路：客户端经隧道穿透两级节点访问内网 Echo
#[tokio::test]
async fn client_to_node_to_downstream_chain() -> Result<()> {
    let echo_addr = get_free_addr();
    let relay_addr = get_free_addr();

    start_echo_server(echo_addr).await;

    // Node-A：上游 listener（校验节点 PSK 与客户端 tunnel_token）
    let listener = Arc::new(RelayListener::with_validator(
        relay_addr,
        Arc::new(TestValidator),
        agile_net_core::tunnel::tls::TlsConfigBuilder::new()
            .build_server()
            .map(|(cfg, _)| tokio_rustls::TlsAcceptor::from(cfg))?,
    ));
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.start().await;
    });
    tokio::time::sleep(Duration::from_millis(80)).await;

    // Node-B：下游 connector，通告 127.0.0.0/8 网段
    let connector = RelayConnector::new(relay_addr, "node-b", "node-psk")?
        .with_advertise(vec!["127.0.0.0/8".to_string()]);
    connector.connect().await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(listener.peer_count(), 1);
    assert_eq!(
        listener.resolve_peer("127.0.0.1"),
        Some("node-b".to_string())
    );

    // Client：隧道 + 本地 SOCKS5 入站
    let tunnel = Arc::new(ClientTunnel::new_insecure(
        relay_addr,
        "acc-zhangsan",
        "tun_secret",
    )?);
    tunnel.connect().await?;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(listener.is_client_online("acc-zhangsan"));

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

    // SOCKS5 握手 + CONNECT echo
    let mut sock = tokio::net::TcpStream::connect(proxy_addr).await?;
    sock.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    sock.read_exact(&mut resp).await?;
    assert_eq!(resp, [0x05, 0x00]);

    let ip = echo_addr.ip().to_string();
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&[127, 0, 0, 1]);
    req.extend_from_slice(&echo_addr.port().to_be_bytes());
    let _ = ip; // 直接使用字面量 127.0.0.1
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

/// ACL 拒绝：目标不在客户端权限组规则内
#[tokio::test]
async fn client_acl_denied() -> Result<()> {
    let relay_addr = get_free_addr();

    let listener = Arc::new(RelayListener::with_validator(
        relay_addr,
        Arc::new(TestValidator),
        agile_net_core::tunnel::tls::TlsConfigBuilder::new()
            .build_server()
            .map(|(cfg, _)| tokio_rustls::TlsAcceptor::from(cfg))?,
    ));
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.start().await;
    });
    tokio::time::sleep(Duration::from_millis(80)).await;

    let tunnel = ClientTunnel::new_insecure(relay_addr, "acc-lisi", "tun_secret")?;
    tunnel.connect().await?;

    // 10.9.9.9 不在 ACL (127.0.0.0/8) 内 → Open 应失败
    let res = tunnel.open_channel("10.9.9.9", 8080).await;
    assert!(res.is_err(), "ACL 之外的目标必须被拒绝");

    // 错误 tunnel_token 直接认证失败
    let bad = ClientTunnel::new_insecure(relay_addr, "acc-lisi", "tun_wrong")?;
    assert!(bad.connect().await.is_err());

    Ok(())
}
