//! M3 里程碑 Proxy 路由集成测试
//!
//! 包含 AT-M3-01 ~ AT-M3-07 完整测试套件

use agile_net_core::error::Result;
use agile_net_core::proxy::inbound::ProxyInbound;
use agile_net_core::proxy::outbound::DirectOutbound;
use agile_net_core::proxy::router::{Outbound, ProxyRouter};
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

/// AT-M3-03：CIDR 路由匹配
#[test]
fn cidr_routing() {
    let mut router = ProxyRouter::new();
    router
        .add_cidr("10.12.0.0/16", Outbound::tunnel("tunnel-b"))
        .unwrap();
    router
        .add_cidr("10.152.0.0/16", Outbound::tunnel("tunnel-c"))
        .unwrap();

    assert_eq!(
        router.resolve_ip("10.12.186.133"),
        Some(&Outbound::tunnel("tunnel-b"))
    );
    assert_eq!(
        router.resolve_ip("10.152.1.1"),
        Some(&Outbound::tunnel("tunnel-c"))
    );
    assert_eq!(router.resolve_ip("8.8.8.8"), None);
}

/// AT-M3-04：HOST 路由匹配
#[test]
fn host_routing() {
    let mut router = ProxyRouter::new();
    router.add_host_exact("git.internal", Outbound::tunnel("tunnel-b"));
    router.add_host_suffix("*.dev.internal", Outbound::tunnel("tunnel-b"));

    assert_eq!(
        router.resolve_host("git.internal"),
        Some(&Outbound::tunnel("tunnel-b"))
    );
    assert_eq!(
        router.resolve_host("app.dev.internal"),
        Some(&Outbound::tunnel("tunnel-b"))
    );
    assert_eq!(router.resolve_host("google.com"), None);
}

/// AT-M3-05：最长前缀匹配
#[test]
fn longest_prefix_match() {
    let mut router = ProxyRouter::new();
    router
        .add_cidr("10.0.0.0/8", Outbound::tunnel("wide"))
        .unwrap();
    router
        .add_cidr("10.12.0.0/16", Outbound::tunnel("narrow"))
        .unwrap();

    assert_eq!(
        router.resolve_ip("10.12.1.1"),
        Some(&Outbound::tunnel("narrow"))
    );
    assert_eq!(
        router.resolve_ip("10.13.1.1"),
        Some(&Outbound::tunnel("wide"))
    );
}

/// AT-M3-06：路由表热更新
#[tokio::test]
async fn hot_reload_router() {
    let router = Arc::new(ArcSwap::from_pointee(ProxyRouter::new()));

    // 初始无规则
    assert_eq!(router.load().resolve_ip("10.12.1.1"), None);

    // 热更新
    let mut new_router = ProxyRouter::new();
    new_router
        .add_cidr("10.12.0.0/16", Outbound::tunnel("tunnel-b"))
        .unwrap();
    router.store(Arc::new(new_router));

    // 立即生效
    assert_eq!(
        router.load().resolve_ip("10.12.1.1"),
        Some(&Outbound::tunnel("tunnel-b"))
    );
}

/// AT-M3-01：SOCKS5 入站与 DIRECT 转发
#[tokio::test]
async fn socks5_proxy_works() -> Result<()> {
    let target_addr = get_free_addr();
    let proxy_addr = get_free_addr();

    // 1. 启动 Echo 服务
    let listener = TcpListener::bind(target_addr).await?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 128];
            if let Ok(n) = stream.read(&mut buf).await {
                let _ = stream.write_all(&buf[..n]).await;
            }
        }
    });

    // 2. 启动 ProxyInbound
    let router = Arc::new(ArcSwap::from_pointee(ProxyRouter::new()));
    let inbound = ProxyInbound::new(proxy_addr, router);
    tokio::spawn(async move {
        let _ = inbound.start().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 3. SOCKS5 客户端连接
    let mut client = tokio::net::TcpStream::connect(proxy_addr).await?;

    // SOCKS5 Greeting: VER=0x05, NMETHODS=1, METHOD=0x00
    client.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting_resp = [0u8; 2];
    client.read_exact(&mut greeting_resp).await?;
    assert_eq!(greeting_resp, [0x05, 0x00]);

    // SOCKS5 Request: VER=0x05, CMD=0x01(CONNECT), RSV=0x00, ATYP=0x01(IPv4)
    let ip = match target_addr.ip() {
        std::net::IpAddr::V4(ip4) => ip4.octets(),
        _ => panic!("expected ipv4"),
    };
    let port = target_addr.port().to_be_bytes();
    let req = [
        0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], port[0], port[1],
    ];
    client.write_all(&req).await?;

    let mut req_resp = [0u8; 10];
    client.read_exact(&mut req_resp).await?;
    assert_eq!(req_resp[1], 0x00); // SUCCESS

    // 4. 数据交互
    client.write_all(b"socks5-test").await?;
    let mut buf = [0u8; 64];
    let n = client.read(&mut buf).await?;
    assert_eq!(&buf[..n], b"socks5-test");

    Ok(())
}

/// AT-M3-02：HTTP CONNECT 入站
#[tokio::test]
async fn http_connect_proxy_works() -> Result<()> {
    let target_addr = get_free_addr();
    let proxy_addr = get_free_addr();

    // 1. 启动 Echo 服务
    let listener = TcpListener::bind(target_addr).await?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 128];
            if let Ok(n) = stream.read(&mut buf).await {
                let _ = stream.write_all(&buf[..n]).await;
            }
        }
    });

    // 2. 启动 ProxyInbound
    let router = Arc::new(ArcSwap::from_pointee(ProxyRouter::new()));
    let inbound = ProxyInbound::new(proxy_addr, router);
    tokio::spawn(async move {
        let _ = inbound.start().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 3. HTTP CONNECT 客户端连接
    let mut client = tokio::net::TcpStream::connect(proxy_addr).await?;
    let req = format!("CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\n\r\n");
    client.write_all(req.as_bytes()).await?;

    let mut resp_buf = [0u8; 128];
    let n = client.read(&mut resp_buf).await?;
    let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
    assert!(resp_str.contains("200 Connection Established"));

    // 4. 数据交互
    client.write_all(b"http-test").await?;
    let mut buf = [0u8; 64];
    let n_data = client.read(&mut buf).await?;
    assert_eq!(&buf[..n_data], b"http-test");

    Ok(())
}

/// AT-M3-07：自动探测 SOCKS5 / HTTP 协议
#[tokio::test]
async fn auto_detect_protocol() -> Result<()> {
    let target_addr = get_free_addr();
    let proxy_addr = get_free_addr();

    // 启动 Echo 服务
    let listener = TcpListener::bind(target_addr).await?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 128];
            if let Ok(n) = stream.read(&mut buf).await {
                let _ = stream.write_all(&buf[..n]).await;
            }
        }
    });

    let router = Arc::new(ArcSwap::from_pointee(ProxyRouter::new()));
    let inbound = ProxyInbound::new(proxy_addr, router);
    tokio::spawn(async move {
        let _ = inbound.start().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 1. 同一端口，验证 SOCKS5 握手 OK
    let mut s_client = tokio::net::TcpStream::connect(proxy_addr).await?;
    s_client.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut s_resp = [0u8; 2];
    s_client.read_exact(&mut s_resp).await?;
    assert_eq!(s_resp, [0x05, 0x00]);

    // 2. 同一端口，验证 HTTP CONNECT 握手 OK
    let mut h_client = tokio::net::TcpStream::connect(proxy_addr).await?;
    let req = format!("CONNECT {target_addr} HTTP/1.1\r\n\r\n");
    h_client.write_all(req.as_bytes()).await?;
    let mut h_buf = [0u8; 64];
    let n = h_client.read(&mut h_buf).await?;
    assert!(String::from_utf8_lossy(&h_buf[..n]).contains("200"));

    Ok(())
}
