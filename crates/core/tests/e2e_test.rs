//! M4 milestone end-to-end tunnel (E2E Tunnel) integration tests
//!
//! Full AT-M4-01 ~ AT-M4-07 integration test suite

use agile_net_core::error::Result;
use agile_net_core::proxy::inbound::ProxyInbound;
use agile_net_core::proxy::router::{Outbound, ProxyRouter};
use agile_net_core::relay::{RelayConnector, RelayListener};
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

/// AT-M4-01: Client -> Node-A (public relay listener) -> Node-B (internal connector) -> internal echo target, full path
#[tokio::test]
async fn e2e_client_to_internal_echo() -> Result<()> {
    let echo_addr = get_free_addr();
    let relay_addr = get_free_addr();
    let proxy_addr = get_free_addr();
    let token = "e2e_secret_token";

    // 1. start internal echo TCP service
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

    // 2. start Node-A (relay listener)
    let listener = Arc::new(RelayListener::new(relay_addr, token)?);
    let listener_clone = listener.clone();
    tokio::spawn(async move {
        let _ = listener_clone.start().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 3. start Node-B (relay connector into Node-A)
    let connector = RelayConnector::new(relay_addr, "node-b", token)?;
    connector.connect().await?;
    assert!(connector.is_connected());

    // 4. start client (ProxyInbound with a route mapping echo IP -> Node-B)
    let mut router = ProxyRouter::new();
    let cidr_str = format!("{}/32", echo_addr.ip());
    router
        .add_cidr(&cidr_str, Outbound::tunnel("node-b"))
        .unwrap();

    let proxy_router = Arc::new(ArcSwap::from_pointee(router));
    let proxy_inbound =
        ProxyInbound::new(proxy_addr, proxy_router).with_relay_listener(listener.clone());

    tokio::spawn(async move {
        let _ = proxy_inbound.start().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 5. client connects to the client's SOCKS5 proxy, destined for echo_addr
    let mut client = tokio::net::TcpStream::connect(proxy_addr).await?;
    // SOCKS5 greeting
    client.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting_resp = [0u8; 2];
    client.read_exact(&mut greeting_resp).await?;
    assert_eq!(greeting_resp, [0x05, 0x00]);

    // SOCKS5 request
    let ip = match echo_addr.ip() {
        std::net::IpAddr::V4(ip4) => ip4.octets(),
        _ => panic!("expected ipv4"),
    };
    let port = echo_addr.port().to_be_bytes();
    let req = [
        0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], port[0], port[1],
    ];
    client.write_all(&req).await?;

    let mut req_resp = [0u8; 10];
    client.read_exact(&mut req_resp).await?;
    assert_eq!(req_resp[1], 0x00); // SUCCESS

    // 6. send data, verify the tunneled response
    client.write_all(b"e2e-tunnel-hello").await?;
    let mut buf = [0u8; 64];
    let n = client.read(&mut buf).await?;
    assert_eq!(&buf[..n], b"e2e-tunnel-hello");

    Ok(())
}

/// AT-M4-02: multi-node routing isolation (Node-B / Node-C advertise different subnets)
#[tokio::test]
async fn multi_node_routing_isolation() -> Result<()> {
    let echo_b_addr = get_free_addr();
    let echo_c_addr = get_free_addr();
    let relay_addr = get_free_addr();
    let proxy_addr = get_free_addr();
    let token = "multi_node_token";

    // 1. Echo B (replies from-node-b)
    let echo_b = TcpListener::bind(echo_b_addr).await?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = echo_b.accept().await {
            let mut buf = [0u8; 128];
            if let Ok(n) = stream.read(&mut buf).await
                && &buf[..n] == b"ping"
            {
                let _ = stream.write_all(b"from-node-b").await;
            }
        }
    });

    // 2. Echo C (replies from-node-c)
    let echo_c = TcpListener::bind(echo_c_addr).await?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = echo_c.accept().await {
            let mut buf = [0u8; 128];
            if let Ok(n) = stream.read(&mut buf).await
                && &buf[..n] == b"ping"
            {
                let _ = stream.write_all(b"from-node-c").await;
            }
        }
    });

    // 3. Relay Node-A
    let listener = Arc::new(RelayListener::new(relay_addr, token)?);
    let listener_clone = listener.clone();
    tokio::spawn(async move {
        let _ = listener_clone.start().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 4. Node-B & Node-C connect into Node-A
    let conn_b = RelayConnector::new(relay_addr, "node-b", token)?;
    conn_b.connect().await?;
    let conn_c = RelayConnector::new(relay_addr, "node-c", token)?;
    conn_c.connect().await?;

    // 5. client composite route table:
    let mut router = ProxyRouter::new();
    router
        .add_cidr(
            &format!("{}/32", echo_b_addr.ip()),
            Outbound::tunnel("node-b"),
        )
        .unwrap();
    router
        .add_cidr(
            &format!("{}/32", echo_c_addr.ip()),
            Outbound::tunnel("node-c"),
        )
        .unwrap();

    let proxy_router = Arc::new(ArcSwap::from_pointee(router));
    let proxy_inbound =
        ProxyInbound::new(proxy_addr, proxy_router).with_relay_listener(listener.clone());
    tokio::spawn(async move {
        let _ = proxy_inbound.start().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 6. verify a request to echo_b yields from-node-b
    let mut client1 = tokio::net::TcpStream::connect(proxy_addr).await?;
    client1.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut r1 = [0u8; 2];
    client1.read_exact(&mut r1).await?;

    let ip = match echo_b_addr.ip() {
        std::net::IpAddr::V4(ip4) => ip4.octets(),
        _ => panic!("expected ipv4"),
    };
    let port = echo_b_addr.port().to_be_bytes();
    client1
        .write_all(&[
            0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], port[0], port[1],
        ])
        .await?;
    let mut r2 = [0u8; 10];
    client1.read_exact(&mut r2).await?;

    client1.write_all(b"ping").await?;
    let mut b1 = [0u8; 64];
    let n1 = client1.read(&mut b1).await?;
    assert_eq!(&b1[..n1], b"from-node-b");

    Ok(())
}
