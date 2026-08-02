//! 中继途径流量核算集成测试（TransitMeter + RelayConnector::traffic）
//!
//! 覆盖：
//! - connector 当前会话流量访问器（断连归零）
//! - 扇入对端发起：到下游对端 / 到本机终结 的途径对分类
//! - 扇出 connector 反向来流：链式到下游对端 / 本机直连 的途径对分类
//! - 本地代理入站：隧道出站 / 直连出站 的途径对分类

use agile_net_core::error::Result;
use agile_net_core::proxy::inbound::ProxyInbound;
use agile_net_core::proxy::router::{Outbound, ProxyRouter};
use agile_net_core::relay::transit::{FROM_PROXY, TO_LOCAL, TransitMeter, TransitPair};
use agile_net_core::relay::{RelayConnector, RelayListener};
use agile_net_core::tunnel::opener::PeerAutoOpener;
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

/// 在指定 loopback 地址上取空闲端口（127.0.0.2 用于规避 127.0.0.1/32 路由规则）。
fn get_free_addr_on(ip: &str) -> SocketAddr {
    let listener = std::net::TcpListener::bind(format!("{ip}:0")).unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

/// 启动一个 echo TCP 服务（每连接一次回声后即继续服务下一个）。
async fn spawn_echo(addr: SocketAddr) {
    let listener = TcpListener::bind(addr).await.unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
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

/// 在快照里查指定途径对。
fn find_pair<'a>(pairs: &'a [TransitPair], from: &str, to: &str) -> Option<&'a TransitPair> {
    pairs.iter().find(|p| p.from == from && p.to == to)
}

/// 等指定途径对出现（桥接关闭后打点有级联时延），最长 3s。
async fn wait_pair(meter: &TransitMeter, from: &str, to: &str) -> TransitPair {
    for _ in 0..30 {
        let (_, _, pairs) = meter.snapshot();
        if let Some(p) = find_pair(&pairs, from, to) {
            return p.clone();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("transit pair {from} -> {to} not recorded in time");
}

/// 经通道写入并读回 echo，随后 shutdown 触发桥接关闭级联。
async fn roundtrip<C>(ch: &mut C, msg: &[u8])
where
    C: AsyncReadExt + AsyncWriteExt + Unpin,
{
    ch.write_all(msg).await.unwrap();
    let mut buf = vec![0u8; msg.len()];
    ch.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, msg);
    ch.shutdown().await.unwrap();
}

/// connector 当前会话流量访问器：传输后计数非零，断连后归零。
#[tokio::test]
async fn connector_traffic_accessor() -> Result<()> {
    let relay_addr = get_free_addr();
    let echo_addr = get_free_addr();
    let token = "traffic_token";
    spawn_echo(echo_addr).await;

    let listener = Arc::new(RelayListener::new(relay_addr, token)?);
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.start().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let connector = RelayConnector::new(relay_addr, "node-b", token)?;
    connector.connect().await?;
    assert_eq!(connector.traffic(), (0, 0));

    // listener → connector 开流（connector 本机直连 echo），双向过数据
    let mut ch = listener
        .open_channel("node-b", &echo_addr.ip().to_string(), echo_addr.port())
        .await?;
    roundtrip(&mut ch, b"connector-traffic-probe").await;
    drop(ch);

    // 计数由读写任务异步累加，轮询等待非零
    let mut traffic = (0u64, 0u64);
    for _ in 0..30 {
        traffic = connector.traffic();
        if traffic.0 > 0 && traffic.1 > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        traffic.0 >= 22 && traffic.1 >= 22,
        "connector traffic should count both directions, got {traffic:?}"
    );

    // 断连后当前会话句柄清空 → (0, 0)
    connector.disconnect().await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(connector.traffic(), (0, 0));
    Ok(())
}

/// 扇入对端发起的转发：按 from=对端 node_id 分类（到下游对端 / 到本机终结）。
#[tokio::test]
async fn listener_transit_classification() -> Result<()> {
    let relay_addr = get_free_addr();
    let echo_local = get_free_addr(); // B 本机终结目标
    let echo_peer = get_free_addr(); // C 侧服务目标（127.0.0.1 由 C 通告）
    let token = "transit_listener_token";
    spawn_echo(echo_local).await;
    spawn_echo(echo_peer).await;

    let meter = TransitMeter::new();
    let listener = Arc::new(RelayListener::new(relay_addr, token)?.with_transit_meter(meter.clone()));
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.start().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 下游对端 C：通告 127.0.0.1（/32），其本机有 echo_peer 服务
    let peer_c = RelayConnector::new(relay_addr, "node-c", token)?
        .with_advertise(vec!["127.0.0.1/32".to_string()]);
    peer_c.connect().await?;
    // 下游对端 A：流量来源
    let peer_a = RelayConnector::new(relay_addr, "node-a", token)?;
    peer_a.connect().await?;

    // A → 127.0.0.1:echo_peer（命中 C 通告路由 → 链式到 C → C 本机 echo）
    let mut ch = peer_a.open_stream("127.0.0.1", echo_peer.port()).await?;
    roundtrip(&mut ch, b"via-peer-c").await;
    drop(ch);

    // A → localhost:echo_local（无路由命中 → B 本机直连）
    let mut ch2 = peer_a.open_stream("localhost", echo_local.port()).await?;
    roundtrip(&mut ch2, b"to-local-end").await;
    drop(ch2);

    let p1 = wait_pair(&meter, "node-a", "node-c").await;
    assert!(p1.bytes_up >= 10 && p1.bytes_down >= 10, "pair node-a->node-c: {p1:?}");
    let p2 = wait_pair(&meter, "node-a", TO_LOCAL).await;
    assert!(p2.bytes_up >= 11 && p2.bytes_down >= 11, "pair node-a->local: {p2:?}");

    // 汇总 = 途径对之和
    let (up, down, _) = meter.snapshot();
    assert_eq!(up, p1.bytes_up + p2.bytes_up);
    assert_eq!(down, p1.bytes_down + p2.bytes_down);
    Ok(())
}

/// 扇出 connector 反向来流：按 from=connector 名分类（链式到下游对端 / 本机直连）。
#[tokio::test]
async fn connector_transit_classification() -> Result<()> {
    let upstream_addr = get_free_addr(); // 上游 U 的 listener
    let mid_addr = get_free_addr(); // 中间节点 B 的 listener
    let echo_local = get_free_addr(); // B 本机终结目标
    let echo_peer = get_free_addr(); // C 侧服务目标
    let token = "transit_connector_token";
    spawn_echo(echo_local).await;
    spawn_echo(echo_peer).await;

    // 上游 U
    let upstream = Arc::new(RelayListener::new(upstream_addr, token)?);
    let u = upstream.clone();
    tokio::spawn(async move {
        let _ = u.start().await;
    });

    // 中间节点 B：listener 接 C + connector 出 U（带途径核算，来源标识 "b-up"）
    let meter = TransitMeter::new();
    let mid_listener = Arc::new(RelayListener::new(mid_addr, token)?);
    let m = mid_listener.clone();
    tokio::spawn(async move {
        let _ = m.start().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mid_connector = RelayConnector::new(upstream_addr, "node-b", token)?
        .with_peer_router(mid_listener.clone())
        .with_transit_meter(meter.clone(), "b-up".to_string());
    mid_connector.connect().await?;

    // 下游 C：接入 B 的 listener 并通告 127.0.0.1
    let peer_c = RelayConnector::new(mid_addr, "node-c", token)?
        .with_advertise(vec!["127.0.0.1/32".to_string()]);
    peer_c.connect().await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // U → B（经 connector）→ 127.0.0.1:echo_peer（B 链式转发给 C → C 本机 echo）
    let mut ch = upstream
        .open_channel("node-b", "127.0.0.1", echo_peer.port())
        .await?;
    roundtrip(&mut ch, b"chain-to-c").await;
    drop(ch);

    // U → B → localhost:echo_local（B 本机直连）
    let mut ch2 = upstream
        .open_channel("node-b", "localhost", echo_local.port())
        .await?;
    roundtrip(&mut ch2, b"up-to-local").await;
    drop(ch2);

    let p1 = wait_pair(&meter, "b-up", "node-c").await;
    assert!(p1.bytes_up >= 10 && p1.bytes_down >= 10, "pair b-up->node-c: {p1:?}");
    let p2 = wait_pair(&meter, "b-up", TO_LOCAL).await;
    assert!(p2.bytes_up >= 11 && p2.bytes_down >= 11, "pair b-up->local: {p2:?}");
    Ok(())
}

/// 本地代理入站：from="proxy"（隧道出站到下游对端 / 直连本机终结）。
#[tokio::test]
async fn proxy_transit_classification() -> Result<()> {
    let relay_addr = get_free_addr();
    let proxy_addr = get_free_addr();
    let echo_local = get_free_addr_on("127.0.0.2"); // 本机直连目标（规避 127.0.0.1/32 规则）
    let echo_peer = get_free_addr(); // C 侧服务目标
    let token = "transit_proxy_token";
    spawn_echo(echo_local).await;
    spawn_echo(echo_peer).await;

    // 节点 listener + 下游 C（通告 127.0.0.1）
    let listener = Arc::new(RelayListener::new(relay_addr, token)?);
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.start().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let peer_c = RelayConnector::new(relay_addr, "node-c", token)?
        .with_advertise(vec!["127.0.0.1/32".to_string()]);
    peer_c.connect().await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 代理路由：127.0.0.1/32 走隧道（自动选路），其余直连；ProxyInbound 挂途径核算
    let mut router = ProxyRouter::new();
    router.add_cidr("127.0.0.1/32", Outbound::tunnel("")).unwrap();
    let meter = TransitMeter::new();
    let inbound = ProxyInbound::new(proxy_addr, Arc::new(ArcSwap::from_pointee(router)))
        .with_default_opener(Arc::new(PeerAutoOpener::new(listener.clone())))
        .with_transit_meter(meter.clone());
    tokio::spawn(async move {
        let _ = inbound.start().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // socks5 请求 127.0.0.1:echo_peer → 隧道 → C
    let mut c1 = socks5_connect_ipv4(proxy_addr, echo_peer).await?;
    roundtrip(&mut c1, b"proxy-via-tunnel").await;
    drop(c1);

    // socks5 请求 127.0.0.2:echo_local（无路由命中 → 直连本机）
    let mut c2 = socks5_connect_ipv4(proxy_addr, echo_local).await?;
    roundtrip(&mut c2, b"proxy-direct").await;
    drop(c2);

    let p1 = wait_pair(&meter, FROM_PROXY, "node-c").await;
    assert!(p1.bytes_up >= 16 && p1.bytes_down >= 16, "pair proxy->node-c: {p1:?}");
    let p2 = wait_pair(&meter, FROM_PROXY, TO_LOCAL).await;
    assert!(p2.bytes_up >= 12 && p2.bytes_down >= 12, "pair proxy->local: {p2:?}");
    Ok(())
}

/// SOCKS5 CONNECT（IPv4 形式）到目标并返回就绪流。
async fn socks5_connect_ipv4(
    proxy_addr: SocketAddr,
    target: SocketAddr,
) -> Result<tokio::net::TcpStream> {
    let mut client = tokio::net::TcpStream::connect(proxy_addr).await?;
    client.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).await?;
    assert_eq!(greeting, [0x05, 0x00]);

    let ip = match target.ip() {
        std::net::IpAddr::V4(ip4) => ip4.octets(),
        _ => panic!("expected ipv4"),
    };
    let port = target.port().to_be_bytes();
    client
        .write_all(&[0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], port[0], port[1]])
        .await?;
    let mut resp = [0u8; 10];
    client.read_exact(&mut resp).await?;
    assert_eq!(resp[1], 0x00, "socks5 connect failed");
    Ok(client)
}
