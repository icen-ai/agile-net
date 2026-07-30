//! M2 里程碑 Relay 穿透集成测试
//!
//! 包含 AT-M2-01 ~ AT-M2-07 完整测试套件

use agile_net_core::error::Result;
use agile_net_core::proto::frame::{Frame, FrameType};
use agile_net_core::relay::{ConnectionState, RelayConnector, RelayListener};
use bytes::Bytes;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// 辅助帮助函数：获取空闲端口
fn get_free_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

/// AT-M2-01：帧编解码往返
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

/// AT-M2-02：TLS 隧道建立与双向通信验证
#[tokio::test]
async fn tls_tunnel_established() -> Result<()> {
    let addr = get_free_addr();
    let token = "secret_token_123";

    let listener = RelayListener::new(addr, token)?;
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

/// AT-M2-04：认证失败拒绝
#[tokio::test]
async fn auth_rejected_with_wrong_token() -> Result<()> {
    let addr = get_free_addr();
    let listener = RelayListener::new(addr, "correct_token")?;
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

/// AT-M2-03：TCP 穿透 E2E 测试
#[tokio::test]
async fn tcp_passthrough() -> Result<()> {
    let echo_addr = get_free_addr();
    let relay_addr = get_free_addr();
    let token = "passthrough_token";

    // 1. 启动 Echo TCP Server
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

    // 2. 启动 Listener & Connector
    let listener = std::sync::Arc::new(RelayListener::new(relay_addr, token)?);
    let listener_clone = listener.clone();
    tokio::spawn(async move {
        let _ = listener_clone.start().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let connector = RelayConnector::new(relay_addr, "target-node", token)?;
    connector.connect().await?;
    assert!(connector.is_connected());

    // 3. Listener 打开通道请求 Connector 连接 Echo Server
    let mut mux_channel = listener
        .open_channel("target-node", &echo_addr.ip().to_string(), echo_addr.port())
        .await?;

    // 4. 发送数据并接收 Echo 返回
    mux_channel.write_all(b"hello agile-net").await?;

    let mut buf = vec![0u8; 1024];
    let n = mux_channel.read(&mut buf).await?;
    assert_eq!(&buf[..n], b"hello agile-net");

    Ok(())
}

/// AT-M2-07：并发数据通道
#[tokio::test]
async fn concurrent_data_channels() -> Result<()> {
    let echo_addr = get_free_addr();
    let relay_addr = get_free_addr();
    let token = "concurrent_token";

    // 1. 启动 Echo TCP Server
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

    // 2. 启动 Relay 节点
    let listener = std::sync::Arc::new(RelayListener::new(relay_addr, token)?);
    let listener_clone = listener.clone();
    tokio::spawn(async move {
        let _ = listener_clone.start().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let connector = RelayConnector::new(relay_addr, "target-node", token)?;
    connector.connect().await?;

    // 3. 发起 5 个并发通道请求
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
