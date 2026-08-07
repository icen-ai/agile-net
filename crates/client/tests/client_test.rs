//! Client integration tests (local engine parts; the delegated data-plane path is covered
//! end to end by the node-side federation tests).

use agile_net_client::{AgileNetClient, Credential, CredentialStore, HostsManager};

/// Credential persistence and read-back (tightened file permissions)
#[tokio::test]
async fn credentials_persist() {
    let store = CredentialStore::open_temp().unwrap();

    store
        .save(
            "alice@delegated:1.2.3.4:54430",
            &Credential {
                addr: "1.2.3.4:54430".into(),
                label: "alice".into(),
                token: "psk_secret".into(),
                name: None,
                myname: None,
                visibility: None,
                insecure: false,
                pinned_fingerprint: Some("ab12".into()),
                entries: vec!["1.2.3.4:54430".into()],
                entry_fps: vec!["ab12".into()],
                en: Some("en_a1b2c3d4e5f6".into()),
                emode: None,
                eadmin: false,
            },
        )
        .await;

    let store2 = CredentialStore::open(store.path()).unwrap();
    let cred = store2.get("alice@delegated:1.2.3.4:54430").await.unwrap();
    assert_eq!(cred.label, "alice");
    assert_eq!(cred.token, "psk_secret");
    assert_eq!(cred.en.as_deref(), Some("en_a1b2c3d4e5f6"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(store.path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "凭据文件必须为 0600");
    }
}

/// Proxy engine start/stop
#[tokio::test]
async fn proxy_engine_start_stop() {
    let client = AgileNetClient::new();
    client.start_proxy(0).await.unwrap();
    let port = client.proxy_port();
    assert!(port > 0);

    let conn = tokio::net::TcpStream::connect(("127.0.0.1", port)).await;
    assert!(conn.is_ok());

    client.stop_proxy().await;
}

/// stop_proxy must kill every accepted connection and free the listen port immediately.
/// Regression: accepted connections used to be detached tasks that outlived "stop", keeping their
/// local port occupied — on Windows the next bind then failed with EADDRINUSE (os error 10048),
/// so the proxy toggle got stuck "impossible to turn back on" until the stale tunnels drained.
#[tokio::test]
async fn stop_proxy_kills_lingering_connections_and_frees_port() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The peer must observe the connection closed (EOF/reset), not silently kept alive
    async fn assert_closed(s: &mut tokio::net::TcpStream, what: &str) {
        let mut buf = [0u8; 8];
        match tokio::time::timeout(std::time::Duration::from_secs(2), s.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!("{what} still readable {n} bytes after stop_proxy"),
            Err(_) => panic!("{what} still alive 2s after stop_proxy"),
        }
    }

    let client = AgileNetClient::new();
    client.start_proxy(0).await.unwrap();
    let port = client.proxy_port();

    // Local echo target (the tunnel rides the direct arm: loopback hits the LAN preset bypass)
    let echo = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    let echo_task = tokio::spawn(async move {
        if let Ok((mut s, _)) = echo.accept().await {
            let mut buf = [0u8; 64];
            let _ = s.read(&mut buf).await; // first payload
            let _ = s.write_all(b"pong").await;
            let _ = s.read(&mut buf).await; // park until killed
        }
    });

    // Fully-established tunnel through the proxy (SOCKS5 CONNECT 127.0.0.1:echo_port)
    let mut tunnel = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    tunnel.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut buf = [0u8; 2];
    tunnel.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, [0x05, 0x00]);
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&echo_port.to_be_bytes());
    tunnel.write_all(&req).await.unwrap();
    let mut resp = [0u8; 10];
    tunnel.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[1], 0x00, "SOCKS5 connect must succeed");
    tunnel.write_all(b"ping").await.unwrap();
    let mut pong = [0u8; 4];
    tunnel.read_exact(&mut pong).await.unwrap();
    assert_eq!(&pong, b"pong", "tunnel must be pumping before stop");

    // Plus a bare accepted connection parked mid-handshake (never completes one)
    let mut parked = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    parked.write_all(&[0x05]).await.unwrap(); // partial greeting: the handler waits for more

    client.stop_proxy().await;

    assert_closed(&mut tunnel, "established tunnel").await;
    assert_closed(&mut parked, "parked connection").await;

    // The port must be reusable immediately (the Windows EADDRINUSE regression)
    client
        .start_proxy(port)
        .await
        .expect("immediate rebind on the same port must succeed");
    assert_eq!(client.proxy_port(), port);
    client.stop_proxy().await;
    echo_task.abort();
}

/// Hosts management: write and clean up the BEGIN/END block
#[test]
fn hosts_manager_apply_and_cleanup() {
    let dir = std::env::temp_dir().join(format!("agile-hosts-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let hosts_path = dir.join("hosts");
    std::fs::write(&hosts_path, "127.0.0.1 localhost\n::1 localhost\n").unwrap();

    let mgr = HostsManager::with_path(hosts_path.clone());
    mgr.apply(&["git.internal".to_string(), "wiki.internal".to_string()])
        .unwrap();

    let content = std::fs::read_to_string(&hosts_path).unwrap();
    assert!(content.contains("# BEGIN AGILE-NET"));
    assert!(content.contains("127.0.0.1 git.internal"));
    assert!(content.contains("127.0.0.1 localhost"));

    // Idempotent update
    mgr.apply(&["git.internal".to_string()]).unwrap();
    let content = std::fs::read_to_string(&hosts_path).unwrap();
    assert!(!content.contains("wiki.internal"));
    assert_eq!(content.matches("# BEGIN AGILE-NET").count(), 1);

    mgr.cleanup();
    let content = std::fs::read_to_string(&hosts_path).unwrap();
    assert!(!content.contains("AGILE-NET"));
    assert!(content.contains("127.0.0.1 localhost"));
}

/// Multi-node route merging (pure routing layer)
#[tokio::test]
async fn multi_node_route_merge() {
    let mut router = agile_net_core::proxy::router::ProxyRouter::new();
    let _ = router.add_cidr(
        "10.12.0.0/16",
        agile_net_core::proxy::router::Outbound::tunnel("node-a"),
    );
    let _ = router.add_cidr(
        "172.16.0.0/12",
        agile_net_core::proxy::router::Outbound::tunnel("node-b"),
    );

    assert!(router.matches_target("10.12.0.1"));
    assert!(router.matches_target("172.16.0.1"));
    assert!(!router.matches_target("8.8.8.8"));
}
