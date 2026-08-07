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
