//! Client integration tests: login → config pull → tunnel data plane → proxy forwarding, end to end

use agile_net_client::{
    AgileNetClient, ConnectParams, Credential, CredentialStore, HostsManager, NodeStatus,
};
use agile_net_core::relay::RelayListener;
use agile_net_core::tunnel::tls::TlsConfigBuilder;
use agile_net_node::api::{ApiState, NodeRuntime, create_app};
use agile_net_node::auth::jwt::JwtService;
use agile_net_node::db::{Database, hash_password};
use agile_net_node::logs::LogBuffer;
use agile_net_node::relay_auth::DbTokenValidator;
use agile_net_node::service::connectors::ConnectorManager;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn get_free_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

/// Start a full-stack test node: API (HTTP) + Relay Listener (TLS data plane).
/// Pre-seeded: admin, a group (bound to the 127.0.0.0/8 rule), account user1/TestPass123
async fn start_full_node() -> (String, SocketAddr, SocketAddr) {
    let db = Database::in_memory().unwrap();

    // Data: rule + group + account
    let rule = db
        .create_rule("ip-cidr", "127.0.0.0/8", false, "loopback")
        .unwrap();
    let group = db.create_group("测试组", "").unwrap();
    db.set_group_rules(&group.id, &[rule.id]).unwrap();
    db.create_account(
        "user1",
        &hash_password("TestPass123").unwrap(),
        &group.id,
        "测试",
    )
    .unwrap();
    db.create_admin("admin", &hash_password("AdminPass123").unwrap())
        .unwrap();

    // Relay data plane
    let relay_addr = get_free_addr();
    let (server_config, _) = TlsConfigBuilder::new().build_server().unwrap();
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(server_config);
    let validator = Arc::new(DbTokenValidator::new(db.clone()));
    let listener = Arc::new(RelayListener::with_validator(
        relay_addr,
        validator,
        tls_acceptor,
    ));
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.start().await;
    });

    // API plane (bind first to get the port, then build the state)
    let api_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = api_listener.local_addr().unwrap();

    let jwt = Arc::new(JwtService::load_or_create(db.clone()).unwrap());
    let runtime = Arc::new(NodeRuntime {
        started_at: Instant::now(),
        listener: Some(listener),
        connector_manager: Arc::new(ConnectorManager::new(db.clone())),
        proxy_stats: None,
        proxy_listen: None,
        log_buffer: LogBuffer::new(),
        cert_fingerprint: None,
        relay_sni: None,
        manageable: Default::default(),
        client_proxy_slot: Default::default(),
        transit_meter: agile_net_core::relay::transit::TransitMeter::new(),
    });
    let state = ApiState::new(
        db,
        jwt,
        runtime,
        "127.0.0.1".into(),
        api_addr.port(),
        relay_addr.port(),
    );
    let app = create_app(state);

    tokio::spawn(async move {
        let _ = axum::serve(api_listener, app).await;
    });

    (
        format!("127.0.0.1:{}", api_addr.port()),
        api_addr,
        relay_addr,
    )
}

async fn start_echo_server(addr: SocketAddr) {
    let echo = tokio::net::TcpListener::bind(addr).await.unwrap();
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

/// Connect to the node and pull config and rules
#[tokio::test]
async fn client_connect_and_pull_config() {
    let (node_addr, _, _) = start_full_node().await;

    let client = AgileNetClient::new();
    let state = client
        .connect(ConnectParams {
            addr: node_addr.clone(),
            username: "user1".into(),
            password: "TestPass123".into(),
            insecure: true,
            pinned_cert_path: None,
            pinned_fingerprint: None,
            manage_hosts: false,
        })
        .await
        .unwrap();

    assert_eq!(state.status, NodeStatus::Connected);
    assert_eq!(state.rules.len(), 1);
    assert_eq!(state.rules[0].value, "127.0.0.0/8");
    assert_eq!(client.node_status(&state.node_id), NodeStatus::Connected);

    client.disconnect(&state.node_id).await;
    assert_eq!(client.node_status(&state.node_id), NodeStatus::Disconnected);
}

/// Full path: local SOCKS5 → tunnel → node → Echo
#[tokio::test]
async fn client_socks5_through_tunnel_to_echo() {
    let (node_addr, _, _) = start_full_node().await;
    let echo_addr = get_free_addr();
    start_echo_server(echo_addr).await;

    let client = AgileNetClient::new();
    let state = client
        .connect(ConnectParams {
            addr: node_addr,
            username: "user1".into(),
            password: "TestPass123".into(),
            insecure: true,
            pinned_cert_path: None,
            pinned_fingerprint: None,
            manage_hosts: false,
        })
        .await
        .unwrap();

    client.start_proxy(0).await.unwrap();
    let proxy_port = client.proxy_port();
    assert!(proxy_port > 0);

    // SOCKS5 handshake
    let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .unwrap();
    sock.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    sock.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00]);

    // CONNECT 127.0.0.1:echo_port (hits the 127.0.0.0/8 rule → tunnel)
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&echo_addr.port().to_be_bytes());
    sock.write_all(&req).await.unwrap();
    let mut resp = [0u8; 10];
    sock.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[1], 0x00, "SOCKS5 connect should succeed via tunnel");

    sock.write_all(b"full-stack-ping").await.unwrap();
    let mut buf = vec![0u8; 64];
    let n = sock.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"full-stack-ping");

    client.disconnect(&state.node_id).await;
    client.stop_proxy().await;
}

/// Disabling an account immediately drops its active tunnel (P0-2 security semantics)
#[tokio::test]
async fn disable_account_kicks_active_tunnel() {
    let (node_addr, api_addr, _) = start_full_node().await;
    let client = AgileNetClient::new();
    let state = client
        .connect(ConnectParams {
            addr: node_addr,
            username: "user1".into(),
            password: "TestPass123".into(),
            insecure: true,
            pinned_cert_path: None,
            pinned_fingerprint: None,
            manage_hosts: false,
        })
        .await
        .unwrap();
    assert_eq!(client.node_status(&state.node_id), NodeStatus::Connected);

    // Admin login and disable the account
    let http = reqwest::Client::new();
    let login = http
        .post(format!("http://{api_addr}/api/v1/auth/login"))
        .json(&serde_json::json!({"username":"admin","password":"AdminPass123"}))
        .send()
        .await
        .unwrap();
    let login_json: serde_json::Value = login.json().await.unwrap();
    let admin_token = login_json["data"]["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Find the account ID (admin list)
    let list = http
        .get(format!("http://{api_addr}/api/v1/admin/accounts"))
        .bearer_auth(&admin_token)
        .send()
        .await
        .unwrap();
    let list_json: serde_json::Value = list.json().await.unwrap();
    let account_id = list_json["data"]["items"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Disable
    let resp = http
        .put(format!(
            "http://{api_addr}/api/v1/admin/accounts/{account_id}"
        ))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({"enabled": false}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // The active tunnel must be dropped by the server immediately
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_ne!(
        client.node_status(&state.node_id),
        NodeStatus::Connected,
        "禁用账号后隧道必须被服务端主动断开"
    );
}

/// Routes are removed dynamically after disconnecting a node
#[tokio::test]
async fn disconnect_removes_routes() {
    let (node_addr, _, _) = start_full_node().await;
    let client = AgileNetClient::new();
    let state = client
        .connect(ConnectParams {
            addr: node_addr,
            username: "user1".into(),
            password: "TestPass123".into(),
            insecure: true,
            pinned_cert_path: None,
            pinned_fingerprint: None,
            manage_hosts: false,
        })
        .await
        .unwrap();

    let router = client.proxy_router();
    assert!(router.matches_target("127.0.0.1"));

    client.disconnect(&state.node_id).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let router = client.proxy_router();
    assert!(!router.matches_target("127.0.0.1"));
}

/// Offline config cache: save/load/remove
#[test]
fn config_cache_roundtrip() {
    let dir = std::env::temp_dir().join(format!("agile-cache-test-{}", uuid::Uuid::new_v4()));
    let cache = agile_net_client::ConfigCache::with_dir(dir.clone());
    let cfg = agile_net_client::CachedNodeConfig {
        addr: "node-a:59090".into(),
        username: "user1".into(),
        node_name: "节点A".into(),
        rules: vec![agile_net_client::ClientRule {
            id: "r1".into(),
            rule_type: "ip-cidr".into(),
            value: "10.0.0.0/8".into(),
            resolve: false,
        }],
        config_version: 7,
        tunnel_server: "node-a".into(),
        tunnel_port: 54430,
        tunnel_token: "tun_x".into(),
        refresh_token: "rt_y".into(),
        insecure: true,
        pinned_fingerprint: None,
        updated_at: "now".into(),
    };
    cache.save(&cfg);
    let loaded = cache.load("node-a:59090", "user1").unwrap();
    assert_eq!(loaded.config_version, 7);
    assert_eq!(loaded.rules.len(), 1);
    assert_eq!(loaded.node_name, "节点A");
    cache.remove("node-a:59090", "user1");
    assert!(cache.load("node-a:59090", "user1").is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Credential persistence and read-back (tightened file permissions)
#[tokio::test]
async fn credentials_persist() {
    let store = CredentialStore::open_temp().unwrap();

    store
        .save(
            "node-1",
            &Credential {
                addr: "1.2.3.4:443".into(),
                username: "zhangsan".into(),
                password: "secret".into(),
                insecure: false,
                pinned_fingerprint: None,
            },
        )
        .await;

    let store2 = CredentialStore::open(store.path()).unwrap();
    let cred = store2.get("node-1").await.unwrap();
    assert_eq!(cred.username, "zhangsan");
    assert_eq!(cred.password, "secret");

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
