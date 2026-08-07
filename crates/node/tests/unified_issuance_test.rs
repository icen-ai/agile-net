//! Unified issuance integration tests (direct entry + concurrency tiers):
//! a direct-tier token self-registers into the issuer listener's persistent local registry at
//! issuance and serves consumers dialing the issuer's own listener (TLS is already end-to-end,
//! the transparent tier trusts the plaintext channel); the listener enforces the token's
//! concurrency policy — multi admits distinct consumer identities up to the max_sessions
//! snapshot, single kicks every older session of the token on re-auth.

use agile_net_client::{AgileNetClient, ConnectParams, NodeStatus};
use agile_net_core::config::node::{ListenerConfig, NodeConfig};
use agile_net_node::service::{NodeServer, NodeServerOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("anet-ui-test-{}-{}", tag, uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

async fn boot(tag: &str, listener_port: u16) -> (NodeServer, std::path::PathBuf) {
    let dir = temp_dir(tag);
    let config = NodeConfig {
        listener: Some(ListenerConfig {
            addr: format!("127.0.0.1:{listener_port}"),
            cert_path: dir.join("relay-cert.pem").to_string_lossy().to_string(),
            key_path: dir.join("relay-key.pem").to_string_lossy().to_string(),
            sni_hostname: "fed.test".into(),
        }),
        ..Default::default()
    };
    let server = NodeServer::start_with(
        config,
        NodeServerOptions {
            db_path: Some(dir.join("node.db").to_string_lossy().to_string()),
            api_listen: Some("127.0.0.1:0".into()),
            skip_env_seed: true,
            ..Default::default()
        },
    )
    .await
    .unwrap_or_else(|e| panic!("boot {tag}: {e}"));
    (server, dir)
}

async fn admin_token(base: &str) -> String {
    let http = reqwest::Client::new();
    let resp = http
        .post(format!("{base}/api/v1/auth/init"))
        .json(&serde_json::json!({"username": "admin", "password": "TestPassword123!"}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "init: {}", resp.status());
    let resp = http
        .post(format!("{base}/api/v1/auth/login"))
        .json(&serde_json::json!({"username": "admin", "password": "TestPassword123!"}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    body["data"]["access_token"].as_str().unwrap().to_string()
}

async fn start_echo_server(port: u16) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
}

/// SOCKS5 CONNECT through the client's local proxy; returns whether the echo roundtrip worked.
async fn socks_echo(proxy_port: u16, target_ip: [u8; 4], target_port: u16, payload: &[u8]) -> bool {
    let Ok(mut sock) = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port)).await else {
        return false;
    };
    if sock.write_all(&[0x05, 0x01, 0x00]).await.is_err() {
        return false;
    }
    let mut resp = [0u8; 2];
    if sock.read_exact(&mut resp).await.is_err() || resp != [0x05, 0x00] {
        return false;
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&target_ip);
    req.extend_from_slice(&target_port.to_be_bytes());
    if sock.write_all(&req).await.is_err() {
        return false;
    }
    let mut head = [0u8; 10];
    if sock.read_exact(&mut head).await.is_err() || head[1] != 0x00 {
        return false;
    }
    if sock.write_all(payload).await.is_err() {
        return false;
    }
    let mut buf = vec![0u8; payload.len()];
    matches!(
        tokio::time::timeout(std::time::Duration::from_secs(3), sock.read_exact(&mut buf)).await,
        Ok(Ok(_))
    ) && buf == payload
}

fn connect_params(relay_port: u16, label: &str, token: &str) -> ConnectParams {
    ConnectParams {
        addr: format!("127.0.0.1:{relay_port}"),
        label: label.to_string(),
        token: token.to_string(),
        insecure: true,
        pinned_fingerprint: None,
        manage_hosts: false,
        entries: Vec::new(),
        entry_fps: Vec::new(),
        en: None,
        emode: None,
        eadmin: false,
        myname: None,
    }
}

/// Issue a delegated token over the API; returns the response `data` object.
async fn issue(base: &str, admin: &str, req: serde_json::Value) -> serde_json::Value {
    let http = reqwest::Client::new();
    let resp = http
        .post(format!("{base}/api/v1/admin/delegation/tokens"))
        .bearer_auth(admin)
        .json(&req)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(status, 201, "issue: {body}");
    body["data"].clone()
}

/// Boot an issuer with a listener and one guarded group; returns (server, api base, admin token, group id).
async fn boot_issuer(tag: &str) -> (NodeServer, u16, String, String, String) {
    let relay_port = free_port();
    let (server, _dir) = boot(tag, relay_port).await;
    let base = format!("http://{}", server.api_addr());
    let token = admin_token(&base).await;
    let gid = server.db().create_group("ops", "guarded").expect("group").id;
    (server, relay_port, base, token, gid)
}

/// Direct tier: issuance self-registers into the local registry (no fan-out session involved),
/// the consumer dials the issuer's own listener and reaches the guarded segment; revocation
/// drops the local registration.
#[tokio::test]
async fn direct_issue_self_registers_and_consumes() {
    let (issuer, relay_port, base, token, gid) = boot_issuer("direct").await;

    // guarded segment: a loopback CIDR with an echo server as the resource
    let echo_port = free_port();
    start_echo_server(echo_port).await;
    let rid = issuer
        .db()
        .create_rule("ip-cidr", "127.0.0.0/8", false, "")
        .expect("rule")
        .id;
    issuer.db().set_group_rules(&gid, &[rid]).expect("bind");

    let data = issue(
        &base,
        &token,
        serde_json::json!({
            "label": "laptop", "group_ids": [gid], "entry_mode": "direct", "concurrency": "multi",
        }),
    )
    .await;
    let plaintext = data["token"].as_str().unwrap().to_string();
    assert_eq!(data["entry_mode"], "direct");
    assert_eq!(data["concurrency"], "multi");
    // direct share link: this node's own endpoints, no disaster-set regs
    let share_url = data["share_url"].as_str().unwrap();
    assert!(share_url.starts_with("anet://connect?"), "share_url: {share_url}");
    assert!(data["regs"].as_array().unwrap().is_empty());

    // self-registered into the persistent local registry during issuance (no session needed)
    let token_hash = agile_net_node::db::sha256_hex(plaintext.as_bytes());
    let listener = issuer.runtime().listener.clone().expect("listener");
    let registry = listener.local_delegated_registry();
    let entry = registry
        .get(&token_hash)
        .expect("direct token self-registers at issuance")
        .clone();
    assert_eq!(entry.groups, vec!["ops".to_string()]);
    assert!(
        entry.acl_rules.iter().any(|r| r == "127.0.0.0/8"),
        "transparent ACL snapshot: {:?}",
        entry.acl_rules
    );

    // M3-T2 default policy blocks pending (uncertified) consumer devices at open; this test
    // exercises the issuance flow, not certification — allow pending devices (gray flag)
    issuer
        .runtime()
        .device_gate
        .as_ref()
        .expect("device gate wired")
        .set_allow_pending(true);

    // the consumer dials the issuer's own listener and reaches the guarded segment
    let a = AgileNetClient::new();
    let state = a
        .connect(connect_params(relay_port, "laptop", &plaintext))
        .await
        .expect("direct delegated connect");
    assert_eq!(state.status, NodeStatus::Connected);
    a.start_proxy(0).await.unwrap();
    assert!(
        socks_echo(a.proxy_port(), [127, 0, 0, 1], echo_port, b"direct-e2e").await,
        "consumer reaches the issuer's guarded segment through the direct tier"
    );

    // revoke → the local registration drops immediately
    let token_id = data["id"].as_str().unwrap().to_string();
    let http = reqwest::Client::new();
    let resp = http
        .delete(format!("{base}/api/v1/admin/delegation/tokens/{token_id}"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    assert!(
        !registry.contains_key(&token_hash),
        "revocation drops the local registration"
    );

    a.disconnect_all().await;
    issuer.stop().await;
}

/// Multi tier: two consumer identities (distinct labels, same token) hold concurrent sessions.
#[tokio::test]
async fn multi_tier_coexisting_sessions() {
    let (issuer, relay_port, base, token, gid) = boot_issuer("multi").await;
    let data = issue(
        &base,
        &token,
        serde_json::json!({
            "label": "team", "group_ids": [gid], "entry_mode": "direct", "concurrency": "multi",
        }),
    )
    .await;
    let plaintext = data["token"].as_str().unwrap().to_string();
    assert_eq!(data["max_sessions"], 8, "default snapshot");

    let c1 = AgileNetClient::new();
    c1.connect(connect_params(relay_port, "phone", &plaintext))
        .await
        .expect("consumer 1 connects");
    let c2 = AgileNetClient::new();
    c2.connect(connect_params(relay_port, "tablet", &plaintext))
        .await
        .expect("consumer 2 connects");

    let token_hash = agile_net_node::db::sha256_hex(plaintext.as_bytes());
    let listener = issuer.runtime().listener.clone().expect("listener");
    let key1 = agile_net_core::relay::listener::delegated_session_key(&token_hash, "d:phone");
    let key2 = agile_net_core::relay::listener::delegated_session_key(&token_hash, "d:tablet");
    assert!(
        listener.is_client_online(&key1),
        "consumer 1 stays online under the multi tier"
    );
    assert!(
        listener.is_client_online(&key2),
        "consumer 2 coexists under the multi tier"
    );

    c1.disconnect_all().await;
    c2.disconnect_all().await;
    issuer.stop().await;
}

/// Single tier: a new session of the same token kicks every older one (asserted on the listener
/// the instant the second auth lands, before the kicked consumer's supervisor can redial).
#[tokio::test]
async fn single_tier_kicks_old_session() {
    let (issuer, relay_port, base, token, gid) = boot_issuer("single").await;
    let data = issue(
        &base,
        &token,
        serde_json::json!({
            "label": "solo", "group_ids": [gid], "entry_mode": "direct", "concurrency": "single",
        }),
    )
    .await;
    let plaintext = data["token"].as_str().unwrap().to_string();
    assert_eq!(data["concurrency"], "single");

    let token_hash = agile_net_node::db::sha256_hex(plaintext.as_bytes());
    let listener = issuer.runtime().listener.clone().expect("listener");
    let key_old = agile_net_core::relay::listener::delegated_session_key(&token_hash, "d:old");
    let key_new = agile_net_core::relay::listener::delegated_session_key(&token_hash, "d:new");

    let c1 = AgileNetClient::new();
    c1.connect(connect_params(relay_port, "old", &plaintext))
        .await
        .expect("first consumer connects");
    assert!(listener.is_client_online(&key_old));

    let c2 = AgileNetClient::new();
    c2.connect(connect_params(relay_port, "new", &plaintext))
        .await
        .expect("second consumer connects");
    assert!(
        listener.is_client_online(&key_new),
        "the new session is admitted"
    );
    assert!(
        !listener.is_client_online(&key_old),
        "single tier kicks the older session of the same token"
    );

    c1.disconnect_all().await;
    c2.disconnect_all().await;
    issuer.stop().await;
}

/// Multi tier cap: the max_sessions snapshot (node_config.delegation_max_sessions at issuance)
/// bounds concurrent consumer sessions — the next auth is rejected.
#[tokio::test]
async fn multi_tier_max_sessions_caps_auth() {
    let (issuer, relay_port, base, token, gid) = boot_issuer("cap").await;
    issuer
        .db()
        .set_config("delegation_max_sessions", "2")
        .expect("cap config");
    let data = issue(
        &base,
        &token,
        serde_json::json!({
            "label": "capped", "group_ids": [gid], "entry_mode": "direct", "concurrency": "multi",
        }),
    )
    .await;
    let plaintext = data["token"].as_str().unwrap().to_string();
    assert_eq!(data["max_sessions"], 2, "snapshot taken at issuance");

    let c1 = AgileNetClient::new();
    c1.connect(connect_params(relay_port, "one", &plaintext))
        .await
        .expect("session 1 within the cap");
    let c2 = AgileNetClient::new();
    c2.connect(connect_params(relay_port, "two", &plaintext))
        .await
        .expect("session 2 within the cap");

    // the third concurrent session exceeds the snapshot cap → auth rejected (fail fast)
    let c3 = AgileNetClient::new();
    let result = c3.connect(connect_params(relay_port, "three", &plaintext)).await;
    assert!(
        result.is_err(),
        "the session over the max_sessions cap must be rejected"
    );

    // a freed slot is reusable: drop one, the retry connects
    c1.disconnect_all().await;
    let token_hash = agile_net_node::db::sha256_hex(plaintext.as_bytes());
    let listener = issuer.runtime().listener.clone().expect("listener");
    let key1 = agile_net_core::relay::listener::delegated_session_key(&token_hash, "d:one");
    for _ in 0..50 {
        if !listener.is_client_online(&key1) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let c4 = AgileNetClient::new();
    c4.connect(connect_params(relay_port, "four", &plaintext))
        .await
        .expect("a freed slot admits a new session");

    c2.disconnect_all().await;
    c4.disconnect_all().await;
    issuer.stop().await;
}
