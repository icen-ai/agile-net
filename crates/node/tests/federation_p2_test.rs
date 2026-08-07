//! Federation P2 end-to-end test (acceptance of docs/plan/federation-p2p3.md §2.7):
//! resource owner C issues a delegated token (git group, disaster set = B1/B2) → consumer A
//! authenticates at B1 (delegated registry hit) → B1 stamps the group tags and routes to C →
//! C enforces its local git rules. Failover: B1 dies, A rotates to B2 by the entry list.
//! Revocation clears the relay registry and kicks A's session; a connector reconnect
//! re-registers automatically (the relay side is volatile by design).

use agile_net_client::{AgileNetClient, ConnectParams, NodeStatus};
use agile_net_core::config::node::{ListenerConfig, NodeConfig};
use agile_net_node::service::{NodeServer, NodeServerOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("anet-fedp2-test-{}-{}", tag, uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

async fn boot(tag: &str, listener_port: Option<u16>) -> (NodeServer, std::path::PathBuf) {
    let dir = temp_dir(tag);
    let mut config = NodeConfig::default();
    if let Some(port) = listener_port {
        config.listener = Some(ListenerConfig {
            addr: format!("127.0.0.1:{port}"),
            cert_path: dir.join("relay-cert.pem").to_string_lossy().to_string(),
            key_path: dir.join("relay-key.pem").to_string_lossy().to_string(),
            sni_hostname: "fed.test".into(),
        });
    }
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

/// Echo server (one accepted connection per task spawn is fine for these tests)
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
    // let the listener task settle
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

fn delegated_params(entries: Vec<String>, label: &str, token: &str) -> ConnectParams {
    ConnectParams {
        addr: entries[0].clone(),
        label: label.to_string(),
        token: token.to_string(),
        insecure: true,
        pinned_fingerprint: None,
        manage_hosts: false,
        entries,
        entry_fps: Vec::new(),
        en: None,
        emode: None,
        eadmin: false,
        myname: None,
    }
}

struct Fanout {
    port: u16,
    server: NodeServer,
    _dir: std::path::PathBuf,
}

async fn boot_fanout(tag: &str, psk: &str) -> Fanout {
    let port = free_port();
    let (server, dir) = boot(tag, Some(port)).await;
    server
        .db()
        .create_relay_token_with_quota(
            &agile_net_node::db::sha256_hex(psk.as_bytes()),
            "psk_test",
            "for peer-c",
            false,
            "full",
            None,
            None,
        )
        .expect("create relay token");
    Fanout {
        port,
        server,
        _dir: dir,
    }
}

/// Boot C with the git group, one echo server and connectors to the given upstreams.
/// Returns (server, base, admin token, git group id, echo port, connector ids).
async fn boot_resource_owner(
    upstreams: &[(&str, u16, &str)],
    echo_port: u16,
) -> (NodeServer, String, String, String, u16, Vec<String>) {
    start_echo_server(echo_port).await;
    let (c, _dir) = boot("c", None).await;
    let base = format!("http://{}", c.api_addr());
    let token = admin_token(&base).await;

    let gid = c.db().create_group("git", "code group").expect("group").id;
    let rid = c
        .db()
        .create_rule("ip-cidr", "127.0.0.0/8", false, "")
        .expect("rule")
        .id;
    c.db().set_group_rules(&gid, &[rid]).expect("bind");
    // direct-DB setup bypasses the API handlers: bump the version so the hot-reload watcher
    // picks the group up (delegation enforcement cache included)
    c.db().bump_config_version().expect("bump");

    let mut cids = Vec::new();
    for (name, port, psk) in upstreams {
        let cid = c
            .db()
            .create_connector(
                name,
                "",
                &format!("127.0.0.1:{port}"),
                psk,
                "fed.test",
                true,
                "",
                "",
                "",
                "127.0.0.0/8",
                None,
                "fan out",
            )
            .expect("connector")
            .id;
        c.db().set_connector_push_groups(&cid, &gid).expect("push");
        c.connector_manager()
            .upsert_from_db(&cid)
            .await
            .expect("upsert");
        cids.push(cid);
    }
    (c, base, token, gid, echo_port, cids)
}

async fn wait_connected(c: &NodeServer, cids: &[String]) {
    for _ in 0..60 {
        if cids
            .iter()
            .all(|id| c.connector_manager().state_of(id) == Some("connected"))
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("connectors did not connect in time");
}

async fn wait_registered(base: &str, token: &str, want: usize) {
    let http = reqwest::Client::new();
    for _ in 0..60 {
        let resp = http
            .get(format!("{base}/api/v1/admin/delegation/tokens"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        let items = body["data"]["items"].as_array().unwrap();
        let registered = items
            .iter()
            .flat_map(|t| t["regs"].as_array().unwrap().clone())
            .filter(|r| r["state"].as_str() == Some("registered"))
            .count();
        if registered >= want {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("delegated token was not registered in time");
}

#[tokio::test]
async fn p2_full_chain_and_failover() {
    // ---- B1/B2: two public rendezvous relays ----
    let b1 = boot_fanout("b1", "psk_b1-shared-token-0123456789").await;
    let b2 = boot_fanout("b2", "psk_b2-shared-token-0123456789").await;

    // ---- C: resource owner (git group -> 127.0.0.0/8; echo as the guarded resource) ----
    let echo_port = free_port();
    let (c, c_base, c_token, gid, _, cids) = boot_resource_owner(
        &[
            ("b1-rendezvous", b1.port, "psk_b1-shared-token-0123456789"),
            ("b2-rendezvous", b2.port, "psk_b2-shared-token-0123456789"),
        ],
        echo_port,
    )
    .await;
    wait_connected(&c, &cids).await;

    // ---- C issues a delegated token: git group, disaster set = B1(primary)/B2 ----
    let http = reqwest::Client::new();
    let resp = http
        .post(format!("{c_base}/api/v1/admin/delegation/tokens"))
        .bearer_auth(&c_token)
        .json(&serde_json::json!({
            "label": "alice",
            "group_ids": [gid],
            "regs": [
                { "connector_id": cids[0], "is_primary": true },
                { "connector_id": cids[1], "is_primary": false },
            ],
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(status, 201, "issue: {body}");
    let token = body["data"]["token"].as_str().unwrap().to_string();
    let share_url = body["data"]["share_url"].as_str().unwrap().to_string();
    assert!(
        share_url.contains("account=d%3Aalice"),
        "delegated mark in link: {share_url}"
    );
    assert!(
        share_url.contains("entry="),
        "disaster set in link: {share_url}"
    );

    // registration rides the fan-out sessions onto both relays
    wait_registered(&c_base, &c_token, 2).await;
    let token_hash = agile_net_node::db::sha256_hex(token.as_bytes());
    let b1_reg = b1
        .server
        .runtime()
        .listener
        .as_ref()
        .unwrap()
        .delegated_registry();
    assert!(
        b1_reg.contains_key(&token_hash),
        "B1 holds the registration"
    );
    let b2_reg = b2
        .server
        .runtime()
        .listener
        .as_ref()
        .unwrap()
        .delegated_registry();
    assert!(
        b2_reg.contains_key(&token_hash),
        "B2 holds the registration"
    );

    // ---- A: consumer connects with the delegated link fields (primary = B1) ----
    let entries = vec![
        format!("127.0.0.1:{}", b1.port),
        format!("127.0.0.1:{}", b2.port),
    ];
    let a = AgileNetClient::new();
    let state = a
        .connect(delegated_params(entries.clone(), "alice", &token))
        .await
        .expect("delegated connect");
    assert_eq!(state.status, NodeStatus::Connected);
    assert_eq!(state.label, "alice");
    assert_eq!(state.current_entry, entries[0]);
    a.start_proxy(0).await.unwrap();
    let proxy_port = a.proxy_port();

    // transparent tier: A -> B1 (registry auth) -> C (local git rules) -> echo
    assert!(
        socks_echo(proxy_port, [127, 0, 0, 1], echo_port, b"p2-via-b1").await,
        "echo through B1 and C's group enforcement"
    );

    // ---- failover: B1 dies, the supervisor rotates A to B2 ----
    b1.server.stop().await;
    for _ in 0..80 {
        let nodes = a.list_nodes().await;
        let n = &nodes[0];
        if n.status == NodeStatus::Connected && n.current_entry == entries[1] {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let nodes = a.list_nodes().await;
    assert_eq!(
        nodes[0].status,
        NodeStatus::Connected,
        "A reconnected after failover"
    );
    assert_eq!(nodes[0].current_entry, entries[1], "A failed over to B2");
    assert!(
        socks_echo(proxy_port, [127, 0, 0, 1], echo_port, b"p2-via-b2").await,
        "echo through B2 after failover"
    );

    a.disconnect_all().await;
    c.stop().await;
    b2.server.stop().await;
}

#[tokio::test]
async fn p2_revoke_kicks_and_reconnect_reregisters() {
    let b1 = boot_fanout("b1", "psk_b1-shared-token-0123456789").await;
    let echo_port = free_port();
    let (c, c_base, c_token, gid, _, cids) = boot_resource_owner(
        &[("b1-rendezvous", b1.port, "psk_b1-shared-token-0123456789")],
        echo_port,
    )
    .await;
    wait_connected(&c, &cids).await;

    let http = reqwest::Client::new();
    let resp = http
        .post(format!("{c_base}/api/v1/admin/delegation/tokens"))
        .bearer_auth(&c_token)
        .json(&serde_json::json!({
            "label": "carol",
            "group_ids": [gid],
            "regs": [{ "connector_id": cids[0], "is_primary": true }],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "issue: {:?}", resp);
    let body: serde_json::Value = resp.json().await.unwrap();
    let token = body["data"]["token"].as_str().unwrap().to_string();
    let token_id = body["data"]["id"].as_str().unwrap().to_string();
    wait_registered(&c_base, &c_token, 1).await;

    // ---- reconnect re-registers: rebuild the connector, the registry recovers by itself ----
    c.connector_manager()
        .upsert_from_db(&cids[0])
        .await
        .expect("rebuild connector");
    wait_connected(&c, &cids).await;
    wait_registered(&c_base, &c_token, 1).await;

    let a = AgileNetClient::new();
    let state = a
        .connect(delegated_params(
            vec![format!("127.0.0.1:{}", b1.port)],
            "carol",
            &token,
        ))
        .await
        .expect("delegated connect");
    a.start_proxy(0).await.unwrap();
    let proxy_port = a.proxy_port();
    assert!(socks_echo(proxy_port, [127, 0, 0, 1], echo_port, b"p2-live").await);

    // ---- revoke: the registry entry dies and A's session is kicked ----
    let resp = http
        .delete(format!(
            "{c_base}/api/v1/admin/delegation/tokens/{token_id}"
        ))
        .bearer_auth(&c_token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let token_hash = agile_net_node::db::sha256_hex(token.as_bytes());
    let b1_reg = b1
        .server
        .runtime()
        .listener
        .as_ref()
        .unwrap()
        .delegated_registry();
    for _ in 0..50 {
        if !b1_reg.contains_key(&token_hash) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        !b1_reg.contains_key(&token_hash),
        "revocation cleared B1's registry"
    );

    // A's live session was kicked; further opens fail (auth keeps failing on redial)
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    assert!(
        !socks_echo(proxy_port, [127, 0, 0, 1], echo_port, b"p2-dead").await,
        "revoked token must not pass"
    );
    assert_ne!(
        a.node_status(&state.node_id),
        NodeStatus::Connected,
        "A no longer connected after revocation"
    );

    a.disconnect_all().await;
    c.stop().await;
    b1.server.stop().await;
}
