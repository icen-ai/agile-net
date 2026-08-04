//! Federation P3 end-to-end test (acceptance of docs/plan/federation-p2p3.md §4.5):
//! an e2e_required group hangs on a delegated token; consumer A reaches R1 (a rule that only
//! exists in C's local fine group) through relay B — while B's delegated vocabulary contains
//! nothing but the coarse hint (blind forwarding). A plaintext Open hitting the e2e_required
//! group is refused by C (fail-close, hard discipline 3); record replay/reorder rejection and
//! per-channel salt isolation are covered by core::relay::e2e unit tests.

use agile_net_client::{AgileNetClient, ConnectParams, NodeStatus};
use agile_net_core::config::node::{ListenerConfig, NodeConfig};
use agile_net_node::service::{NodeServer, NodeServerOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("anet-fedp3-test-{}-{}", tag, uuid::Uuid::new_v4()));
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

async fn start_echo_server(port: u16) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.unwrap();
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

#[tokio::test]
async fn p3_e2e_blind_relay_and_fail_close() {
    // ---- B: the public rendezvous ----
    let relay_port = free_port();
    let (b, _bdir) = boot("b", Some(relay_port)).await;
    let psk = "psk_p3-shared-token-0123456789";
    b.db()
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

    // ---- C: coarse pushed group + fine local-only e2e_required group ----
    let echo_port = free_port();
    start_echo_server(echo_port).await;
    let (c, _cdir) = boot("c", None).await;
    let c_base = format!("http://{}", c.api_addr());
    let c_token = admin_token(&c_base).await;

    // git-pub: coarse rules, pushed upstream (B's delegated ACL vocabulary)
    let gid_pub = c.db().create_group("git-pub", "coarse").expect("group").id;
    let rid = c
        .db()
        .create_rule("ip-cidr", "127.0.0.0/8", false, "")
        .expect("rule")
        .id;
    c.db().set_group_rules(&gid_pub, &[rid]).expect("bind");

    // db-fine: the fine rule R1 (127.0.0.1/32) — never pushed, e2e_required
    let gid_fine = c.db().create_group("db-fine", "fine R1").expect("group").id;
    let rid_fine = c
        .db()
        .create_rule("ip-cidr", "127.0.0.1/32", false, "")
        .expect("rule fine")
        .id;
    c.db().set_group_rules(&gid_fine, &[rid_fine]).expect("bind fine");
    c.db().set_group_e2e_required(&gid_fine, true).expect("e2e flag");

    // fan out with a domain-suffix advertise (hint source) plus the coarse CIDR (so B routes
    // R1's IP to C instead of dialing it locally); push only the coarse group
    let cid = c
        .db()
        .create_connector(
            "b-rendezvous",
            &format!("127.0.0.1:{relay_port}"),
            psk,
            "fed.test",
            true,
            "",
            "",
            "",
            "*.internal,127.0.0.0/8",
            None,
            "fan out to B",
        )
        .expect("connector")
        .id;
    c.db().set_connector_push_groups(&cid, &gid_pub).expect("push");
    c.connector_manager().upsert_from_db(&cid).await.expect("upsert");
    c.db().bump_config_version().expect("bump");
    for _ in 0..60 {
        if c.connector_manager().state_of(&cid) == Some("connected") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // ---- C issues the delegated token over both groups; the hint is auto-derived ----
    let http = reqwest::Client::new();
    let resp = http
        .post(format!("{c_base}/api/v1/admin/delegation/tokens"))
        .bearer_auth(&c_token)
        .json(&serde_json::json!({
            "label": "alice",
            "group_ids": [gid_pub.clone(), gid_fine.clone()],
            "regs": [{ "connector_id": cid, "is_primary": true }],
        }))
        .send()
        .await;
    let resp = resp.unwrap();
    assert_eq!(resp.status(), 201, "issue: {:?}", resp);
    let body: serde_json::Value = resp.json().await.unwrap();
    let token = body["data"]["token"].as_str().unwrap().to_string();
    let share_url = body["data"]["share_url"].as_str().unwrap().to_string();
    assert!(
        share_url.contains("ehint=relay.internal"),
        "auto-derived hint rides the link: {share_url}"
    );

    // registration arrives at B (state polling via C's API)
    for _ in 0..60 {
        let resp = http
            .get(format!("{c_base}/api/v1/admin/delegation/tokens"))
            .bearer_auth(&c_token)
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        if body["data"]["items"][0]["regs"][0]["state"].as_str() == Some("registered") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // ---- B-side assertions (blind relay): vocabulary holds the coarse hint only ----
    let token_hash = agile_net_node::db::sha256_hex(token.as_bytes());
    let registry = b.runtime().listener.as_ref().unwrap().delegated_registry();
    let entry = registry.get(&token_hash).expect("registration on B").clone();
    assert_eq!(entry.groups, vec!["git-pub".to_string()], "B never sees the fine group");
    assert_eq!(entry.hint_map.len(), 1);
    assert_eq!(entry.hint_map[0].hint, "relay.internal");
    assert!(
        !entry.acl_rules.iter().any(|r| r.contains("127.0.0.1")),
        "B's delegated ACL must not contain R1: {:?}",
        entry.acl_rules
    );

    // ---- A: import the link verbatim (parse path), connect and reach R1 via E2E ----
    let parsed = agile_net_client::parse_connect_url(&share_url).expect("parse delegate link");
    assert!(parsed.delegated);
    assert_eq!(parsed.ehint.as_deref(), Some("relay.internal"));
    let a = AgileNetClient::new();
    let state = a
        .connect(ConnectParams {
            addr: parsed.addr,
            username: parsed.username,
            password: parsed.password,
            insecure: true,
            pinned_cert_path: None,
            pinned_fingerprint: parsed.pinned_fingerprint,
            manage_hosts: false,
            delegated: parsed.delegated,
            entries: parsed.entries,
            entry_fps: parsed.entry_fps,
            ehint: parsed.ehint,
            emode: parsed.emode,
        })
        .await
        .expect("delegated connect");
    assert_eq!(state.status, NodeStatus::Connected);
    a.start_proxy(0).await.unwrap();
    let proxy_port = a.proxy_port();

    // R1 (127.0.0.1:echo_port) — visible to nobody but C — is reachable through the E2E channel
    assert!(
        socks_echo(proxy_port, [127, 0, 0, 1], echo_port, b"p3-e2e-secret").await,
        "E2E channel reaches R1 through the blind relay"
    );

    // ---- hard discipline 3: a plaintext Open hitting the e2e_required group is refused ----
    // issue a transparent-tier token over the coarse group only (no hint in its link)
    let resp = http
        .post(format!("{c_base}/api/v1/admin/delegation/tokens"))
        .bearer_auth(&c_token)
        .json(&serde_json::json!({
            "label": "mallory",
            "group_ids": [gid_pub],
            "regs": [{ "connector_id": cid, "is_primary": true }],
        }))
        .send()
        .await;
    let resp = resp.unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let mallory_url = body["data"]["share_url"].as_str().unwrap().to_string();
    assert!(!mallory_url.contains("ehint="), "transparent tier has no hint");
    // wait for the second token's registration before dialing (the sync task polls every 2s)
    for _ in 0..60 {
        let resp = http
            .get(format!("{c_base}/api/v1/admin/delegation/tokens"))
            .bearer_auth(&c_token)
            .send()
            .await;
        let body: serde_json::Value = resp.unwrap().json().await.unwrap();
        let registered = body["data"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|t| t["label"].as_str() == Some("mallory"))
            .flat_map(|t| t["regs"].as_array().unwrap().clone())
            .any(|r| r["state"].as_str() == Some("registered"));
        if registered {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let parsed2 = agile_net_client::parse_connect_url(&mallory_url).unwrap();
    let a2 = AgileNetClient::new();
    a2.connect(ConnectParams {
        addr: parsed2.addr,
        username: parsed2.username,
        password: parsed2.password,
        insecure: true,
        pinned_cert_path: None,
        pinned_fingerprint: parsed2.pinned_fingerprint,
        manage_hosts: false,
        delegated: parsed2.delegated,
        entries: parsed2.entries,
        entry_fps: parsed2.entry_fps,
        ehint: parsed2.ehint,
        emode: parsed2.emode,
    })
    .await
    .expect("transparent delegated connect");
    a2.start_proxy(0).await.unwrap();
    let proxy_port2 = a2.proxy_port();

    // the plaintext Open towards R1 hits C's e2e_required group -> refused (fail-close),
    // even though B's transparent ACL would have routed it
    assert!(
        !socks_echo(proxy_port2, [127, 0, 0, 1], echo_port, b"p3-plaintext-downgrade").await,
        "plaintext downgrade must fail closed"
    );

    // the E2E channel stays healthy afterwards (fail-close is per-open, not per-session)
    assert!(
        socks_echo(proxy_port, [127, 0, 0, 1], echo_port, b"p3-e2e-still-ok").await,
        "E2E channel unaffected by the refused plaintext open"
    );

    a2.disconnect_all().await;
    a.disconnect_all().await;
    c.stop().await;
    b.stop().await;
}

/// Split tier (federation P3): the consumer pulls the token's effective rule vocabulary over
/// the E2E config channel and routes selectively — including the fine rule B never sees.
#[tokio::test]
async fn p3_split_tier_rule_delivery() {
    // ---- B: the public rendezvous ----
    let relay_port = free_port();
    let (b, _bdir) = boot("b-split", Some(relay_port)).await;
    let psk = "psk_p3-split-token-0123456789ab";
    b.db()
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

    // ---- C: coarse pushed group + fine local-only e2e_required group ----
    let echo_port = free_port();
    start_echo_server(echo_port).await;
    let (c, _cdir) = boot("c-split", None).await;
    let c_base = format!("http://{}", c.api_addr());
    let c_token = admin_token(&c_base).await;

    let gid_pub = c.db().create_group("git-pub", "coarse").expect("group").id;
    let rid = c
        .db()
        .create_rule("ip-cidr", "127.0.0.0/8", false, "")
        .expect("rule")
        .id;
    c.db().set_group_rules(&gid_pub, &[rid]).expect("bind");
    let gid_fine = c.db().create_group("db-fine", "fine R1").expect("group").id;
    let rid_fine = c
        .db()
        .create_rule("ip-cidr", "127.0.0.1/32", false, "")
        .expect("rule fine")
        .id;
    c.db().set_group_rules(&gid_fine, &[rid_fine]).expect("bind fine");
    c.db().set_group_e2e_required(&gid_fine, true).expect("e2e flag");

    let cid = c
        .db()
        .create_connector(
            "b-rendezvous",
            &format!("127.0.0.1:{relay_port}"),
            psk,
            "fed.test",
            true,
            "",
            "",
            "",
            "*.internal,127.0.0.0/8",
            None,
            "fan out to B",
        )
        .expect("connector")
        .id;
    c.db().set_connector_push_groups(&cid, &gid_pub).expect("push");
    c.connector_manager().upsert_from_db(&cid).await.expect("upsert");
    c.db().bump_config_version().expect("bump");
    for _ in 0..60 {
        if c.connector_manager().state_of(&cid) == Some("connected") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let http = reqwest::Client::new();

    // split requires at least one e2e_required group (the vocabulary rides the E2E channel)
    let resp = http
        .post(format!("{c_base}/api/v1/admin/delegation/tokens"))
        .bearer_auth(&c_token)
        .json(&serde_json::json!({
            "label": "bad-split",
            "group_ids": [gid_pub.clone()],
            "regs": [{ "connector_id": cid.clone(), "is_primary": true }],
            "mode": "split",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "split without an e2e group must be rejected");

    // ---- issue the split token over both groups ----
    let resp = http
        .post(format!("{c_base}/api/v1/admin/delegation/tokens"))
        .bearer_auth(&c_token)
        .json(&serde_json::json!({
            "label": "alice-split",
            "group_ids": [gid_pub.clone(), gid_fine.clone()],
            "regs": [{ "connector_id": cid, "is_primary": true }],
            "mode": "split",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "issue split: {:?}", resp);
    let body: serde_json::Value = resp.json().await.unwrap();
    let token = body["data"]["token"].as_str().unwrap().to_string();
    let share_url = body["data"]["share_url"].as_str().unwrap().to_string();
    assert!(share_url.contains("emode=split"), "split tier rides the link: {share_url}");
    assert_eq!(body["data"]["mode"].as_str(), Some("split"));

    // registration arrives at B
    for _ in 0..60 {
        let resp = http
            .get(format!("{c_base}/api/v1/admin/delegation/tokens"))
            .bearer_auth(&c_token)
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        if body["data"]["items"][0]["regs"][0]["state"].as_str() == Some("registered") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // ---- A: connect with the split tier — rules swap from catch-all to the token vocabulary ----
    let parsed = agile_net_client::parse_connect_url(&share_url).expect("parse split link");
    assert_eq!(parsed.emode.as_deref(), Some("split"));
    let a = AgileNetClient::new();
    a.connect(ConnectParams {
        addr: parsed.addr,
        username: parsed.username,
        password: parsed.password,
        insecure: true,
        pinned_cert_path: None,
        pinned_fingerprint: parsed.pinned_fingerprint,
        manage_hosts: false,
        delegated: parsed.delegated,
        entries: parsed.entries,
        entry_fps: parsed.entry_fps,
        ehint: parsed.ehint,
        emode: parsed.emode,
    })
    .await
    .expect("split delegated connect");

    let mut rules: Vec<String> = Vec::new();
    for _ in 0..60 {
        let nodes = a.list_nodes().await;
        rules = nodes[0].rules.iter().map(|r| r.value.clone()).collect();
        if !rules.is_empty() && !rules.iter().any(|v| v == "0.0.0.0/0") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        rules.iter().any(|v| v == "127.0.0.0/8"),
        "coarse rule delivered: {rules:?}"
    );
    assert!(
        rules.iter().any(|v| v == "127.0.0.1/32"),
        "fine rule R1 delivered E2E-sealed: {rules:?}"
    );
    assert!(
        !rules.iter().any(|v| v == "0.0.0.0/0" || v == "*"),
        "catch-all replaced by the selective set: {rules:?}"
    );

    // B stays blind: the delivered fine rule never enters B's delegated vocabulary
    let token_hash = agile_net_node::db::sha256_hex(token.as_bytes());
    let registry = b.runtime().listener.as_ref().unwrap().delegated_registry();
    let entry = registry.get(&token_hash).expect("registration on B").clone();
    assert!(
        !entry.acl_rules.iter().any(|r| r.contains("127.0.0.1")),
        "B must not learn R1 from rule delivery: {:?}",
        entry.acl_rules
    );

    // the data plane works through the selective routes
    a.start_proxy(0).await.unwrap();
    let proxy_port = a.proxy_port();
    assert!(
        socks_echo(proxy_port, [127, 0, 0, 1], echo_port, b"p3-split-secret").await,
        "E2E channel reaches R1 through selective routes"
    );

    a.disconnect_all().await;
    c.stop().await;
    b.stop().await;
}
