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
    let dir =
        std::env::temp_dir().join(format!("anet-fedp3-test-{}-{}", tag, uuid::Uuid::new_v4()));
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
    c.db()
        .set_group_rules(&gid_fine, &[rid_fine])
        .expect("bind fine");
    c.db()
        .set_group_e2e_required(&gid_fine, true)
        .expect("e2e flag");

    // fan out with a domain-suffix advertise (hint source) plus the coarse CIDR (so B routes
    // R1's IP to C instead of dialing it locally); push only the coarse group
    let cid = c
        .db()
        .create_connector(
            "b-rendezvous",
            "",
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
    c.db()
        .set_connector_push_groups(&cid, &gid_pub)
        .expect("push");
    c.connector_manager()
        .upsert_from_db(&cid)
        .await
        .expect("upsert");
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
        share_url.contains("&en=en_"),
        "the entrust word rides the link: {share_url}"
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
    let entry = registry
        .get(&token_hash)
        .expect("registration on B")
        .clone();
    assert_eq!(
        entry.groups,
        vec!["git-pub".to_string()],
        "B never sees the fine group"
    );
    // the entrust word is the whole routing vocabulary (zero disclosure; no legacy hints)
    assert_eq!(entry.hint_map.len(), 1);
    assert!(
        entry.hint_map[0]
            .hint
            .starts_with(agile_net_core::relay::e2e::ENTRUST_PREFIX),
        "the entrust word leads the hint map: {:?}",
        entry.hint_map
    );
    assert!(
        !entry.acl_rules.iter().any(|r| r.contains("127.0.0.1")),
        "B's delegated ACL must not contain R1: {:?}",
        entry.acl_rules
    );

    // ---- A: import the link verbatim (parse path), connect and reach R1 via E2E ----
    let parsed = agile_net_client::parse_connect_url(&share_url).expect("parse delegate link");
    assert!(
        parsed
            .en
            .as_deref()
            .is_some_and(|w| w.starts_with(agile_net_core::relay::e2e::ENTRUST_PREFIX)),
        "entrust word parsed from the link"
    );
    let a = AgileNetClient::new();
    let state = a
        .connect(ConnectParams {
            addr: parsed.addr,
            label: parsed.label,
            token: parsed.token,
            insecure: true,
            pinned_fingerprint: parsed.pinned_fingerprint,
            manage_hosts: false,
            entries: parsed.entries,
            entry_fps: parsed.entry_fps,
            en: parsed.en,
            emode: parsed.emode,
            eadmin: parsed.eadmin,
            myname: parsed.myname,
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
    assert!(
        !mallory_url.contains("&en="),
        "transparent tier has no entrust word"
    );
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
        label: parsed2.label,
        token: parsed2.token,
        insecure: true,
        pinned_fingerprint: parsed2.pinned_fingerprint,
        manage_hosts: false,
        entries: parsed2.entries,
        entry_fps: parsed2.entry_fps,
        en: parsed2.en,
        emode: parsed2.emode,
        eadmin: parsed2.eadmin,
        myname: parsed2.myname,
    })
    .await
    .expect("transparent delegated connect");
    a2.start_proxy(0).await.unwrap();
    let proxy_port2 = a2.proxy_port();

    // the plaintext Open towards R1 hits C's e2e_required group -> refused (fail-close),
    // even though B's transparent ACL would have routed it
    assert!(
        !socks_echo(
            proxy_port2,
            [127, 0, 0, 1],
            echo_port,
            b"p3-plaintext-downgrade"
        )
        .await,
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
    c.db()
        .set_group_rules(&gid_fine, &[rid_fine])
        .expect("bind fine");
    c.db()
        .set_group_e2e_required(&gid_fine, true)
        .expect("e2e flag");

    let cid = c
        .db()
        .create_connector(
            "b-rendezvous",
            "",
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
    c.db()
        .set_connector_push_groups(&cid, &gid_pub)
        .expect("push");
    c.connector_manager()
        .upsert_from_db(&cid)
        .await
        .expect("upsert");
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
    assert_eq!(
        resp.status(),
        400,
        "split without an e2e group must be rejected"
    );

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
    assert!(
        share_url.contains("emode=split"),
        "split tier rides the link: {share_url}"
    );
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
        label: parsed.label,
        token: parsed.token,
        insecure: true,
        pinned_fingerprint: parsed.pinned_fingerprint,
        manage_hosts: false,
        entries: parsed.entries,
        entry_fps: parsed.entry_fps,
        en: parsed.en,
        emode: parsed.emode,
        eadmin: parsed.eadmin,
        myname: parsed.myname,
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
    let entry = registry
        .get(&token_hash)
        .expect("registration on B")
        .clone();
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

    // ---- hot follow (no reconnect): an issuer-side rule edit must reach the client via config
    // re-pull (the production path is the 45s periodic pull; here we drive the same re-pull
    // directly). Replace the fine group's rule: the new one must arrive AND the old one must go.
    let rid_hot = c
        .db()
        .create_rule("host", "hot-follow.internal", false, "")
        .expect("rule hot")
        .id;
    c.db()
        .set_group_rules(&gid_fine, &[rid_hot])
        .expect("rebind fine");
    c.db().bump_config_version().expect("bump hot");
    tokio::time::sleep(std::time::Duration::from_millis(2400)).await; // issuer watcher tick is 2s
    let node_id = a.list_nodes().await[0].node_id.clone();
    a.refresh_delegation_config(&node_id)
        .await
        .expect("config re-pull");
    let rules2: Vec<String> = a.list_nodes().await[0]
        .rules
        .iter()
        .map(|r| r.value.clone())
        .collect();
    assert!(
        rules2.iter().any(|v| v == "hot-follow.internal"),
        "new rule followed without reconnect: {rules2:?}"
    );
    assert!(
        !rules2.iter().any(|v| v == "127.0.0.1/32"),
        "removed rule must leave the vocabulary without reconnect: {rules2:?}"
    );

    a.disconnect_all().await;
    c.stop().await;
    b.stop().await;
}

/// Delegated admin + transit management (federation P3): a full-scope token pulls its
/// bootstrap ticket over the E2E config channel, manages the issuer through the reserved
/// admin bridge, and reaches a discovered upstream's API through the issuer's fan-out session.
#[tokio::test]
async fn p3_delegated_admin_and_transit_management() {
    // ---- B: the rendezvous, control plane exposed to C ----
    let relay_port = free_port();
    let (b, _bdir) = boot("b-admin", Some(relay_port)).await;
    b.db()
        .set_config("node_name", "b-relay")
        .expect("node name");
    let b_base = format!("http://{}", b.api_addr());
    let psk = "psk_p3-admin-token-0123456789abc";
    b.db()
        .create_relay_token_with_quota(
            &agile_net_node::db::sha256_hex(psk.as_bytes()),
            "psk_test",
            "for peer-c",
            true, // expose_control: B offers its control endpoint to C
            "full",
            None,
            None,
        )
        .expect("create relay token");

    // ---- C: one e2e_required group + fan-out ----
    let (c, _cdir) = boot("c-admin", None).await;
    let c_base = format!("http://{}", c.api_addr());
    let c_token = admin_token(&c_base).await;
    let gid_fine = c.db().create_group("db-fine", "fine").expect("group").id;
    // a host wildcard keeps every 127.x address out of C's advertised set — pushed rules union
    // into advertise, and an entry covering B's loopback would swallow the nested transit open
    let rid_fine = c
        .db()
        .create_rule("host", "*.internal", false, "")
        .expect("rule")
        .id;
    c.db()
        .set_group_rules(&gid_fine, &[rid_fine])
        .expect("bind");
    c.db()
        .set_group_e2e_required(&gid_fine, true)
        .expect("e2e flag");
    let cid = c
        .db()
        .create_connector(
            "b-rendezvous",
            "",
            &format!("127.0.0.1:{relay_port}"),
            psk,
            "fed.test",
            true,
            "",
            "",
            "",
            // only the wildcard suffix: a 127/8 advertise would swallow B's own loopback API
            // in the nested transit-management open (B must dial it locally)
            "*.internal",
            None,
            "fan out to B",
        )
        .expect("connector")
        .id;
    c.db()
        .set_connector_push_groups(&cid, &gid_fine)
        .expect("push");
    c.connector_manager()
        .upsert_from_db(&cid)
        .await
        .expect("upsert");
    c.db().bump_config_version().expect("bump");
    for _ in 0..60 {
        if c.connector_manager().state_of(&cid) == Some("connected") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let http = reqwest::Client::new();

    // admin on a transparent token is rejected (a ticket must never cross a relay in plaintext)
    let gid_plain = c.db().create_group("plain", "no e2e").expect("group").id;
    let resp = http
        .post(format!("{c_base}/api/v1/admin/delegation/tokens"))
        .bearer_auth(&c_token)
        .json(&serde_json::json!({
            "label": "bad-admin",
            "group_ids": [gid_plain],
            "regs": [{ "connector_id": cid.clone(), "is_primary": true }],
            "admin_scope": "ro",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "admin requires an e2e group");

    // ---- issue the full-admin token ----
    let resp = http
        .post(format!("{c_base}/api/v1/admin/delegation/tokens"))
        .bearer_auth(&c_token)
        .json(&serde_json::json!({
            "label": "root-laptop",
            "group_ids": [gid_fine.clone()],
            "regs": [{ "connector_id": cid, "is_primary": true }],
            "admin_scope": "full",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "issue admin token: {:?}", resp);
    let body: serde_json::Value = resp.json().await.unwrap();
    let share_url = body["data"]["share_url"].as_str().unwrap().to_string();
    assert!(
        share_url.contains("eadmin=1"),
        "admin hint rides the link: {share_url}"
    );
    assert_eq!(body["data"]["admin_scope"].as_str(), Some("full"));

    // registration must reach B before A dials (the sync task registers over the fan-out session)
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

    // ---- A connects (eadmin) and pulls the config: admin ticket + upstream offer ----
    let parsed = agile_net_client::parse_connect_url(&share_url).expect("parse admin link");
    assert!(parsed.eadmin);
    let a = AgileNetClient::new();
    let state = a
        .connect(ConnectParams {
            addr: parsed.addr,
            label: parsed.label,
            token: parsed.token,
            insecure: true,
            pinned_fingerprint: parsed.pinned_fingerprint,
            manage_hosts: false,
            entries: parsed.entries,
            entry_fps: parsed.entry_fps,
            en: parsed.en,
            emode: parsed.emode,
            eadmin: parsed.eadmin,
            myname: parsed.myname,
        })
        .await
        .expect("delegated admin connect");
    let node_id = state.node_id.clone();
    let mut admin_ready = false;
    let mut last_seen = String::new();
    for _ in 0..60 {
        let n = a.get_node(&node_id).await.unwrap();
        last_seen = format!(
            "admin_console={} manageable={:?} deleg_admin={}",
            n.admin_console,
            n.manageable.iter().map(|m| m.node_name.clone()).collect::<Vec<_>>(),
            a.delegated_console_ticket(&node_id).is_some(),
        );
        if n.admin_console && n.manageable.iter().any(|m| m.node_name == "b-relay") {
            admin_ready = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        admin_ready,
        "config channel should deliver the ticket + upstream offer; last: {last_seen}"
    );

    // admin bridge: bootstrap through the reserved channel straight into C's API
    let opener = a.opener(&node_id).expect("delegated opener");
    let (ticket, _) = a
        .delegated_console_ticket(&node_id)
        .expect("admin ticket stashed");
    let payload = serde_json::json!({ "ticket": ticket }).to_string();
    let mut ch = opener
        .open("", agile_net_core::relay::e2e::DELEGATION_ADMIN_TARGET, 0)
        .await
        .expect("admin bridge open");
    let req = format!(
        "POST /api/v1/auth/admin-bootstrap HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        payload.len(),
        payload
    );
    ch.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(5), ch.read_to_end(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let resp_text = String::from_utf8_lossy(&buf);
    assert!(
        resp_text.contains("access_token"),
        "issuer API answered through the E2E admin bridge: {}",
        &resp_text[..resp_text.len().min(200)]
    );
    assert!(resp_text.contains("\"full\""), "scope honored: {resp_text}");

    // transit management: A dials B's API through C's fan-out session (nested channel)
    let (uticket, _, _, _) = a
        .delegated_upstream_ticket(&node_id, "b-relay")
        .expect("upstream offer stashed");
    let mut ch2 = opener
        .open("", "upstream:b-relay", 0)
        .await
        .expect("transit management open");
    let payload2 = serde_json::json!({ "ticket": uticket }).to_string();
    let req2 = format!(
        "POST /api/v1/auth/admin-bootstrap HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        payload2.len(),
        payload2
    );
    ch2.write_all(req2.as_bytes()).await.unwrap();
    let mut buf2 = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        ch2.read_to_end(&mut buf2),
    )
    .await
    .unwrap()
    .unwrap();
    let resp2 = String::from_utf8_lossy(&buf2);
    assert!(
        resp2.contains("access_token"),
        "B's API answered through the transit path (A->E2E->C->fan-out->B): {}",
        &resp2[..resp2.len().min(200)]
    );

    // sanity: the same ticket also exchanges directly against B (it is a real relay ticket)
    let r = http
        .post(format!("{b_base}/api/v1/auth/admin-bootstrap"))
        .json(&serde_json::json!({ "ticket": a.delegated_upstream_ticket(&node_id, "b-relay").unwrap().0 }))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "upstream ticket valid on B");

    a.disconnect_all().await;
    c.stop().await;
    b.stop().await;
}

/// Federation P3 entrust mode (docs/todo/e2e.md §2 en_xxx): an E2E delegated token issues with
/// NO push_groups and NO advertise on the fan-out — the opaque entrust word (en_xxx) routes the
/// opens while the relay learns nothing about the issuer's groups or routes (zero disclosure).
/// Covers: issuance without the legacy 400, link en= param, registration without pushed groups
/// (§7.2.4), entrust-registry routing, and revoke-by-disconnect of entrust entries.
#[tokio::test]
async fn p3_entrust_zero_disclosure() {
    // ---- B: the public rendezvous ----
    let relay_port = free_port();
    let (b, _bdir) = boot("b", Some(relay_port)).await;
    let b_base = format!("http://{}", b.api_addr());
    let b_token = admin_token(&b_base).await;
    let http = reqwest::Client::new();
    let psk = "psk_p3-entrust-token-0123456789abcdef";
    b.db()
        .create_relay_token_with_quota(
            &agile_net_node::db::sha256_hex(psk.as_bytes()),
            "psk_ente",
            "for peer-c",
            false,
            "full",
            None,
            None,
        )
        .expect("create relay token");

    // ---- C: e2e_required group ONLY; connector with NO push_groups and NO advertise ----
    let echo_port = free_port();
    start_echo_server(echo_port).await;
    let (c, _cdir) = boot("c", None).await;
    let c_base = format!("http://{}", c.api_addr());
    let c_token = admin_token(&c_base).await;
    let gid = c.db().create_group("git-e2e", "fine").expect("group").id;
    let rid = c
        .db()
        .create_rule("ip-cidr", "127.0.0.1/32", false, "")
        .expect("rule")
        .id;
    c.db().set_group_rules(&gid, &[rid]).expect("bind");
    c.db()
        .set_group_e2e_required(&gid, true)
        .expect("e2e flag");
    let cid = c
        .db()
        .create_connector(
            "b-rendezvous",
            "",
            &format!("127.0.0.1:{relay_port}"),
            psk,
            "fed.test",
            true,
            "",
            "",
            "",
            "",
            None,
            "fan out to B",
        )
        .expect("connector")
        .id;
    c.connector_manager()
        .upsert_from_db(&cid)
        .await
        .expect("upsert");

    // ---- issue an E2E delegated token: previously a 400 without advertise/push, entrust covers it now ----
    let resp = http
        .post(format!("{c_base}/api/v1/admin/delegation/tokens"))
        .bearer_auth(&c_token)
        .json(&serde_json::json!({
            "label": "alice",
            "group_ids": [gid],
            "regs": [{ "connector_id": cid, "is_primary": true }],
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        status, 201,
        "entrust issuance needs no advertise/push groups: {body}"
    );
    let share_url = body["data"]["share_url"].as_str().unwrap().to_string();
    let token_id = body["data"]["id"].as_str().unwrap().to_string();
    assert!(
        share_url.contains("&en=en_"),
        "the link carries the entrust word: {share_url}"
    );

    // ---- wait for the registration ack (the sync task polls every 2s) ----
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
            .filter(|t| t["label"].as_str() == Some("alice"))
            .flat_map(|t| t["regs"].as_array().unwrap().clone())
            .any(|r| r["state"].as_str() == Some("registered"));
        if registered {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // ---- zero disclosure: B's pool for C shows neither groups nor advertise ----
    let resp = http
        .get(format!("{b_base}/api/v1/admin/federation/offered"))
        .bearer_auth(&b_token)
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let offer = body["data"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["node_id"].as_str().is_some())
        .expect("C online in B's pool")
        .clone();
    assert!(
        offer["groups"].as_array().unwrap().is_empty(),
        "B sees none of C's groups: {offer}"
    );
    assert!(
        offer["advertise"].as_array().unwrap().is_empty(),
        "B sees none of C's advertised routes: {offer}"
    );

    // ---- B's entrust registry routes the word back to C ----
    let parsed = agile_net_client::parse_connect_url(&share_url).expect("parse entrust link");
    let en = parsed.en.clone().expect("entrust word parsed");
    let listener = b.runtime().listener.clone().expect("listener");
    let issuer = listener
        .entrust_resolve(&en)
        .expect("entrust word registered on B");
    assert_eq!(issuer, offer["node_id"].as_str().unwrap());

    // ---- A: import the link verbatim, connect and reach the segment through the blind relay ----
    let a = AgileNetClient::new();
    let state = a
        .connect(ConnectParams {
            addr: parsed.addr,
            label: parsed.label,
            token: parsed.token,
            insecure: true,
            pinned_fingerprint: parsed.pinned_fingerprint,
            manage_hosts: false,
            entries: parsed.entries,
            entry_fps: parsed.entry_fps,
            en: parsed.en,
            emode: parsed.emode,
            eadmin: parsed.eadmin,
            myname: parsed.myname,
        })
        .await
        .expect("entrust delegated connect");
    assert_eq!(state.status, NodeStatus::Connected);
    a.start_proxy(0).await.unwrap();
    let proxy_port = a.proxy_port();
    assert!(
        socks_echo(proxy_port, [127, 0, 0, 1], echo_port, b"p3-entrust").await,
        "A reaches C's segment through the entrust-routed blind relay"
    );
    a.disconnect_all().await;

    // ---- revoke: the token's entrust words leave B's registry with it ----
    let resp = http
        .delete(format!("{c_base}/api/v1/admin/delegation/tokens/{token_id}"))
        .bearer_auth(&c_token)
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"].as_u64(), Some(0), "revoke: {body}");
    for _ in 0..50 {
        if listener.entrust_resolve(&en).is_none() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        listener.entrust_resolve(&en).is_none(),
        "revocation drops the entrust word from B's registry"
    );
    // disconnect death rides the same teardown block as delegated registrations (pre-existing
    // session semantics — the entrust retain lives in that very block)
    c.stop().await;
    b.stop().await;
}
