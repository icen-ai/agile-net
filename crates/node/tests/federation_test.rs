//! Federation P1 end-to-end test (acceptance of docs/todo/federation.md §4-P1):
//! resource owner C pushes policy groups with its fan-out handshake; upstream B pools them
//! source-tagged; the B admin adopts "C's git group" in one click and issues a delegated token
//! for consumer A against it — without C ever touching a credential on B.

use agile_net_core::config::node::{ListenerConfig, NodeConfig};
use agile_net_node::service::{NodeServer, NodeServerOptions};

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("anet-fed-test-{}-{}", tag, uuid::Uuid::new_v4()));
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

#[tokio::test]
async fn federation_push_pool_adopt_grant() {
    // ---- B: the public rendezvous (listener + admin API) ----
    let relay_port = free_port();
    let (b, _bdir) = boot("b", Some(relay_port)).await;
    let b_base = format!("http://{}", b.api_addr());
    let b_token = admin_token(&b_base).await;
    let http = reqwest::Client::new();

    // A fan-in token on B (the credential C fans out with; issuance stays on B in P1)
    let psk = "psk_federation-e2e-token-0123456789abcdef";
    b.db()
        .create_relay_token_with_quota(
            &agile_net_node::db::sha256_hex(psk.as_bytes()),
            "psk_fede",
            "for peer-c",
            false,
            "full",
            None,
            None,
        )
        .expect("create relay token");

    // ---- C: the resource owner (local group "git" + connector pushing it upstream) ----
    let (c, _cdir) = boot("c", None).await;
    let gid = c.db().create_group("git", "代码组").expect("group").id;
    let rid = c
        .db()
        .create_rule("host", "git.internal", false, "")
        .expect("rule")
        .id;
    let rid2 = c
        .db()
        .create_rule("ip-cidr", "10.12.0.0/16", false, "")
        .expect("rule2")
        .id;
    c.db().set_group_rules(&gid, &[rid.clone(), rid2.clone()]).expect("bind");
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
    c.db()
        .set_connector_push_groups(&cid, &gid)
        .expect("push groups");
    c.connector_manager()
        .upsert_from_db(&cid)
        .await
        .expect("upsert");

    // ---- B: the pool shows C's pushed group (source-tagged), then one-click adoption ----
    let mut offered = serde_json::json!([]);
    for _ in 0..50 {
        let resp = http
            .get(format!("{b_base}/api/v1/admin/federation/offered"))
            .bearer_auth(&b_token)
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        offered = body["data"]["items"].clone();
        if offered
            .as_array()
            .unwrap()
            .iter()
            .any(|o| !o["groups"].as_array().unwrap().is_empty())
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let offer = offered
        .as_array()
        .unwrap()
        .iter()
        .find(|o| !o["groups"].as_array().unwrap().is_empty())
        .expect("C's pushed groups should appear in B's pool")
        .clone();
    let node_id = offer["node_id"].as_str().unwrap().to_string();
    assert_eq!(offer["groups"][0]["name"], "git");
    assert_eq!(
        offer["groups"][0]["rules"].as_array().unwrap().len(),
        2,
        "both group rules ride the push"
    );

    // One-click adoption: B's admin materializes "C's git group" (C never touches an account on B)
    let resp = http
        .post(format!("{b_base}/api/v1/admin/federation/adopt"))
        .bearer_auth(&b_token)
        .json(&serde_json::json!({ "node_id": node_id, "group": "git" }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"].as_u64(), Some(0), "adopt: {body}");
    let adopted = body["data"].clone();
    // naming sovereignty: the source tag is B's own title for the peer (the relay token remark
    // "for peer-c"), never the peer's self-reported node name (a default like "AgileNet Node")
    assert_eq!(adopted["name"].as_str().unwrap(), "git");
    assert_eq!(adopted["rule_count"].as_u64(), Some(2));
    let adopted_gid = adopted["id"].as_str().unwrap().to_string();

    // Adoption is idempotent: a second adopt returns the existing mirror (already=true)
    let resp = http
        .post(format!("{b_base}/api/v1/admin/federation/adopt"))
        .bearer_auth(&b_token)
        .json(&serde_json::json!({ "node_id": node_id, "group": "git" }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"].as_u64(), Some(0));
    assert_eq!(body["data"]["id"].as_str().unwrap(), adopted_gid);
    assert_eq!(body["data"]["already"].as_bool(), Some(true));

    // The offered pool folds the adoption state (the dialog's 待采纳/跟随中 split)
    let resp = http
        .get(format!("{b_base}/api/v1/admin/federation/offered"))
        .bearer_auth(&b_token)
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let g = body["data"]["items"][0]["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["name"].as_str() == Some("git"))
        .expect("pushed group listed")
        .clone();
    assert_eq!(g["adopted"].as_bool(), Some(true));
    assert_eq!(g["adopted_id"].as_str().unwrap(), adopted_gid);

    // The mirror is read-only: update / rebind are refused (copy first, then edit)
    let resp = http
        .put(format!("{b_base}/api/v1/admin/groups/{adopted_gid}"))
        .bearer_auth(&b_token)
        .json(&serde_json::json!({ "remark": "should fail" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400, "adopted mirror must be read-only");
    let resp = http
        .put(format!("{b_base}/api/v1/admin/groups/{adopted_gid}/rules"))
        .bearer_auth(&b_token)
        .json(&serde_json::json!({ "rule_ids": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400, "adopted mirror rebind must be refused");

    // The mirror follows the source: C swaps one pushed rule; B's adopted group re-syncs
    // (push slot refresh -> reconnect re-push -> adoption sync tick, all ≤ a few seconds)
    let new_rule = c
        .db()
        .create_rule("host", "ops.internal", false, "")
        .expect("new rule")
        .id;
    let old_rules: Vec<String> = vec![rid.clone(), rid2.clone()];
    c.db().set_group_rules(&gid, &[new_rule, rid2.clone()]).unwrap(); // git.internal -> ops.internal
    c.db().bump_config_version().unwrap();
    let mut mirrored: Vec<String> = Vec::new();
    for _ in 0..80 {
        mirrored = b
            .db()
            .rules_of_group(&adopted_gid)
            .unwrap()
            .into_iter()
            .map(|r| r.value)
            .collect();
        if mirrored.iter().any(|v| v == "ops.internal") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    assert!(
        mirrored.iter().any(|v| v == "ops.internal"),
        "mirror should follow the pushed source: {mirrored:?}"
    );

    // Copy detaches into an editable local group; the mirror keeps following
    let resp = http
        .post(format!("{b_base}/api/v1/admin/federation/adopted/{adopted_gid}/copy"))
        .bearer_auth(&b_token)
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"].as_u64(), Some(0), "copy: {body}");
    let copy_gid = body["data"]["id"].as_str().unwrap().to_string();
    let resp = http
        .put(format!("{b_base}/api/v1/admin/groups/{copy_gid}"))
        .bearer_auth(&b_token)
        .json(&serde_json::json!({ "remark": "editable copy" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "the copy is editable");

    // restore C's pushed rules so the downstream assertions see the original pair
    c.db().set_group_rules(&gid, &old_rules).unwrap();
    c.db().bump_config_version().unwrap();
    for _ in 0..80 {
        let vals: Vec<String> = b
            .db()
            .rules_of_group(&adopted_gid)
            .unwrap()
            .into_iter()
            .map(|r| r.value)
            .collect();
        // wait for the full restored pair (the swapped mirror may still hold ops.internal)
        if vals.iter().any(|v| v == "git.internal")
            && vals.iter().any(|v| v == "10.12.0.0/16")
            && !vals.iter().any(|v| v == "ops.internal")
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }

    // Grant to consumer A: issue a delegated token on B bound to the adopted group (direct entry)
    let resp = http
        .post(format!("{b_base}/api/v1/admin/delegation/tokens"))
        .bearer_auth(&b_token)
        .json(&serde_json::json!({ "label": "consumer-a", "group_ids": [adopted_gid], "entry_mode": "direct" }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(status, 201, "issue delegated token: {body}");
    let share_url = body["data"]["share_url"].as_str().unwrap();
    assert!(share_url.starts_with("anet://connect?"));
    let parsed = agile_net_core::link::parse_connect_url(share_url).expect("share_url parses");
    assert_eq!(parsed.delegated_label(), Some("consumer-a"));

    // The adopted ACL actually drives fan-in auth: the token's group resolves to C's targets.
    // (Data-plane reachability of C's intra-net is covered by the route-convergence chain tests.)
    let values: Vec<String> = b
        .db()
        .rules_of_group(&adopted_gid)
        .unwrap()
        .into_iter()
        .map(|r| r.value)
        .collect();
    assert!(values.contains(&"git.internal".to_string()));
    assert!(values.contains(&"10.12.0.0/16".to_string()));

    c.stop().await;
    b.stop().await;
}

// ==================== adopted-group delegated grant (issuer-side ACL) ====================

use agile_net_client::{AgileNetClient, ConnectParams, NodeStatus};
use agile_net_core::proxy::router::Outbound;

/// New-world chain: C pushes a group, B adopts it, B issues a direct delegated token against the
/// adopted group — the issuer-side ACL snapshot (union of the mirror's rules) is what gates the
/// fan-in Open on B, and the consumer session authenticates against B's persistent local registry.
/// (The old preset-shadowing regression is obsolete by design: for the dedicated tier the LAN
/// presets now intentionally win — 专线委托 LAN 保持直连 — so no preset is seeded. The multi-hop
/// data plane to C's own segment is covered by federation_p2/p3: a transparent open forwarded to
/// another issuer carries this issuer's local group stamps, which the far endpoint fail-closes
/// on unless it issued them — B-issued tokens terminate at B by design.)
#[tokio::test]
async fn federation_adopted_group_delegated_grant() {
    // ---- B: the public rendezvous ----
    let relay_port = free_port();
    let (b, _bdir) = boot("b", Some(relay_port)).await;
    let b_base = format!("http://{}", b.api_addr());
    let b_token = admin_token(&b_base).await;
    let http = reqwest::Client::new();
    let psk = "psk_federation-dataplane-0123456789abcdef";
    b.db()
        .create_relay_token_with_quota(
            &agile_net_node::db::sha256_hex(psk.as_bytes()),
            "psk_fedp",
            "for peer-c",
            false,
            "full",
            None,
            None,
        )
        .expect("create relay token");

    // ---- C: group with a loopback CIDR (stands in for C's intra-net segment) ----
    let (c, _cdir) = boot("c", None).await;
    let gid = c.db().create_group("git", "代码组").expect("group").id;
    let rid = c
        .db()
        .create_rule("ip-cidr", "127.0.0.1/32", false, "")
        .expect("rule")
        .id;
    c.db().set_group_rules(&gid, &[rid]).expect("bind");
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
    c.db()
        .set_connector_push_groups(&cid, &gid)
        .expect("push groups");
    c.connector_manager()
        .upsert_from_db(&cid)
        .await
        .expect("upsert");

    // Pushed group rules must converge into B's route table (effective advertise = manual ∪ pushed)
    let mut c_node = None;
    for _ in 0..50 {
        c_node = b
            .runtime()
            .listener
            .as_ref()
            .and_then(|l| l.resolve_peer("127.0.0.1"));
        if c_node.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let c_node = c_node.expect("pushed group rules must converge into B's route table");

    // ---- B: one-click adoption + delegated token bound to the adopted group (direct entry) ----
    let resp = http
        .post(format!("{b_base}/api/v1/admin/federation/adopt"))
        .bearer_auth(&b_token)
        .json(&serde_json::json!({ "node_id": c_node, "group": "git" }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"].as_u64(), Some(0), "adopt: {body}");
    let adopted_gid = body["data"]["id"].as_str().unwrap().to_string();

    let resp = http
        .post(format!("{b_base}/api/v1/admin/delegation/tokens"))
        .bearer_auth(&b_token)
        .json(&serde_json::json!({ "label": "consumer-a", "group_ids": [adopted_gid], "entry_mode": "direct" }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(status, 201, "issue delegated token: {body}");
    let plaintext = body["data"]["token"].as_str().unwrap().to_string();

    // The adopted mirror's rules land in B's issuer-side ACL snapshot at issuance
    // (the fan-in enforcement point for this token's consumers)
    let token_hash = agile_net_node::db::sha256_hex(plaintext.as_bytes());
    let listener = b.runtime().listener.clone().expect("listener");
    let entry = listener
        .local_delegated_registry()
        .get(&token_hash)
        .expect("direct token self-registers on B at issuance")
        .clone();
    assert_eq!(entry.groups, vec!["git".to_string()]);
    assert!(
        entry.acl_rules.iter().any(|r| r == "127.0.0.1/32"),
        "ACL snapshot from the adopted mirror: {:?}",
        entry.acl_rules
    );

    // ---- A: delegated consumer dials B's own listener (direct entry = TLS already end-to-end) ----
    // M3-T2: a fresh consumer device is pending (opens gated) until certified; this test grants
    // and consumes without certification, so allow pending devices on B (gray-flag policy)
    b.runtime()
        .device_gate
        .as_ref()
        .expect("device gate wired")
        .set_allow_pending(true);
    let a = AgileNetClient::new();
    let state = a
        .connect(ConnectParams {
            addr: format!("127.0.0.1:{relay_port}"),
            label: "consumer-a".into(),
            token: plaintext,
            insecure: true,
            pinned_fingerprint: None,
            manage_hosts: false,
            entries: Vec::new(),
            entry_fps: Vec::new(),
            en: None,
            emode: None,
            eadmin: false,
            myname: None,
        })
        .await
        .expect("delegated connect");
    assert_eq!(state.status, NodeStatus::Connected);
    assert!(
        state.rules.iter().any(|r| r.value == "0.0.0.0/0"),
        "dedicated tier registers the catch-all route: {:?}",
        state.rules
    );

    // No preset bypass seeded: the catch-all tunnel route wins the inbound decision
    assert!(
        matches!(
            a.proxy_router().decide_inbound("127.0.0.1"),
            Outbound::Tunnel { .. }
        ),
        "dedicated tier routes the segment through the tunnel"
    );

    a.disconnect_all().await;
    c.stop().await;
    b.stop().await;
}
