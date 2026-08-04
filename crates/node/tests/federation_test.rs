//! Federation P1 end-to-end test (acceptance of docs/todo/federation.md §4-P1):
//! resource owner C pushes policy groups with its fan-out handshake; upstream B pools them
//! source-tagged; the B admin adopts "C's git group" in one click and grants it to account A —
//! without C ever touching an account on B.

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
    c.db().set_group_rules(&gid, &[rid, rid2]).expect("bind");
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
    assert_eq!(adopted["name"].as_str().unwrap(), format!("git@{node_id}"));
    assert_eq!(adopted["rule_count"].as_u64(), Some(2));
    let adopted_gid = adopted["id"].as_str().unwrap().to_string();

    // Adoption is idempotent-friendly: a second adopt gets a deduped name and reuses rules
    let resp = http
        .post(format!("{b_base}/api/v1/admin/federation/adopt"))
        .bearer_auth(&b_token)
        .json(&serde_json::json!({ "node_id": node_id, "group": "git" }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"].as_u64(), Some(0));
    assert_eq!(body["data"]["name"].as_str().unwrap(), format!("git@{node_id}·2"));
    assert_eq!(body["data"]["reused"].as_u64(), Some(2));

    // Grant to consumer A: create an account on B bound to the adopted group
    let resp = http
        .post(format!("{b_base}/api/v1/admin/accounts"))
        .bearer_auth(&b_token)
        .json(&serde_json::json!({ "username": "consumer-a", "group_id": adopted_gid, "remark": "" }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(status, 201, "create account: {body}");
    assert!(
        body["data"]["connect_url"]
            .as_str()
            .unwrap()
            .starts_with("anet://connect?")
    );

    // The adopted ACL actually drives fan-in auth: A's tunnel rules resolve to C's targets.
    // (Data-plane reachability of C's intra-net is covered by the route-convergence chain tests.)
    let rules = b.db().rules_of_account(body["data"]["id"].as_str().unwrap());
    let values: Vec<String> = rules
        .unwrap()
        .into_iter()
        .map(|r| r.value)
        .collect();
    assert!(values.contains(&"git.internal".to_string()));
    assert!(values.contains(&"10.12.0.0/16".to_string()));

    c.stop().await;
    b.stop().await;
}
