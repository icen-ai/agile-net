//! P2 control-plane exposure and manageable-upstream discovery integration tests (handshake v2).
//!
//! Topology: node A (listener + relay_token.expose_control) ← node B (connector).
//! Assert: B auto-discovers A's control endpoint → admin client config gets manageable →
//! ticket chain exchanges for a scoped admin session (rules tier enforced) → toggle change audited.

use agile_net_core::config::NodeConfig;
use agile_net_core::config::node::{ConnectorConfig, ListenerConfig};
use agile_net_node::db::{Database, hash_password, sha256_hex};
use agile_net_node::service::{NodeServer, NodeServerOptions};

use std::time::Duration;

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("anet-p2-test-{}-{}", tag, uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Grab a free port (bind then release; test-env race is negligible).
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

const RELAY_TOKEN: &str = "psk_p2test_0000000000000000000000000000000000000";

/// Start upstream A: relay listener + exposed control plane (rules tier).
async fn start_upstream() -> (NodeServer, u16) {
    let dir = temp_dir("up");
    let relay_port = free_port();
    let config = NodeConfig {
        name: "node-root".into(),
        listener: Some(ListenerConfig {
            addr: format!("127.0.0.1:{relay_port}"),
            cert_path: dir.join("cert.pem").to_string_lossy().to_string(),
            key_path: dir.join("key.pem").to_string_lossy().to_string(),
            sni_hostname: "cdn.cloudflare.com".into(),
        }),
        ..Default::default()
    };
    let server = NodeServer::start_with(
        config,
        NodeServerOptions {
            db_path: Some(dir.join("a.db").to_string_lossy().to_string()),
            api_listen: Some("127.0.0.1:0".into()),
            public_host: Some("127.0.0.1".into()),
            skip_env_seed: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    // Expose control plane: rules tier
    let hash = sha256_hex(RELAY_TOKEN.as_bytes());
    server
        .db()
        .create_relay_token_with_quota(&hash, "psk_p2te****", "P2 测试下游", true, "rules", None, None)
        .unwrap();
    (server, relay_port)
}

/// Start downstream B: connector into A.
async fn start_downstream(relay_port: u16) -> NodeServer {
    let dir = temp_dir("down");
    let config = NodeConfig {
        name: "node-mid".into(),
        connectors: vec![ConnectorConfig {
            upstream_addr: format!("127.0.0.1:{relay_port}"),
            token: RELAY_TOKEN.into(),
            sni_hostname: "cdn.cloudflare.com".into(),
            advertise: Vec::new(),
            ca_cert_path: None,
            pinned_cert_path: None,
            insecure: true,
        }],
        ..Default::default()
    };
    NodeServer::start_with(
        config,
        NodeServerOptions {
            db_path: Some(dir.join("b.db").to_string_lossy().to_string()),
            api_listen: Some("127.0.0.1:0".into()),
            skip_env_seed: true,
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn handshake_v2_control_offer_and_manageable_discovery() {
    let (a, relay_port) = start_upstream().await;
    let b = start_downstream(relay_port).await;

    // 1. B auto-discovers A's control endpoint (connector handshake → registry sync ≤ 2s)
    let mut offer = None;
    for _ in 0..20 {
        if let Some(o) = b.runtime().manageable.iter().next().map(|i| i.clone()) {
            offer = Some(o);
            break;
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    let offer = offer.expect("B 应发现 A 暴露的控制端点");
    assert!(offer.exposed);
    assert_eq!(offer.node_name, "node-root");
    assert_eq!(offer.scope, "rules");
    assert_eq!(offer.api_host.as_deref(), Some("127.0.0.1"));
    assert_eq!(offer.api_port, a.api_addr().port());
    assert!(offer.ticket.starts_with("adt_"));

    // 1b. B dials A's control endpoint through the fan-out session (manageable stream opener,
    // the path the desktop server-role console forwarder uses); unknown upstreams miss
    assert!(
        b.connector_manager()
            .open_manageable_stream("no-such-node", "127.0.0.1", 1)
            .await
            .is_none()
    );
    let mut ch = b
        .connector_manager()
        .open_manageable_stream("node-root", "127.0.0.1", offer.api_port)
        .await
        .expect("fan-out connector should open a stream to the discovered upstream");
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    ch.write_all(b"GET /api/v1/admin/node/status HTTP/1.0\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(3), ch.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let head = String::from_utf8_lossy(&buf[..n]);
    assert!(
        head.starts_with("HTTP/1.1") || head.starts_with("HTTP/1.0"),
        "A's API answered through the fan-out session: {head}"
    );

    // 2. Relay ticket exchanges on A for an admin session (rules tier: GET ok, rule write ok, group write denied)
    let http = reqwest::Client::new();
    let base_a = format!("http://{}", a.api_addr());
    let r = http
        .post(format!("{base_a}/api/v1/auth/admin-bootstrap"))
        .json(&serde_json::json!({ "ticket": offer.ticket }))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "bootstrap: {}", r.status());
    let j: serde_json::Value = r.json().await.unwrap();
    assert_eq!(j["data"]["scope"].as_str(), Some("rules"));
    let jwt = j["data"]["access_token"].as_str().unwrap().to_string();

    let r = http
        .get(format!("{base_a}/api/v1/admin/node/status"))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "rules 档位应可读");
    let r = http
        .post(format!("{base_a}/api/v1/admin/rules"))
        .bearer_auth(&jwt)
        .json(&serde_json::json!({"type": "ip-cidr", "value": "10.77.0.0/16"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 201, "rules 档位应可写规则");
    let r = http
        .post(format!("{base_a}/api/v1/admin/groups"))
        .bearer_auth(&jwt)
        .json(&serde_json::json!({"name": "should-deny"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 403, "rules 档位应拒绝非规则写");

    // 3. Audit on A: relay exchange attribution
    let admin_token = {
        let r = http
            .post(format!("{base_a}/api/v1/auth/init"))
            .json(&serde_json::json!({"username": "admin", "password": "AdminPass123!"}))
            .send()
            .await
            .unwrap();
        assert!(r.status().is_success());
        let r = http
            .post(format!("{base_a}/api/v1/auth/login"))
            .json(&serde_json::json!({"username": "admin", "password": "AdminPass123!"}))
            .send()
            .await
            .unwrap();
        r.json::<serde_json::Value>().await.unwrap()["data"]["access_token"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let r = http
        .get(format!(
            "{base_a}/api/v1/admin/audit-logs?action=admin.session_via_relay"
        ))
        .bearer_auth(&admin_token)
        .send()
        .await
        .unwrap();
    let j: serde_json::Value = r.json().await.unwrap();
    let items = j["data"]["items"].as_array().unwrap();
    assert!(
        items.iter().any(|i| i["operator"]
            .as_str()
            .is_some_and(|o| o.starts_with("relay:psk_p2te****@"))),
        "relay 换取审计应归因令牌前缀与下游节点: {items:?}"
    );

    // 4. B's admin client: config carries manageable, console-ticket fetches upstream ticket
    let db_b = b.db();
    let gid = {
        let r = http
            .post(format!("http://{}/api/v1/auth/init", b.api_addr()))
            .json(&serde_json::json!({"username": "admin", "password": "AdminPass123!"}))
            .send()
            .await
            .unwrap();
        assert!(r.status().is_success());
        let r = http
            .post(format!("http://{}/api/v1/auth/login", b.api_addr()))
            .json(&serde_json::json!({"username": "admin", "password": "AdminPass123!"}))
            .send()
            .await
            .unwrap();
        let bt = r.json::<serde_json::Value>().await.unwrap()["data"]["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        let r = http
            .post(format!("http://{}/api/v1/admin/groups", b.api_addr()))
            .bearer_auth(&bt)
            .json(&serde_json::json!({"name": "ops"}))
            .send()
            .await
            .unwrap();
        r.json::<serde_json::Value>().await.unwrap()["data"]["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let pw = agile_net_node::db::generate_password();
    let acc = db_b
        .create_account_with_admin("carol", &hash_password(&pw).unwrap(), &gid, "", true)
        .unwrap();
    assert!(acc.admin_console);

    let r = http
        .post(format!("http://{}/api/v1/auth/login", b.api_addr()))
        .json(&serde_json::json!({"username": "carol", "password": pw}))
        .send()
        .await
        .unwrap();
    let ctoken = r.json::<serde_json::Value>().await.unwrap()["data"]["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let r = http
        .get(format!("http://{}/api/v1/client/config", b.api_addr()))
        .bearer_auth(&ctoken)
        .send()
        .await
        .unwrap();
    let j: serde_json::Value = r.json().await.unwrap();
    let manageable = j["data"]["manageable"].as_array().unwrap();
    assert!(
        manageable.iter().any(|m| m["node_name"] == "node-root"),
        "管理版客户端应自动发现可管理上游: {manageable:?}"
    );

    // console-ticket upstream: returns current handshake-v2 ticket
    let r = http
        .post(format!(
            "http://{}/api/v1/client/console-ticket",
            b.api_addr()
        ))
        .bearer_auth(&ctoken)
        .json(&serde_json::json!({"upstream": "node-root"}))
        .send()
        .await
        .unwrap();
    let j: serde_json::Value = r.json().await.unwrap();
    assert_eq!(j["code"].as_u64(), Some(0), "console-ticket: {j}");
    assert!(j["data"]["ticket"].as_str().unwrap().starts_with("adt_"));
    assert_eq!(j["data"]["scope"].as_str(), Some("rules"));

    b.stop().await;
    a.stop().await;
}

#[tokio::test]
async fn expose_control_toggle_audited() {
    let (a, _port) = start_upstream().await;
    let http = reqwest::Client::new();
    let base = format!("http://{}", a.api_addr());
    let r = http
        .post(format!("{base}/api/v1/auth/init"))
        .json(&serde_json::json!({"username": "admin", "password": "AdminPass123!"}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let r = http
        .post(format!("{base}/api/v1/auth/login"))
        .json(&serde_json::json!({"username": "admin", "password": "AdminPass123!"}))
        .send()
        .await
        .unwrap();
    let token = r.json::<serde_json::Value>().await.unwrap()["data"]["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Find the P2 test token id
    let r = http
        .get(format!("{base}/api/v1/admin/node/relay-tokens"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let j: serde_json::Value = r.json().await.unwrap();
    let items = j["data"]["items"].as_array().unwrap();
    let t = items
        .iter()
        .find(|t| t["token_prefix"] == "psk_p2te****")
        .unwrap();
    assert_eq!(t["expose_control"].as_bool(), Some(true));
    assert_eq!(t["control_scope"].as_str(), Some("rules"));
    let id = t["id"].as_str().unwrap();

    // Disable exposure → audit relay_token.expose_control
    let r = http
        .put(format!("{base}/api/v1/admin/node/relay-tokens/{id}"))
        .bearer_auth(&token)
        .json(&serde_json::json!({"expose_control": false, "control_scope": "rules"}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let r = http
        .get(format!(
            "{base}/api/v1/admin/audit-logs?action=relay_token.expose_control"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let j: serde_json::Value = r.json().await.unwrap();
    let items = j["data"]["items"].as_array().unwrap();
    assert!(
        items
            .iter()
            .any(|i| i["detail"].as_str().is_some_and(|d| d.contains("off"))),
        "开关变更应落审计: {items:?}"
    );

    a.stop().await;
}

/// Verify the in-memory migration path also has v3 columns (idempotent migration).
#[tokio::test]
async fn migration_v3_columns_present() {
    let db = Database::in_memory().unwrap();
    let rec = db
        .create_relay_token_with_quota(&sha256_hex(b"psk_x"), "psk_x***", "", true, "ro", None, None)
        .unwrap();
    assert!(rec.expose_control);
    assert_eq!(rec.control_scope, "ro");
    let (_, expose, scope) = db
        .get_relay_token_control(&sha256_hex(b"psk_x"))
        .unwrap()
        .unwrap();
    assert!(expose);
    assert_eq!(scope, "ro");
    db.update_relay_token_control(&rec.id, false, "full")
        .unwrap();
    let (_, expose, scope) = db
        .get_relay_token_control(&sha256_hex(b"psk_x"))
        .unwrap()
        .unwrap();
    assert!(!expose);
    assert_eq!(scope, "full");
}
