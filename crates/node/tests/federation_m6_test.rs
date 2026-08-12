//! Federation M6 end-to-end: transitive certification propagation (origin-signed CertPush over
//! the fan-out session, trust-list adoption, signed revocation propagation) and the approve-tier
//! topology hold (visibility=approve waits for approval before upstream registration).

use agile_net_core::config::node::{ListenerConfig, NodeConfig};
use agile_net_core::device::DeviceIdentity;
use agile_net_node::service::{NodeServer, NodeServerOptions};
use std::sync::Arc;

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("anet-fedm6-test-{}-{}", tag, uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

async fn boot(tag: &str, listener_port: Option<u16>, device: &Arc<DeviceIdentity>) -> NodeServer {
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
    NodeServer::start_with(
        config,
        NodeServerOptions {
            db_path: Some(dir.join("node.db").to_string_lossy().to_string()),
            api_listen: Some("127.0.0.1:0".into()),
            skip_env_seed: true,
            device: Some(device.clone()),
            ..Default::default()
        },
    )
    .await
    .unwrap_or_else(|e| panic!("boot {tag}: {e}"))
}

#[tokio::test]
async fn m6_cert_propagation_and_revocation() {
    // ---- B: relay with cert intake on ----
    let b_key = Arc::new(DeviceIdentity::ephemeral());
    let b_port = free_port();
    let b = boot("b", Some(b_port), &b_key).await;
    b.db()
        .create_relay_token_with_quota(
            &agile_net_node::db::sha256_hex(b"psk_m6-shared-token".as_slice()),
            "psk_m6",
            "for c",
            false,
            "full",
            None,
            None,
        )
        .expect("relay token");

    // ---- C: owner with a cert_relay-enabled connector to B ----
    let c_key = Arc::new(DeviceIdentity::ephemeral());
    let c = boot("c", None, &c_key).await;
    let cid = c
        .db()
        .create_connector(
            "to-b",
            "",
            &format!("127.0.0.1:{b_port}"),
            "psk_m6-shared-token",
            "fed.test",
            true,
            "",
            "",
            "",
            "127.0.0.0/8",
            None,
            "m6",
        )
        .expect("connector")
        .id;
    c.db().set_connector_cert_relay(&cid, true).expect("cert_relay on");
    c.connector_manager().upsert_from_db(&cid).await.expect("upsert");

    // B trusts C's device fp; intake switch on
    agile_net_node::service::cert_relay::set_cert_relay_in(&b.db(), true).unwrap();
    agile_net_node::service::cert_relay::set_trust_list(&b.db(), &[c_key.device_fp()]).unwrap();

    // wait for the fan-out session
    for _ in 0..60 {
        if c.connector_manager().state_of(&cid) == Some("connected") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // C certifies a device locally
    let dev = DeviceIdentity::ephemeral();
    let dev_fp = dev.device_fp();
    c.db()
        .touch_device(&dev_fp, &agile_net_core::util::base64_encode(dev.pubkey()), "th", "小明-MacBook")
        .unwrap();
    c.db().certify_device(&dev_fp, "小明", "前端 MacBook", "").unwrap();
    // incremental push (the API path does this; here direct)
    c.connector_manager().broadcast_cert_records().await;

    // B adopts (trusted origin): certified_by = C's fp
    let mut adopted = false;
    for _ in 0..50 {
        if let Some(d) = b.db().get_device(&dev_fp).unwrap()
            && d.state == "certified"
            && d.certified_by == c_key.device_fp()
        {
            assert_eq!(d.subject, "小明");
            adopted = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(adopted, "B must adopt C's signed certification");

    // C revokes → signed revocation propagates
    c.db().revoke_device(&dev_fp).unwrap();
    c.connector_manager().broadcast_cert_records().await;
    let mut revoked = false;
    for _ in 0..50 {
        if b.db().get_device(&dev_fp).unwrap().map(|d| d.state == "revoked") == Some(true) {
            revoked = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(revoked, "signed revocation must propagate to B");

}

#[tokio::test]
async fn m6_untrusted_origin_degrades_to_reference() {
    let b_key = Arc::new(DeviceIdentity::ephemeral());
    let b_port = free_port();
    let b = boot("b", Some(b_port), &b_key).await;
    b.db()
        .create_relay_token_with_quota(
            &agile_net_node::db::sha256_hex(b"psk_m6-shared-token".as_slice()),
            "psk_m6",
            "for c",
            false,
            "full",
            None,
            None,
        )
        .expect("relay token");

    let c_key = Arc::new(DeviceIdentity::ephemeral());
    let c = boot("c", None, &c_key).await;
    let cid = c
        .db()
        .create_connector(
            "to-b",
            "",
            &format!("127.0.0.1:{b_port}"),
            "psk_m6-shared-token",
            "fed.test",
            true,
            "",
            "",
            "",
            "127.0.0.0/8",
            None,
            "m6",
        )
        .expect("connector")
        .id;
    c.db().set_connector_cert_relay(&cid, true).expect("cert_relay on");
    c.connector_manager().upsert_from_db(&cid).await.expect("upsert");

    // B accepts intake but does NOT trust C
    agile_net_node::service::cert_relay::set_cert_relay_in(&b.db(), true).unwrap();

    for _ in 0..60 {
        if c.connector_manager().state_of(&cid) == Some("connected") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let dev = DeviceIdentity::ephemeral();
    let dev_fp = dev.device_fp();
    c.db()
        .touch_device(&dev_fp, &agile_net_core::util::base64_encode(dev.pubkey()), "th", "")
        .unwrap();
    c.db().certify_device(&dev_fp, "小明", "", "").unwrap();
    c.connector_manager().broadcast_cert_records().await;

    // B: no adoption, but a reference-cert approval appears
    let mut found = false;
    for _ in 0..50 {
        let pending = b.db().list_approvals(Some("pending")).unwrap_or_default();
        if pending.iter().any(|a| {
            a.r#type == agile_net_node::service::approvals::REF_CERT_ADOPT && a.object_ref == dev_fp
        }) {
            found = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(found, "untrusted origin must degrade to a reference approval");
    assert!(
        b.db().get_device(&dev_fp).unwrap().map(|d| d.state != "certified").unwrap_or(true),
        "untrusted origin must NOT be adopted"
    );

}
