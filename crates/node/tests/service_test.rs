//! NodeServer 装配根集成测试：start → API 可用 → stop 释放端口。

use agile_net_core::config::NodeConfig;
use agile_net_node::service::{NodeServer, NodeServerOptions};

fn temp_db_path(tag: &str) -> String {
    let dir = std::env::temp_dir().join(format!("anet-svc-test-{}-{}", tag, uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("node.db").to_string_lossy().to_string()
}

#[tokio::test]
async fn node_server_start_serve_stop() {
    let config = NodeConfig::default();
    let server = NodeServer::start_with(
        config,
        NodeServerOptions {
            db_path: Some(temp_db_path("basic")),
            api_listen: Some("127.0.0.1:0".into()),
            skip_env_seed: true,
            ..Default::default()
        },
    )
    .await
    .expect("start node server");

    let addr = server.api_addr();
    assert_ne!(addr.port(), 0, "动态端口应回填实际值");
    assert_eq!(addr.ip().to_string(), "127.0.0.1");

    let base = format!("http://{addr}");
    let http = reqwest::Client::new();

    // Web 后台 SPA 可访问
    let resp = http.get(format!("{base}/")).send().await.unwrap();
    assert!(
        resp.status().is_success(),
        "SPA 应可访问: {}",
        resp.status()
    );

    // 首开初始化管理员 → 登录 → 管理接口可用
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
    assert!(resp.status().is_success(), "login: {}", resp.status());
    let body: serde_json::Value = resp.json().await.unwrap();
    let token = body["data"]["access_token"].as_str().unwrap().to_string();

    let resp = http
        .get(format!("{base}/api/v1/admin/node/status"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "status: {}", resp.status());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["code"].as_u64(),
        Some(0),
        "API 信封应保持 {{code,data}} 约定"
    );

    server.stop().await;

    // 停止后端口应释放
    let after = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        tokio::net::TcpStream::connect(addr),
    )
    .await;
    assert!(
        after.is_err() || after.unwrap().is_err(),
        "stop 后 API 端口应不再接受连接"
    );
}

#[tokio::test]
async fn node_server_restart_same_db() {
    // 同一数据库可重复 start/stop（GUI 服务端角色开关路径）
    let db_path = temp_db_path("restart");
    for round in 0..2 {
        let server = NodeServer::start_with(
            NodeConfig::default(),
            NodeServerOptions {
                db_path: Some(db_path.clone()),
                api_listen: Some("127.0.0.1:0".into()),
                skip_env_seed: true,
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|e| panic!("round {round} start: {e}"));
        assert!(server.db().get_config("node_name").unwrap().is_some());
        server.stop().await;
    }
}
