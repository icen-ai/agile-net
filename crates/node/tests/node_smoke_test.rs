//! 节点二进制冒烟测试：以真实进程启动 agile-net-node（listener + API + env 种子），
//! 验证 CryptoProvider 安装、env 预置、API 登录与 relay 数据面认证。

use agile_net_core::relay::RelayConnector;
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct NodeGuard(Child);
impl Drop for NodeGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn node_binary_smoke() {
    let api_port = free_port();
    let relay_port = free_port();
    let tmp = std::env::temp_dir().join(format!("anet-smoke-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp).unwrap();

    let config = format!(
        r#"
name = "smoke-node"
db_path = "{db}"

[api]
addr = "127.0.0.1:{api_port}"

[listener]
addr = "127.0.0.1:{relay_port}"
cert_path = "{certs}/cert.pem"
key_path = "{certs}/key.pem"
"#,
        db = tmp.join("smoke.db").to_string_lossy().replace('\\', "/"),
        api_port = api_port,
        relay_port = relay_port,
        certs = tmp.join("certs").to_string_lossy().replace('\\', "/"),
    );
    let config_path = tmp.join("node.toml");
    std::fs::write(&config_path, &config).unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_agile-net-node"))
        .arg(&config_path)
        .env("AGILE_ADMIN_PASSWORD", "SmokeTest123!")
        .env("AGILE_RELAY_TOKENS", "psk_smoketoken_00000000000000000000000000000000")
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agile-net-node");
    let mut _guard = NodeGuard(child);

    // 等待 API 就绪
    let client = reqwest::Client::new();
    let mut api_up = false;
    for _ in 0..60 {
        if let Ok(r) = client
            .get(format!("http://127.0.0.1:{api_port}/api/v1/admin/node/status"))
            .send()
            .await
        {
            if r.status() == reqwest::StatusCode::UNAUTHORIZED {
                api_up = true; // 401 说明 API 已在服务（只是未认证）
                break;
            }
        }
        if _guard.0.try_wait().unwrap().is_some() {
            panic!("node process exited prematurely");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(api_up, "API 未在 30s 内就绪");

    // 管理员登录（env 预置）
    let resp = client
        .post(format!("http://127.0.0.1:{api_port}/api/v1/auth/login"))
        .json(&serde_json::json!({"username":"admin","password":"SmokeTest123!"}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "env 预置管理员登录失败");

    // relay 数据面认证（env 预置 token）
    let relay_addr: SocketAddr = format!("127.0.0.1:{relay_port}").parse().unwrap();
    let connector = RelayConnector::new(
        relay_addr,
        "smoke-down",
        "psk_smoketoken_00000000000000000000000000000000",
    )
    .unwrap();
    connector.connect().await.unwrap();
    assert!(connector.is_connected());

    // 错误 token 被拒
    let bad = RelayConnector::new(relay_addr, "smoke-evil", "psk_wrong").unwrap();
    assert!(bad.connect().await.is_err());

    connector.disconnect().await;
    let _ = std::fs::remove_dir_all(&tmp);
}
