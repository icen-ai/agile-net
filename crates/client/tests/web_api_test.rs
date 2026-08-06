//! Client control-plane Web API tests: auth / rate limiting / envelope / command mapping / second confirmation.

use agile_net_client::api::{ClientWebAuth, SpaAssets, start_client_api};
use agile_net_client::{AgileNetClient, Credential, CredentialStore};
use std::sync::{Arc, Mutex};

struct MockAuth {
    password_set: Mutex<bool>,
    audits: Mutex<Vec<String>>,
}

impl MockAuth {
    fn new(has_pw: bool) -> Self {
        Self {
            password_set: Mutex::new(has_pw),
            audits: Mutex::new(Vec::new()),
        }
    }
}

impl ClientWebAuth for MockAuth {
    fn has_password(&self) -> bool {
        *self.password_set.lock().unwrap()
    }
    fn set_password(&self, password: &str) -> Result<(), String> {
        if password.len() < 10 {
            return Err("管理密码至少 10 位".into());
        }
        *self.password_set.lock().unwrap() = true;
        Ok(())
    }
    fn verify_password(&self, password: &str) -> bool {
        *self.password_set.lock().unwrap() && password == "Test123456"
    }
    fn jwt_secret(&self) -> String {
        "test-secret-key".into()
    }
    fn audit(&self, action: &str, _detail: serde_json::Value) {
        self.audits.lock().unwrap().push(action.to_string());
    }
}

const PW: &str = "Test123456";

async fn boot(
    has_pw: bool,
) -> (
    String,
    Arc<MockAuth>,
    agile_net_client::api::ClientApiHandle,
) {
    let auth = Arc::new(MockAuth::new(has_pw));
    let handle = start_client_api(
        AgileNetClient::new(),
        None,
        auth.clone(),
        "127.0.0.1:0".parse().unwrap(),
        None,
    )
    .await
    .unwrap();
    let base = format!("http://{}", handle.addr());
    (base, auth, handle)
}

#[tokio::test]
async fn auth_init_login_and_envelope() {
    let (base, _auth, server) = boot(false).await;
    let http = reqwest::Client::new();

    // Login with no password set → 400
    let r = http
        .post(format!("{base}/api/v1/auth/login"))
        .json(&serde_json::json!({"password": PW}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);

    // Init (short password → 40001)
    let r = http
        .post(format!("{base}/api/v1/auth/init"))
        .json(&serde_json::json!({"password": "short"}))
        .send()
        .await
        .unwrap();
    let j: serde_json::Value = r.json().await.unwrap();
    assert_eq!(j["code"].as_u64(), Some(40001));

    // Init succeeds → repeat init rejected
    let r = http
        .post(format!("{base}/api/v1/auth/init"))
        .json(&serde_json::json!({"password": PW}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let r = http
        .post(format!("{base}/api/v1/auth/init"))
        .json(&serde_json::json!({"password": PW}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);

    // Wrong password → 40100
    let r = http
        .post(format!("{base}/api/v1/auth/login"))
        .json(&serde_json::json!({"password": "wrong-password"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);
    let j: serde_json::Value = r.json().await.unwrap();
    assert_eq!(j["code"].as_u64(), Some(40100));

    // Correct password → token
    let r = http
        .post(format!("{base}/api/v1/auth/login"))
        .json(&serde_json::json!({"password": PW}))
        .send()
        .await
        .unwrap();
    let j: serde_json::Value = r.json().await.unwrap();
    assert_eq!(j["code"].as_u64(), Some(0));
    let token = j["data"]["access_token"].as_str().unwrap().to_string();

    // Access without token → 401
    let r = http
        .get(format!("{base}/api/v1/proxy/status"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);

    // With token → {code:0,data}
    let r = http
        .get(format!("{base}/api/v1/proxy/status"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let j: serde_json::Value = r.json().await.unwrap();
    assert_eq!(j["code"].as_u64(), Some(0));
    assert_eq!(j["data"]["running"].as_bool(), Some(false));

    server.stop().await;
}

#[tokio::test]
async fn login_rate_limit_locks() {
    let (base, _auth, server) = boot(true).await;
    let http = reqwest::Client::new();
    let mut last_code = 0u64;
    for _ in 0..6 {
        let r = http
            .post(format!("{base}/api/v1/auth/login"))
            .json(&serde_json::json!({"password": "wrong-password"}))
            .send()
            .await
            .unwrap();
        last_code = r.json::<serde_json::Value>().await.unwrap()["code"]
            .as_u64()
            .unwrap();
    }
    assert_eq!(last_code, 42900, "连续失败应触发限流/锁定");
    server.stop().await;
}

#[tokio::test]
async fn export_requires_confirm() {
    let store = CredentialStore::open_temp().unwrap();
    store
        .save(
            "u1@delegated:127.0.0.1:54430",
            &Credential {
                addr: "127.0.0.1:54430".into(),
                label: "u1".into(),
                token: "psk_test".into(),
                name: None,
                insecure: false,
                pinned_fingerprint: None,
                entries: Vec::new(),
                entry_fps: Vec::new(),
                en: None,
                emode: None,
                eadmin: false,
            },
        )
        .await;
    let auth = Arc::new(MockAuth::new(true));
    let handle = start_client_api(
        AgileNetClient::new(),
        Some(Arc::new(store)),
        auth.clone(),
        "127.0.0.1:0".parse().unwrap(),
        None,
    )
    .await
    .unwrap();
    let base = format!("http://{}", handle.addr());
    let http = reqwest::Client::new();
    let r = http
        .post(format!("{base}/api/v1/auth/login"))
        .json(&serde_json::json!({"password": PW}))
        .send()
        .await
        .unwrap();
    let token = r.json::<serde_json::Value>().await.unwrap()["data"]["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    // No second confirmation → 409 + 40001
    let r = http
        .get(format!(
            "{base}/api/v1/credentials/export?key=u1@delegated:127.0.0.1:54430"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 409);
    let j: serde_json::Value = r.json().await.unwrap();
    assert_eq!(j["code"].as_u64(), Some(40001));

    // Confirmed export → connect URL + audit
    let r = http
        .get(format!(
            "{base}/api/v1/credentials/export?confirm=true&key=u1@delegated:127.0.0.1:54430"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let j: serde_json::Value = r.json().await.unwrap();
    assert_eq!(j["code"].as_u64(), Some(0));
    let url = j["data"].as_str().unwrap();
    assert!(
        url.starts_with("anet://connect?"),
        "导出应为接入链接: {url}"
    );
    assert!(url.contains("account=d%3Au1") || url.contains("account=d:u1"));
    assert!(
        auth.audits
            .lock()
            .unwrap()
            .iter()
            .any(|a| a == "web.credential_export"),
        "凭据导出应落审计"
    );

    handle.stop().await;
}

#[tokio::test]
async fn paused_rules_and_parse_url() {
    let (base, _auth, server) = boot(true).await;
    let http = reqwest::Client::new();
    let r = http
        .post(format!("{base}/api/v1/auth/login"))
        .json(&serde_json::json!({"password": PW}))
        .send()
        .await
        .unwrap();
    let token = r.json::<serde_json::Value>().await.unwrap()["data"]["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Pause/query rules
    let r = http
        .put(format!("{base}/api/v1/nodes/paused-rules"))
        .bearer_auth(&token)
        .json(&serde_json::json!({"node_id": "n1@a:1", "keys": ["host:example.com"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.json::<serde_json::Value>().await.unwrap()["code"].as_u64(),
        Some(0)
    );
    let r = http
        .get(format!("{base}/api/v1/nodes/paused-rules?node_id=n1@a:1"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let j: serde_json::Value = r.json().await.unwrap();
    assert_eq!(j["data"][0].as_str(), Some("host:example.com"));

    // Parse a delegated connect URL
    let r = http
        .post(format!("{base}/api/v1/parse-connect-url"))
        .bearer_auth(&token)
        .json(&serde_json::json!({"url": "anet://connect?server=example.com&port=54430&account=d:u&password=psk_x&fp=ab12"}))
        .send()
        .await
        .unwrap();
    let j: serde_json::Value = r.json().await.unwrap();
    assert_eq!(j["data"]["addr"].as_str(), Some("example.com:54430"));
    assert_eq!(j["data"]["label"].as_str(), Some("u"));
    assert_eq!(j["data"]["token"].as_str(), Some("psk_x"));
    assert_eq!(j["data"]["pinned_fingerprint"].as_str(), Some("ab12"));

    server.stop().await;
}

#[tokio::test]
async fn spa_assets_served() {
    let auth = Arc::new(MockAuth::new(true));
    let handle = start_client_api(
        AgileNetClient::new(),
        None,
        auth,
        "127.0.0.1:0".parse().unwrap(),
        Some(SpaAssets {
            index: "<html>spa</html>",
            app_js: "app",
            icons_js: "icons",
            agchart_js: "agchart",
            app_core_js: "core",
            app_views_js: "views",
            app_subscription_js: "subscription",
            app_hero_js: "hero",
            app_logs_js: "logs",
            app_settings_js: "settings",
            style_css: "css",
            tokens_css: "tokens",
            components_css: "components",
        }),
    )
    .await
    .unwrap();
    let base = format!("http://{}", handle.addr());
    let http = reqwest::Client::new();
    let r = http.get(format!("{base}/")).send().await.unwrap();
    assert!(r.status().is_success());
    assert_eq!(r.text().await.unwrap(), "<html>spa</html>");
    let r = http.get(format!("{base}/app.js")).send().await.unwrap();
    assert_eq!(r.text().await.unwrap(), "app");
    let r = http.get(format!("{base}/tokens.css")).send().await.unwrap();
    assert_eq!(r.text().await.unwrap(), "tokens");
    let r = http
        .get(format!("{base}/components.css"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.text().await.unwrap(), "components");
    let r = http.get(format!("{base}/agchart.js")).send().await.unwrap();
    assert_eq!(r.text().await.unwrap(), "agchart");
    let r = http
        .get(format!("{base}/app-core.js"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.text().await.unwrap(), "core");
    let r = http
        .get(format!("{base}/app-settings.js"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.text().await.unwrap(), "settings");
    handle.stop().await;
}
