//! M8 安全加固测试：审计、密码哈希、密钥持久化、令牌生成

use agile_net_node::auth::jwt::JwtService;
use agile_net_node::db::{Database, generate_password, generate_relay_token, generate_secret_hex, hash_password, sha256_hex, verify_password};
use std::sync::Arc;

/// 审计日志写入与读取（含 detail 字段）
#[tokio::test]
async fn audit_log_records() {
    let db = Database::in_memory().unwrap();

    db.record_audit_log(None, "admin", "admin.login", None, None, Some("127.0.0.1"))
        .unwrap();
    db.record_audit_log(
        Some("admin-id"),
        "admin",
        "rule.create",
        Some("rule-id"),
        Some(r#"{"value":"10.0.0.0/8"}"#),
        Some("127.0.0.1"),
    )
    .unwrap();

    let (logs, total) = db.list_audit_logs(1, 20, None).unwrap();
    assert_eq!(total, 2);
    assert_eq!(logs[0].action, "rule.create");
    assert_eq!(logs[1].action, "admin.login");
    assert!(logs[0].detail.as_ref().unwrap().contains("10.0.0.0/8"));

    // 按 action 过滤
    let (logs, total) = db.list_audit_logs(1, 20, Some("admin.login")).unwrap();
    assert_eq!(total, 1);
    assert_eq!(logs.len(), 1);
}

/// Argon2id 密码 Hash 与校验
#[test]
fn password_hashing_security() {
    let raw_pass = "MyStrongP@ssw0rd!";
    let hash = hash_password(raw_pass).unwrap();

    assert!(hash.starts_with("$argon2id$"));
    assert!(verify_password(raw_pass, &hash).unwrap());
    assert!(!verify_password("WrongP@ss", &hash).unwrap());
}

/// 强密码生成：sk- 前缀、51 字符、高熵、每次唯一
#[test]
fn strong_password_generation() {
    let p1 = generate_password();
    let p2 = generate_password();
    assert!(p1.starts_with("sk-"));
    assert_eq!(p1.len(), 51);
    assert_ne!(p1, p2);
    assert!(p1.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));

    let t = generate_relay_token();
    assert!(t.starts_with("psk_"));
    assert_eq!(t.len(), 52);

    let s = generate_secret_hex();
    assert_eq!(s.len(), 64);
    assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
}

/// JWT 密钥从数据库持久化装载（同库同密）
#[test]
fn jwt_secret_persisted() {
    let db = Database::in_memory().unwrap();
    let s1 = Arc::new(JwtService::load_or_create(db.clone()).unwrap());
    let s2 = Arc::new(JwtService::load_or_create(db.clone()).unwrap());

    // 同一数据库装载的服务签发的 token 可以互相验证
    let tokens = s1.issue("uid-1", "admin", "admin").unwrap();
    let claims = s2.verify(&tokens.access_token).unwrap();
    assert_eq!(claims.sub, "uid-1");
    assert_eq!(claims.role, "admin");
    assert_eq!(claims.typ, "access");
}

/// Refresh token 轮换与吊销
#[test]
fn refresh_token_rotation_and_revocation() {
    let db = Database::in_memory().unwrap();
    let jwt = JwtService::load_or_create(db.clone()).unwrap();

    let issued = jwt.issue("uid-2", "admin", "admin").unwrap();
    // client 角色才有 tunnel_token
    assert!(issued.tunnel_token.is_none());

    // 刷新成功且旧 refresh 失效
    let (_claims, rotated) = jwt.refresh(&issued.refresh_token).unwrap();
    assert!(jwt.refresh(&issued.refresh_token).is_err());

    // 吊销全部 → 无法刷新
    jwt.revoke_all("uid-2").unwrap();
    assert!(jwt.refresh(&rotated.refresh_token).is_err());
}

/// client 角色签发时轮换 tunnel_token 并落库哈希
#[test]
fn client_tunnel_token_issued() {
    let db = Database::in_memory().unwrap();
    let gid = db.create_group("g1", "").unwrap().id;
    let account = db
        .create_account("user1", &hash_password("x").unwrap(), &gid, "")
        .unwrap();

    let jwt = JwtService::load_or_create(db.clone()).unwrap();
    let issued = jwt.issue(&account.id, "user1", "client").unwrap();
    let tunnel_token = issued.tunnel_token.expect("client should get tunnel token");
    assert!(tunnel_token.starts_with("tun_"));

    // 数据面可按哈希找回账号
    let found = db
        .find_account_by_tunnel_hash(&sha256_hex(tunnel_token.as_bytes()))
        .unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().username, "user1");
}
