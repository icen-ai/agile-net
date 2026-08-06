//! M8 security hardening tests: audit, password hashing, secret persistence, token generation

use agile_net_node::auth::jwt::JwtService;
use agile_net_node::db::{
    Database, generate_relay_token, generate_secret_hex, hash_password, verify_password,
};
use std::sync::Arc;

/// Audit log write and read (with detail field)
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

    // filter by action
    let (logs, total) = db.list_audit_logs(1, 20, Some("admin.login")).unwrap();
    assert_eq!(total, 1);
    assert_eq!(logs.len(), 1);
}

/// Argon2id password hashing and verification
#[test]
fn password_hashing_security() {
    let raw_pass = "MyStrongP@ssw0rd!";
    let hash = hash_password(raw_pass).unwrap();

    assert!(hash.starts_with("$argon2id$"));
    assert!(verify_password(raw_pass, &hash).unwrap());
    assert!(!verify_password("WrongP@ss", &hash).unwrap());
}

/// Strong secret generation: relay token prefix/length, hex secret entropy
#[test]
fn strong_secret_generation() {
    let t1 = generate_relay_token();
    let t2 = generate_relay_token();
    assert!(t1.starts_with("psk_"));
    assert_eq!(t1.len(), 52);
    assert_ne!(t1, t2);

    let s = generate_secret_hex();
    assert_eq!(s.len(), 64);
    assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
}

/// JWT secret loaded from database persistence (same db, same secret)
#[test]
fn jwt_secret_persisted() {
    let db = Database::in_memory().unwrap();
    let s1 = Arc::new(JwtService::load_or_create(db.clone()).unwrap());
    let s2 = Arc::new(JwtService::load_or_create(db.clone()).unwrap());

    // tokens issued by services loaded from the same database verify each other
    let tokens = s1.issue("uid-1", "admin", "admin").unwrap();
    let claims = s2.verify(&tokens.access_token).unwrap();
    assert_eq!(claims.sub, "uid-1");
    assert_eq!(claims.role, "admin");
    assert_eq!(claims.typ, "access");
}

/// Refresh token rotation and revocation
#[test]
fn refresh_token_rotation_and_revocation() {
    let db = Database::in_memory().unwrap();
    let jwt = JwtService::load_or_create(db.clone()).unwrap();

    let issued = jwt.issue("uid-2", "admin", "admin").unwrap();

    // refresh succeeds and the old refresh token is invalidated
    let (_claims, rotated) = jwt.refresh(&issued.refresh_token).unwrap();
    assert!(jwt.refresh(&issued.refresh_token).is_err());

    // revoke all → refresh no longer possible
    jwt.revoke_all("uid-2").unwrap();
    assert!(jwt.refresh(&rotated.refresh_token).is_err());
}
