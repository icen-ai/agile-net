//! M8 里程碑 安全加固与生产化 集成与单元测试

use agile_net_node::db::Database;

/// AT-M8-01：审计日志写入与读取
#[tokio::test]
async fn audit_log_records() {
    let db = Database::in_memory().unwrap();

    // 记录两条日志
    db.record_audit_log("admin", "login", "auth", "127.0.0.1")
        .unwrap();
    db.record_audit_log("admin", "rule.create", "10.0.0.0/8", "127.0.0.1")
        .unwrap();

    let logs = db.list_audit_logs().unwrap();
    assert_eq!(logs.len(), 2);
    assert_eq!(logs[0]["action"], "rule.create");
    assert_eq!(logs[1]["action"], "login");
}

/// AT-M8-02：Argon2 密码 Hash 与校验安全性
#[test]
fn password_hashing_security() {
    let raw_pass = "MyStrongP@ssw0rd!";
    let hash = agile_net_node::db::hash_password(raw_pass).unwrap();

    assert!(agile_net_node::db::verify_password(raw_pass, &hash).unwrap());
    assert!(!agile_net_node::db::verify_password("WrongP@ss", &hash).unwrap());
}
