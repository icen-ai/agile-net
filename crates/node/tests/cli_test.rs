//! CLI 命令解析与集成测试

use agile_net_node::cli::{Cli, Commands, RuleSub, TokenSub};
use clap::Parser;

#[test]
fn cli_rule_add_parsing() {
    let cli = Cli::parse_from([
        "anet",
        "rule",
        "add",
        "--type",
        "ip-cidr",
        "--value",
        "10.0.0.0/8",
        "--remark",
        "办公网",
    ]);
    match cli.command {
        Commands::Rule(args) => match args.command {
            RuleSub::Add(a) => {
                assert_eq!(a.rule_type, "ip-cidr");
                assert_eq!(a.value, "10.0.0.0/8");
                assert_eq!(a.remark.as_deref(), Some("办公网"));
            }
            _ => panic!("expected rule add"),
        },
        _ => panic!("expected rule command"),
    }
}

#[test]
fn cli_status_parsing() {
    let cli = Cli::parse_from(["anet", "status"]);
    assert!(matches!(cli.command, Commands::Status));
}

#[test]
fn cli_global_flags() {
    let cli = Cli::parse_from(["anet", "--api", "http://1.2.3.4:59090", "--json", "status"]);
    assert_eq!(cli.api.as_deref(), Some("http://1.2.3.4:59090"));
    assert!(cli.json);
}

#[test]
fn cli_token_add_parsing() {
    let cli = Cli::parse_from(["anet", "token", "add", "--remark", "分公司"]);
    match cli.command {
        Commands::Token(args) => match args.command {
            TokenSub::Add(a) => assert_eq!(a.remark.as_deref(), Some("分公司")),
            _ => panic!("expected token add"),
        },
        _ => panic!("expected token command"),
    }
}

#[test]
fn cli_rule_delete_force_parsing() {
    let cli = Cli::parse_from(["anet", "rule", "delete", "abc123", "--force"]);
    match cli.command {
        Commands::Rule(args) => match args.command {
            RuleSub::Delete(d) => {
                assert_eq!(d.id, "abc123");
                assert!(d.force);
            }
            _ => panic!("expected rule delete"),
        },
        _ => panic!("expected rule command"),
    }
}

/// CLI 登录 → 全命令链路（对真实节点 API）
#[tokio::test]
async fn cli_full_workflow_against_live_api() {
    use agile_net_node::api::{ApiState, NodeRuntime, create_app};
    use agile_net_node::auth::jwt::JwtService;
    use agile_net_node::db::{Database, hash_password};
    use agile_net_node::logs::LogBuffer;
    use std::sync::Arc;
    use std::time::Instant;

    // 启动真实 API
    let db = Database::in_memory().unwrap();
    db.create_admin("admin", &hash_password("AdminPass123").unwrap())
        .unwrap();
    let jwt = Arc::new(JwtService::load_or_create(db.clone()).unwrap());
    let runtime = Arc::new(NodeRuntime {
        started_at: Instant::now(),
        listener: None,
        connector: None,
        proxy_stats: None,
        proxy_listen: None,
        log_buffer: LogBuffer::new(),
        cert_fingerprint: None,
        manageable: Default::default(),
    });
    let state = ApiState::new(db.clone(), jwt, runtime, "127.0.0.1".into(), 59090, 54430);
    let app = create_app(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // 登录（写临时 session）
    let tmp = std::env::temp_dir().join(format!("anet-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp).unwrap();
    unsafe { std::env::set_var("USERPROFILE", &tmp) };
    unsafe { std::env::set_var("HOME", &tmp) };

    let api_url = format!("http://127.0.0.1:{port}");
    agile_net_node::cli::run_cli(Cli::parse_from([
        "anet",
        "--api",
        &api_url,
        "login",
        "-u",
        "admin",
        "-p",
        "AdminPass123",
    ]))
    .await
    .unwrap();

    // 新建规则
    agile_net_node::cli::run_cli(Cli::parse_from([
        "anet",
        "rule",
        "add",
        "--type",
        "ip-cidr",
        "--value",
        "10.99.0.0/16",
    ]))
    .await
    .unwrap();

    // 新建组 + 账号
    agile_net_node::cli::run_cli(Cli::parse_from(["anet", "group", "add", "--name", "cli组"]))
        .await
        .unwrap();
    agile_net_node::cli::run_cli(Cli::parse_from([
        "anet",
        "account",
        "add",
        "--username",
        "cliuser",
        "--group",
        "cli组",
    ]))
    .await
    .unwrap();

    // 验证数据落库
    let (rules, total) = db.list_rules(1, 20, None, Some("10.99")).unwrap();
    assert_eq!(total, 1);
    assert_eq!(rules[0].value, "10.99.0.0/16");
    assert!(db.get_account_by_username("cliuser").unwrap().is_some());

    // relay token
    agile_net_node::cli::run_cli(Cli::parse_from([
        "anet", "token", "add", "--remark", "测试",
    ]))
    .await
    .unwrap();
    assert_eq!(db.list_relay_tokens().unwrap().len(), 1);

    let _ = std::fs::remove_dir_all(&tmp);
}
