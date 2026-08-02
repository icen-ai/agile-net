//! CLI 命令解析与集成测试

use agile_net_node::cli::{Cli, Commands, ConnectorSub, RuleSub, TokenSub};
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
fn cli_token_add_group_parsing() {
    for sub in ["add", "create"] {
        let cli = Cli::parse_from(["anet", "token", sub, "--group", "开发组"]);
        match cli.command {
            Commands::Token(ref args) => match args.command {
                TokenSub::Add(ref a) => assert_eq!(a.group.as_deref(), Some("开发组")),
                _ => panic!("expected token add"),
            },
            _ => panic!("expected token command"),
        }
    }
}

#[test]
fn cli_connector_add_parsing() {
    let cli = Cli::parse_from([
        "anet",
        "connector",
        "add",
        "--name",
        "上海机房",
        "--addr",
        "10.0.0.1:54430",
        "--token",
        "psk_abc",
        "--advertise",
        "10.1.0.0/16,git.internal",
        "--group",
        "dev",
        "--insecure",
    ]);
    match cli.command {
        Commands::Connector(args) => match args.command {
            ConnectorSub::Add(a) => {
                assert_eq!(a.name, "上海机房");
                assert_eq!(a.addr, "10.0.0.1:54430");
                assert_eq!(a.token, "psk_abc");
                assert_eq!(a.advertise.as_deref(), Some("10.1.0.0/16,git.internal"));
                assert_eq!(a.group.as_deref(), Some("dev"));
                assert!(a.insecure);
            }
            _ => panic!("expected connector add"),
        },
        _ => panic!("expected connector command"),
    }
}

#[test]
fn cli_connector_update_parsing() {
    let cli = Cli::parse_from(["anet", "connector", "update", "上海", "--remark", "新备注"]);
    match cli.command {
        Commands::Connector(args) => match args.command {
            ConnectorSub::Update(u) => {
                assert_eq!(u.id, "上海");
                assert_eq!(u.remark.as_deref(), Some("新备注"));
                assert!(u.token.is_none());
            }
            _ => panic!("expected connector update"),
        },
        _ => panic!("expected connector command"),
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
    use agile_net_node::service::connectors::ConnectorManager;
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
        connector_manager: Arc::new(ConnectorManager::new(db.clone())),
        proxy_stats: None,
        proxy_listen: None,
        log_buffer: LogBuffer::new(),
        cert_fingerprint: None,
        manageable: Default::default(),
        client_proxy_slot: Default::default(),
        transit_meter: agile_net_core::relay::transit::TransitMeter::new(),
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

    // token --group 收敛挂组
    agile_net_node::cli::run_cli(Cli::parse_from([
        "anet", "token", "add", "--remark", "收敛令牌", "--group", "cli组",
    ]))
    .await
    .unwrap();
    let tokens = db.list_relay_tokens().unwrap();
    assert_eq!(tokens.len(), 2);
    let scoped = tokens.iter().find(|t| t.remark == "收敛令牌").unwrap();
    let gid = scoped.group_id.clone().expect("令牌应挂组");

    // connector 全链路（add/list/update/disable/enable/remove；上游不可达仅热装配失败，不阻断）
    agile_net_node::cli::run_cli(Cli::parse_from([
        "anet",
        "connector",
        "add",
        "--name",
        "上海机房",
        "--addr",
        "127.0.0.1:1",
        "--token",
        "psk_test",
        "--advertise",
        "10.1.0.0/16,git.internal",
        "--group",
        "cli组",
        "--insecure",
    ]))
    .await
    .unwrap();
    let connectors = db.list_connectors().unwrap();
    assert_eq!(connectors.len(), 1);
    assert_eq!(connectors[0].group_id.as_deref(), Some(gid.as_str()));
    assert_eq!(connectors[0].advertise, "10.1.0.0/16,git.internal");

    agile_net_node::cli::run_cli(Cli::parse_from(["anet", "connector", "list"]))
        .await
        .unwrap();

    // 更新：缺省参数保留原值（组/地址不变），token 留空 = 保留
    agile_net_node::cli::run_cli(Cli::parse_from([
        "anet", "connector", "update", "上海机房", "--remark", "更新备注",
    ]))
    .await
    .unwrap();
    let connectors = db.list_connectors().unwrap();
    assert_eq!(connectors[0].remark, "更新备注");
    assert_eq!(connectors[0].upstream_addr, "127.0.0.1:1");
    assert_eq!(connectors[0].group_id.as_deref(), Some(gid.as_str()));

    agile_net_node::cli::run_cli(Cli::parse_from(["anet", "connector", "disable", "上海机房"]))
        .await
        .unwrap();
    assert!(!db.list_connectors().unwrap()[0].enabled);
    agile_net_node::cli::run_cli(Cli::parse_from(["anet", "connector", "enable", "上海机房"]))
        .await
        .unwrap();
    assert!(db.list_connectors().unwrap()[0].enabled);
    agile_net_node::cli::run_cli(Cli::parse_from(["anet", "connector", "remove", "上海机房"]))
        .await
        .unwrap();
    assert!(db.list_connectors().unwrap().is_empty());

    let _ = std::fs::remove_dir_all(&tmp);
}
