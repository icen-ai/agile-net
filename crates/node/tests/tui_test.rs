//! Node TUI 终端界面集成测试（数据源抽象后：DB 直连为只读兜底模式）

use agile_net_node::db::Database;
use agile_net_node::tui::source::{ConnectOutcome, Source};
use agile_net_node::tui::{Tab, TuiApp};
use crossterm::event::KeyCode;

fn db_app(db: Database) -> TuiApp {
    TuiApp::new(ConnectOutcome {
        source: Source::Db(db),
        degraded_note: None,
    })
}

/// TUI 运行状态初始化与干净退出验证
#[tokio::test]
async fn tui_app_state_initialization() {
    let app = db_app(Database::in_memory().unwrap());

    assert_eq!(app.current_tab, Tab::Dashboard);
    assert!(!app.should_quit);
    assert!(app.source.readonly());
}

/// 按键事件与 Tab 循环切换
#[tokio::test]
async fn tui_key_event_handling() {
    let mut app = db_app(Database::in_memory().unwrap());

    // Tab 键依次切换 6 个页签后回到起点
    app.handle_key(KeyCode::Tab);
    assert_eq!(app.current_tab, Tab::Rules);
    app.handle_key(KeyCode::Tab);
    assert_eq!(app.current_tab, Tab::Groups);
    app.handle_key(KeyCode::Tab);
    assert_eq!(app.current_tab, Tab::Accounts);
    app.handle_key(KeyCode::Tab);
    assert_eq!(app.current_tab, Tab::Tokens);
    app.handle_key(KeyCode::Tab);
    assert_eq!(app.current_tab, Tab::Audit);
    app.handle_key(KeyCode::Tab);
    assert_eq!(app.current_tab, Tab::Dashboard);

    // 反向切换
    app.handle_key(KeyCode::BackTab);
    assert_eq!(app.current_tab, Tab::Audit);

    // 退出
    app.handle_key(KeyCode::Char('q'));
    assert!(app.should_quit);
}

/// DB 只读模式：生成令牌被拒绝并提示（写操作需 API 管理模式）
#[tokio::test]
async fn tui_create_token_readonly_rejected() {
    let mut app = db_app(Database::in_memory().unwrap());

    // 切到 Tokens 页签
    app.handle_key(KeyCode::Tab); // Rules
    app.handle_key(KeyCode::Tab); // Groups
    app.handle_key(KeyCode::Tab); // Accounts
    app.handle_key(KeyCode::Tab); // Tokens
    assert_eq!(app.current_tab, Tab::Tokens);

    assert_eq!(app.tokens.len(), 0);
    app.handle_key(KeyCode::Char('n'));
    // 只读模式：不产生令牌，状态栏提示需 API 模式
    assert_eq!(app.tokens.len(), 0);
    assert!(app.status_msg.contains("只读"));
}

/// DB 只读模式：账号启停被拒绝且状态不变
#[tokio::test]
async fn tui_toggle_account_readonly_rejected() {
    let db = Database::in_memory().unwrap();
    let gid = db.create_group("g", "").unwrap().id;
    let hash = agile_net_node::db::hash_password("TestPass123").unwrap();
    db.create_account("user1", &hash, &gid, "").unwrap();

    let mut app = db_app(db);
    // 切到 Accounts 页签
    app.handle_key(KeyCode::Tab);
    app.handle_key(KeyCode::Tab);
    app.handle_key(KeyCode::Tab);
    assert_eq!(app.current_tab, Tab::Accounts);
    assert_eq!(app.accounts.len(), 1);
    assert!(app.accounts[0].enabled);

    app.handle_key(KeyCode::Char('e'));
    // 只读模式：状态不变并提示
    assert!(app.accounts[0].enabled);
    assert!(app.status_msg.contains("只读"));
}
