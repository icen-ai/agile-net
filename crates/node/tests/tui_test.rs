//! Node TUI 终端界面集成测试

use agile_net_node::db::Database;
use agile_net_node::tui::{Tab, TuiApp};
use crossterm::event::KeyCode;

/// TUI 运行状态初始化与干净退出验证
#[tokio::test]
async fn tui_app_state_initialization() {
    let db = Database::in_memory().unwrap();
    let app = TuiApp::new(db);

    assert_eq!(app.current_tab, Tab::Dashboard);
    assert!(!app.should_quit);
}

/// 按键事件与 Tab 循环切换
#[tokio::test]
async fn tui_key_event_handling() {
    let db = Database::in_memory().unwrap();
    let mut app = TuiApp::new(db);

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

/// TUI 创建 Relay Token 动作
#[tokio::test]
async fn tui_create_token_action() {
    let db = Database::in_memory().unwrap();
    let mut app = TuiApp::new(db);

    // 切到 Tokens 页签
    app.handle_key(KeyCode::Tab); // Rules
    app.handle_key(KeyCode::Tab); // Groups
    app.handle_key(KeyCode::Tab); // Accounts
    app.handle_key(KeyCode::Tab); // Tokens
    assert_eq!(app.current_tab, Tab::Tokens);

    assert_eq!(app.tokens.len(), 0);
    app.handle_key(KeyCode::Char('n'));
    assert_eq!(app.tokens.len(), 1);
    // 明文 token 显示在状态栏（仅此一次）
    assert!(app.status_msg.contains("psk_"));
}

/// TUI 账号启停动作
#[tokio::test]
async fn tui_toggle_account() {
    let db = Database::in_memory().unwrap();
    let gid = db.create_group("g", "").unwrap().id;
    let hash = agile_net_node::db::hash_password("TestPass123").unwrap();
    db.create_account("user1", &hash, &gid, "").unwrap();

    let mut app = TuiApp::new(db);
    // 切到 Accounts 页签
    app.handle_key(KeyCode::Tab);
    app.handle_key(KeyCode::Tab);
    app.handle_key(KeyCode::Tab);
    assert_eq!(app.current_tab, Tab::Accounts);
    assert_eq!(app.accounts.len(), 1);
    assert!(app.accounts[0].enabled);

    app.handle_key(KeyCode::Char('e'));
    assert!(!app.accounts[0].enabled);
    app.handle_key(KeyCode::Char('e'));
    assert!(app.accounts[0].enabled);
}
