//! M6.5 里程碑 Node TUI 终端界面集成测试

use agile_net_node::db::Database;
use agile_net_node::tui::{Tab, TuiApp};
use crossterm::event::KeyCode;

/// AT-M6.5-01：TUI 运行状态初始化与干净退出验证
#[tokio::test]
async fn tui_app_state_initialization() {
    let db = Database::in_memory().unwrap();
    let app = TuiApp::new(db);

    assert_eq!(app.current_tab, Tab::Nodes);
    assert!(!app.should_quit);
}

/// AT-M6.5-02：TUI 按键事件与 Tab 切换路由处理
#[tokio::test]
async fn tui_key_event_handling() {
    let db = Database::in_memory().unwrap();
    let mut app = TuiApp::new(db);

    // 模拟 Tab 键切换标签页
    app.handle_key(KeyCode::Tab);
    assert_eq!(app.current_tab, Tab::Routes);

    app.handle_key(KeyCode::Tab);
    assert_eq!(app.current_tab, Tab::Nodes);

    // 模拟按下 'q' 触发退出
    app.handle_key(KeyCode::Char('q'));
    assert!(app.should_quit);
}
