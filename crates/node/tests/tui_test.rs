//! Node TUI terminal UI integration tests (after the data-source abstraction: direct DB is the readonly fallback mode)

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

/// TUI runtime state initialization and clean quit
#[tokio::test]
async fn tui_app_state_initialization() {
    let app = db_app(Database::in_memory().unwrap());

    assert_eq!(app.current_tab, Tab::Dashboard);
    assert!(!app.should_quit);
    assert!(app.source.readonly());
}

/// Key events and Tab cycling
#[tokio::test]
async fn tui_key_event_handling() {
    let mut app = db_app(Database::in_memory().unwrap());

    // Tab cycles through 7 tabs and back to the start
    app.handle_key(KeyCode::Tab);
    assert_eq!(app.current_tab, Tab::Rules);
    app.handle_key(KeyCode::Tab);
    assert_eq!(app.current_tab, Tab::Groups);
    app.handle_key(KeyCode::Tab);
    assert_eq!(app.current_tab, Tab::Accounts);
    app.handle_key(KeyCode::Tab);
    assert_eq!(app.current_tab, Tab::Tokens);
    app.handle_key(KeyCode::Tab);
    assert_eq!(app.current_tab, Tab::Connectors);
    app.handle_key(KeyCode::Tab);
    assert_eq!(app.current_tab, Tab::Audit);
    app.handle_key(KeyCode::Tab);
    assert_eq!(app.current_tab, Tab::Dashboard);

    // reverse cycling
    app.handle_key(KeyCode::BackTab);
    assert_eq!(app.current_tab, Tab::Audit);

    // quit
    app.handle_key(KeyCode::Char('q'));
    assert!(app.should_quit);
}

/// DB readonly mode: token creation refused with a hint (writes require API management mode)
#[tokio::test]
async fn tui_create_token_readonly_rejected() {
    let mut app = db_app(Database::in_memory().unwrap());

    // switch to the Tokens tab
    app.handle_key(KeyCode::Tab); // Rules
    app.handle_key(KeyCode::Tab); // Groups
    app.handle_key(KeyCode::Tab); // Accounts
    app.handle_key(KeyCode::Tab); // Tokens
    assert_eq!(app.current_tab, Tab::Tokens);

    assert_eq!(app.tokens.len(), 0);
    app.handle_key(KeyCode::Char('n'));
    // readonly mode: no token produced, status bar hints API mode is needed
    assert_eq!(app.tokens.len(), 0);
    assert!(app.status_msg.contains("只读"));
}

/// DB readonly mode: account enable/disable refused, state unchanged
#[tokio::test]
async fn tui_toggle_account_readonly_rejected() {
    let db = Database::in_memory().unwrap();
    let gid = db.create_group("g", "").unwrap().id;
    let hash = agile_net_node::db::hash_password("TestPass123").unwrap();
    db.create_account("user1", &hash, &gid, "").unwrap();

    let mut app = db_app(db);
    // switch to the Accounts tab
    app.handle_key(KeyCode::Tab);
    app.handle_key(KeyCode::Tab);
    app.handle_key(KeyCode::Tab);
    assert_eq!(app.current_tab, Tab::Accounts);
    assert_eq!(app.accounts.len(), 1);
    assert!(app.accounts[0].enabled);

    app.handle_key(KeyCode::Char('e'));
    // readonly mode: state unchanged with a hint
    assert!(app.accounts[0].enabled);
    assert!(app.status_msg.contains("只读"));
}
