//! Node TUI console (terminal management UI)
//!
//! Data source: `tui::source` — by default goes through the node API via the `anet login`
//! session (writes are audited, same as the admin UI); when the API is unreachable / no
//! session / `--offline`, degrades to a direct **read-only** DB fallback (the status bar
//! shows the degradation reason).
//!
//! Tabs: Dashboard / Rules / Groups / Accounts / Tokens / Fan-out / Audit
//! Keys: Tab/arrows switch tabs, up/down select a row, r refresh, e enable/disable an
//!       account (API mode), n mint a Relay Token (API mode), d delete the selected row
//!       (y to confirm, API mode), q quit.

pub mod source;

use source::{
    AccountRow, AuditRow, ConnectOutcome, ConnectorRow, DashboardRow, GroupRow, RuleRow, Source,
    TokenRow,
};

use agile_net_core::error::{Error, Result};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    Frame, Terminal,
    backend::Backend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Tabs},
};

/// TUI startup options (`anet tui`).
#[derive(Debug, Clone, Default)]
pub struct TuiOptions {
    /// Force direct-DB read-only mode
    pub offline: bool,
    /// Database path (used with --offline or on API degradation)
    pub db_path: String,
    /// Node API override address (defaults to the session's)
    pub api: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Rules,
    Groups,
    Accounts,
    Tokens,
    Connectors,
    Audit,
}

impl Tab {
    const ALL: [Tab; 7] = [
        Tab::Dashboard,
        Tab::Rules,
        Tab::Groups,
        Tab::Accounts,
        Tab::Tokens,
        Tab::Connectors,
        Tab::Audit,
    ];

    fn title(&self) -> &'static str {
        match self {
            Tab::Dashboard => "概览",
            Tab::Rules => "规则",
            Tab::Groups => "权限组",
            Tab::Accounts => "账号",
            Tab::Tokens => "令牌",
            Tab::Connectors => "扇出",
            Tab::Audit => "审计",
        }
    }

    fn index(&self) -> usize {
        match self {
            Tab::Dashboard => 0,
            Tab::Rules => 1,
            Tab::Groups => 2,
            Tab::Accounts => 3,
            Tab::Tokens => 4,
            Tab::Connectors => 5,
            Tab::Audit => 6,
        }
    }

    fn from_index(i: usize) -> Tab {
        Tab::ALL[i % Tab::ALL.len()]
    }
}

pub struct TuiApp {
    pub source: Source,
    pub current_tab: Tab,
    pub should_quit: bool,
    pub dashboard: DashboardRow,
    pub rules: Vec<RuleRow>,
    pub groups: Vec<GroupRow>,
    pub accounts: Vec<AccountRow>,
    pub tokens: Vec<TokenRow>,
    pub connectors: Vec<ConnectorRow>,
    pub audit_logs: Vec<AuditRow>,
    pub table_state: TableState,
    pub status_msg: String,
    /// Target row awaiting delete confirmation
    pub pending_delete: bool,
}

impl TuiApp {
    pub fn new(outcome: ConnectOutcome) -> Self {
        let mut app = Self {
            source: outcome.source,
            current_tab: Tab::Dashboard,
            should_quit: false,
            dashboard: DashboardRow::default(),
            rules: Vec::new(),
            groups: Vec::new(),
            accounts: Vec::new(),
            tokens: Vec::new(),
            connectors: Vec::new(),
            audit_logs: Vec::new(),
            table_state: TableState::default(),
            status_msg: outcome
                .degraded_note
                .unwrap_or_else(|| "就绪".to_string()),
            pending_delete: false,
        };
        app.refresh();
        app.table_state.select(Some(0));
        app
    }

    pub fn refresh(&mut self) {
        if let Ok(d) = self.source.dashboard() {
            self.dashboard = d;
        }
        if let Ok(items) = self.source.rules() {
            self.rules = items;
        }
        if let Ok(items) = self.source.groups() {
            self.groups = items;
        }
        if let Ok(items) = self.source.accounts() {
            self.accounts = items;
        }
        if let Ok(items) = self.source.tokens() {
            self.tokens = items;
        }
        if let Ok(items) = self.source.connectors() {
            self.connectors = items;
        }
        if let Ok(items) = self.source.audit_logs() {
            self.audit_logs = items;
        }
    }

    fn current_row_count(&self) -> usize {
        match self.current_tab {
            Tab::Dashboard => 0,
            Tab::Rules => self.rules.len(),
            Tab::Groups => self.groups.len(),
            Tab::Accounts => self.accounts.len(),
            Tab::Tokens => self.tokens.len(),
            Tab::Connectors => self.connectors.len(),
            Tab::Audit => self.audit_logs.len(),
        }
    }

    fn selected_index(&self) -> Option<usize> {
        self.table_state.selected()
    }

    pub fn handle_key(&mut self, code: KeyCode) {
        // delete-confirmation mode
        if self.pending_delete {
            match code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.pending_delete = false;
                    self.do_delete_selected();
                }
                _ => {
                    self.pending_delete = false;
                    self.status_msg = "已取消删除".into();
                }
            }
            return;
        }

        match code {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Tab | KeyCode::Right => {
                self.current_tab = Tab::from_index(self.current_tab.index() + 1);
                self.table_state.select(Some(0));
            }
            KeyCode::BackTab | KeyCode::Left => {
                let idx = (self.current_tab.index() + Tab::ALL.len() - 1) % Tab::ALL.len();
                self.current_tab = Tab::from_index(idx);
                self.table_state.select(Some(0));
            }
            KeyCode::Up => self.move_selection(-1),
            KeyCode::Down => self.move_selection(1),
            KeyCode::Char('r') => {
                self.refresh();
                self.status_msg = "已刷新".into();
            }
            KeyCode::Char('e') => self.toggle_selected_account(),
            KeyCode::Char('n') => self.create_token_action(),
            KeyCode::Char('d') => {
                if self.current_row_count() > 0
                    && !matches!(
                        self.current_tab,
                        Tab::Dashboard | Tab::Connectors | Tab::Audit
                    )
                {
                    if self.source.readonly() {
                        self.status_msg = "只读模式（数据库直连）：删除需 API 管理模式".into();
                    } else {
                        self.pending_delete = true;
                        self.status_msg = "确认删除选中行？按 y 确认，其他键取消".into();
                    }
                }
            }
            _ => {}
        }
    }

    fn move_selection(&mut self, delta: i32) {
        let count = self.current_row_count();
        if count == 0 {
            return;
        }
        let current = self.selected_index().unwrap_or(0) as i32;
        let next = (current + delta).rem_euclid(count as i32);
        self.table_state.select(Some(next as usize));
    }

    fn toggle_selected_account(&mut self) {
        if self.current_tab != Tab::Accounts {
            return;
        }
        if self.source.readonly() {
            self.status_msg = "只读模式（数据库直连）：启停需 API 管理模式".into();
            return;
        }
        if let Some(account) = self.selected_index().and_then(|i| self.accounts.get(i)).cloned() {
            let new_enabled = !account.enabled;
            match self.source.set_account_enabled(&account.id, new_enabled) {
                Ok(_) => {
                    self.status_msg = format!(
                        "账号 {} 已{}（已落审计）",
                        account.username,
                        if new_enabled { "启用" } else { "禁用" }
                    );
                    self.refresh();
                }
                Err(e) => self.status_msg = format!("操作失败: {e}"),
            }
        }
    }

    fn create_token_action(&mut self) {
        if self.current_tab != Tab::Tokens {
            return;
        }
        if self.source.readonly() {
            self.status_msg = "只读模式（数据库直连）：生成令牌需 API 管理模式".into();
            return;
        }
        match self.source.create_token("created via TUI") {
            Ok(token) => {
                // plaintext token is shown only this once
                self.status_msg = format!("新 Token（仅此一次显示）: {token}");
                self.refresh();
            }
            Err(e) => self.status_msg = format!("创建失败: {e}"),
        }
    }

    fn do_delete_selected(&mut self) {
        let Some(idx) = self.selected_index() else {
            return;
        };
        let result = match self.current_tab {
            Tab::Rules => self
                .rules
                .get(idx)
                .map(|r| r.id.clone())
                .map(|id| self.source.delete_rule(&id)),
            Tab::Groups => self
                .groups
                .get(idx)
                .map(|g| g.id.clone())
                .map(|id| self.source.delete_group(&id)),
            Tab::Accounts => self
                .accounts
                .get(idx)
                .map(|a| a.id.clone())
                .map(|id| self.source.delete_account(&id)),
            Tab::Tokens => self
                .tokens
                .get(idx)
                .map(|t| t.id.clone())
                .map(|id| self.source.delete_token(&id)),
            _ => None,
        };
        match result {
            Some(Ok(_)) => self.status_msg = "已删除（已落审计）".into(),
            Some(Err(e)) => self.status_msg = format!("删除失败: {e}"),
            None => self.status_msg = "无可删除项".into(),
        }
        self.refresh();
    }

    pub fn draw<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> Result<()> {
        terminal
            .draw(|f| self.render(f))
            .map_err(|e| Error::Other(e.to_string()))?;
        Ok(())
    }

    fn render(&mut self, f: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(10),
                Constraint::Length(3),
            ])
            .split(f.area());

        // tab bar
        let titles: Vec<_> = Tab::ALL.iter().map(|t| t.title()).collect();
        let tabs = Tabs::new(titles)
            .select(self.current_tab.index())
            .style(Style::default().fg(Color::Gray))
            .highlight_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("AgileNet TUI"),
            );
        f.render_widget(tabs, chunks[0]);

        // main content
        match self.current_tab {
            Tab::Dashboard => self.render_dashboard(f, chunks[1]),
            Tab::Rules => self.render_rules(f, chunks[1]),
            Tab::Groups => self.render_groups(f, chunks[1]),
            Tab::Accounts => self.render_accounts(f, chunks[1]),
            Tab::Tokens => self.render_tokens(f, chunks[1]),
            Tab::Connectors => self.render_connectors(f, chunks[1]),
            Tab::Audit => self.render_audit(f, chunks[1]),
        }

        // status bar (data-source label pinned: mode and degradation reason at a glance)
        let footer = Paragraph::new(format!(
            "{} | {} | [Tab]切换 [↑↓]选择 [r]刷新 [e]启停 [n]令牌 [d]删除 [q]退出",
            self.source.label(),
            self.status_msg
        ))
        .style(Style::default().fg(if self.pending_delete || self.source.readonly() {
            Color::Yellow
        } else {
            Color::Gray
        }))
        .block(Block::default().borders(Borders::ALL));
        f.render_widget(footer, chunks[2]);
    }

    fn render_dashboard(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        let d = &self.dashboard;
        let mut text = format!(
            "端点名称:  {}\n程序版本:  {}\n配置版本:  v{}\n",
            d.name, d.version, d.config_version
        );
        for (k, v) in &d.extra {
            text.push_str(&format!("{k}:  {v}\n"));
        }
        text.push_str(&format!(
            "\n规则 {} · 权限组 {} · 令牌 {} · 扇出 {} · 审计 {}",
            self.rules.len(),
            self.groups.len(),
            self.tokens.len(),
            self.connectors.len(),
            self.audit_logs.len()
        ));
        let p =
            Paragraph::new(text).block(Block::default().borders(Borders::ALL).title("端点概览"));
        f.render_widget(p, area);
    }

    fn render_rules(&mut self, f: &mut Frame, area: ratatui::layout::Rect) {
        let rows: Vec<Row> = self
            .rules
            .iter()
            .map(|r| {
                Row::new(vec![
                    Cell::from(r.rule_type.clone()),
                    Cell::from(r.value.clone()),
                    Cell::from(if r.resolve { "是" } else { "否" }),
                    Cell::from(format!("{} 组", r.group_count)),
                    Cell::from(r.remark.clone()),
                ])
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Length(10),
                Constraint::Min(24),
                Constraint::Length(6),
                Constraint::Length(8),
                Constraint::Min(16),
            ],
        )
        .header(
            Row::new(vec!["类型", "匹配值", "解析", "引用", "备注"])
                .style(Style::default().fg(Color::Yellow)),
        )
        .row_highlight_style(Style::default().bg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL).title("路由规则"));
        f.render_stateful_widget(table, area, &mut self.table_state);
    }

    fn render_groups(&mut self, f: &mut Frame, area: ratatui::layout::Rect) {
        let rows: Vec<Row> = self
            .groups
            .iter()
            .map(|g| {
                Row::new(vec![
                    Cell::from(g.name.clone()),
                    Cell::from(format!("{}", g.rule_count)),
                    Cell::from(format!("{}", g.account_count)),
                    Cell::from(g.remark.clone()),
                ])
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Min(16),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Min(20),
            ],
        )
        .header(
            Row::new(vec!["名称", "规则数", "账号数", "备注"])
                .style(Style::default().fg(Color::Yellow)),
        )
        .row_highlight_style(Style::default().bg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL).title("权限组"));
        f.render_stateful_widget(table, area, &mut self.table_state);
    }

    fn render_accounts(&mut self, f: &mut Frame, area: ratatui::layout::Rect) {
        let rows: Vec<Row> = self
            .accounts
            .iter()
            .map(|a| {
                let status = if a.enabled { "启用" } else { "禁用" };
                let online = if a.online { "在线" } else { "离线" };
                Row::new(vec![
                    Cell::from(a.username.clone()),
                    Cell::from(a.group_name.clone()),
                    Cell::from(format!("{status}/{online}")),
                    Cell::from(a.last_seen.clone()),
                    Cell::from(a.remark.clone()),
                ])
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Min(14),
                Constraint::Length(12),
                Constraint::Length(10),
                Constraint::Length(22),
                Constraint::Min(14),
            ],
        )
        .header(
            Row::new(vec!["账号", "权限组", "状态", "最后在线", "备注"])
                .style(Style::default().fg(Color::Yellow)),
        )
        .row_highlight_style(Style::default().bg(Color::DarkGray))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("客户端账号（按 e 启停）"),
        );
        f.render_stateful_widget(table, area, &mut self.table_state);
    }

    fn render_tokens(&mut self, f: &mut Frame, area: ratatui::layout::Rect) {
        let rows: Vec<Row> = self
            .tokens
            .iter()
            .map(|t| {
                Row::new(vec![
                    Cell::from(t.prefix.clone()),
                    Cell::from(t.group_name.clone()),
                    Cell::from(if t.expose { t.scope.clone() } else { "关".into() }),
                    Cell::from(t.remark.clone()),
                    Cell::from(t.last_used.clone()),
                    Cell::from(t.created_at.clone()),
                ])
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Length(16),
                Constraint::Length(12),
                Constraint::Length(8),
                Constraint::Min(18),
                Constraint::Length(22),
                Constraint::Length(22),
            ],
        )
        .header(
            Row::new(vec!["Token 前缀", "权限组", "暴露面", "备注", "最近使用", "创建时间"])
                .style(Style::default().fg(Color::Yellow)),
        )
        .row_highlight_style(Style::default().bg(Color::DarkGray))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Relay 令牌（按 n 生成新令牌）"),
        );
        f.render_stateful_widget(table, area, &mut self.table_state);
    }

    fn render_connectors(&mut self, f: &mut Frame, area: ratatui::layout::Rect) {
        let rows: Vec<Row> = self
            .connectors
            .iter()
            .map(|c| {
                // disabled takes display priority; DB read-only mode has no runtime state ("-")
                let status = if !c.enabled {
                    "已禁用".into()
                } else if c.state.is_empty() {
                    "-".into()
                } else {
                    c.state.clone()
                };
                Row::new(vec![
                    Cell::from(c.name.clone()),
                    Cell::from(c.upstream_addr.clone()),
                    Cell::from(c.group_name.clone()),
                    Cell::from(status),
                    Cell::from(c.remark.clone()),
                ])
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Min(16),
                Constraint::Min(22),
                Constraint::Length(12),
                Constraint::Length(14),
                Constraint::Min(14),
            ],
        )
        .header(
            Row::new(vec!["名称", "地址", "权限组", "状态", "备注"])
                .style(Style::default().fg(Color::Yellow)),
        )
        .row_highlight_style(Style::default().bg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL).title("扇出对端"));
        f.render_stateful_widget(table, area, &mut self.table_state);
    }

    fn render_audit(&mut self, f: &mut Frame, area: ratatui::layout::Rect) {
        let rows: Vec<Row> = self
            .audit_logs
            .iter()
            .map(|l| {
                Row::new(vec![
                    Cell::from(l.created_at.clone()),
                    Cell::from(l.operator.clone()),
                    Cell::from(l.action.clone()),
                    Cell::from(l.target.clone()),
                    Cell::from(l.ip.clone()),
                ])
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Length(22),
                Constraint::Length(12),
                Constraint::Length(24),
                Constraint::Min(20),
                Constraint::Length(14),
            ],
        )
        .header(
            Row::new(vec!["时间", "操作人", "动作", "目标", "来源 IP"])
                .style(Style::default().fg(Color::Yellow)),
        )
        .row_highlight_style(Style::default().bg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL).title("审计日志"));
        f.render_stateful_widget(table, area, &mut self.table_state);
    }
}

/// Run the TUI interactive loop (API first, direct-DB read-only fallback).
pub fn run_tui(opts: TuiOptions) -> Result<()> {
    let outcome = source::connect(opts.api, opts.offline, &opts.db_path)
        .map_err(|e| Error::Other(e.to_string()))?;
    if let Some(note) = &outcome.degraded_note {
        eprintln!("{note}");
    }

    crossterm::terminal::enable_raw_mode().map_err(|e| Error::Other(e.to_string()))?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen)
        .map_err(|e| Error::Other(e.to_string()))?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(|e| Error::Other(e.to_string()))?;

    let mut app = TuiApp::new(outcome);

    loop {
        app.draw(&mut terminal)?;

        if event::poll(std::time::Duration::from_millis(200))
            .map_err(|e| Error::Other(e.to_string()))?
            && let Ok(Event::Key(key)) = event::read()
            && key.kind == KeyEventKind::Press
        {
            app.handle_key(key.code);
        }

        if app.should_quit {
            break;
        }
    }

    crossterm::terminal::disable_raw_mode().map_err(|e| Error::Other(e.to_string()))?;
    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::terminal::LeaveAlternateScreen
    )
    .map_err(|e| Error::Other(e.to_string()))?;
    terminal
        .show_cursor()
        .map_err(|e| Error::Other(e.to_string()))?;

    Ok(())
}
