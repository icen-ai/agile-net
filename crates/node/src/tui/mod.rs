//! Node TUI 控制台（企业级终端管理界面）
//!
//! 页签：Dashboard / Rules / Groups / Accounts / Relay Tokens / Audit Logs
//! 操作：Tab/←→ 切换页签，↑↓ 选择行，r 刷新，e 启用/禁用账号，
//!       n 生成 Relay Token，d 删除选中行（y 确认），q 退出。

use crate::db::models::{AccountRecord, AuditLogRecord, GroupRecord, RelayTokenRecord, RuleRecord};
use crate::db::{Database, generate_relay_token, sha256_hex};
use agile_net_core::error::{Error, Result};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    backend::Backend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Tabs},
    Frame, Terminal,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Rules,
    Groups,
    Accounts,
    Tokens,
    Audit,
}

impl Tab {
    const ALL: [Tab; 6] = [
        Tab::Dashboard,
        Tab::Rules,
        Tab::Groups,
        Tab::Accounts,
        Tab::Tokens,
        Tab::Audit,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Dashboard => "概览",
            Tab::Rules => "规则",
            Tab::Groups => "权限组",
            Tab::Accounts => "账号",
            Tab::Tokens => "令牌",
            Tab::Audit => "审计",
        }
    }

    fn index(self) -> usize {
        Self::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }

    fn from_index(i: usize) -> Self {
        Self::ALL[i % Self::ALL.len()]
    }
}

pub struct TuiApp {
    pub db: Database,
    pub current_tab: Tab,
    pub should_quit: bool,
    pub rules: Vec<RuleRecord>,
    pub groups: Vec<GroupRecord>,
    pub accounts: Vec<AccountRecord>,
    pub tokens: Vec<RelayTokenRecord>,
    pub audit_logs: Vec<AuditLogRecord>,
    pub table_state: TableState,
    pub status_msg: String,
    /// 等待删除确认的目标行
    pub pending_delete: bool,
}

impl TuiApp {
    pub fn new(db: Database) -> Self {
        let mut app = Self {
            db,
            current_tab: Tab::Dashboard,
            should_quit: false,
            rules: Vec::new(),
            groups: Vec::new(),
            accounts: Vec::new(),
            tokens: Vec::new(),
            audit_logs: Vec::new(),
            table_state: TableState::default(),
            status_msg: "就绪".to_string(),
            pending_delete: false,
        };
        app.refresh();
        app.table_state.select(Some(0));
        app
    }

    pub fn refresh(&mut self) {
        if let Ok((items, _)) = self.db.list_rules(1, 500, None, None) {
            self.rules = items;
        }
        if let Ok((items, _)) = self.db.list_groups(1, 500, None) {
            self.groups = items;
        }
        if let Ok((items, _)) = self.db.list_accounts(1, 500, None, None, None) {
            self.accounts = items;
        }
        if let Ok(items) = self.db.list_relay_tokens() {
            self.tokens = items;
        }
        if let Ok((items, _)) = self.db.list_audit_logs(1, 100, None) {
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
            Tab::Audit => self.audit_logs.len(),
        }
    }

    fn selected_index(&self) -> Option<usize> {
        self.table_state.selected()
    }

    pub fn handle_key(&mut self, code: KeyCode) {
        // 删除确认模式
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
                if self.current_row_count() > 0 && !matches!(self.current_tab, Tab::Dashboard | Tab::Audit) {
                    self.pending_delete = true;
                    self.status_msg = "确认删除选中行？按 y 确认，其他键取消".into();
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
        if let Some(idx) = self.selected_index()
            && let Some(account) = self.accounts.get(idx)
        {
                let new_enabled = !account.enabled;
                let id = account.id.clone();
                let username = account.username.clone();
                match self.db.update_account(&id, None, Some(new_enabled), None) {
                    Ok(_) => {
                        let _ = self.db.bump_config_version();
                        self.status_msg = format!(
                            "账号 {} 已{}",
                            username,
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
        let token = generate_relay_token();
        let hash = sha256_hex(token.as_bytes());
        let prefix = format!("{}****", &token[..8]);
        match self.db.create_relay_token(&hash, &prefix, "created via TUI") {
            Ok(_) => {
                // 明文令牌仅在此显示一次
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
                .map(|r| self.db.delete_rule(&r.id, false)),
            Tab::Groups => self
                .groups
                .get(idx)
                .map(|g| self.db.delete_group(&g.id, false)),
            Tab::Accounts => self
                .accounts
                .get(idx)
                .map(|a| self.db.delete_account(&a.id)),
            Tab::Tokens => self
                .tokens
                .get(idx)
                .map(|t| self.db.delete_relay_token(&t.id)),
            _ => None,
        };
        match result {
            Some(Ok(_)) => {
                let _ = self.db.bump_config_version();
                self.status_msg = "已删除".into();
            }
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

        // 页签栏
        let titles: Vec<_> = Tab::ALL.iter().map(|t| t.title()).collect();
        let tabs = Tabs::new(titles)
            .select(self.current_tab.index())
            .style(Style::default().fg(Color::Gray))
            .highlight_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .block(Block::default().borders(Borders::ALL).title("AgileNet Node"));
        f.render_widget(tabs, chunks[0]);

        // 主内容
        match self.current_tab {
            Tab::Dashboard => self.render_dashboard(f, chunks[1]),
            Tab::Rules => self.render_rules(f, chunks[1]),
            Tab::Groups => self.render_groups(f, chunks[1]),
            Tab::Accounts => self.render_accounts(f, chunks[1]),
            Tab::Tokens => self.render_tokens(f, chunks[1]),
            Tab::Audit => self.render_audit(f, chunks[1]),
        }

        // 状态栏
        let footer = Paragraph::new(format!(
            "{} | [Tab/←→] 切换  [↑↓] 选择  [r] 刷新  [e] 启停账号  [n] 新令牌  [d] 删除  [q] 退出",
            self.status_msg
        ))
        .style(Style::default().fg(if self.pending_delete {
            Color::Yellow
        } else {
            Color::Gray
        }))
        .block(Block::default().borders(Borders::ALL));
        f.render_widget(footer, chunks[2]);
    }

    fn render_dashboard(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        let node_name = self
            .db
            .get_config("node_name")
            .ok()
            .flatten()
            .unwrap_or_else(|| "AgileNet Node".into());
        let version = self.db.config_version().unwrap_or(0);
        let (total_accounts, disabled_accounts) = self.db.account_stats().unwrap_or((0, 0));

        let text = format!(
            "节点名称:  {node_name}\n\
             程序版本:  v{}\n\
             配置版本:  v{version}\n\n\
             规则数量:  {}\n\
             权限组:    {}\n\
             客户端账号: {} (禁用 {})\n\
             Relay 令牌: {}\n\
             审计日志:  {} 条\n",
            env!("CARGO_PKG_VERSION"),
            self.rules.len(),
            self.groups.len(),
            total_accounts,
            disabled_accounts,
            self.tokens.len(),
            self.audit_logs.len(),
        );
        let p = Paragraph::new(text).block(
            Block::default()
                .borders(Borders::ALL)
                .title("节点概览"),
        );
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
        .header(Row::new(vec!["名称", "规则数", "账号数", "备注"]).style(Style::default().fg(Color::Yellow)))
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
                Row::new(vec![
                    Cell::from(a.username.clone()),
                    Cell::from(a.group_name.clone().unwrap_or_else(|| "-".into())),
                    Cell::from(status),
                    Cell::from(a.last_seen_at.clone().unwrap_or_else(|| "从未".into())),
                    Cell::from(a.remark.clone()),
                ])
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Min(14),
                Constraint::Length(12),
                Constraint::Length(6),
                Constraint::Length(22),
                Constraint::Min(14),
            ],
        )
        .header(Row::new(vec!["账号", "权限组", "状态", "最后在线", "备注"]).style(Style::default().fg(Color::Yellow)))
        .row_highlight_style(Style::default().bg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL).title("客户端账号（按 e 启停）"));
        f.render_stateful_widget(table, area, &mut self.table_state);
    }

    fn render_tokens(&mut self, f: &mut Frame, area: ratatui::layout::Rect) {
        let rows: Vec<Row> = self
            .tokens
            .iter()
            .map(|t| {
                Row::new(vec![
                    Cell::from(t.token_prefix.clone()),
                    Cell::from(t.remark.clone()),
                    Cell::from(t.last_used_at.clone().unwrap_or_else(|| "未使用".into())),
                    Cell::from(t.created_at.clone()),
                ])
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Length(16),
                Constraint::Min(20),
                Constraint::Length(22),
                Constraint::Length(22),
            ],
        )
        .header(Row::new(vec!["Token 前缀", "备注", "最近使用", "创建时间"]).style(Style::default().fg(Color::Yellow)))
        .row_highlight_style(Style::default().bg(Color::DarkGray))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Relay 令牌（按 n 生成新令牌）"),
        );
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
                    Cell::from(l.target.clone().unwrap_or_else(|| "-".into())),
                    Cell::from(l.ip.clone().unwrap_or_else(|| "-".into())),
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
        .header(Row::new(vec!["时间", "操作人", "动作", "目标", "来源 IP"]).style(Style::default().fg(Color::Yellow)))
        .row_highlight_style(Style::default().bg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL).title("审计日志"));
        f.render_stateful_widget(table, area, &mut self.table_state);
    }
}

/// 运行 TUI 交互式循环
pub fn run_tui(db: Database) -> Result<()> {
    crossterm::terminal::enable_raw_mode().map_err(|e| Error::Other(e.to_string()))?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen)
        .map_err(|e| Error::Other(e.to_string()))?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(|e| Error::Other(e.to_string()))?;

    let mut app = TuiApp::new(db);

    loop {
        app.draw(&mut terminal)?;

        if event::poll(std::time::Duration::from_millis(200)).map_err(|e| Error::Other(e.to_string()))?
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
    terminal.show_cursor().map_err(|e| Error::Other(e.to_string()))?;

    Ok(())
}
