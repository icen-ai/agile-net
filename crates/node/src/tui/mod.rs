//! Node TUI 控制台实现

use crate::db::models::{NodeRecord, RouteRecord};
use crate::db::Database;
use agile_net_core::error::{Error, Result};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    backend::Backend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Paragraph, Row, Table},
    Frame, Terminal,
};

#[derive(Debug, PartialEq, Eq)]
pub enum Tab {
    Nodes,
    Routes,
}

pub struct TuiApp {
    pub db: Database,
    pub current_tab: Tab,
    pub should_quit: bool,
    pub nodes: Vec<NodeRecord>,
    pub routes: Vec<RouteRecord>,
    pub status_msg: String,
}

impl TuiApp {
    pub fn new(db: Database) -> Self {
        let mut app = Self {
            db,
            current_tab: Tab::Nodes,
            should_quit: false,
            nodes: Vec::new(),
            routes: Vec::new(),
            status_msg: "Ready".to_string(),
        };
        app.refresh();
        app
    }

    pub fn refresh(&mut self) {
        if let Ok(nodes) = self.db.list_nodes() {
            self.nodes = nodes;
        }
        if let Ok(routes) = self.db.list_routes() {
            self.routes = routes;
        }
    }

    pub fn handle_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('q') | KeyCode::Esc => {
                self.should_quit = true;
            }
            KeyCode::Tab => {
                self.current_tab = match self.current_tab {
                    Tab::Nodes => Tab::Routes,
                    Tab::Routes => Tab::Nodes,
                };
            }
            KeyCode::Char('r') => {
                self.refresh();
                self.status_msg = "Refreshed".to_string();
            }
            _ => {}
        }
    }

    pub fn draw<B: Backend>(&self, terminal: &mut Terminal<B>) -> Result<()> {
        terminal
            .draw(|f| self.render(f))
            .map_err(|e| Error::Other(e.to_string()))?;
        Ok(())
    }

    fn render(&self, f: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(10),
                Constraint::Length(3),
            ])
            .split(f.area());

        // Header
        let header = Paragraph::new("⚡ AgileNet Node TUI Console (v0.1.0)")
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .block(Block::default().borders(Borders::ALL).title("Header"));
        f.render_widget(header, chunks[0]);

        // Main Body (Tabs: Nodes & Routes)
        let main_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(chunks[1]);

        // Nodes Table
        let node_rows: Vec<Row> = self
            .nodes
            .iter()
            .map(|n| {
                Row::new(vec![
                    n.name.clone(),
                    n.status.as_str().to_string(),
                    n.last_seen.clone().unwrap_or_else(|| "Never".into()),
                ])
            })
            .collect();

        let nodes_table = Table::new(
            node_rows,
            [
                Constraint::Percentage(40),
                Constraint::Percentage(30),
                Constraint::Percentage(30),
            ],
        )
        .header(Row::new(vec!["Node Name", "Status", "Last Seen"]).style(Style::default().fg(Color::Yellow)))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("🌐 Nodes")
                .style(if self.current_tab == Tab::Nodes {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default()
                }),
        );
        f.render_widget(nodes_table, main_chunks[0]);

        // Routes Table
        let route_rows: Vec<Row> = self
            .routes
            .iter()
            .map(|r| {
                Row::new(vec![
                    r.pattern.clone(),
                    r.pattern_type.as_str().to_string(),
                    r.outbound_type.to_uppercase(),
                ])
            })
            .collect();

        let routes_table = Table::new(
            route_rows,
            [
                Constraint::Percentage(40),
                Constraint::Percentage(30),
                Constraint::Percentage(30),
            ],
        )
        .header(Row::new(vec!["Pattern", "Type", "Outbound"]).style(Style::default().fg(Color::Yellow)))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("🔀 Proxy Routes")
                .style(if self.current_tab == Tab::Routes {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default()
                }),
        );
        f.render_widget(routes_table, main_chunks[1]);

        // Footer / Status Bar
        let footer_text = format!(
            "Status: {} | Shortcuts: [Tab] Switch Focus  [r] Refresh  [q] Quit",
            self.status_msg
        );
        let footer = Paragraph::new(footer_text)
            .style(Style::default().fg(Color::Gray))
            .block(Block::default().borders(Borders::ALL).title("Controls"));
        f.render_widget(footer, chunks[2]);
    }
}

/// 运行 TUI 交互式循环
pub fn run_tui(db: Database) -> Result<()> {
    crossterm::terminal::enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = TuiApp::new(db);

    loop {
        app.draw(&mut terminal)?;

        if event::poll(std::time::Duration::from_millis(200))? {
            match event::read() {
                Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => {
                    app.handle_key(key.code);
                }
                _ => {}
            }
        }

        if app.should_quit {
            break;
        }
    }

    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::terminal::LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;

    Ok(())
}
