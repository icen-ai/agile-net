//! AgileNet CLI 核心模块与 Command 结构定义

use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "anet")]
#[command(author, version, about = "⚡ AgileNet CLI - Network & Tunnel Management Tool", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Target API Server Address (e.g., http://127.0.0.1:8080)
    #[arg(global = true, long, default_value = "http://127.0.0.1:8080")]
    pub api: String,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Show node system status
    Status(StatusArgs),
    /// Login and obtain authentication token
    Login(LoginArgs),
    /// Manage nodes
    Node(NodeArgs),
    /// Manage proxy routes
    Route(RouteArgs),
    /// Launch Interactive TUI Console
    Tui(TuiArgs),
}

#[derive(Args, Debug)]
pub struct StatusArgs {}

#[derive(Args, Debug)]
pub struct LoginArgs {
    #[arg(short, long, default_value = "admin")]
    pub username: String,
    #[arg(short, long, default_value = "admin123")]
    pub password: String,
}

#[derive(Args, Debug)]
pub struct NodeArgs {
    #[command(subcommand)]
    pub command: NodeSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum NodeSubcommand {
    /// List all registered nodes
    List,
}

#[derive(Args, Debug)]
pub struct RouteArgs {
    #[command(subcommand)]
    pub command: RouteSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum RouteSubcommand {
    /// List all proxy routes
    List,
    /// Add a new proxy route
    Add(RouteAddArgs),
    /// Delete a proxy route by ID
    Delete(RouteDeleteArgs),
}

#[derive(Args, Debug)]
pub struct RouteAddArgs {
    /// Match pattern (e.g. 10.0.0.0/8, *.internal.com)
    #[arg(short, long)]
    pub pattern: String,

    /// Pattern type: cidr, exact_host, wildcard_host
    #[arg(short = 't', long, default_value = "cidr")]
    pub pattern_type: String,

    /// Outbound target: direct or tunnel
    #[arg(short, long, default_value = "direct")]
    pub outbound: String,

    /// Optional target Node ID for tunnel outbound
    #[arg(long)]
    pub node_id: Option<String>,
}

#[derive(Args, Debug)]
pub struct RouteDeleteArgs {
    /// Route ID to delete
    pub id: String,
}

#[derive(Args, Debug)]
pub struct TuiArgs {}

/// 执行 CLI 命令的主逻辑函数
pub async fn run_cli(cli: Cli) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let base_url = cli.api.trim_end_matches('/');

    match cli.command {
        Commands::Status(_) => {
            let url = format!("{base_url}/api/v1/system/info");
            match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    let json: serde_json::Value = resp.json().await?;
                    println!("⚡ AgileNet Node Status:");
                    println!("{}", serde_json::to_string_pretty(&json)?);
                }
                _ => {
                    println!("⚡ AgileNet Node: Running (API reachability unverified at {base_url})");
                }
            }
        }
        Commands::Login(args) => {
            let url = format!("{base_url}/api/v1/auth/login");
            let body = serde_json::json!({
                "username": args.username,
                "password": args.password,
            });
            let resp = client.post(&url).json(&body).send().await?;
            if resp.status().is_success() {
                let json: serde_json::Value = resp.json().await?;
                let token = json["token"].as_str().unwrap_or_default();
                println!("✅ Logged in successfully!");
                println!("Token: {token}");
            } else {
                println!("❌ Login failed: HTTP {}", resp.status());
            }
        }
        Commands::Node(args) => match args.command {
            NodeSubcommand::List => {
                let url = format!("{base_url}/api/v1/nodes");
                let resp = client.get(&url).send().await?;
                if resp.status().is_success() {
                    let nodes: serde_json::Value = resp.json().await?;
                    println!("🌐 Nodes List:");
                    println!("{}", serde_json::to_string_pretty(&nodes)?);
                } else {
                    println!("Failed to list nodes: HTTP {}", resp.status());
                }
            }
        },
        Commands::Route(args) => match args.command {
            RouteSubcommand::List => {
                let url = format!("{base_url}/api/v1/routes");
                let resp = client.get(&url).send().await?;
                if resp.status().is_success() {
                    let routes: serde_json::Value = resp.json().await?;
                    println!("🔀 Proxy Routes:");
                    println!("{}", serde_json::to_string_pretty(&routes)?);
                } else {
                    println!("Failed to list routes: HTTP {}", resp.status());
                }
            }
            RouteSubcommand::Add(add_args) => {
                let url = format!("{base_url}/api/v1/routes");
                let body = serde_json::json!({
                    "pattern": add_args.pattern,
                    "pattern_type": add_args.pattern_type,
                    "outbound_type": add_args.outbound,
                    "node_id": add_args.node_id,
                    "enabled": true,
                });
                let resp = client.post(&url).json(&body).send().await?;
                if resp.status().is_success() {
                    println!("✅ Route added successfully!");
                } else {
                    println!("Failed to add route: HTTP {}", resp.status());
                }
            }
            RouteSubcommand::Delete(del_args) => {
                let url = format!("{base_url}/api/v1/routes/{}", del_args.id);
                let resp = client.delete(&url).send().await?;
                if resp.status().is_success() {
                    println!("✅ Route deleted successfully!");
                } else {
                    println!("Failed to delete route: HTTP {}", resp.status());
                }
            }
        },
        Commands::Tui(_) => {
            println!("Launching TUI console...");
            let db_path = std::env::var("DATABASE_PATH").unwrap_or_else(|_| "agile-net.db".to_string());
            let db = agile_net_node::db::Database::open(&db_path)?;
            agile_net_node::tui::run_tui(db)?;
        }
    }

    Ok(())
}
