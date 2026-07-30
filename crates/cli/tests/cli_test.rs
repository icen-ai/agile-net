//! M6.6 里程碑 CLI 命令与交互测试

use agile_net_cli::{Cli, Commands, NodeArgs, NodeSubcommand, RouteArgs, RouteSubcommand, StatusArgs};
use clap::Parser;

/// AT-M6.6-01：CLI 路由规则子命令解析
#[test]
fn cli_route_add_arg_parsing() {
    let cli = Cli::parse_from([
        "anet",
        "route",
        "add",
        "--pattern",
        "10.0.0.0/8",
        "--pattern-type",
        "cidr",
        "--outbound",
        "direct",
    ]);

    match cli.command {
        Commands::Route(RouteArgs {
            command: RouteSubcommand::Add(add_args),
        }) => {
            assert_eq!(add_args.pattern, "10.0.0.0/8");
            assert_eq!(add_args.pattern_type, "cidr");
            assert_eq!(add_args.outbound, "direct");
        }
        _ => panic!("Expected Route Add subcommand"),
    }
}

/// AT-M6.6-02：CLI 节点状态命令解析
#[test]
fn cli_status_command_parsing() {
    let cli = Cli::parse_from(["anet", "status"]);
    assert!(matches!(cli.command, Commands::Status(StatusArgs {})));
}

/// AT-M6.6-03：CLI 节点列表子命令解析
#[test]
fn cli_node_list_command_parsing() {
    let cli = Cli::parse_from(["anet", "node", "list"]);
    match cli.command {
        Commands::Node(NodeArgs {
            command: NodeSubcommand::List,
        }) => {}
        _ => panic!("Expected Node List subcommand"),
    }
}

/// AT-M6.6-04：CLI 删除路由子命令解析
#[test]
fn cli_route_delete_arg_parsing() {
    let cli = Cli::parse_from(["anet", "route", "delete", "test-route-id-123"]);
    match cli.command {
        Commands::Route(RouteArgs {
            command: RouteSubcommand::Delete(del_args),
        }) => {
            assert_eq!(del_args.id, "test-route-id-123");
        }
        _ => panic!("Expected Route Delete subcommand"),
    }
}
