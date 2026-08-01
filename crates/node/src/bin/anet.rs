//! anet — AgileNet 管理命令入口（与 anet-svc 同一实现，按 argv[0] 分人格）。

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    agile_net_node::app::run().await
}
