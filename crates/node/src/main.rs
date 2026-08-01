//! anet-svc — AgileNet 服务器二进制入口（实现见 agile_net_node::app）。

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    agile_net_node::app::run().await
}
