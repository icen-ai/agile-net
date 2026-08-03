//! anet-svc — AgileNet server binary entry (implementation in agile_net_node::app).

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    agile_net_node::app::run().await
}
