//! anet — AgileNet admin command entry (same implementation as anet-svc, persona by argv[0]).

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    agile_net_node::app::run().await
}
