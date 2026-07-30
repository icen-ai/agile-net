use agile_net_client::AgileNetClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("⚡ AgileNet Client Core Daemon starting...");
    let client = AgileNetClient::new();
    client.start_proxy(1080).await?;
    println!("Proxy listening on port 1080");
    tokio::signal::ctrl_c().await?;
    client.stop_proxy().await;
    Ok(())
}
