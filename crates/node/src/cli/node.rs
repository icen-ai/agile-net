//! Endpoint status overview and rename (shared by `anet status` and `anet node status|rename`).

use anyhow::Result;
use serde_json::json;

use super::common::{AnetClient, print_json};

/// Node status overview (`anet-svc node status`).
pub async fn cmd_node_status(api: Option<String>, json_out: bool) -> Result<()> {
    let mut client = AnetClient::from_session(api)?;
    let d = client.api("GET", "/api/v1/admin/node/status", None).await?;
    if json_out {
        print_json(&d);
    } else {
        println!("端点状态");
        println!("  名称:     {}", d["node_name"].as_str().unwrap_or("-"));
        println!("  版本:     v{}", d["version"].as_str().unwrap_or("-"));
        println!("  运行时长: {}s", d["uptime"].as_u64().unwrap_or(0));
        let l = &d["roles"]["listener"];
        println!(
            "  Relay:    {} (扇入 {} · 在线客户端 {})",
            if l["enabled"].as_bool().unwrap_or(false) {
                l["addr"].as_str().unwrap_or("启用")
            } else {
                "未启用"
            },
            l["connected_connectors"].as_u64().unwrap_or(0),
            l["online_clients"].as_u64().unwrap_or(0)
        );
        let cs_summary = d["roles"]["connector_status"].as_str().unwrap_or("disabled");
        println!(
            "  扇出:     {}",
            if cs_summary == "disabled" {
                "未配置".to_string()
            } else {
                d["roles"]["connectors"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .map(|c| {
                                format!(
                                    "{} [{}]",
                                    c["upstream"].as_str().unwrap_or("-"),
                                    c["status"].as_str().unwrap_or("-")
                                )
                            })
                            .collect::<Vec<_>>()
                            .join(" · ")
                    })
                    .unwrap_or_else(|| "-".into())
            }
        );
    }
    Ok(())
}

/// Endpoint rename (`anet-svc node rename <name>`; written to config, effective immediately, audited).
pub async fn cmd_node_rename(api: Option<String>, name: String) -> Result<()> {
    let mut client = AnetClient::from_session(api)?;
    client
        .api(
            "PUT",
            "/api/v1/admin/node/settings",
            Some(json!({ "node_name": name })),
        )
        .await?;
    println!("端点已更名");
    Ok(())
}
