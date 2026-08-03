//! Audit log queries (`anet audit ...`).

use anyhow::Result;
use clap::{Args, Subcommand};

use super::common::{AnetClient, print_json, print_table};

#[derive(Args, Debug)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub command: AuditSub,
}

#[derive(Subcommand, Debug)]
pub enum AuditSub {
    List(AuditListArgs),
}

#[derive(Args, Debug)]
pub struct AuditListArgs {
    /// 按动作过滤（如 account.create）
    #[arg(long)]
    pub action: Option<String>,
    #[arg(long, default_value = "1")]
    pub page: u32,
}

pub(super) async fn cmd_audit(api: Option<String>, args: AuditArgs, json_out: bool) -> Result<()> {
    let mut client = AnetClient::from_session(api)?;
    match args.command {
        AuditSub::List(l) => {
            let mut path = format!("/api/v1/admin/audit-logs?page={}&page_size=20", l.page);
            if let Some(a) = &l.action {
                path += &format!("&action={a}");
            }
            let d = client.api("GET", &path, None).await?;
            if json_out {
                print_json(&d);
            } else {
                let rows = d["items"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .map(|l| {
                        vec![
                            l["created_at"]
                                .as_str()
                                .unwrap_or("-")
                                .replace('T', " ")
                                .replace('Z', ""),
                            l["operator"].as_str().unwrap_or("-").to_string(),
                            l["action"].as_str().unwrap_or("-").to_string(),
                            l["target"]
                                .as_str()
                                .unwrap_or("-")
                                .chars()
                                .take(8)
                                .collect(),
                            l["ip"].as_str().unwrap_or("-").to_string(),
                        ]
                    })
                    .collect();
                print_table(&["时间", "操作人", "动作", "目标", "来源 IP"], rows);
                println!("共 {} 条", d["total"].as_i64().unwrap_or(0));
            }
        }
    }
    Ok(())
}
