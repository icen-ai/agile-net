//! Relay token management (`anet token ...`).

use anyhow::Result;
use clap::{Args, Subcommand};
use serde_json::json;

use super::common::{
    AnetClient, IdOnlyArgs, group_set_display, print_json, print_table, resolve_id, resolve_id_set,
};

#[derive(Args, Debug)]
pub struct TokenArgs {
    #[command(subcommand)]
    pub command: TokenSub,
}

#[derive(Subcommand, Debug)]
pub enum TokenSub {
    /// 列出令牌（前缀/权限组/暴露控制面/档位/最近使用）
    List,
    /// 生成令牌（明文仅显示一次；--group 收敛到权限组，--expose-control 暴露控制面）
    #[command(alias = "create")]
    Add(TokenAddArgs),
    /// 吊销令牌（在线下游立即被踢）
    Delete(IdOnlyArgs),
}

#[derive(Args, Debug)]
pub struct TokenAddArgs {
    #[arg(long)]
    pub remark: Option<String>,
    /// 允许持该令牌的下游中继管理本端点（暴露控制面，默认关）
    #[arg(long)]
    pub expose_control: bool,
    /// 控制面授权档位：ro（只读）/ rules（可改规则）/ full（全权）
    #[arg(long, default_value = "full", value_parser = ["ro", "rules", "full"])]
    pub scope: String,
    /// 收敛权限组（名称或 ID，逗号分隔可多组取并集；缺省 = 不收敛，放行一切）
    #[arg(long)]
    pub group: Option<String>,
    /// 带宽配额（KB/s；缺省 = 不限，须为正整数）
    #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
    pub rate_limit_kbps: Option<i64>,
}

pub(super) async fn cmd_token(api: Option<String>, args: TokenArgs, json_out: bool) -> Result<()> {
    let mut client = AnetClient::from_session(api)?;
    match args.command {
        TokenSub::List => {
            let d = client
                .api("GET", "/api/v1/admin/node/relay-tokens", None)
                .await?;
            if json_out {
                print_json(&d);
            } else {
                let rows = d["items"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .map(|t| {
                        vec![
                            t["id"].as_str().unwrap_or("")[..8].to_string(),
                            t["token_prefix"].as_str().unwrap_or("-").to_string(),
                            group_set_display(t, "不收敛"),
                            if t["expose_control"].as_bool().unwrap_or(false) {
                                t["control_scope"].as_str().unwrap_or("开").to_string()
                            } else {
                                "关".to_string()
                            },
                            t["rate_limit_kbps"]
                                .as_i64()
                                .map(|v| v.to_string())
                                .unwrap_or_else(|| "-".to_string()),
                            t["remark"].as_str().unwrap_or("-").to_string(),
                            t["last_used_at"].as_str().unwrap_or("未使用").to_string(),
                            t["created_at"].as_str().unwrap_or("-").to_string(),
                        ]
                    })
                    .collect();
                print_table(
                    &["ID", "前缀", "权限组", "暴露面", "限速KB/s", "备注", "最近使用", "创建时间"],
                    rows,
                );
            }
        }
        TokenSub::Add(a) => {
            let group_id = match &a.group {
                Some(g) => {
                    resolve_id_set(&mut client, "/api/v1/admin/groups?page_size=100", g).await?
                }
                None => None,
            };
            let d = client
                .api(
                    "POST",
                    "/api/v1/admin/node/relay-tokens",
                    Some(json!({
                        "remark": a.remark.unwrap_or_default(),
                        "expose_control": a.expose_control,
                        "control_scope": a.scope,
                        "group_id": group_id,
                        "rate_limit_kbps": a.rate_limit_kbps,
                    })),
                )
                .await?;
            if json_out {
                print_json(&d);
            } else {
                println!(
                    "Relay 令牌已生成（仅此一次）: {}",
                    d["token"].as_str().unwrap_or("-")
                );
                if let Some(g) = &a.group {
                    println!("   已收敛到权限组: {g}");
                }
                if a.expose_control {
                    println!("   已暴露控制面（档位 {}）：持令牌下游可管理本端点", a.scope);
                }
                if let Some(kbps) = a.rate_limit_kbps {
                    println!("   带宽配额: {kbps} KB/s");
                }
                println!("   服务端只存哈希，请立即保存");
            }
        }
        TokenSub::Delete(d) => {
            let id = resolve_id(&mut client, "/api/v1/admin/node/relay-tokens", &d.id).await?;
            client
                .api(
                    "DELETE",
                    &format!("/api/v1/admin/node/relay-tokens/{id}"),
                    None,
                )
                .await?;
            println!("令牌已吊销");
        }
    }
    Ok(())
}
