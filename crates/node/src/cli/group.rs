//! Group management (`anet group ...`).

use anyhow::Result;
use clap::{Args, Subcommand};
use serde_json::json;

use super::common::{AnetClient, IdArgs, IdOnlyArgs, ListArgs, print_json, print_table, resolve_id};

#[derive(Args, Debug)]
pub struct GroupArgs {
    #[command(subcommand)]
    pub command: GroupSub,
}

#[derive(Subcommand, Debug)]
pub enum GroupSub {
    /// 列出权限组（支持搜索/分页）
    List(ListArgs),
    /// 查看权限组详情（含绑定规则）
    Show(IdOnlyArgs),
    /// 新建权限组（可同时绑定规则）
    Add(GroupAddArgs),
    /// 更新权限组名称/备注
    Update(GroupUpdateArgs),
    /// 删除权限组（--force 解除账号引用）
    Delete(IdArgs),
    /// 全量设置绑定规则（传规则 ID 列表）
    SetRules(SetRulesArgs),
}

#[derive(Args, Debug)]
pub struct GroupAddArgs {
    #[arg(long)]
    pub name: String,
    #[arg(long)]
    pub remark: Option<String>,
    /// 逗号分隔的规则 ID
    #[arg(long)]
    pub rule_ids: Option<String>,
}

#[derive(Args, Debug)]
pub struct GroupUpdateArgs {
    pub id: String,
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub remark: Option<String>,
}

#[derive(Args, Debug)]
pub struct SetRulesArgs {
    pub id: String,
    /// 规则 ID 列表（空格分隔，支持前缀）
    pub rule_ids: Vec<String>,
}

pub(super) async fn cmd_group(api: Option<String>, args: GroupArgs, json_out: bool) -> Result<()> {
    let mut client = AnetClient::from_session(api)?;
    match args.command {
        GroupSub::List(l) => {
            let mut path = format!("/api/v1/admin/groups?page={}&page_size=20", l.page);
            if let Some(q) = &l.q {
                path += &format!("&q={q}");
            }
            let d = client.api("GET", &path, None).await?;
            if json_out {
                print_json(&d);
            } else {
                let rows = d["items"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .map(|g| {
                        vec![
                            g["id"].as_str().unwrap_or("")[..8].to_string(),
                            g["name"].as_str().unwrap_or("-").to_string(),
                            g["rule_count"].as_i64().unwrap_or(0).to_string(),
                            g["account_count"].as_i64().unwrap_or(0).to_string(),
                            g["remark"].as_str().unwrap_or("-").to_string(),
                        ]
                    })
                    .collect();
                print_table(&["ID", "名称", "规则数", "账号数", "备注"], rows);
                println!("共 {} 条", d["total"].as_i64().unwrap_or(0));
            }
        }
        GroupSub::Show(s) => {
            let id = resolve_id(&mut client, "/api/v1/admin/groups?page_size=100", &s.id).await?;
            let d = client
                .api("GET", &format!("/api/v1/admin/groups/{id}"), None)
                .await?;
            print_json(&d);
        }
        GroupSub::Add(a) => {
            let rule_ids: Vec<String> = match &a.rule_ids {
                Some(s) => {
                    let mut ids = Vec::new();
                    for part in s.split(',').map(|p| p.trim()).filter(|p| !p.is_empty()) {
                        ids.push(
                            resolve_id(&mut client, "/api/v1/admin/rules?page_size=100", part)
                                .await?,
                        );
                    }
                    ids
                }
                None => Vec::new(),
            };
            let d = client.api("POST", "/api/v1/admin/groups", Some(json!({
                "name": a.name, "remark": a.remark.unwrap_or_default(), "rule_ids": rule_ids,
            }))).await?;
            if json_out {
                print_json(&d);
            } else {
                println!("权限组已创建: {}", d["name"].as_str().unwrap_or("-"));
            }
        }
        GroupSub::Update(u) => {
            let id = resolve_id(&mut client, "/api/v1/admin/groups?page_size=100", &u.id).await?;
            let mut body = json!({});
            if let Some(n) = u.name {
                body["name"] = json!(n);
            }
            if let Some(r) = u.remark {
                body["remark"] = json!(r);
            }
            let d = client
                .api("PUT", &format!("/api/v1/admin/groups/{id}"), Some(body))
                .await?;
            if json_out {
                print_json(&d);
            } else {
                println!("权限组已更新: {}", d["name"].as_str().unwrap_or("-"));
            }
        }
        GroupSub::Delete(d) => {
            let id = resolve_id(&mut client, "/api/v1/admin/groups?page_size=100", &d.id).await?;
            let path = if d.force {
                format!("/api/v1/admin/groups/{id}?force=true")
            } else {
                format!("/api/v1/admin/groups/{id}")
            };
            client.api("DELETE", &path, None).await?;
            println!("权限组已删除");
        }
        GroupSub::SetRules(s) => {
            let id = resolve_id(&mut client, "/api/v1/admin/groups?page_size=100", &s.id).await?;
            let mut ids = Vec::new();
            for prefix in &s.rule_ids {
                ids.push(
                    resolve_id(&mut client, "/api/v1/admin/rules?page_size=100", prefix).await?,
                );
            }
            let d = client
                .api(
                    "PUT",
                    &format!("/api/v1/admin/groups/{id}/rules"),
                    Some(json!({
                        "rule_ids": ids,
                    })),
                )
                .await?;
            println!(
                "规则绑定已更新（{} 条）",
                d["rule_count"].as_i64().unwrap_or(0)
            );
        }
    }
    Ok(())
}
