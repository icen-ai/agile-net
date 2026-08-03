//! 路由规则管理（`anet rule ...`）。

use anyhow::{Context as _, Result};
use clap::{Args, Subcommand};
use serde_json::{Value, json};

use super::common::{AnetClient, IdArgs, ListArgs, print_json, print_table, resolve_id};

#[derive(Args, Debug)]
pub struct RuleArgs {
    #[command(subcommand)]
    pub command: RuleSub,
}

#[derive(Subcommand, Debug)]
pub enum RuleSub {
    /// 列出规则
    List(ListArgs),
    /// 新建规则
    Add(RuleAddArgs),
    /// 更新规则
    Update(RuleUpdateArgs),
    /// 删除规则
    Delete(IdArgs),
    /// 批量导入（JSON 文件）
    Batch(BatchArgs),
}

#[derive(Args, Debug)]
pub struct RuleAddArgs {
    /// 类型：ip-cidr 或 host
    #[arg(long = "type")]
    pub rule_type: String,
    /// 匹配值（10.12.0.0/16 或 git.internal）
    #[arg(long)]
    pub value: String,
    /// host 需要客户端写入系统 hosts
    #[arg(long)]
    pub resolve: bool,
    #[arg(long)]
    pub remark: Option<String>,
}

#[derive(Args, Debug)]
pub struct RuleUpdateArgs {
    pub id: String,
    #[arg(long)]
    pub value: Option<String>,
    #[arg(long)]
    pub resolve: Option<bool>,
    #[arg(long)]
    pub remark: Option<String>,
}

#[derive(Args, Debug)]
pub struct BatchArgs {
    /// JSON 文件路径
    pub file: String,
    /// 冲突处理：skip / overwrite / error
    #[arg(long, default_value = "skip")]
    pub on_conflict: String,
}

pub(super) async fn cmd_rule(api: Option<String>, args: RuleArgs, json_out: bool) -> Result<()> {
    let mut client = AnetClient::from_session(api)?;
    match args.command {
        RuleSub::List(l) => {
            let mut path = format!("/api/v1/admin/rules?page={}&page_size=20", l.page);
            if let Some(q) = &l.q {
                path += &format!("&q={q}");
            }
            if let Some(t) = &l.type_filter {
                path += &format!("&type={t}");
            }
            let d = client.api("GET", &path, None).await?;
            if json_out {
                print_json(&d);
            } else {
                let rows = d["items"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .map(|r| {
                        vec![
                            r["id"].as_str().unwrap_or("")[..8].to_string(),
                            r["type"].as_str().unwrap_or("-").to_string(),
                            r["value"].as_str().unwrap_or("-").to_string(),
                            if r["resolve"].as_bool().unwrap_or(false) {
                                "是"
                            } else {
                                "否"
                            }
                            .to_string(),
                            r["group_count"].as_i64().unwrap_or(0).to_string(),
                            r["remark"].as_str().unwrap_or("-").to_string(),
                        ]
                    })
                    .collect();
                print_table(&["ID", "类型", "匹配值", "解析", "引用组", "备注"], rows);
                println!("共 {} 条", d["total"].as_i64().unwrap_or(0));
            }
        }
        RuleSub::Add(a) => {
            let d = client
                .api(
                    "POST",
                    "/api/v1/admin/rules",
                    Some(json!({
                        "type": a.rule_type, "value": a.value,
                        "resolve": a.resolve, "remark": a.remark.unwrap_or_default(),
                    })),
                )
                .await?;
            if json_out {
                print_json(&d);
            } else {
                println!("规则已创建: {}", d["value"].as_str().unwrap_or("-"));
            }
        }
        RuleSub::Update(u) => {
            let id = resolve_id(&mut client, "/api/v1/admin/rules?page_size=100", &u.id).await?;
            let mut body = json!({});
            if let Some(v) = u.value {
                body["value"] = json!(v);
            }
            if let Some(r) = u.resolve {
                body["resolve"] = json!(r);
            }
            if let Some(r) = u.remark {
                body["remark"] = json!(r);
            }
            let d = client
                .api("PUT", &format!("/api/v1/admin/rules/{id}"), Some(body))
                .await?;
            if json_out {
                print_json(&d);
            } else {
                println!("规则已更新: {}", d["value"].as_str().unwrap_or("-"));
            }
        }
        RuleSub::Delete(d) => {
            let id = resolve_id(&mut client, "/api/v1/admin/rules?page_size=100", &d.id).await?;
            let path = if d.force {
                format!("/api/v1/admin/rules/{id}?force=true")
            } else {
                format!("/api/v1/admin/rules/{id}")
            };
            client.api("DELETE", &path, None).await?;
            println!("规则已删除");
        }
        RuleSub::Batch(b) => {
            let text = std::fs::read_to_string(&b.file)
                .with_context(|| format!("读取文件失败: {}", b.file))?;
            let rules: Value = serde_json::from_str(&text).context("JSON 解析失败")?;
            let d = client
                .api(
                    "POST",
                    "/api/v1/admin/rules/batch",
                    Some(json!({
                        "rules": rules, "on_conflict": b.on_conflict,
                    })),
                )
                .await?;
            if json_out {
                print_json(&d);
            } else {
                println!(
                    "导入完成: 新建 {} · 跳过 {} · 更新 {} · 错误 {}",
                    d["created"],
                    d["skipped"],
                    d["updated"],
                    d["errors"].as_array().map(|e| e.len()).unwrap_or(0)
                );
            }
        }
    }
    Ok(())
}
