//! Client account management (`anet account ...`).

use anyhow::Result;
use clap::{Args, Subcommand};
use serde_json::json;

use super::common::{AnetClient, IdArgs, IdOnlyArgs, print_json, print_table, resolve_id};

#[derive(Args, Debug)]
pub struct AccountArgs {
    #[command(subcommand)]
    pub command: AccountSub,
}

#[derive(Subcommand, Debug)]
pub enum AccountSub {
    /// 列出账号（搜索/权限组/状态过滤）
    List(AccountListArgs),
    /// 新建账号（密码与接入链接仅显示一次；--admin 签发管理版链接）
    Add(AccountAddArgs),
    /// 更新账号（换组/启停/备注/管理权限收放）
    Update(AccountUpdateArgs),
    /// 删除账号
    Delete(IdArgs),
    /// 重置密码（新密码与接入链接仅显示一次）
    ResetPassword(IdOnlyArgs),
}

#[derive(Args, Debug)]
pub struct AccountListArgs {
    #[arg(short, long)]
    pub q: Option<String>,
    #[arg(long)]
    pub page: Option<u32>,
    /// 按权限组过滤（组 ID 或前缀）
    #[arg(long)]
    pub group: Option<String>,
    /// 按状态过滤
    #[arg(long)]
    pub enabled: Option<bool>,
}

#[derive(Args, Debug)]
pub struct AccountAddArgs {
    #[arg(long)]
    pub username: String,
    /// 权限组（ID 或前缀）
    #[arg(long)]
    pub group: String,
    #[arg(long)]
    pub remark: Option<String>,
    /// 同时授予管理权限（签发管理版接入链接，签发记审计，仅发给可信管理员）
    #[arg(long)]
    pub admin: bool,
}

#[derive(Args, Debug)]
pub struct AccountUpdateArgs {
    pub id: String,
    #[arg(long)]
    pub group: Option<String>,
    #[arg(long)]
    pub enabled: Option<bool>,
    #[arg(long)]
    pub remark: Option<String>,
    /// 管理权限收放（true 授予 / false 收回，变更记审计）
    #[arg(long)]
    pub admin: Option<bool>,
}

pub(super) async fn cmd_account(
    api: Option<String>,
    args: AccountArgs,
    json_out: bool,
) -> Result<()> {
    let mut client = AnetClient::from_session(api)?;
    match args.command {
        AccountSub::List(l) => {
            let mut path = format!(
                "/api/v1/admin/accounts?page={}&page_size=20",
                l.page.unwrap_or(1)
            );
            if let Some(q) = &l.q {
                path += &format!("&q={q}");
            }
            if let Some(g) = &l.group {
                let gid = resolve_id(&mut client, "/api/v1/admin/groups?page_size=100", g).await?;
                path += &format!("&group_id={gid}");
            }
            if let Some(e) = l.enabled {
                path += &format!("&enabled={e}");
            }
            let d = client.api("GET", &path, None).await?;
            if json_out {
                print_json(&d);
            } else {
                let rows = d["items"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .map(|a| {
                        vec![
                            a["username"].as_str().unwrap_or("-").to_string(),
                            a["group_name"].as_str().unwrap_or("-").to_string(),
                            if a["online"].as_bool().unwrap_or(false) {
                                "在线"
                            } else {
                                "离线"
                            }
                            .to_string(),
                            if a["enabled"].as_bool().unwrap_or(false) {
                                "启用"
                            } else {
                                "禁用"
                            }
                            .to_string(),
                            a["last_seen_at"].as_str().unwrap_or("从未").to_string(),
                            a["remark"].as_str().unwrap_or("-").to_string(),
                            a["id"].as_str().unwrap_or("")[..8].to_string(),
                        ]
                    })
                    .collect();
                print_table(
                    &["账号", "权限组", "在线", "状态", "最后在线", "备注", "ID"],
                    rows,
                );
                println!("共 {} 条", d["total"].as_i64().unwrap_or(0));
            }
        }
        AccountSub::Add(a) => {
            let gid =
                resolve_id(&mut client, "/api/v1/admin/groups?page_size=100", &a.group).await?;
            let d = client.api("POST", "/api/v1/admin/accounts", Some(json!({
                "username": a.username, "group_id": gid, "remark": a.remark.unwrap_or_default(),
                "admin_console": a.admin,
            }))).await?;
            if json_out {
                print_json(&d);
            } else {
                println!("账号已创建: {}", d["username"].as_str().unwrap_or("-"));
                println!(
                    "   密码（仅此一次）: {}",
                    d["password"].as_str().unwrap_or("-")
                );
                println!("   接入链接: {}", d["connect_url"].as_str().unwrap_or("-"));
                if a.admin {
                    println!("   已授予管理权限：该链接可登录端点控制台，请按管理员凭据级别保管");
                }
                println!("   请立即保存，密码不可找回");
            }
        }
        AccountSub::Update(u) => {
            let id = resolve_id(&mut client, "/api/v1/admin/accounts?page_size=100", &u.id).await?;
            let mut body = json!({});
            if let Some(g) = &u.group {
                let gid = resolve_id(&mut client, "/api/v1/admin/groups?page_size=100", g).await?;
                body["group_id"] = json!(gid);
            }
            if let Some(e) = u.enabled {
                body["enabled"] = json!(e);
            }
            if let Some(r) = u.remark {
                body["remark"] = json!(r);
            }
            if let Some(adm) = u.admin {
                body["admin_console"] = json!(adm);
            }
            client
                .api("PUT", &format!("/api/v1/admin/accounts/{id}"), Some(body))
                .await?;
            println!("账号已更新");
        }
        AccountSub::Delete(d) => {
            let id = resolve_id(&mut client, "/api/v1/admin/accounts?page_size=100", &d.id).await?;
            client
                .api("DELETE", &format!("/api/v1/admin/accounts/{id}"), None)
                .await?;
            println!("账号已删除");
        }
        AccountSub::ResetPassword(r) => {
            let id = resolve_id(&mut client, "/api/v1/admin/accounts?page_size=100", &r.id).await?;
            let d = client
                .api(
                    "POST",
                    &format!("/api/v1/admin/accounts/{id}/reset-password"),
                    None,
                )
                .await?;
            if json_out {
                print_json(&d);
            } else {
                println!(
                    "密码已重置（仅此一次）: {}",
                    d["password"].as_str().unwrap_or("-")
                );
                println!("   接入链接: {}", d["connect_url"].as_str().unwrap_or("-"));
            }
        }
    }
    Ok(())
}
