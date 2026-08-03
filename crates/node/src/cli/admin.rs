//! 管理员管理（`anet admin ...`）。

use anyhow::{Context as _, Result};
use clap::{Args, Subcommand};
use serde_json::json;

use super::common::{AnetClient, IdOnlyArgs, print_json, print_table, resolve_id};

#[derive(Args, Debug)]
pub struct AdminArgs {
    #[command(subcommand)]
    pub command: AdminSub,
}

#[derive(Subcommand, Debug)]
pub enum AdminSub {
    /// 列出管理员
    List,
    /// 新建管理员
    Add(AdminAddArgs),
    /// 删除管理员
    Delete(IdOnlyArgs),
    /// 修改自己的密码
    Passwd(PasswdArgs),
}

#[derive(Args, Debug)]
pub struct AdminAddArgs {
    #[arg(long)]
    pub username: String,
    #[arg(long)]
    pub password: Option<String>,
}

#[derive(Args, Debug)]
pub struct PasswdArgs {
    /// 旧密码（缺省交互输入）
    #[arg(long)]
    pub old_password: Option<String>,
    /// 新密码（缺省交互输入）
    #[arg(long)]
    pub new_password: Option<String>,
}

pub(super) async fn cmd_admin(api: Option<String>, args: AdminArgs, json_out: bool) -> Result<()> {
    let mut client = AnetClient::from_session(api)?;
    match args.command {
        AdminSub::List => {
            let d = client.api("GET", "/api/v1/admin/admins", None).await?;
            if json_out {
                print_json(&d);
            } else {
                let rows = d["items"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .map(|a| {
                        vec![
                            a["id"].as_str().unwrap_or("")[..8].to_string(),
                            a["username"].as_str().unwrap_or("-").to_string(),
                            a["created_at"].as_str().unwrap_or("-").to_string(),
                        ]
                    })
                    .collect();
                print_table(&["ID", "用户名", "创建时间"], rows);
            }
        }
        AdminSub::Add(a) => {
            let password = match a.password {
                Some(p) => p,
                None => rpassword::prompt_password("新管理员密码: ").context("读取密码失败")?,
            };
            let d = client
                .api(
                    "POST",
                    "/api/v1/admin/admins",
                    Some(json!({
                        "username": a.username, "password": password,
                    })),
                )
                .await?;
            if json_out {
                print_json(&d);
            } else {
                println!("管理员已创建: {}", d["username"].as_str().unwrap_or("-"));
            }
        }
        AdminSub::Delete(d) => {
            let id = resolve_id(&mut client, "/api/v1/admin/admins", &d.id).await?;
            client
                .api("DELETE", &format!("/api/v1/admin/admins/{id}"), None)
                .await?;
            println!("管理员已删除（其会话已吊销）");
        }
        AdminSub::Passwd(p) => {
            let old_password = match p.old_password {
                Some(v) => v,
                None => rpassword::prompt_password("旧密码: ").context("读取密码失败")?,
            };
            let new_password = match p.new_password {
                Some(v) => v,
                None => rpassword::prompt_password("新密码（≥10位含大小写数字）: ")
                    .context("读取密码失败")?,
            };
            let d = client
                .api(
                    "PUT",
                    "/api/v1/auth/password",
                    Some(json!({
                        "old_password": old_password, "new_password": new_password,
                    })),
                )
                .await?;
            println!("{}", d["message"].as_str().unwrap_or("密码已修改"));
        }
    }
    Ok(())
}
