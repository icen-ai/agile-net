//! Administrator management (`anet admin ...`).

use anyhow::{Context as _, Result, bail};
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
    /// 重置管理员密码（--offline 数据库直连，无需登录；本机操作视为已授权）
    ResetPassword(ResetPasswordArgs),
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

#[derive(Args, Debug)]
pub struct ResetPasswordArgs {
    /// 管理员用户名或 ID 前缀
    pub id: String,
    /// 数据库直连模式（本机操作视为已授权；WAL 并发安全，服务运行中亦可执行）
    #[arg(long)]
    pub offline: bool,
    /// 数据库路径（缺省读 DATABASE_PATH 环境变量，回退 agile-net.db）
    #[arg(long)]
    pub db: Option<String>,
    /// 新密码（缺省交互输入并二次确认）
    #[arg(long)]
    pub password: Option<String>,
}

pub(super) async fn cmd_admin(api: Option<String>, args: AdminArgs, json_out: bool) -> Result<()> {
    // Offline reset bypasses the API entirely: direct DB write, no session required.
    if let AdminSub::ResetPassword(r) = &args.command {
        return reset_password_offline(r, json_out).await;
    }
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
        AdminSub::ResetPassword(_) => unreachable!("handled before session setup"),
    }
    Ok(())
}

/// Offline admin password reset: direct DB write with the local machine as the trust boundary
/// (same idea as the TUI --offline fallback). Revokes the admin's sessions and writes an audit entry.
async fn reset_password_offline(args: &ResetPasswordArgs, json_out: bool) -> Result<()> {
    if !args.offline {
        bail!(
            "reset-password 需显式加 --offline（数据库直连、无需登录；在线改自己的密码请用 admin passwd）"
        );
    }
    let db_path = args
        .db
        .clone()
        .or_else(|| std::env::var("DATABASE_PATH").ok())
        .unwrap_or_else(|| "agile-net.db".to_string());
    let db = crate::db::Database::open(&db_path).context("打开数据库失败")?;

    // Resolve by exact username first, then unique ID prefix.
    let admin = match db.get_admin_by_username(&args.id)? {
        Some(a) => a,
        None => {
            let matches: Vec<_> = db
                .list_admins()?
                .into_iter()
                .filter(|a| a.id.starts_with(&args.id))
                .collect();
            match matches.len() {
                1 => matches.into_iter().next().unwrap(),
                0 => bail!("未找到管理员: {}", args.id),
                _ => bail!("ID 前缀 \"{}\" 匹配到多个管理员，请补全", args.id),
            }
        }
    };

    let password = match &args.password {
        Some(p) => p.clone(),
        None => {
            let p1 = rpassword::prompt_password("新密码（≥10位含大小写数字）: ")
                .context("读取密码失败")?;
            let p2 = rpassword::prompt_password("确认新密码: ").context("读取密码失败")?;
            if p1 != p2 {
                bail!("两次输入的密码不一致");
            }
            p1
        }
    };
    crate::api::handlers::auth::validate_admin_credentials(&admin.username, &password)
        .map_err(|e| anyhow::anyhow!("密码强度不足: {e}"))?;

    // argon2id hashing is CPU-heavy; keep it off the async executor
    let hash = tokio::task::spawn_blocking(move || crate::db::hash_password(&password))
        .await
        .context("哈希任务失败")??;
    db.update_admin_password(&admin.id, &hash)?;
    db.revoke_all_refresh_tokens(&admin.id)?;
    let _ = db.record_audit_log(
        Some(&admin.id),
        "offline-cli",
        "admin.reset_password",
        Some(&admin.username),
        Some("offline database direct reset"),
        None,
    );

    if json_out {
        print_json(&json!({ "id": admin.id, "username": admin.username }));
    } else {
        println!("管理员 {} 的密码已重置（其会话已全部吊销）", admin.username);
        println!("提示：登录限流为进程内存态，若登录仍提示锁定，重启 anet-svc 即可清空");
    }
    Ok(())
}
