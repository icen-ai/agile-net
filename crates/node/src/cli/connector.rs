//! 扇出对端管理（`anet connector ...`）。

use anyhow::{Result, anyhow};
use clap::{Args, Subcommand};
use serde_json::json;

use super::common::{AnetClient, IdOnlyArgs, print_json, print_table, resolve_id, split_csv};

#[derive(Args, Debug)]
pub struct ConnectorArgs {
    #[command(subcommand)]
    pub command: ConnectorSub,
}

#[derive(Subcommand, Debug)]
pub enum ConnectorSub {
    /// 列出扇出对端（含实时状态）
    List,
    /// 新增扇出对端（token 为对端签发凭据，加密落库不回显）
    Add(ConnectorAddArgs),
    /// 更新扇出对端（缺省参数保留原值；--token 留空 = 保留原 token）
    Update(ConnectorUpdateArgs),
    /// 删除扇出对端
    Remove(IdOnlyArgs),
    /// 启用扇出对端（装配起连）
    Enable(IdOnlyArgs),
    /// 禁用扇出对端（断开移除，记录保留）
    Disable(IdOnlyArgs),
}

#[derive(Args, Debug)]
pub struct ConnectorAddArgs {
    /// 对端显示名（管理端列表/审计用）
    #[arg(long)]
    pub name: String,
    /// 上游地址（host:port）
    #[arg(long)]
    pub addr: String,
    /// 扇出 token（对端签发；加密落库，创建后不回显）
    #[arg(long)]
    pub token: String,
    /// SNI 主机名（TLS 校验用）
    #[arg(long)]
    pub sni: Option<String>,
    /// 跳过 TLS 证书校验（仅调试用）
    #[arg(long)]
    pub insecure: bool,
    /// 宣告路由（逗号分隔，如 10.0.0.0/8,git.internal）
    #[arg(long)]
    pub advertise: Option<String>,
    /// 收敛权限组（名称或 ID；缺省 = 不收敛，放行一切）
    #[arg(long)]
    pub group: Option<String>,
    #[arg(long)]
    pub remark: Option<String>,
}

#[derive(Args, Debug)]
pub struct ConnectorUpdateArgs {
    /// 对端 ID（支持前缀）或名称
    pub id: String,
    #[arg(long)]
    pub name: Option<String>,
    /// 上游地址（host:port）
    #[arg(long)]
    pub addr: Option<String>,
    /// 重置扇出 token（留空 = 保留原值）
    #[arg(long)]
    pub token: Option<String>,
    #[arg(long)]
    pub sni: Option<String>,
    #[arg(long)]
    pub insecure: Option<bool>,
    /// 宣告路由（逗号分隔；缺省 = 保留原值）
    #[arg(long)]
    pub advertise: Option<String>,
    /// 收敛权限组（名称或 ID；缺省 = 保持原组）
    #[arg(long)]
    pub group: Option<String>,
    #[arg(long)]
    pub remark: Option<String>,
}

pub(super) async fn cmd_connector(
    api: Option<String>,
    args: ConnectorArgs,
    json_out: bool,
) -> Result<()> {
    let mut client = AnetClient::from_session(api)?;
    match args.command {
        ConnectorSub::List => {
            let d = client.api("GET", "/api/v1/admin/connectors", None).await?;
            if json_out {
                print_json(&d);
            } else {
                let rows = d["items"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .map(|c| {
                        vec![
                            c["id"].as_str().unwrap_or("")[..8].to_string(),
                            c["name"].as_str().unwrap_or("-").to_string(),
                            c["upstream_addr"].as_str().unwrap_or("-").to_string(),
                            c["group_name"].as_str().unwrap_or("不收敛").to_string(),
                            c["state"].as_str().unwrap_or("-").to_string(),
                            if c["enabled"].as_bool().unwrap_or(false) {
                                "启用"
                            } else {
                                "禁用"
                            }
                            .to_string(),
                            c["remark"].as_str().unwrap_or("-").to_string(),
                        ]
                    })
                    .collect();
                print_table(
                    &["ID", "名称", "上游地址", "权限组", "状态", "启用", "备注"],
                    rows,
                );
            }
        }
        ConnectorSub::Add(a) => {
            let group_id = match &a.group {
                Some(g) => {
                    Some(resolve_id(&mut client, "/api/v1/admin/groups?page_size=100", g).await?)
                }
                None => None,
            };
            let d = client
                .api(
                    "POST",
                    "/api/v1/admin/connectors",
                    Some(json!({
                        "name": a.name, "upstream_addr": a.addr, "token": a.token,
                        "sni_hostname": a.sni.unwrap_or_default(), "insecure": a.insecure,
                        "advertise": split_csv(a.advertise.as_deref().unwrap_or_default()),
                        "group_id": group_id, "remark": a.remark.unwrap_or_default(),
                    })),
                )
                .await?;
            if json_out {
                print_json(&d);
            } else {
                println!("扇出对端已创建: {}", d["name"].as_str().unwrap_or("-"));
                println!("   token 已加密落库不再回显；更换请用 update --token 重置");
            }
        }
        ConnectorSub::Update(u) => {
            let id = resolve_id(&mut client, "/api/v1/admin/connectors", &u.id).await?;
            // PUT 为全量替换（缺省 group_id 即置不收敛）：先取现值合并，缺省参数一律保留原值
            let d = client.api("GET", "/api/v1/admin/connectors", None).await?;
            let cur = d["items"]
                .as_array()
                .and_then(|items| items.iter().find(|c| c["id"].as_str() == Some(id.as_str())))
                .cloned()
                .ok_or_else(|| anyhow!("未找到扇出对端 {id}"))?;
            let advertise = match &u.advertise {
                Some(s) => split_csv(s),
                None => split_csv(cur["advertise"].as_str().unwrap_or_default()),
            };
            let mut body = json!({
                "name": u.name.unwrap_or_else(|| cur["name"].as_str().unwrap_or_default().to_string()),
                "upstream_addr": u.addr.unwrap_or_else(|| cur["upstream_addr"].as_str().unwrap_or_default().to_string()),
                "sni_hostname": u.sni.unwrap_or_else(|| cur["sni_hostname"].as_str().unwrap_or_default().to_string()),
                "insecure": u.insecure.unwrap_or_else(|| cur["insecure"].as_bool().unwrap_or(false)),
                "ca_cert_path": cur["ca_cert_path"].as_str().unwrap_or_default(),
                "pinned_cert_path": cur["pinned_cert_path"].as_str().unwrap_or_default(),
                "advertise": advertise,
                "group_id": cur["group_id"],
                "remark": u.remark.unwrap_or_else(|| cur["remark"].as_str().unwrap_or_default().to_string()),
            });
            // token 留空 = 保留原值（服务端空串/null 视为未提供，绝不回显）
            if let Some(t) = u.token.filter(|t| !t.is_empty()) {
                body["token"] = json!(t);
            }
            // 显式 --group 才换组（名称或 ID 解析）
            if let Some(g) = &u.group {
                body["group_id"] = json!(
                    resolve_id(&mut client, "/api/v1/admin/groups?page_size=100", g).await?
                );
            }
            let d = client
                .api("PUT", &format!("/api/v1/admin/connectors/{id}"), Some(body))
                .await?;
            if json_out {
                print_json(&d);
            } else {
                println!("扇出对端已更新: {}", d["name"].as_str().unwrap_or("-"));
            }
        }
        ConnectorSub::Remove(r) => {
            let id = resolve_id(&mut client, "/api/v1/admin/connectors", &r.id).await?;
            client
                .api("DELETE", &format!("/api/v1/admin/connectors/{id}"), None)
                .await?;
            println!("扇出对端已删除");
        }
        ConnectorSub::Enable(e) => {
            let id = resolve_id(&mut client, "/api/v1/admin/connectors", &e.id).await?;
            let d = client
                .api("POST", &format!("/api/v1/admin/connectors/{id}/enable"), None)
                .await?;
            if json_out {
                print_json(&d);
            } else {
                println!("扇出对端已启用: {}", d["name"].as_str().unwrap_or("-"));
            }
        }
        ConnectorSub::Disable(e) => {
            let id = resolve_id(&mut client, "/api/v1/admin/connectors", &e.id).await?;
            let d = client
                .api("POST", &format!("/api/v1/admin/connectors/{id}/disable"), None)
                .await?;
            if json_out {
                print_json(&d);
            } else {
                println!("扇出对端已禁用: {}", d["name"].as_str().unwrap_or("-"));
            }
        }
    }
    Ok(())
}
