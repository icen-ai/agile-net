//! Log in to an endpoint and save the session (`anet login`).

use anyhow::{Context as _, Result, bail};
use clap::Args;
use serde_json::{Value, json};

use super::common::Session;

#[derive(Args, Debug)]
pub struct LoginArgs {
    #[arg(short, long)]
    pub username: Option<String>,
    #[arg(short, long)]
    pub password: Option<String>,
}

pub(super) async fn cmd_login(api: Option<String>, args: LoginArgs) -> Result<()> {
    let base = api
        .or_else(|| Session::load().map(|s| s.api))
        .unwrap_or_else(|| "http://127.0.0.1:59090".to_string());
    let base = base.trim_end_matches('/').to_string();

    let username = match args.username {
        Some(u) => u,
        None => {
            eprint!("用户名: ");
            let mut s = String::new();
            std::io::stdin().read_line(&mut s)?;
            s.trim().to_string()
        }
    };
    let password = match args.password {
        Some(p) => {
            eprintln!(
                "提示：通过命令行参数传递密码会留在 shell 历史中，建议使用交互式输入（省略 -p）"
            );
            p
        }
        None => rpassword::prompt_password("密码: ").context("读取密码失败")?,
    };

    let http = reqwest::Client::new();
    let resp = http
        .post(format!("{base}/api/v1/auth/login"))
        .json(&json!({ "username": username, "password": password }))
        .send()
        .await
        .context("无法连接节点 API")?;
    let j: Value = resp.json().await?;
    if j["code"].as_i64() != Some(0) {
        bail!("登录失败: {}", j["message"].as_str().unwrap_or("unknown"));
    }
    let session = Session {
        api: base.clone(),
        access_token: j["data"]["access_token"].as_str().unwrap().to_string(),
        refresh_token: j["data"]["refresh_token"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    };
    session.save()?;
    println!("登录成功（{}），会话已保存", base);
    Ok(())
}
