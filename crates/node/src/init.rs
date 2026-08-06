//! `anet init` interactive setup wizard (first-install experience).
//!
//! Steps: config file -> endpoint name -> Web admin/API listen -> Relay listener -> admin -> system service -> start.
//! - Interactive: Enter accepts defaults; password typed twice + strength check
//! - Non-interactive (automation): `--yes` + `AGILE_ADMIN_PASSWORD` (optional AGILE_ADMIN_USERNAME)
//! - System service: auto-detects distro (Ubuntu / Rocky / Kylin / UOS and other systemd
//!   systems), registers and starts; without systemd or root, falls back to printing manual
//!   instructions; on Windows registers via sc.exe

use anyhow::{Context, Result, bail};
use clap::Args;
use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Skip confirmation and use defaults (password still required via AGILE_ADMIN_PASSWORD or TTY)
    #[arg(short = 'y', long)]
    pub yes: bool,
    /// Config file path (defaults to ~/.anet/svc/agile-net.toml)
    #[arg(long)]
    pub config: Option<String>,
    /// Endpoint name (defaults to local hostname)
    #[arg(long)]
    pub name: Option<String>,
    /// API/Web admin listen address (Web admin UI comes up with the API)
    #[arg(long, default_value = "127.0.0.1:59090")]
    pub api: String,
    /// Database path (defaults to agile-net.db next to the config file)
    #[arg(long)]
    pub db: Option<String>,
    /// Disable the Relay listener (default on at 0.0.0.0:54430, cert auto-generated on first start)
    #[arg(long)]
    pub no_listener: bool,
    /// Do not register a system service
    #[arg(long)]
    pub no_service: bool,
    /// Print the systemd unit without writing it (debug/audit)
    #[arg(long, hide = true)]
    pub print_service: bool,
}

// ==================== Interactive input ====================

fn tty() -> bool {
    std::io::stdin().is_terminal()
}

fn prompt(label: &str, default: &str) -> Result<String> {
    eprint!("{label} [{default}]: ");
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    let s = s.trim();
    Ok(if s.is_empty() { default.to_string() } else { s.to_string() })
}

fn prompt_yes_no(label: &str, default_yes: bool) -> Result<bool> {
    let hint = if default_yes { "Y/n" } else { "y/N" };
    eprint!("{label} [{hint}]: ");
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    let s = s.trim().to_ascii_lowercase();
    Ok(match s.as_str() {
        "" => default_yes,
        "y" | "yes" => true,
        "n" | "no" => false,
        _ => default_yes,
    })
}

fn prompt_password_twice() -> Result<String> {
    loop {
        let p1 = rpassword::prompt_password("管理员密码（≥10位，含大小写与数字）: ")
            .context("读取密码失败")?;
        let p2 = rpassword::prompt_password("再次输入确认: ").context("读取密码失败")?;
        if p1 != p2 {
            eprintln!("两次输入不一致，请重试");
            continue;
        }
        return Ok(p1);
    }
}

// ==================== OS / systemd detection ====================

#[derive(Debug, Clone, PartialEq)]
pub struct OsInfo {
    pub id: String,
    pub pretty: String,
    pub systemd: bool,
}

/// Parse /etc/os-release content (ubuntu/debian/rocky/almalinux/kylin/uos etc.).
pub fn parse_os_release(content: &str) -> (String, String) {
    let mut id = String::new();
    let mut pretty = String::new();
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("ID=") {
            id = v.trim_matches('"').to_string();
        } else if let Some(v) = line.strip_prefix("PRETTY_NAME=") {
            pretty = v.trim_matches('"').to_string();
        }
    }
    (id, pretty)
}

pub fn detect_os() -> OsInfo {
    let (id, pretty) = std::fs::read_to_string("/etc/os-release")
        .map(|c| parse_os_release(&c))
        .unwrap_or_else(|_| {
            (
                std::env::consts::OS.to_string(),
                std::env::consts::OS.to_string(),
            )
        });
    let systemd = cfg!(target_os = "linux") && Path::new("/usr/bin/systemctl").exists();
    OsInfo { id, pretty, systemd }
}

pub fn render_systemd_unit(exe: &Path, config: &Path) -> String {
    format!(
        "[Unit]\n\
         Description=AgileNet 节点服务 (anet-svc)\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={} start {}\n\
         Restart=on-failure\n\
         RestartSec=3\n\
         LimitNOFILE=1048576\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        exe.display(),
        config.display()
    )
}

/// Path-safe form for a TOML basic string (Windows backslashes to forward slashes, avoiding \U escape accidents).
fn toml_path(s: &str) -> String {
    s.replace('\\', "/")
}

// ==================== Main flow ====================

pub async fn run(args: InitArgs) -> Result<()> {
    let interactive = tty() && !args.yes;
    if !interactive && !tty() && std::env::var("AGILE_ADMIN_PASSWORD").is_err() {
        // non-TTY without a password: only an error if an admin must be created (validated later on demand)
        eprintln!("提示：非交互环境，管理员密码将读取 AGILE_ADMIN_PASSWORD");
    }
    println!("AgileNet 初始化向导");
    println!("────────────────────");

    // 1. Config file — default to ~/.anet/svc/agile-net.toml (single-machine
    //    demo default; production deployments override with --config).
    let config_default = agile_net_core::util::default_config_path();
    let config_str = args
        .config
        .unwrap_or_else(|| config_default.to_string_lossy().to_string());
    let config_path = PathBuf::from(&config_str);
    if config_path.exists() {
        if interactive && !prompt_yes_no(&format!("配置文件 {} 已存在，在其基础上继续初始化？", config_str), true)? {
            bail!("已取消");
        }
        println!("① 配置文件: {}（已存在，保留）", config_str);
    } else if interactive {
        let p = prompt("① 配置文件路径", &config_str)?;
        println!("① 配置文件: {p}");
    } else {
        println!("① 配置文件: {}", config_str);
    }
    let config_path = PathBuf::from(&config_str);
    let config_parent = config_path.parent().unwrap_or(Path::new("."));
    let config_parent_abs = if config_parent.is_absolute() {
        config_parent.to_path_buf()
    } else {
        std::env::current_dir()?.join(config_parent)
    };
    let config_abs = config_parent_abs.join(config_path.file_name().unwrap());

    // Debug: print the systemd unit only (no config/DB/service writes)
    if args.print_service {
        let exe = std::env::current_exe()?;
        println!("{}", render_systemd_unit(&exe, &config_abs));
        return Ok(());
    }

    // 2. Endpoint name
    let hostname = sysinfo::System::host_name().unwrap_or_else(|| "AgileNet 节点".into());
    let name = match (&args.name, interactive) {
        (Some(n), _) => n.clone(),
        (None, true) => prompt("② 端点名称", &hostname)?,
        (None, false) => hostname,
    };
    println!("② 端点名称: {name}");

    // 3. Web admin / API listen (Web admin UI comes up with the API, on by default)
    let api = if interactive {
        let a = prompt("③ Web 管理后台监听（随 API 开启；0.0.0.0 对局域网暴露）", &args.api)?;
        if a.starts_with("0.0.0.0") {
            eprintln!("   注意：Web 管理后台将对局域网可见，请仅在内网使用或配置 API TLS/前置反代");
        }
        a
    } else {
        args.api.clone()
    };
    println!("③ Web 管理/API: {api}");

    // 4. Relay listener
    let listener_on = if args.no_listener {
        false
    } else if interactive {
        prompt_yes_no("④ 开启 Relay listener（0.0.0.0:54430，供下游/客户端连入）", true)?
    } else {
        true
    };
    println!(
        "④ Relay listener: {}",
        if listener_on { "0.0.0.0:54430（证书首启自动生成）" } else { "关闭" }
    );

    // 4b. Public identity (federation P1 productization): a rendezvous declares its external
    // address — access links and fan-out share links point at it (hot-applied, rewritable in the console)
    let mut public_host: Option<String> = None;
    if listener_on
        && interactive
        && prompt_yes_no("   本机是公网会合点吗？（有公网地址，供外网端点/客户端连入）", false)?
    {
        let h = prompt("   对外地址（公网 IP 或域名，如 anet.example.com）", "")?;
        let h = h.trim();
        if h.is_empty() || h.len() > 253 || h.contains('/') || h.contains(' ') {
            eprintln!("   对外地址格式无效，已跳过（可稍后在控制台「设置」补配）");
        } else {
            public_host = Some(h.to_string());
            println!("   公网身份: {h}（接入/扇出链接将使用该地址）");
        }
    }

    // Write config (only if it does not exist)
    let db_path = args
        .db
        .clone()
        .unwrap_or_else(|| {
            config_abs
                .parent()
                .unwrap_or(Path::new("."))
                .join("agile-net.db")
                .to_string_lossy()
                .to_string()
        });
    if !config_path.exists() {
        let certs_dir = config_abs.parent().unwrap_or(Path::new(".")).join("certs");
        let mut toml = format!(
            "# AgileNet 节点配置（anet init 生成）\nname = \"{name}\"\ndb_path = \"{}\"\n\n[api]\naddr = \"{api}\"\n",
            toml_path(&db_path)
        );
        if let Some(h) = &public_host {
            toml.push_str(&format!("\n# 公网会合点对外地址（接入/扇出链接的展示地址）\npublic_host = \"{h}\"\n"));
        }
        if listener_on {
            toml.push_str(&format!(
                "\n[listener]\naddr = \"0.0.0.0:54430\"\ncert_path = \"{}\"\nkey_path = \"{}\"\nsni_hostname = \"cdn.cloudflare.com\"\n",
                toml_path(&certs_dir.join("relay-cert.pem").to_string_lossy()),
                toml_path(&certs_dir.join("relay-key.pem").to_string_lossy())
            ));
        }
        // Ensure the parent directory exists (default path ~/.anet/svc/ may not
        // exist on a fresh install).
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("创建配置目录失败: {}", parent.display()))?;
        }
        std::fs::write(&config_path, &toml)
            .with_context(|| format!("写入配置失败: {}", config_path.display()))?;
        println!("   已写入 {}", config_path.display());
    }

    // 5. Admin
    let db = crate::db::Database::open(&db_path)?;
    if db.has_admin()? {
        println!("⑤ 管理员: 已存在，跳过");
    } else {
        let username = if interactive {
            prompt("⑤ 管理员用户名", "admin")?
        } else {
            std::env::var("AGILE_ADMIN_USERNAME").unwrap_or_else(|_| "admin".into())
        };
        let password = match std::env::var("AGILE_ADMIN_PASSWORD") {
            Ok(p) => p,
            Err(_) if interactive => prompt_password_twice()?,
            Err(_) => bail!("非交互模式须设置 AGILE_ADMIN_PASSWORD 创建管理员"),
        };
        crate::api::handlers::auth::validate_admin_credentials(&username, &password)
            .map_err(|e| anyhow::anyhow!("管理员凭据强度不足: {e}"))?;
        let hash = crate::db::hash_password(&password)?;
        db.create_admin(&username, &hash)?;
        println!("⑤ 管理员: {username}（已创建，密码不落地只存 argon2id 哈希）");
    }

    // 6. System service
    let os = detect_os();
    println!("⑥ 系统: {}（systemd {}）", os.pretty, if os.systemd { "可用" } else { "不可用" });
    let mut service_started = false;
    if !args.no_service {
        let want = if interactive {
            prompt_yes_no("⑥ 注册为系统服务并开机自启？", os.systemd)?
        } else {
            args.yes && os.systemd
        };
        if want {
            service_started = register_service(&config_abs)?;
        }
    }

    // 7. Start
    if !service_started {
        let want = if interactive {
            prompt_yes_no("⑦ 现在启动节点（后台运行）？", true)?
        } else {
            args.yes
        };
        if want {
            crate::svc::ensure_not_running()?;
            let pid = crate::svc::spawn_daemon(&config_path.to_string_lossy())?;
            println!("⑦ 已启动 (PID {pid})");
        }
    }

    println!("────────────────────");
    println!("初始化完成：");
    println!("  Web 管理:  http://{api}/  （管理员见 ⑤）");
    println!("  服务管理:  anet status · anet stop · anet restart");
    println!("  资源管理:  anet login 后 rule/group/token/admin/audit");
    if listener_on {
        println!("  Relay:     0.0.0.0:54430（接入链接在 Web 管理端「扇出 · 签发委托」页签发）");
    }
    Ok(())
}

/// systemd registration (Linux); without root, degrades to sudo instructions; on Windows uses sc.exe.
fn register_service(config_abs: &Path) -> Result<bool> {
    if cfg!(target_os = "linux") {
        let exe = std::env::current_exe()?;
        let unit = render_systemd_unit(&exe, config_abs);
        let unit_path = Path::new("/etc/systemd/system/anet-svc.service");
        match std::fs::write(unit_path, &unit) {
            Ok(_) => {
                run_cmd("systemctl", &["daemon-reload"])?;
                run_cmd("systemctl", &["enable", "--now", "anet-svc"])?;
                println!("⑥ 已注册并启动系统服务 anet-svc（journalctl -u anet-svc 看日志）");
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                let tmp = std::env::temp_dir().join("anet-svc.service");
                std::fs::write(&tmp, &unit)?;
                println!("⑥ 无 root 权限，unit 已写入 {}，请执行：", tmp.display());
                println!("   sudo cp {} /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now anet-svc", tmp.display());
                Ok(false)
            }
            Err(e) => Err(e.into()),
        }
    } else if cfg!(windows) {
        let exe = std::env::current_exe()?;
        let bin = format!("\"{}\" start \"{}\"", exe.display(), config_abs.display());
        match run_cmd("sc.exe", &["create", "AgileNet", "binPath=", &bin, "start=", "auto"]) {
            Ok(_) => {
                let _ = run_cmd("sc.exe", &["start", "AgileNet"]);
                println!("⑥ 已注册并启动 Windows 服务 AgileNet");
                Ok(true)
            }
            Err(_) => {
                println!("⑥ 注册失败（需管理员权限），可手动执行：");
                println!("   sc.exe create AgileNet binPath= \"{bin}\" start= auto");
                Ok(false)
            }
        }
    } else {
        println!("⑥ 当前系统不支持自动注册服务，请手动配置进程守护");
        Ok(false)
    }
}

fn run_cmd(prog: &str, args: &[&str]) -> Result<()> {
    let out = agile_net_core::util::silent_command(prog).args(args).output()?;
    if out.status.success() {
        Ok(())
    } else {
        bail!(
            "{} {} 失败: {}",
            prog,
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_release_parse_distros() {
        let (id, pretty) = parse_os_release("ID=ubuntu\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"");
        assert_eq!(id, "ubuntu");
        assert_eq!(pretty, "Ubuntu 24.04.1 LTS");
        let (id, _) = parse_os_release("ID=\"rocky\"\nPRETTY_NAME=\"Rocky Linux 9.4 (Blue Onyx)\"");
        assert_eq!(id, "rocky");
        let (id, _) = parse_os_release("ID=kylin\nPRETTY_NAME=\"Kylin Linux Advanced Server V10\"");
        assert_eq!(id, "kylin");
        let (id, _) = parse_os_release("ID=uos\nPRETTY_NAME=\"UnionTech OS Server 20\"");
        assert_eq!(id, "uos");
    }

    #[test]
    fn unit_contains_exec_and_restart() {
        let unit = render_systemd_unit(Path::new("/usr/local/bin/anet-svc"), Path::new("/etc/agilenet/agile-net.toml"));
        assert!(unit.contains("ExecStart=/usr/local/bin/anet-svc start /etc/agilenet/agile-net.toml"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("WantedBy=multi-user.target"));
    }
}
