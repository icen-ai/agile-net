//! 节点服务进程管理：start / stop / restart / status（社区惯例单实例模型）。
//!
//! - PID 文件 `~/.agile-net/anet-svc.pid`（JSON：pid / config / api_addr / started_at）
//! - 启动成功后才写 PID（绑定失败不产生幻尸记录）；正常退出（Ctrl-C）清除
//! - 进程探测与终止经 `sysinfo`（跨平台，先 Term 后 Kill 兜底）

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PidRecord {
    pub pid: u32,
    pub config: String,
    pub api_addr: String,
    pub started_at: u64,
}

fn pid_path() -> PathBuf {
    home_dir().join(".agile-net").join("anet-svc.pid")
}

fn home_dir() -> PathBuf {
    std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

pub fn read_pid() -> Option<PidRecord> {
    let data = std::fs::read_to_string(pid_path()).ok()?;
    serde_json::from_str(&data).ok()
}

pub fn write_pid(rec: &PidRecord) -> Result<()> {
    let path = pid_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(rec)?)?;
    Ok(())
}

pub fn remove_pid() {
    let _ = std::fs::remove_file(pid_path());
}

/// 进程存活探测（pid 复用场景下以启动时间粗校验由调用方负责，单实例模型下从简）。
pub fn process_alive(pid: u32) -> bool {
    use sysinfo::{Pid, ProcessesToUpdate, System};
    let pid = Pid::from_u32(pid);
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    sys.process(pid).is_some()
}

/// 终止进程：先 SIGTERM 等至多 5s，未退则 SIGKILL。返回是否已确认退出。
pub fn kill_process(pid: u32) -> Result<bool> {
    use sysinfo::{Pid, ProcessesToUpdate, Signal, System};
    let spid = Pid::from_u32(pid);
    let mut sys = System::new();
    let fetch = |sys: &mut System| {
        sys.refresh_processes(ProcessesToUpdate::Some(&[spid]), true);
        sys.process(spid).is_some()
    };
    if !fetch(&mut sys) {
        return Ok(true);
    }
    if let Some(p) = sys.process(spid) {
        // Windows 无 SIGTERM 语义，kill_with(Term) 直接硬终止；Unix 上为优雅停止
        let _ = p.kill_with(Signal::Term);
    }
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if !fetch(&mut sys) {
            return Ok(true);
        }
    }
    if let Some(p) = sys.process(spid) {
        let _ = p.kill();
    }
    std::thread::sleep(std::time::Duration::from_millis(300));
    Ok(!fetch(&mut sys))
}

/// 运行中的服务记录（PID 存活）。探测失败不删文件——
/// 新进程对 sysinfo 可能短暂不可见，幻尸记录无害（探测为死即视为未运行），
/// 仅在 write/stop 时覆盖或清除。
pub fn running_record() -> Option<PidRecord> {
    let rec = read_pid()?;
    if process_alive(rec.pid) { Some(rec) } else { None }
}

pub fn cmd_stop() -> Result<()> {
    let Some(rec) = read_pid() else {
        println!("anet-svc 未在运行（无 PID 记录）");
        return Ok(());
    };
    if !process_alive(rec.pid) {
        remove_pid();
        println!("anet-svc 未在运行（已清理幻尸 PID 记录）");
        return Ok(());
    }
    println!("正在停止 anet-svc (PID {})…", rec.pid);
    if kill_process(rec.pid)? {
        remove_pid();
        println!("已停止");
        Ok(())
    } else {
        Err(anyhow!("进程 {} 未能终止，请手动检查", rec.pid))
    }
}

/// `start` 前置检查：已在运行则报错。
pub fn ensure_not_running() -> Result<()> {
    if let Some(rec) = running_record() {
        bail!(
            "anet-svc 已在运行 (PID {}，配置 {}）；请先 `anet stop` 或 `anet restart`",
            rec.pid,
            rec.config
        );
    }
    Ok(())
}

/// 后台守护：分离启动自身 `start <config>`，父进程立即返回。
pub fn spawn_daemon(config: &str) -> Result<u32> {
    let exe = std::env::current_exe().context("无法定位当前可执行文件")?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("start").arg(config);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
        cmd.creation_flags(0x00000008 | 0x00000200 | 0x08000000);
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
    let child = cmd.spawn().context("后台进程拉起失败")?;
    Ok(child.id())
}

pub fn cmd_status() -> Result<()> {
    match running_record() {
        Some(rec) => {
            let started = chrono::DateTime::from_timestamp(rec.started_at as i64, 0)
                .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "-".into());
            let api_ok = std::net::TcpStream::connect_timeout(
                &rec
                    .api_addr
                    .parse()
                    .unwrap_or(std::net::SocketAddr::from(([127, 0, 0, 1], 59090))),
                std::time::Duration::from_millis(800),
            )
            .is_ok();
            println!("anet-svc 运行中 (PID {})", rec.pid);
            println!("  配置文件: {}", rec.config);
            println!("  API 监听: {}（{}）", rec.api_addr, if api_ok { "可达" } else { "不可达" });
            println!("  启动时间: {started}");
            println!("  管理命令: anet login 后使用 rule/group/account/token/admin/audit");
        }
        None => {
            println!("anet-svc 未在运行");
        }
    }
    Ok(())
}

pub fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_record_roundtrip() {
        let rec = PidRecord {
            pid: 424242,
            config: "agile-net.toml".into(),
            api_addr: "127.0.0.1:59090".into(),
            started_at: 1785600000,
        };
        write_pid(&rec).unwrap();
        let got = read_pid().unwrap();
        assert_eq!(got.pid, 424242);
        assert_eq!(got.config, "agile-net.toml");
        remove_pid();
        assert!(read_pid().is_none());
    }

    #[test]
    fn dead_pid_is_not_running() {
        // 取一个几乎不可能存活的 PID
        assert!(!process_alive(u32::MAX - 1));
    }
}
