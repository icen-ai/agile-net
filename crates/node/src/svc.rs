//! Node service process management: start / stop / restart / status (single-instance model).
//!
//! - PID file `~/.anet/svc/anet-svc.pid` (JSON: pid / config / api_addr / started_at)
//! - PID written only after a successful bind (no phantom records on bind failure);
//!   removed on clean exit (Ctrl-C)
//! - Process probe/termination via `sysinfo` (cross-platform, Term first then Kill)

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
    agile_net_core::util::svc_data_dir().join("anet-svc.pid")
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

/// Process liveness probe (start-time cross-check for pid reuse is the caller's job; kept simple under the single-instance model).
pub fn process_alive(pid: u32) -> bool {
    use sysinfo::{Pid, ProcessesToUpdate, System};
    let pid = Pid::from_u32(pid);
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    sys.process(pid).is_some()
}

/// Terminate a process: SIGTERM first, wait up to 5s, then SIGKILL. Returns whether exit was confirmed.
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
        // Windows has no SIGTERM semantics; kill_with(Term) hard-kills there. On Unix it is a graceful stop.
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

/// Running service record (PID alive). A failed probe does not delete the file —
/// a fresh process may be briefly invisible to sysinfo, and a phantom record is harmless
/// (a dead probe reads as not-running); it is only overwritten on write or cleared on stop.
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

/// `start` precondition: fails if already running.
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

/// Background daemon: spawn a detached `start <config>` of self; the parent returns immediately.
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
        // pick a PID that is almost certainly not alive
        assert!(!process_alive(u32::MAX - 1));
    }
}
