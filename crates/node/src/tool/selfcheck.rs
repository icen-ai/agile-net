//! selfcheck — PATH inspection (P0, zero new dependencies).
//!
//! Scans PATH for common commands (telnet/nc/curl/ping/traceroute/nslookup/netstat/lsof/
//! ifconfig/ss), reports missing ones plus the corresponding `anet tool` replacement;
//! also serves as the entry-point guide to the whole toolkit.

use super::ToolOutcome;
use serde::Serialize;
use std::ffi::OsStr;
use std::path::PathBuf;

/// Commands under inspection: (command name, purpose, anet tool replacement).
const CHECKS: &[(&str, &str, &str)] = &[
    ("telnet", "TCP 连通性测试", "anet tool tcping <host> <port>（别名 telnet）"),
    ("nc", "TCP/UDP 探测", "anet tool tcping <host> <port>（别名 nc）/ anet tool scan"),
    ("curl", "HTTP 请求", "anet tool curl <url>"),
    ("ping", "ICMP 连通性", "anet tool ping <host>"),
    ("traceroute", "路由追踪", "anet tool traceroute <host>（别名 tracert）"),
    ("nslookup", "DNS 查询", "anet tool dns <domain>（别名 nslookup）"),
    ("netstat", "socket 列表", "anet tool listen（别名 netstat）"),
    ("lsof", "按端口查进程", "anet tool portof <port>（兼容 lsof -i:<port>）"),
    ("ifconfig", "网卡信息", "anet tool ifconfig（别名 ip）"),
    ("ss", "socket 列表", "anet tool listen"),
];

/// Inspection result for a single command (--json structured output entry).
#[derive(Debug, Clone, Serialize)]
pub struct CheckItem {
    pub cmd: String,
    pub desc: String,
    pub present: bool,
    pub path: Option<String>,
    pub alt: String,
}

/// `anet tool selfcheck`: inspect PATH and report missing commands with replacements.
///
/// Exit-code semantics: all present → exit 0; any missing → exit 1 (scripts can test environment readiness).
pub fn selfcheck() -> ToolOutcome {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let items = inspect(&path, &pathext());
    render(items)
}

/// Inspection core (PATH and extension list are injectable, so tests assert against a controlled environment).
fn inspect(path_env: &OsStr, exts: &[String]) -> Vec<CheckItem> {
    let dirs: Vec<PathBuf> = std::env::split_paths(path_env).collect();
    CHECKS
        .iter()
        .map(|(cmd, desc, alt)| {
            let found = which(cmd, &dirs, exts);
            CheckItem {
                cmd: cmd.to_string(),
                desc: desc.to_string(),
                present: found.is_some(),
                path: found.map(|p| p.display().to_string()),
                alt: alt.to_string(),
            }
        })
        .collect()
}

/// Find the first executable for a command across directories (Windows tries extensions, Unix checks the exec bit).
fn which(cmd: &str, dirs: &[PathBuf], exts: &[String]) -> Option<PathBuf> {
    for dir in dirs {
        #[cfg(windows)]
        {
            // Bare name first (the command may already carry an extension), then each PATHEXT entry;
            // the Windows filesystem is usually case-insensitive, so appending the extension as-is hits
            let bare = dir.join(cmd);
            if bare.is_file() {
                return Some(bare);
            }
            for ext in exts {
                let candidate = dir.join(format!("{cmd}.{ext}"));
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
        #[cfg(not(windows))]
        {
            let _ = exts;
            use std::os::unix::fs::PermissionsExt;
            let candidate = dir.join(cmd);
            let executable = candidate
                .metadata()
                .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false);
            if executable {
                return Some(candidate);
            }
        }
    }
    None
}

/// Parse PATHEXT on Windows (e.g. `.COM;.EXE;.BAT`; strip the dot, keep the original case);
/// returns empty elsewhere (exec bit decides, no extensions needed).
#[cfg(windows)]
fn pathext() -> Vec<String> {
    std::env::var("PATHEXT")
        .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into())
        .split(';')
        .map(|s| s.trim().trim_start_matches('.'))
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Non-Windows has no PATHEXT concept.
#[cfg(not(windows))]
fn pathext() -> Vec<String> {
    Vec::new()
}

/// Render the summary: missing > 0 → fail (exit 1); all present → ok (exit 0).
fn render(items: Vec<CheckItem>) -> ToolOutcome {
    use std::fmt::Write;

    let missing: Vec<&CheckItem> = items.iter().filter(|i| !i.present).collect();
    let present_count = items.len() - missing.len();

    let mut human = String::new();
    let _ = writeln!(
        human,
        "anet tool selfcheck — PATH 巡检：受检 {} 项，存在 {} 项，缺失 {} 项",
        items.len(),
        present_count,
        missing.len()
    );
    for item in &items {
        if let Some(path) = &item.path {
            let _ = writeln!(human, "  存在  {:<11} {}", item.cmd, path);
        } else {
            let _ = writeln!(human, "  缺失  {:<11} {} → {}", item.cmd, item.desc, item.alt);
        }
    }
    if !missing.is_empty() {
        human.push_str("\n缺失项均可由 anet tool 内置实现替代（见 → 列），无需安装外部命令。\n");
    }
    human.push_str("提示：`anet tool <sub> --help` 查看子命令详情；全部子命令支持 `--json` 结构化输出。");

    let json = serde_json::json!({
        "total": items.len(),
        "present_count": present_count,
        "missing_count": missing.len(),
        "missing": missing.iter().map(|i| i.cmd.clone()).collect::<Vec<_>>(),
        "items": items,
    });

    if missing.is_empty() {
        ToolOutcome::ok(human, json)
    } else {
        ToolOutcome::fail(human, json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::fs;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Controlled PATH temp directory (auto-cleaned on Drop).
    struct TempPathDir(PathBuf);

    impl TempPathDir {
        fn new() -> Self {
            static SEQ: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!(
                "anet-selfcheck-test-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::SeqCst)
            ));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        /// Drop in a fake command (Windows gets an .exe suffix, Unix gets the exec bit).
        fn add(&self, cmd: &str) {
            #[cfg(windows)]
            let name = format!("{cmd}.exe");
            #[cfg(not(windows))]
            let name = cmd.to_string();
            let file = self.0.join(name);
            fs::write(&file, b"fake").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
            }
        }

        /// As a single-entry PATH string (no separator issues).
        fn as_path_env(&self) -> OsString {
            self.0.clone().into_os_string()
        }
    }

    impl Drop for TempPathDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Extension list matching the test fake files (Windows fakes are .exe).
    fn test_exts() -> Vec<String> {
        #[cfg(windows)]
        {
            vec!["exe".into()]
        }
        #[cfg(not(windows))]
        {
            Vec::new()
        }
    }

    fn item<'a>(items: &'a [CheckItem], cmd: &str) -> &'a CheckItem {
        items.iter().find(|i| i.cmd == cmd).unwrap()
    }

    #[test]
    fn missing_reported_with_alternative() {
        let dir = TempPathDir::new();
        dir.add("ping");
        dir.add("curl");

        let items = inspect(&dir.as_path_env(), &test_exts());
        assert_eq!(items.len(), CHECKS.len());
        assert!(item(&items, "ping").present);
        assert!(item(&items, "curl").present);
        assert!(item(&items, "ping").path.is_some());
        assert!(!item(&items, "telnet").present);
        assert!(!item(&items, "nc").present);
        assert!(!item(&items, "ss").present);

        let outcome = render(items);
        assert!(!outcome.success);
        assert_eq!(outcome.exit_code, 1);
        assert_eq!(outcome.json["missing_count"], 8);
        assert_eq!(outcome.json["present_count"], 2);
        assert!(outcome.human.contains("缺失  telnet"));
        // Missing entries must name the anet tool replacement
        assert!(outcome.human.contains("anet tool tcping <host> <port>"));
        assert!(outcome.human.contains("anet tool dns <domain>"));
        assert!(outcome.human.contains("内置实现替代"));
    }

    #[test]
    fn all_present_is_ok() {
        let dir = TempPathDir::new();
        for (cmd, _, _) in CHECKS {
            dir.add(cmd);
        }

        let outcome = render(inspect(&dir.as_path_env(), &test_exts()));
        assert!(outcome.success);
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(outcome.json["missing_count"], 0);
        assert_eq!(outcome.json["total"], CHECKS.len());
        assert!(outcome.human.contains("缺失 0 项"));
    }

    #[test]
    fn empty_path_all_missing() {
        // A nonexistent directory as PATH: everything missing, exit 1
        let ghost = OsString::from("Z:\\anet-selfcheck-no-such-dir-8f3d2c1b");
        let outcome = render(inspect(&ghost, &test_exts()));
        assert!(!outcome.success);
        assert_eq!(outcome.exit_code, 1);
        assert_eq!(outcome.json["missing_count"], CHECKS.len());
    }

    #[test]
    fn real_path_smoke() {
        // Real-PATH smoke test: no result assertions (machine-dependent), only no panic and structural integrity
        let outcome = selfcheck();
        assert_eq!(outcome.json["total"], CHECKS.len());
        assert!(outcome.exit_code == 0 || outcome.exit_code == 1);
        assert!(outcome.human.contains("PATH 巡检"));
    }
}
