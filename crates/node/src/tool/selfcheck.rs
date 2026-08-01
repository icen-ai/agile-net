//! selfcheck — PATH 巡检（P0，零新增依赖）。
//!
//! 扫描 PATH 常见命令（telnet/nc/curl/ping/traceroute/nslookup/netstat/lsof/
//! ifconfig/ss）是否存在，输出缺失清单 + 对应 `anet tool` 替代方案；
//! 兼作整套工具的入口引导。

use super::ToolOutcome;
use serde::Serialize;
use std::ffi::OsStr;
use std::path::PathBuf;

/// 受检命令清单：(命令名, 用途, anet tool 替代方案)。
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

/// 单个命令的巡检结果（--json 结构化输出条目）。
#[derive(Debug, Clone, Serialize)]
pub struct CheckItem {
    pub cmd: String,
    pub desc: String,
    pub present: bool,
    pub path: Option<String>,
    pub alt: String,
}

/// `anet tool selfcheck`：巡检 PATH 并输出缺失清单与替代方案。
///
/// 退出码语义：全部命中 exit 0；任一缺失 exit 1（脚本可据此判断环境是否齐全）。
pub fn selfcheck() -> ToolOutcome {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let items = inspect(&path, &pathext());
    render(items)
}

/// 巡检核心（PATH 与扩展名列表可注入，测试用受控环境断言）。
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

/// 在目录列表中查找命令的首个可执行文件（Windows 按扩展名尝试，Unix 校验执行位）。
fn which(cmd: &str, dirs: &[PathBuf], exts: &[String]) -> Option<PathBuf> {
    for dir in dirs {
        #[cfg(windows)]
        {
            // 裸名（命令本身可能已带扩展名）优先，再按 PATHEXT 逐一尝试；
            // Windows 文件系统通常大小写不敏感，扩展名原样拼接即可命中
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

/// Windows 下解析 PATHEXT（如 `.COM;.EXE;.BAT`，去点转原样保留大小写）；
/// 非 Windows 返回空（按执行位判断，无需扩展名）。
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

/// 非 Windows 无 PATHEXT 概念。
#[cfg(not(windows))]
fn pathext() -> Vec<String> {
    Vec::new()
}

/// 汇总渲染：缺失 > 0 时 fail（exit 1），全命中 ok（exit 0）。
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

    /// 受控 PATH 临时目录（Drop 自动清理）。
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

        /// 放入一个假命令（Windows 加 .exe 后缀，Unix 加执行位）。
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

        /// 作为单条目 PATH 字符串（无分隔符问题）。
        fn as_path_env(&self) -> OsString {
            self.0.clone().into_os_string()
        }
    }

    impl Drop for TempPathDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// 与测试假文件匹配的扩展名列表（Windows 假文件为 .exe）。
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
        // 缺失项须给出 anet tool 替代方案
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
        // 不存在的目录作为 PATH：全部缺失，exit 1
        let ghost = OsString::from("Z:\\anet-selfcheck-no-such-dir-8f3d2c1b");
        let outcome = render(inspect(&ghost, &test_exts()));
        assert!(!outcome.success);
        assert_eq!(outcome.exit_code, 1);
        assert_eq!(outcome.json["missing_count"], CHECKS.len());
    }

    #[test]
    fn real_path_smoke() {
        // 真实 PATH 冒烟：不断言结果（随机器而异），只断言不 panic、结构完整
        let outcome = selfcheck();
        assert_eq!(outcome.json["total"], CHECKS.len());
        assert!(outcome.exit_code == 0 || outcome.exit_code == 1);
        assert!(outcome.human.contains("PATH 巡检"));
    }
}
