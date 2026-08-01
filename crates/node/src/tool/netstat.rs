//! listen / portof / portsof — socket 枚举（P1，netstat2 + sysinfo 富化进程信息）。
//!
//! 权限：读全量进程 socket 需 root 或 CAP_NET_ADMIN；权限受限时只显示本用户进程，
//! 输出中标注「权限受限，列表可能不完整」。

use super::ToolOutcome;
use serde::Serialize;

/// 单条 socket 的结构化结果（listen/portof/portsof/killport 共用数据源）。
#[derive(Debug, Clone, Serialize)]
pub struct SocketInfo {
    /// 协议："tcp" | "udp"
    pub proto: String,
    /// 本地地址（"addr:port"）
    pub local: String,
    /// 对端地址（监听态为 None）
    pub remote: Option<String>,
    /// 状态（LISTEN / ESTABLISHED ...；UDP 为 None）
    pub state: Option<String>,
    /// 所属进程 PID（无权限时为 None）
    pub pid: Option<u32>,
    /// 所属进程名（无权限时为 None）
    pub process: Option<String>,
}

/// socket 枚举核心（listen/portof/portsof/killport 共用）。
pub fn sockets() -> Result<Vec<SocketInfo>, String> {
    use netstat2::{
        get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState,
    };
    use sysinfo::{Pid, ProcessesToUpdate, System};

    let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let infos = get_sockets_info(af, proto).map_err(|e| format!("枚举 socket 失败: {e}"))?;

    // 进程名富化：收集全部关联 PID 一次刷新，避免逐 socket 查询
    let mut pids: Vec<Pid> = infos
        .iter()
        .flat_map(|si| si.associated_pids.iter().map(|&p| Pid::from_u32(p)))
        .collect();
    pids.sort_unstable();
    pids.dedup();
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::Some(&pids), true);

    let out = infos
        .into_iter()
        .map(|si| {
            let (proto, local, remote, state) = match si.protocol_socket_info {
                ProtocolSocketInfo::Tcp(t) => {
                    // 监听态无对端，按 SocketInfo 约定置 None
                    let remote = (t.state != TcpState::Listen)
                        .then(|| format!("{}:{}", t.remote_addr, t.remote_port));
                    (
                        "tcp".to_string(),
                        format!("{}:{}", t.local_addr, t.local_port),
                        remote,
                        Some(t.state.to_string()),
                    )
                }
                ProtocolSocketInfo::Udp(u) => (
                    "udp".to_string(),
                    format!("{}:{}", u.local_addr, u.local_port),
                    None,
                    None,
                ),
            };
            // 同一 socket 可能关联多个 PID（fork 共享），取第一个展示
            let pid = si.associated_pids.first().copied();
            let process = pid
                .and_then(|p| sys.process(Pid::from_u32(p)))
                .map(|p| p.name().to_string_lossy().into_owned());
            SocketInfo {
                proto,
                local,
                remote,
                state,
                pid,
                process,
            }
        })
        .collect();
    Ok(out)
}

/// `anet tool listen`（等同 netstat -tunlp / ss -tulnp）；proto 过滤 "tcp"/"udp"。
pub fn listen(proto: Option<&str>) -> ToolOutcome {
    let socks = match sockets() {
        Ok(s) => s,
        Err(e) => return ToolOutcome::fail(e.clone(), serde_json::json!({ "error": e })),
    };
    let filtered: Vec<SocketInfo> = socks
        .iter()
        .filter(|s| proto.is_none_or(|p| s.proto == p))
        .cloned()
        .collect();
    let limited = permission_limited(&socks);

    let mut human = format!("共 {} 条 socket", filtered.len());
    if let Some(p) = proto {
        human.push_str(&format!("（proto={p}）"));
    }
    human.push('\n');
    if filtered.is_empty() {
        human.push_str("无匹配 socket");
    } else {
        human.push_str(&render_table(&filtered));
    }
    if limited {
        human.push_str(LIMITED_NOTE);
    }
    ToolOutcome::ok(
        human,
        serde_json::json!({
            "proto": proto,
            "count": filtered.len(),
            "limited": limited,
            "sockets": filtered,
        }),
    )
}

/// `anet tool portof <port>`（等同 lsof -i:<port>）。
pub fn portof(port: u16) -> ToolOutcome {
    let socks = match sockets() {
        Ok(s) => s,
        Err(e) => return ToolOutcome::fail(e.clone(), serde_json::json!({ "error": e })),
    };
    let matched: Vec<SocketInfo> = socks
        .iter()
        .filter(|s| local_port(s) == Some(port) || remote_port(s) == Some(port))
        .cloned()
        .collect();
    let limited = permission_limited(&socks);

    if matched.is_empty() {
        let mut human = format!("未发现占用端口 {port} 的进程");
        if limited {
            human.push_str(LIMITED_NOTE);
        }
        return ToolOutcome::fail(
            human,
            serde_json::json!({ "port": port, "limited": limited, "sockets": [] }),
        );
    }
    let mut human = format!("端口 {port} 共 {} 条 socket\n", matched.len());
    human.push_str(&render_table(&matched));
    if limited {
        human.push_str(LIMITED_NOTE);
    }
    ToolOutcome::ok(
        human,
        serde_json::json!({ "port": port, "limited": limited, "sockets": matched }),
    )
}

/// `anet tool portsof <pid>`（等同 lsof -i | grep <pid>）。
pub fn portsof(pid: u32) -> ToolOutcome {
    let socks = match sockets() {
        Ok(s) => s,
        Err(e) => return ToolOutcome::fail(e.clone(), serde_json::json!({ "error": e })),
    };
    let matched: Vec<SocketInfo> = socks
        .iter()
        .filter(|s| s.pid == Some(pid))
        .cloned()
        .collect();

    if matched.is_empty() {
        return ToolOutcome::fail(
            format!("进程 {pid} 无 socket（进程不存在、未联网或无权限查看）"),
            serde_json::json!({ "pid": pid, "sockets": [] }),
        );
    }
    let process = matched
        .iter()
        .find_map(|s| s.process.clone())
        .unwrap_or_else(|| "-".into());
    let mut human = format!("进程 {pid}（{process}）共 {} 条 socket\n", matched.len());
    human.push_str(&render_table(&matched));
    ToolOutcome::ok(
        human,
        serde_json::json!({ "pid": pid, "process": process, "sockets": matched }),
    )
}

/// 权限受限提示（human 输出追加）。
const LIMITED_NOTE: &str = "\n注意：权限受限，列表可能不完整（读全量进程 socket 需 root 或 CAP_NET_ADMIN）";

/// 权限受限启发式：存在无 PID 关联的活动 socket（TIME_WAIT 本身无属主，除外），
/// 说明只能看到本用户进程的 fd（需 root 或 CAP_NET_ADMIN 才能读全量）。
fn permission_limited(socks: &[SocketInfo]) -> bool {
    socks
        .iter()
        .any(|s| s.pid.is_none() && s.state.as_deref() != Some("TIME_WAIT"))
}

/// 从 "addr:port" 取本地端口（IPv6 形如 "::1:80"，取最后一段）。
fn local_port(s: &SocketInfo) -> Option<u16> {
    s.local.rsplit_once(':').and_then(|(_, p)| p.parse().ok())
}

/// 从对端地址取端口。
fn remote_port(s: &SocketInfo) -> Option<u16> {
    s.remote
        .as_deref()
        .and_then(|r| r.rsplit_once(':'))
        .and_then(|(_, p)| p.parse().ok())
}

/// 渲染对齐表格（listen/portof/portsof 共用 human 输出）。
fn render_table(socks: &[SocketInfo]) -> String {
    let wl = socks.iter().map(|s| s.local.len()).max().unwrap_or(5).max(5);
    let wr = socks
        .iter()
        .filter_map(|s| s.remote.as_ref())
        .map(|r| r.len())
        .max()
        .unwrap_or(6)
        .max(6);
    let mut out = format!(
        "{:<5} {:<wl$} {:<wr$} {:<12} {:<8} PROCESS\n",
        "PROTO",
        "LOCAL",
        "REMOTE",
        "STATE",
        "PID",
        wl = wl,
        wr = wr,
    );
    for s in socks {
        let pid = s.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into());
        out.push_str(&format!(
            "{:<5} {:<wl$} {:<wr$} {:<12} {:<8} {}\n",
            s.proto,
            s.local,
            s.remote.as_deref().unwrap_or("-"),
            s.state.as_deref().unwrap_or("-"),
            pid,
            s.process.as_deref().unwrap_or("-"),
            wl = wl,
            wr = wr,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, UdpSocket};

    /// 临时 TCP listener 应被 sockets() 枚举到，且归属当前进程。
    #[test]
    fn sockets_finds_tcp_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let socks = sockets().unwrap();
        let hit = socks
            .iter()
            .find(|s| {
                s.proto == "tcp"
                    && local_port(s) == Some(port)
                    && s.state.as_deref() == Some("LISTEN")
            })
            .expect("临时 listener 应被枚举到");
        assert_eq!(hit.pid, Some(std::process::id()));
        assert!(hit.process.is_some());
    }

    /// 临时 UDP socket 应被枚举到（UDP 无状态、无对端）。
    #[test]
    fn sockets_finds_udp_socket() {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = udp.local_addr().unwrap().port();
        let socks = sockets().unwrap();
        assert!(socks.iter().any(|s| {
            s.proto == "udp" && local_port(s) == Some(port) && s.state.is_none()
        }));
    }

    /// portof 通/断两路：绑定中可找到（exit 0），释放后找不到（exit 1）。
    #[test]
    fn portof_hit_and_miss() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hit = portof(port);
        assert!(hit.success);
        assert_eq!(hit.exit_code, 0);
        assert!(hit.human.contains(&port.to_string()));

        drop(listener);
        let miss = portof(port);
        assert!(!miss.success);
        assert_eq!(miss.exit_code, 1);
        assert!(miss.human.contains("未发现"));
    }

    /// portsof 应能找到当前进程持有的临时 listener。
    #[test]
    fn portsof_finds_self() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let out = portsof(std::process::id());
        assert!(out.success);
        assert!(out.human.contains(&port.to_string()));
    }

    /// 不存在的 PID 应得到 fail（exit 1）。
    #[test]
    fn portsof_missing_pid() {
        let out = portsof(u32::MAX);
        assert!(!out.success);
        assert_eq!(out.exit_code, 1);
    }

    /// listen proto 过滤：tcp 含临时 listener，udp 过滤结果中不含该端口。
    #[test]
    fn listen_proto_filter() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let tcp = listen(Some("tcp"));
        assert!(tcp.success);
        assert!(tcp.human.contains(&format!(":{port}")));

        let udp = listen(Some("udp"));
        assert!(udp.success);
        let empty = vec![];
        let udp_socks = udp.json["sockets"].as_array().unwrap_or(&empty);
        assert!(udp_socks
            .iter()
            .all(|s| !s["local"].as_str().unwrap_or("").ends_with(&format!(":{port}"))));

        assert!(listen(None).success);
    }
}
