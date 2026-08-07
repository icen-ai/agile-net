//! listen / portof / portsof — socket enumeration (P1, netstat2 + sysinfo for richer process info).
//!
//! Permissions: reading all processes' sockets requires root or CAP_NET_ADMIN; when restricted
//! only the current user's processes are shown, and the output notes "permission limited, list may be incomplete".

use super::ToolOutcome;
use serde::Serialize;

/// Structured result for a single socket (shared data source for listen/portof/portsof/killport).
#[derive(Debug, Clone, Serialize)]
pub struct SocketInfo {
    /// Protocol: "tcp" | "udp"
    pub proto: String,
    /// Local address ("addr:port")
    pub local: String,
    /// Remote address (None for listening sockets)
    pub remote: Option<String>,
    /// State (LISTEN / ESTABLISHED ...; None for UDP)
    pub state: Option<String>,
    /// Owning process PID (None without permission)
    pub pid: Option<u32>,
    /// Owning process name (None without permission)
    pub process: Option<String>,
}

/// Socket enumeration core (shared by listen/portof/portsof/killport).
pub fn sockets() -> Result<Vec<SocketInfo>, String> {
    use netstat2::{
        get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState,
    };
    use sysinfo::{Pid, ProcessesToUpdate, System};

    let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let infos = get_sockets_info(af, proto).map_err(|e| format!("枚举 socket 失败: {e}"))?;

    // Process-name enrichment: collect all associated PIDs and refresh once, avoiding per-socket queries
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
                    // Listening sockets have no remote; per SocketInfo convention set None
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
            // A socket may map to multiple PIDs (shared via fork); display the first
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

/// `anet tool listen` (equivalent to netstat -tunlp / ss -tulnp); proto filters "tcp"/"udp".
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

/// `anet tool portof <port>` (equivalent to lsof -i:<port>).
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

/// `anet tool portsof <pid>` (equivalent to lsof -i | grep <pid>).
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

/// Permission-limited notice (appended to human output).
const LIMITED_NOTE: &str = "\n注意：权限受限，列表可能不完整（读全量进程 socket 需 root 或 CAP_NET_ADMIN）";

/// Permission-limited heuristic: an active socket with no associated PID (except TIME_WAIT,
/// which has no owner) means only the current user's fds are visible (root or CAP_NET_ADMIN reads all).
fn permission_limited(socks: &[SocketInfo]) -> bool {
    socks
        .iter()
        .any(|s| s.pid.is_none() && s.state.as_deref() != Some("TIME_WAIT"))
}

/// Extract the local port from "addr:port" (IPv6 looks like "::1:80"; take the last segment).
fn local_port(s: &SocketInfo) -> Option<u16> {
    s.local.rsplit_once(':').and_then(|(_, p)| p.parse().ok())
}

/// Extract the port from the remote address.
fn remote_port(s: &SocketInfo) -> Option<u16> {
    s.remote
        .as_deref()
        .and_then(|r| r.rsplit_once(':'))
        .and_then(|(_, p)| p.parse().ok())
}

/// Render an aligned table (shared human output for listen/portof/portsof).
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

    /// A temporary TCP listener should be enumerated by sockets() and owned by the current process.
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

    /// A temporary UDP socket should be enumerated (UDP has no state, no remote).
    #[test]
    fn sockets_finds_udp_socket() {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = udp.local_addr().unwrap().port();
        let socks = sockets().unwrap();
        assert!(socks.iter().any(|s| {
            s.proto == "udp" && local_port(s) == Some(port) && s.state.is_none()
        }));
    }

    /// portof both ways: found while bound (exit 0), not found after release (exit 1).
    #[test]
    fn portof_hit_and_miss() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hit = portof(port);
        assert!(hit.success);
        assert_eq!(hit.exit_code, 0);
        assert!(hit.human.contains(&port.to_string()));
        drop(listener);

        // the miss half is racy under full-suite parallel load (a released port can be re-bound
        // by another test immediately) — retry with fresh ports until a miss is observed
        // (32 consecutive parallel rebinds is practically impossible; any single miss proves the path)
        let mut saw_miss = !portof(port).success;
        for _ in 0..32 {
            if saw_miss {
                break;
            }
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            let miss = portof(port);
            if !miss.success {
                assert_eq!(miss.exit_code, 1);
                assert!(miss.human.contains("未发现"));
                saw_miss = true;
            }
        }
        assert!(saw_miss, "released ports kept getting re-bound by parallel tests");
    }

    /// portsof should find the temporary listener held by the current process.
    #[test]
    fn portsof_finds_self() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let out = portsof(std::process::id());
        assert!(out.success);
        assert!(out.human.contains(&port.to_string()));
    }

    /// A nonexistent PID should yield fail (exit 1).
    #[test]
    fn portsof_missing_pid() {
        let out = portsof(u32::MAX);
        assert!(!out.success);
        assert_eq!(out.exit_code, 1);
    }

    /// listen proto filter: tcp includes the temporary listener, udp results exclude that port.
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
