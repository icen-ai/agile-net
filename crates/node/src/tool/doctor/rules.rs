//! Section 7: rule conflicts (invalid/duplicate custom-rule cleanup, managed hosts-block drift
//! rewrite, CIDR containment conflicts in the node database).

use super::{DoctorContext, DoctorSection, DoctorStatus, item, section};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// GUI managed-block markers (kept in sync with apps/desktop/src/custom_rules.rs).
const GUI_BLOCK_BEGIN: &str = "# AgileNet begin";
const GUI_BLOCK_END: &str = "# AgileNet end";

fn system_hosts_path() -> PathBuf {
    if cfg!(windows) {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        PathBuf::from(root)
            .join("System32")
            .join("drivers")
            .join("etc")
            .join("hosts")
    } else {
        PathBuf::from("/etc/hosts")
    }
}

/// Bypass-pattern validity (aligned with desktop add_bypass: non-empty, no whitespace).
fn valid_bypass_pattern(p: &str) -> bool {
    !p.is_empty() && !p.chars().any(|c| c.is_whitespace())
}

/// hosts-mapping validity (aligned with desktop add_host: hostname is not an IP, no whitespace/*/#; IP parses).
fn valid_host_entry(host: &str, ip: &str) -> bool {
    !host.is_empty()
        && !host.chars().any(|c| c.is_whitespace() || c == '*' || c == '#')
        && host.parse::<IpAddr>().is_err()
        && ip.parse::<IpAddr>().is_ok()
}

/// Extract the effective hosts mappings from gui-custom-rules.json (enabled and to_system).
fn expected_hosts_entries(v: &serde_json::Value) -> Vec<(String, String)> {
    v["hosts"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter(|r| r["enabled"].as_bool().unwrap_or(true) && r["to_system"].as_bool().unwrap_or(false))
                .filter_map(|r| {
                    Some((
                        r["hostname"].as_str()?.to_lowercase(),
                        r["ip"].as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Parse the GUI managed-block entries in the system hosts file.
pub(super) fn read_managed_block(content: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut in_block = false;
    for line in content.lines() {
        let t = line.trim();
        match t {
            GUI_BLOCK_BEGIN => in_block = true,
            GUI_BLOCK_END => in_block = false,
            _ if in_block && !t.is_empty() && !t.starts_with('#') => {
                let mut tokens = t.split_whitespace();
                if let (Some(ip), Some(host)) = (tokens.next(), tokens.next()) {
                    out.push((host.to_lowercase(), ip.to_string()));
                }
            }
            _ => {}
        }
    }
    out
}

/// Strip the managed block (semantics aligned with desktop strip_block).
pub(super) fn strip_managed_block(content: &str) -> String {
    let mut out = Vec::new();
    let mut in_block = false;
    for line in content.lines() {
        let t = line.trim();
        if t == GUI_BLOCK_BEGIN {
            in_block = true;
            continue;
        }
        if t == GUI_BLOCK_END {
            in_block = false;
            continue;
        }
        if !in_block {
            out.push(line);
        }
    }
    let mut s = out.join("\n");
    if !s.is_empty() && !s.ends_with('\n') {
        s.push('\n');
    }
    s
}

/// Idempotently rewrite the system hosts managed block (temp + rename; Err on insufficient permission).
pub(super) fn rewrite_managed_block(path: &Path, entries: &[(String, String)]) -> Result<(), String> {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    let mut new_content = strip_managed_block(&content);
    if !entries.is_empty() {
        new_content.push_str(GUI_BLOCK_BEGIN);
        new_content.push('\n');
        for (host, ip) in entries {
            new_content.push_str(&format!("{ip} {host}\n"));
        }
        new_content.push_str(GUI_BLOCK_END);
        new_content.push('\n');
    }
    if new_content == content {
        return Ok(());
    }
    let tmp = path.with_extension("anet-doctor-tmp");
    std::fs::write(&tmp, &new_content).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

/// Remove invalid entries from the rules file (operates at the Value level to preserve unknown
/// fields); returns descriptions of removed entries.
pub(super) fn sanitize_rules_file(v: &mut serde_json::Value) -> Vec<String> {
    let mut removed = Vec::new();
    let mut removed_ids: Vec<String> = Vec::new();
    if let Some(arr) = v["bypass"].as_array_mut() {
        arr.retain(|r| {
            let pattern = r["pattern"].as_str().unwrap_or("");
            let ok = valid_bypass_pattern(pattern);
            if !ok {
                removed.push(format!("bypass:{pattern}"));
                if let Some(id) = r["id"].as_str() {
                    removed_ids.push(id.to_string());
                }
            }
            ok
        });
    }
    if let Some(arr) = v["hosts"].as_array_mut() {
        arr.retain(|r| {
            let host = r["hostname"].as_str().unwrap_or("");
            let ip = r["ip"].as_str().unwrap_or("");
            let ok = valid_host_entry(host, ip);
            if !ok {
                removed.push(format!("host:{host}"));
                if let Some(id) = r["id"].as_str() {
                    removed_ids.push(id.to_string());
                }
            }
            ok
        });
    }
    // Cascade-remove stale member keys from combos (aligned with desktop remove semantics)
    if !removed_ids.is_empty()
        && let Some(combos) = v["combos"].as_array_mut()
    {
        for c in combos {
            if let Some(keys) = c["rule_keys"].as_array_mut() {
                keys.retain(|k| {
                    k.as_str()
                        .map(|s| !removed_ids.iter().any(|id| id == s))
                        .unwrap_or(true)
                });
            }
        }
    }
    removed
}

/// Duplicate bypass-pattern detection (case-insensitive); returns the duplicated patterns.
pub(super) fn duplicate_patterns(v: &serde_json::Value) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    let mut dups: Vec<String> = Vec::new();
    if let Some(arr) = v["bypass"].as_array() {
        for r in arr {
            let Some(p) = r["pattern"].as_str() else { continue };
            let key = p.to_lowercase();
            if seen.contains(&key) {
                if !dups.contains(&key) {
                    dups.push(key);
                }
            } else {
                seen.push(key);
            }
        }
    }
    dups
}

pub(super) fn section_rules(ctx: &DoctorContext) -> DoctorSection {
    let mut items = Vec::new();
    let rules_path = ctx.data_dir.join("gui-custom-rules.json");
    let rules_val: Option<serde_json::Value> = std::fs::read_to_string(&rules_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());

    if let Some(mut v) = rules_val {
        // Invalid entries (err + removed on fix)
        let invalid = sanitize_rules_file(&mut v);
        if !invalid.is_empty() {
            let fixed = ctx.fix
                && std::fs::write(&rules_path, serde_json::to_string_pretty(&v).unwrap_or_default())
                    .is_ok();
            if fixed {
                items.push(item(
                    "custom-invalid",
                    "非法自定义规则",
                    DoctorStatus::Fixed,
                    format!("已移除 {} 条非法规则（{}）", invalid.len(), invalid.join(", ")),
                    None,
                ));
            } else {
                items.push(item(
                    "custom-invalid",
                    "非法自定义规则",
                    DoctorStatus::Err,
                    format!("存在 {} 条非法规则（{}）", invalid.len(), invalid.join(", ")),
                    Some("删除 gui-custom-rules.json 中对应条目或重置该文件".into()),
                ));
            }
        }
        // Duplicated patterns (warn)
        let dups = duplicate_patterns(&v);
        if !dups.is_empty() {
            items.push(item(
                "custom-dup",
                "放行规则重复",
                DoctorStatus::Warn,
                format!("重复 pattern：{}", dups.join(", ")),
                Some("在 GUI「自定义规则」中删除重复项".into()),
            ));
        }
        if invalid.is_empty() && dups.is_empty() {
            items.push(item(
                "custom",
                "自定义规则",
                DoctorStatus::Ok,
                "无重复/非法项",
                None,
            ));
        }
        // Managed hosts-block drift (rewritten on fix)
        let expected = expected_hosts_entries(&v);
        let hosts_path = system_hosts_path();
        let content = std::fs::read_to_string(&hosts_path).unwrap_or_default();
        let current = read_managed_block(&content);
        let mut exp = expected.clone();
        let mut cur = current.clone();
        exp.sort();
        cur.sort();
        if exp != cur {
            if ctx.fix {
                match rewrite_managed_block(&hosts_path, &expected) {
                    Ok(()) => items.push(item(
                        "hosts-drift",
                        "系统 hosts 托管块",
                        DoctorStatus::Fixed,
                        format!(
                            "托管块与规则库不一致（期望 {} 条/实际 {} 条），已重写",
                            expected.len(),
                            current.len()
                        ),
                        None,
                    )),
                    Err(e) => items.push(item(
                        "hosts-drift",
                        "系统 hosts 托管块",
                        DoctorStatus::Warn,
                        format!("托管块漂移，重写失败：{e}"),
                        Some("以管理员/root 身份运行 doctor 或在 GUI 中重新保存 hosts 映射".into()),
                    )),
                }
            } else {
                items.push(item(
                    "hosts-drift",
                    "系统 hosts 托管块",
                    DoctorStatus::Warn,
                    format!(
                        "托管块与规则库不一致（期望 {} 条/实际 {} 条）",
                        expected.len(),
                        current.len()
                    ),
                    Some("在 GUI「自定义规则」重新保存 hosts 映射以重写托管块".into()),
                ));
            }
        }
    } else if rules_path.exists() {
        // Corrupt files are repaired by the "config & data" section (it runs before this one, so the file is {} by then)
        items.push(item(
            "custom",
            "自定义规则",
            DoctorStatus::Info,
            "规则文件不可解析（见「配置与数据」节处理）",
            None,
        ));
    }

    // CIDR containment conflicts in the node database (read-only; skipped without a database)
    match &ctx.db_path {
        Some(db) if db.exists() => match read_db_cidrs(db) {
            Ok(values) => {
                let conflicts = cidr_conflicts(&values);
                if conflicts.is_empty() {
                    items.push(item(
                        "cidr",
                        "节点 CIDR 规则",
                        DoctorStatus::Ok,
                        format!("{} 条 ip-cidr 规则无包含冲突", values.len()),
                        None,
                    ));
                } else {
                    for (i, (big, small)) in conflicts.iter().take(10).enumerate() {
                        items.push(item(
                            format!("cidr-{i}"),
                            "CIDR 包含冲突",
                            DoctorStatus::Warn,
                            format!("{big} 完全包含 {small}（后者永不命中）"),
                            Some("确认包含关系是否有意；无意则删除被包含规则".into()),
                        ));
                    }
                    if conflicts.len() > 10 {
                        items.push(item(
                            "cidr-more",
                            "CIDR 包含冲突",
                            DoctorStatus::Warn,
                            format!("另有 {} 对包含冲突未列出", conflicts.len() - 10),
                            None,
                        ));
                    }
                }
            }
            Err(e) => items.push(item(
                "cidr",
                "节点 CIDR 规则",
                DoctorStatus::Info,
                format!("数据库只读打开失败，跳过 CIDR 冲突检查：{e}"),
                None,
            )),
        },
        _ => items.push(item(
            "cidr",
            "节点 CIDR 规则",
            DoctorStatus::Info,
            "未发现节点数据库，跳过 CIDR 冲突检查",
            None,
        )),
    }
    section("rules", "规则冲突", items)
}

/// Open the node database read-only and read ip-cidr rule values (bypasses the db module — avoids triggering migration writes).
fn read_db_cidrs(path: &Path) -> Result<Vec<String>, String> {
    let conn = rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| e.to_string())?;
    let mut stmt = conn
        .prepare("SELECT value FROM rule WHERE type = 'ip-cidr'")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

/// CIDR containment pairs (containing net, contained net); exact duplicates are also reported.
/// Pure function for testability.
pub(super) fn cidr_conflicts(values: &[String]) -> Vec<(String, String)> {
    let nets: Vec<Option<ip_network::IpNetwork>> =
        values.iter().map(|v| v.parse().ok()).collect();
    let contains = |a: &ip_network::IpNetwork, b: &ip_network::IpNetwork| {
        a.is_ipv4() == b.is_ipv4()
            && a.netmask() <= b.netmask()
            && a.contains(b.network_address())
    };
    let mut out = Vec::new();
    for i in 0..nets.len() {
        for j in (i + 1)..nets.len() {
            let (Some(a), Some(b)) = (&nets[i], &nets[j]) else {
                continue;
            };
            if contains(a, b) {
                out.push((values[i].clone(), values[j].clone()));
            } else if contains(b, a) {
                out.push((values[j].clone(), values[i].clone()));
            }
        }
    }
    out
}
