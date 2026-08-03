//! 第 7 节：规则冲突（非法/重复自定义规则清理、hosts 托管块漂移重写、节点库 CIDR 包含冲突）。

use super::{DoctorContext, DoctorSection, DoctorStatus, item, section};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// GUI 托管块标记（与 apps/desktop/src/custom_rules.rs 一致）。
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

/// 放行 pattern 合法性（对齐 desktop add_bypass：非空且无空白字符）。
fn valid_bypass_pattern(p: &str) -> bool {
    !p.is_empty() && !p.chars().any(|c| c.is_whitespace())
}

/// hosts 映射合法性（对齐 desktop add_host：主机名非 IP、无空白/*/#；IP 可解析）。
fn valid_host_entry(host: &str, ip: &str) -> bool {
    !host.is_empty()
        && !host.chars().any(|c| c.is_whitespace() || c == '*' || c == '#')
        && host.parse::<IpAddr>().is_err()
        && ip.parse::<IpAddr>().is_ok()
}

/// 从 gui-custom-rules.json 提取生效的 hosts 映射（enabled 且 to_system）。
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

/// 解析系统 hosts 中的 GUI 托管块条目。
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

/// 剔除托管块（语义对齐 desktop strip_block）。
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

/// 幂等重写系统 hosts 托管块（temp + rename；权限不足返回 Err）。
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

/// 清理规则文件中的非法项（Value 层面操作以保留未知字段）；返回移除项描述。
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
    // 级联清理组合中的失效成员 key（对齐 desktop remove 语义）
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

/// 放行 pattern 重复检测（大小写不敏感）；返回重复的 pattern 列表。
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
        // 非法项（err + fix 移除）
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
        // pattern 重复（warn）
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
        // hosts 托管块漂移（fix 重写）
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
        // 损坏文件由「配置与数据」节负责修复（本节在其后执行，届时已重置为 {}）
        items.push(item(
            "custom",
            "自定义规则",
            DoctorStatus::Info,
            "规则文件不可解析（见「配置与数据」节处理）",
            None,
        ));
    }

    // 节点库 CIDR 包含关系冲突（只读；无库跳过）
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

/// 只读打开节点库读取 ip-cidr 规则值（不走 db 模块——避免触发迁移写）。
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

/// CIDR 包含关系对（大网, 被包含网）；同值重复也报告。纯函数便于测试。
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
