//! 第 6 节：配置与数据（数据目录可写 / GUI 数据文件损坏备份重置 / 磁盘剩余空间）。

use super::{DoctorContext, DoctorItem, DoctorSection, DoctorStatus, item, section};
use std::path::Path;

/// GUI 数据文件（文件名, 损坏重置时的默认内容；内容须能被桌面端反序列化为默认值）。
const GUI_DATA_FILES: &[(&str, &str)] = &[
    // RoleSettings 必填三字段写全，其余字段 serde default 兜底
    ("gui-settings.json", r#"{"client":true,"server":false,"web":false}"#),
    ("subscriptions.json", "{}"),
    ("gui-custom-rules.json", "{}"),
];

pub(super) fn section_config(ctx: &DoctorContext) -> DoctorSection {
    let mut items = Vec::new();
    let dir = &ctx.data_dir;
    if !dir.exists() {
        items.push(item(
            "data-dir",
            "数据目录",
            DoctorStatus::Info,
            format!("{} 不存在（将在首次使用时创建）", dir.display()),
            None,
        ));
    } else {
        // 目录可写
        let probe = dir.join(".doctor-write-test");
        match std::fs::write(&probe, b"t").and_then(|_| std::fs::remove_file(&probe)) {
            Ok(()) => items.push(item(
                "writable",
                "数据目录可写",
                DoctorStatus::Ok,
                dir.display().to_string(),
                None,
            )),
            Err(e) => items.push(item(
                "writable",
                "数据目录可写",
                DoctorStatus::Err,
                format!("{} 写入失败：{e}", dir.display()),
                Some("检查目录权限与占用（杀毒软件实时防护可能拦截）".into()),
            )),
        }
        // GUI 数据文件可解析（CLI 上下文只检已存在的文件；GUI 上下文缺失也报告）
        for &(name, default_content) in GUI_DATA_FILES {
            let path = dir.join(name);
            if !path.exists() {
                if ctx.gui {
                    items.push(item(
                        format!("file-{name}"),
                        name,
                        DoctorStatus::Info,
                        "不存在（按需创建）",
                        None,
                    ));
                }
                continue;
            }
            let parsed = std::fs::read_to_string(&path)
                .ok()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
            if parsed.is_some() {
                items.push(item(
                    format!("file-{name}"),
                    name,
                    DoctorStatus::Ok,
                    "可解析",
                    None,
                ));
                continue;
            }
            // 损坏：备份为 .bak-时间戳 并重置默认
            if ctx.fix {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let bak = dir.join(format!("{name}.bak-{ts}"));
                let res = std::fs::rename(&path, &bak)
                    .and_then(|_| std::fs::write(&path, default_content));
                match res {
                    Ok(()) => items.push(item(
                        format!("file-{name}"),
                        name,
                        DoctorStatus::Fixed,
                        format!("文件损坏，已备份为 {} 并重置默认", bak.display()),
                        None,
                    )),
                    Err(e) => items.push(item(
                        format!("file-{name}"),
                        name,
                        DoctorStatus::Err,
                        format!("文件损坏且重置失败：{e}"),
                        Some(format!("手动备份并删除 {} 后重启应用", path.display())),
                    )),
                }
            } else {
                items.push(item(
                    format!("file-{name}"),
                    name,
                    DoctorStatus::Err,
                    "文件损坏（JSON 不可解析）",
                    Some("备份后删除该文件，应用将以默认值重建".into()),
                ));
            }
        }
    }

    // 磁盘剩余空间（<1GiB err / <5GiB warn）
    items.push(check_disk_space(dir));
    section("config", "配置与数据", items)
}

/// 数据目录所在卷的剩余空间检查（sysinfo Disks，最长挂载点前缀匹配）。
fn check_disk_space(dir: &Path) -> DoctorItem {
    const GIB: u64 = 1024 * 1024 * 1024;
    let disks = sysinfo::Disks::new_with_refreshed_list();
    let disk = disks
        .iter()
        .filter(|d| dir.starts_with(d.mount_point()))
        .max_by_key(|d| d.mount_point().as_os_str().len());
    match disk {
        None => item(
            "disk",
            "磁盘剩余空间",
            DoctorStatus::Info,
            "未找到数据目录所在卷",
            None,
        ),
        Some(d) => {
            let avail = d.available_space();
            let detail = format!(
                "剩余 {:.1} GiB（卷 {}）",
                avail as f64 / GIB as f64,
                d.mount_point().display()
            );
            if avail < GIB {
                item(
                    "disk",
                    "磁盘剩余空间",
                    DoctorStatus::Err,
                    detail,
                    Some("剩余空间不足 1 GiB：清理磁盘，数据库/日志写入即将失败".into()),
                )
            } else if avail < 5 * GIB {
                item(
                    "disk",
                    "磁盘剩余空间",
                    DoctorStatus::Warn,
                    detail,
                    Some("剩余空间不足 5 GiB：建议清理（下载制品与日志将持续占用）".into()),
                )
            } else {
                item("disk", "磁盘剩余空间", DoctorStatus::Ok, detail, None)
            }
        }
    }
}
