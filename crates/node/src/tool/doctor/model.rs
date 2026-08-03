//! 报告模型与诊断上下文（serde 字段名即 GUI 契约，一字不得改）。

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// 单项检查结论：`ok` 通过 / `info` 提示 / `warn` 警告 / `err` 错误 / `fixed` 已自动修复。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DoctorStatus {
    Ok,
    Info,
    Warn,
    Err,
    Fixed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorItem {
    pub id: String,
    pub label: String,
    pub status: DoctorStatus,
    pub detail: String,
    pub suggestion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorSection {
    pub id: String,
    pub title: String,
    pub items: Vec<DoctorItem>,
}

/// 汇总计数（info 项不计入；fixed 不抵消 err——修复前的 err 已转为 fixed）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DoctorSummary {
    pub ok: usize,
    pub warn: usize,
    pub err: usize,
    pub fixed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    pub sections: Vec<DoctorSection>,
    pub summary: DoctorSummary,
    pub duration_ms: u64,
}

/// 诊断上下文：控制 GUI 特有路径（GUI 数据文件 / 内核与 wintun 钉值 / 孤儿 sweep / 系统代理）。
#[derive(Debug, Clone)]
pub struct DoctorContext {
    /// GUI 上下文：检查 GUI 数据文件、订阅内核与 wintun、系统代理残留、hosts 托管块漂移
    pub gui: bool,
    /// 允许自动修复（false = 只诊断不动手；测试与只读场景用）
    pub fix: bool,
    /// AgileNet 数据目录（默认 ~/.agile-net；测试注入临时目录）
    pub data_dir: PathBuf,
    /// 节点 SQLite 路径（只读查 CIDR 冲突；None 或不存在 = 跳过）
    pub db_path: Option<PathBuf>,
    /// 已知受管的 mihomo PID（孤儿判定白名单，叠加控制面监听者自动豁免）
    pub managed_pids: Vec<u32>,
}

impl DoctorContext {
    /// anet-gui 自我诊断：检查 GUI 数据文件 + 内嵌节点库（存在时）。
    pub fn gui() -> Self {
        let data_dir = default_data_dir();
        let embedded_db = data_dir.join("embedded-node").join("node.db");
        Self {
            gui: true,
            fix: true,
            db_path: embedded_db.exists().then_some(embedded_db),
            data_dir,
            managed_pids: Vec::new(),
        }
    }

    /// `anet doctor`：本机体检；节点库取 DATABASE_PATH 或 ./agile-net.db（存在时）。
    pub fn cli() -> Self {
        let db_path = std::env::var("DATABASE_PATH")
            .ok()
            .map(PathBuf::from)
            .filter(|p| p.exists())
            .or_else(|| {
                let p = PathBuf::from("agile-net.db");
                p.exists().then_some(p)
            });
        Self {
            gui: false,
            fix: true,
            data_dir: default_data_dir(),
            db_path,
            managed_pids: Vec::new(),
        }
    }
}

/// 数据目录（与 apps/desktop roles::data_dir 同规则）。
fn default_data_dir() -> PathBuf {
    std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".agile-net")
}
