//! Report model and diagnosis context (serde field names are the GUI contract — never change them).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Verdict of a single check: `ok` passed / `info` note / `warn` warning / `err` error / `fixed` auto-fixed.
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

/// Summary counts (info items not counted; fixed does not cancel err — the pre-fix err became fixed).
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

/// Diagnosis context: controls GUI-specific paths (GUI data files / kernel & wintun pins / orphan sweep / system proxy).
#[derive(Debug, Clone)]
pub struct DoctorContext {
    /// GUI context: check GUI data files, subscription kernel and wintun, leftover system proxy, managed hosts-block drift
    pub gui: bool,
    /// Allow auto-fix (false = diagnose only, never touch; for tests and read-only scenarios)
    pub fix: bool,
    /// AgileNet GUI data directory (default ~/.anet/gui; tests inject a temp dir)
    pub data_dir: PathBuf,
    /// Node SQLite path (read-only CIDR conflict check; None or missing = skip)
    pub db_path: Option<PathBuf>,
    /// Known managed mihomo PIDs (orphan-detection whitelist, on top of the automatic exemption for control-plane listeners)
    pub managed_pids: Vec<u32>,
}

impl DoctorContext {
    /// anet-gui self-diagnosis: check GUI data files + the embedded node database (when present).
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

    /// `anet doctor`: local health check; node database from DATABASE_PATH or ./agile-net.db (when present).
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

/// Data directory (same rule as apps/desktop roles::data_dir — both resolve to
/// `~/.anet/gui`, since doctor inspects GUI-side data files and the embedded node DB).
fn default_data_dir() -> PathBuf {
    agile_net_core::util::gui_data_dir()
}
