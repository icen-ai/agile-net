//! Split from lib.rs: self-diagnosis (pure move, zero logic change)

use crate::{map_err, roles};

/// Self-diagnosis (shares the same engine as `anet doctor`; checks involve blocking ops such as
/// netstat/registry/file IO, so the whole run is offloaded to spawn_blocking and async probes are
/// driven via block_on, avoiding monopolizing runtime threads)
#[tauri::command]
pub(crate) async fn run_doctor(app: tauri::AppHandle) -> Result<agile_net_node::tool::doctor::DoctorReport, String> {
    use agile_net_node::tool::doctor as doc;
    use tauri::Emitter as _;
    roles::audit("gui.doctor", serde_json::json!({}));
    // Streaming diagnosis: emit the section plan first (frontend renders a skeleton), push one event per finished section, then return the full report
    let _ = app.emit("ag-doctor-begin", doc::SECTION_PLAN);
    tauri::async_runtime::spawn_blocking(move || {
        tauri::async_runtime::block_on(doc::run_streaming(doc::DoctorContext::gui(), |sec| {
            let _ = app.emit("ag-doctor-section", sec);
        }))
    })
    .await
    .map_err(map_err)
}
