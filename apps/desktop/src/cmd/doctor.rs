//! 从 lib.rs 拆分：自我诊断（纯搬运，零逻辑变更）

use crate::{map_err, roles};

/// 自我诊断（与 `anet doctor` 共用同一引擎；检查含 netstat/注册表/文件 IO 等阻塞操作，
/// 整体丢进 spawn_blocking 再 block_on 驱动异步探测，避免占住运行时线程）
#[tauri::command]
pub(crate) async fn run_doctor(app: tauri::AppHandle) -> Result<agile_net_node::tool::doctor::DoctorReport, String> {
    use agile_net_node::tool::doctor as doc;
    use tauri::Emitter as _;
    roles::audit("gui.doctor", serde_json::json!({}));
    // 流式诊断：先发检查节计划（前端渲染骨架），每完成一节推一个事件，最后返回完整报告
    let _ = app.emit("ag-doctor-begin", doc::SECTION_PLAN);
    tauri::async_runtime::spawn_blocking(move || {
        tauri::async_runtime::block_on(doc::run_streaming(doc::DoctorContext::gui(), |sec| {
            let _ = app.emit("ag-doctor-section", sec);
        }))
    })
    .await
    .map_err(map_err)
}
