//! 从 lib.rs 拆分：悬浮球 / 气泡通知 / 窗口几何（纯搬运，零逻辑变更）

use crate::{map_err, roles, AppState};
#[cfg(windows)]
use crate::floatball;
use std::sync::atomic::Ordering;
use tauri::{Manager, State};

/// 统一开窗规格：主屏逻辑宽 1/2、宽高比 4:3、屏幕居中（主窗与控制台一致）
pub(crate) fn normalize_window_geometry(window: &tauri::WebviewWindow) {
    if let Ok(Some(monitor)) = window.primary_monitor() {
        let scale = monitor.scale_factor();
        let logical_w = monitor.size().width as f64 / scale;
        let w = (logical_w * 0.5).round().max(860.0);
        let h = (w * 0.75).round().max(600.0);
        let _ = window.set_size(tauri::Size::Logical(tauri::LogicalSize {
            width: w,
            height: h,
        }));
    }
    let _ = window.center();
}

// ==================== 悬浮球窗口（仅桌面） ====================

/// 悬浮球锚点信息：球体可视区左上物理坐标 (x, y)、球可视高、球所在显示器工作区与缩放因子。
/// 用 inner_position/inner_size：outer_* 在 Windows 含 DWM 隐形边框（72→170），会算歪菜单位置。
/// 球不存在返回 None。
pub(crate) fn ball_anchor(app: &tauri::AppHandle) -> Option<(f64, f64, f64, (f64, f64, f64, f64), f64)> {
    // Windows 原生球：位置由 floatball 静态槽提供（无 webview 窗口）
    #[cfg(windows)]
    if let Some((bx, by, bs)) = floatball::rect() {
        let (area, scale) = crate::work_area_at(app, bx as f64, by as f64);
        return Some((bx as f64, by as f64, bs as f64, area, scale));
    }
    let ball = app.get_webview_window("float-ball")?;
    let pos = ball.inner_position().ok()?;
    let size = ball.inner_size().ok()?;
    let (area, scale) = crate::work_area_at(app, pos.x as f64, pos.y as f64);
    Some((pos.x as f64, pos.y as f64, size.height as f64, area, scale))
}

/// 悬浮球气泡通知（桥接既有告警点与 float_ball_notify 命令共用）：
/// 单例窗口 float-bubble + 事件 ag-bubble-text 续命——窗口已存在则只发新文本，
/// 前端渲染后 4s 自行 close（窗口销毁由前端驱动，后端无需清理）。
/// 用户关闭「悬浮球通知」偏好后全局静默（含既有桥接点）。
pub(crate) fn float_notify(app: &tauri::AppHandle, text: impl Into<String>) {
    use tauri::Emitter;
    if let Some(state) = app.try_state::<AppState>() {
        if !state.notify_float_ball.load(Ordering::Relaxed) {
            return;
        }
    }
    let text = text.into();
    if app.get_webview_window("float-bubble").is_some() {
        let _ = app.emit_to("float-bubble", "ag-bubble-text", text);
        return;
    }
    // ball_anchor/build 等 channel 阻塞式调用：本函数可能被主线程上下文
    // （sync 命令）调到，窗口操作整体丢工作线程，杜绝自锁。
    let app = app.clone();
    std::thread::spawn(move || {
        float_notify_inner(&app, text);
    });
}
/// 气泡待读文本：float_notify_inner 写入，float-bubble 页加载完成后经 float_bubble_take 取走。
/// （替代原先的 emit + 600ms 补发：首帧 webview 未挂监听会丢事件，气泡空卡常驻）
static BUBBLE_PENDING: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// float-bubble 页就绪后取待读文本（取走即清；None = 无通知，前端应立即自关窗口）。
#[tauri::command]
pub(crate) fn float_bubble_take() -> Option<String> {
    BUBBLE_PENDING.lock().ok()?.take()
}

pub(crate) fn float_notify_inner(app: &tauri::AppHandle, text: String) {
    const W: f64 = 220.0;
    const H: f64 = 96.0;
    // 不透明卡片（气泡即卡片，不依赖 transparent；同源同窗扩容方案在 Windows 透明失效后废弃）
    let Ok(window) = tauri::WebviewWindowBuilder::new(
        app,
        "float-bubble",
        tauri::WebviewUrl::App("float-bubble.html".into()),
    )
    .title("AgileNet")
    .inner_size(W, H)
    .decorations(false)
    .always_on_top(true)
    .skip_taskbar(true)
    .resizable(false)
    .visible(false) // 先定位后显示
    .build()
    else {
        return;
    };
    // 位置：球左边 10px、垂直与球居中，clamp 进球所在工作区
    if let Some((bx, by, bh, area, scale)) = ball_anchor(app) {
        let (x, y) = crate::clamp_popup(
            bx - W * scale - 10.0,
            by + (bh - H * scale) / 2.0,
            W * scale,
            H * scale,
            area,
        );
        let _ = window.set_position(tauri::PhysicalPosition::new(x, y));
    }
    // 文本落待读槽（若槽里有旧文本被覆盖：前端取最新一条即可），页面 ready 后自取
    if let Ok(mut p) = BUBBLE_PENDING.lock() {
        *p = Some(text);
    }
    let _ = window.show();
}

/// 创建悬浮球窗口（幂等）：72×72 无框透明常驻，默认定位主屏右下角偏移
/// （取主屏方式与 normalize_window_geometry 一致）。
#[cfg(desktop)]
#[cfg(all(desktop, windows))]
pub(crate) fn create_float_ball(app: &tauri::AppHandle) -> Result<(), String> {
    // Windows：原生分层窗球（GDI+ 绘制，不经 WebView；透明/窗框/裁剪整类问题根绝）
    floatball::create(app)
}

#[cfg(all(desktop, not(windows)))]
pub(crate) fn create_float_ball(app: &tauri::AppHandle) -> Result<(), String> {
    const SIZE: f64 = 72.0;
    if app.get_webview_window("float-ball").is_some() {
        return Ok(());
    }
    let mut x = 100.0;
    let mut y = 100.0;
    if let Ok(Some(m)) = app.primary_monitor() {
        let scale = m.scale_factor();
        let logical_w = m.size().width as f64 / scale;
        let logical_h = m.size().height as f64 / scale;
        x = (logical_w - SIZE - 24.0).max(0.0);
        y = (logical_h - SIZE - 96.0).max(0.0);
    }
    tauri::WebviewWindowBuilder::new(
        app,
        "float-ball",
        tauri::WebviewUrl::App("float.html".into()),
    )
    .title("AgileNet")
    .inner_size(SIZE, SIZE)
    .decorations(false)
    .transparent(true)
    .always_on_top(true)
    .skip_taskbar(true)
    .resizable(false)
    .position(x, y)
    .build()
    .map_err(map_err)?;
    Ok(())
}

/// 移动端不支持悬浮球（平台判定返回不支持；保持 mobile 目标编译不破）。
#[cfg(not(desktop))]
pub(crate) fn create_float_ball(_app: &tauri::AppHandle) -> Result<(), String> {
    Err("悬浮球仅支持桌面端".into())
}

/// 悬浮球开关：on=创建窗口，off=销毁；持久化 + 审计（setup 恢复读取同一字段）。
#[tauri::command]
pub(crate) async fn set_float_ball(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    on: bool,
) -> Result<(), String> {
    if on {
        create_float_ball(&app)?;
    } else {
        #[cfg(windows)]
        floatball::destroy();
        if let Some(w) = app.get_webview_window("float-ball") {
            let _ = w.close();
        }
    }
    {
        let mut roles = state.roles.lock().await;
        roles.float_ball = on;
        roles.save()?;
    }
    roles::audit("gui.float_ball", serde_json::json!({"on": on}));
    Ok(())
}

/// 悬浮球气泡通知开关：false 时 float_notify 桥接点与 float_ball_notify 命令均不再 emit。
#[tauri::command]
pub(crate) async fn set_notify_float_ball(state: State<'_, AppState>, on: bool) -> Result<(), String> {
    {
        let mut roles = state.roles.lock().await;
        roles.notify_float_ball = on;
        roles.save()?;
    }
    state.notify_float_ball.store(on, Ordering::Relaxed);
    roles::audit("gui.notify_float_ball", serde_json::json!({"on": on}));
    Ok(())
}

/// 悬浮球气泡通知通道（前端主窗 → 悬浮球气泡窗口）。
#[tauri::command]
pub(crate) fn float_ball_notify(app: tauri::AppHandle, text: String) -> Result<(), String> {
    float_notify(&app, text);
    Ok(())
}

/// 悬浮球右键菜单（独立小窗 float-menu；toggle 语义：已可见则关闭）。
/// 不透明卡片（菜单本就该不透明，不依赖 transparent）；失焦自动关闭（延迟武装 400ms）。
/// 必须 async：ball_anchor 的 outer_position/outer_size 是 channel 阻塞式调用，
/// sync 命令跑在主线程会自锁（菜单弹不出 + 主窗卡死）。
#[tauri::command]
pub(crate) async fn float_open_menu(app: tauri::AppHandle) -> Result<(), String> {
    float_open_menu_impl(&app).await
}

/// 菜单打开/定位的共享实现（命令与原生悬浮球右键共用）。
pub(crate) async fn float_open_menu_impl(app: &tauri::AppHandle) -> Result<(), String> {
    const W: f64 = 200.0;
    const H: f64 = 320.0; // 268 + 出站模式按钮组（规则/全局/直连）
    // 期望位：菜单右边距球左边 10px，底边对齐球底，clamp 进球所在工作区
    let position = |app: &tauri::AppHandle| -> Option<tauri::PhysicalPosition<i32>> {
        let (bx, by, bh, area, scale) = ball_anchor(app)?;
        let (x, y) = crate::clamp_popup(bx - W * scale - 10.0, by + bh - H * scale, W * scale, H * scale, area);
        Some(tauri::PhysicalPosition::new(x, y))
    };
    if let Some(w) = app.get_webview_window("float-menu") {
        if w.is_visible().unwrap_or(false) {
            let _ = w.close();
            return Ok(());
        }
        if let Some(p) = position(&app) {
            let _ = w.set_position(p);
        }
        let _ = w.show();
        let _ = w.set_focus();
        return Ok(());
    }
    let window = tauri::WebviewWindowBuilder::new(
        app,
        "float-menu",
        tauri::WebviewUrl::App("float-menu.html".into()),
    )
    .title("AgileNet")
    .inner_size(W, H)
    .decorations(false)
    .always_on_top(true)
    .skip_taskbar(true)
    .resizable(false)
    .visible(false) // 先定位后显示
    .build()
    .map_err(map_err)?;
    crate::arm_blur_close(&window, true);
    if let Some(p) = position(&app) {
        let _ = window.set_position(p);
    }
    let _ = window.show();
    let _ = window.set_focus();
    Ok(())
}
