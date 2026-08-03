//! 从 lib.rs 拆分：系统托盘与托盘弹窗（纯搬运，零逻辑变更）

use crate::{subscription, AppState};
use tauri::Manager;

// ==================== 托盘图标（zap 开 / zap-off 关，黑白随系统主题自适应） ====================

/// 托盘图标（64px 透明底 PNG；dark=黑色图形用于浅色任务栏，light=白色图形用于深色任务栏）
const TRAY_ZAP_DARK: &[u8] = include_bytes!("../../icons/tray-zap-dark.png");
const TRAY_ZAP_LIGHT: &[u8] = include_bytes!("../../icons/tray-zap-light.png");
const TRAY_ZAP_OFF_DARK: &[u8] = include_bytes!("../../icons/tray-zap-off-dark.png");
const TRAY_ZAP_OFF_LIGHT: &[u8] = include_bytes!("../../icons/tray-zap-off-light.png");

/// 当前系统主题下应使用的托盘图标。
/// macOS 走模板图标（icon_as_template），系统按菜单栏外观自动反色，固定取黑色版本；
/// Windows/Linux 按主窗口跟踪的系统主题手动选黑白。
pub(crate) fn tray_icon(app: &tauri::AppHandle, proxy_on: bool) -> tauri::image::Image<'static> {
    #[cfg(target_os = "macos")]
    let dark_taskbar = false;
    #[cfg(not(target_os = "macos"))]
    let dark_taskbar = app
        .get_webview_window("main")
        .and_then(|w| w.theme().ok())
        .map(|t| matches!(t, tauri::Theme::Dark))
        .unwrap_or(false);
    let bytes = match (proxy_on, dark_taskbar) {
        (true, true) => TRAY_ZAP_LIGHT,
        (true, false) => TRAY_ZAP_DARK,
        (false, true) => TRAY_ZAP_OFF_LIGHT,
        (false, false) => TRAY_ZAP_OFF_DARK,
    };
    tauri::image::Image::from_bytes(bytes).expect("托盘图标 PNG 解码失败")
}

/// 刷新托盘图标：代理运行=zap / 停止=zap-off，黑白随系统主题。
pub(crate) fn refresh_tray_icon(app: &tauri::AppHandle) {
    let Some(tray) = app.tray_by_id("anet-tray") else {
        return;
    };
    let proxy_on = app.state::<AppState>().client.proxy_port() > 0;
    let _ = tray.set_icon(Some(tray_icon(app, proxy_on)));
}

/// 托盘 tooltip 实时网速（1s）：内核运行且有速率时显示 ↑/↓，否则回退静态文案；
/// 平台差异容错（set_tooltip 失败静默，不 panic）。
pub(crate) async fn tray_speed_watch(app: tauri::AppHandle) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let Some(tray) = app.tray_by_id("anet-tray") else {
            continue;
        };
        let state = app.state::<AppState>();
        let snap = state.kernel.traffic();
        let tip = if state.kernel.running().await && (snap.up_rate > 0 || snap.down_rate > 0) {
            format!(
                "↑ {}/s ↓ {}/s · AgileNet",
                subscription::format_rate(snap.up_rate),
                subscription::format_rate(snap.down_rate)
            )
        } else {
            "AgileNet 客户端".to_string()
        };
        let _ = tray.set_tooltip(Some(&tip));
    }
}

/// 构建系统托盘（左键/双击打开主窗口，右键弹出菜单面板；无系统原生菜单）
pub(crate) fn setup_tray(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

    TrayIconBuilder::with_id("anet-tray")
        .icon(tray_icon(app.handle(), false))
        .icon_as_template(true) // macOS 模板图标：系统按菜单栏深浅自动反色
        .tooltip("AgileNet 客户端")
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button,
                button_state,
                position,
                ..
            } = event
            {
                if button_state != MouseButtonState::Up {
                    return;
                }
                match button {
                    // 左键（含双击，两次单击事件）：直接打开主窗口
                    MouseButton::Left => show_main_window(tray.app_handle()),
                    // 右键：托盘菜单面板
                    MouseButton::Right => toggle_tray_popup(
                        tray.app_handle(),
                        tauri::PhysicalPosition::new(position.x, position.y),
                    ),
                    _ => {}
                }
            }
        })
        .build(app)?;
    Ok(())
}

/// 显示并聚焦主窗口（托盘左键与托盘面板共用）
pub(crate) fn show_main_window(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

// ---- 弹窗定位（全程物理坐标；clamp_popup / tray_popup_position 为纯函数，单测覆盖） ----

/// 把期望矩形 (ex, ey, w, h) 收进工作区 (left, top, right, bottom)，四边留 8px 边距。
/// 工作区比窗口还小时退化为贴左上边距（clamp 的 min>max 防御）。
pub(crate) fn clamp_popup(ex: f64, ey: f64, w: f64, h: f64, area: (f64, f64, f64, f64)) -> (i32, i32) {
    const M: f64 = 8.0;
    let (left, top, right, bottom) = area;
    let x = ex.clamp(left + M, (right - w - M).max(left + M));
    let y = ey.clamp(top + M, (bottom - h - M).max(top + M));
    (x.round() as i32, y.round() as i32)
}

/// 托盘弹窗期望位：弹窗底边贴 anchor 上方 8px、水平居中；anchor 上方空间不足
/// （y 越出工作区顶边距）则翻转到 anchor 下方 8px；最后 clamp 进工作区。
/// 多显示器 / 任务栏在任意边（含 macOS 顶部菜单栏）均正确。
pub(crate) fn tray_popup_position(anchor: (f64, f64), size: (f64, f64), area: (f64, f64, f64, f64)) -> (i32, i32) {
    let (w, h) = size;
    let mut y = anchor.1 - h - 8.0;
    if y < area.1 + 8.0 {
        y = anchor.1 + 8.0;
    }
    clamp_popup(anchor.0 - w / 2.0, y, w, h, area)
}

/// anchor 所在显示器的工作区（物理坐标 (left, top, right, bottom)）与缩放因子。
/// 取不到显示器信息时给一个足够大的区域（仅保证 clamp 后非负）。
pub(crate) fn work_area_at(app: &tauri::AppHandle, x: f64, y: f64) -> ((f64, f64, f64, f64), f64) {
    let monitor = app
        .monitor_from_point(x, y)
        .ok()
        .flatten()
        .or_else(|| app.primary_monitor().ok().flatten());
    match monitor {
        Some(m) => {
            let area = m.work_area();
            let p = area.position;
            let s = area.size;
            (
                (
                    p.x as f64,
                    p.y as f64,
                    p.x as f64 + s.width as f64,
                    p.y as f64 + s.height as f64,
                ),
                m.scale_factor(),
            )
        }
        None => ((0.0, 0.0, f64::MAX / 2.0, f64::MAX / 2.0), 1.0),
    }
}

/// 失焦隐藏/关闭监听「延迟武装」：show 首帧会立即触发一次 Focused(false)，
/// 若在 build 期就挂监听会把刚显示的窗口当场隐藏/关闭（用户看到闪一下不出现，第二次才好）。
/// 故 show 之后延时 400ms 再挂监听。close=false 隐藏（托盘面板复用语义），true 关闭（一次性小窗）。
pub(crate) fn arm_blur_close(window: &tauri::WebviewWindow, close: bool) {
    let w = window.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(400));
        let w2 = w.clone();
        w.on_window_event(move |event| {
            if let tauri::WindowEvent::Focused(false) = event {
                if close {
                    let _ = w2.close();
                } else {
                    let _ = w2.hide();
                }
            }
        });
    });
}

/// 弹出/收起托盘面板（懒创建；失焦自动隐藏）。
/// 坐标全程物理坐标系：anchor 来自托盘事件（物理），工作区同样物理；
/// builder 不设 position，build 后以物理坐标 set_position → show → set_focus，杜绝首击闪帧。
pub(crate) fn toggle_tray_popup(app: &tauri::AppHandle, anchor: tauri::PhysicalPosition<f64>) {
    // 托盘事件跑在主线程：work_area_at/monitor_from_point/is_visible 等 getter 均
    // channel 阻塞式（等事件循环应答），主线程调用即自锁——整体移到工作线程。
    let app = app.clone();
    std::thread::spawn(move || {
        toggle_tray_popup_inner(&app, anchor);
    });
}
pub(crate) fn toggle_tray_popup_inner(app: &tauri::AppHandle, anchor: tauri::PhysicalPosition<f64>) {
    const W: f64 = 292.0;
    const H: f64 = 420.0;
    // 尺寸×缩放 = 物理像素：anchor/工作区均物理坐标，逻辑尺寸不换算会把弹窗放出屏外
    let (area, scale) = work_area_at(app, anchor.x, anchor.y);
    let (x, y) = tray_popup_position((anchor.x, anchor.y), (W * scale, H * scale), area);
    if let Some(w) = app.get_webview_window("tray-popup") {
        if w.is_visible().unwrap_or(false) {
            let _ = w.hide();
            return;
        }
        let _ = w.set_position(tauri::PhysicalPosition::new(x, y));
        let _ = w.show();
        let _ = w.set_focus();
        return;
    }
    let Ok(window) = tauri::WebviewWindowBuilder::new(
        app,
        "tray-popup",
        tauri::WebviewUrl::App("tray.html".into()),
    )
    .title("AgileNet")
    .inner_size(W, H)
    .resizable(false)
    .decorations(false)
    .always_on_top(true)
    .skip_taskbar(true)
    .visible(false) // 先定位后显示，杜绝左上角闪帧
    .build()
    else {
        return;
    };
    arm_blur_close(&window, false);
    let _ = window.set_position(tauri::PhysicalPosition::new(x, y));
    let _ = window.show();
    let _ = window.set_focus();
}

/// 托盘面板：显示主窗口
#[tauri::command]
pub(crate) fn tray_show_main(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(w) = app.get_webview_window("tray-popup") {
        let _ = w.hide();
    }
    show_main_window(&app);
    Ok(())
}

/// 托盘面板：退出应用
#[tauri::command]
pub(crate) fn tray_quit(app: tauri::AppHandle) {
    app.exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clamps_popup_into_work_area() {
        // 工作区 (0,0)-(1920,1040)（底部任务栏占 40）
        let area = (0.0, 0.0, 1920.0, 1040.0);
        // 期望位越出右/下边界 → 收回并留 8px 边距
        assert_eq!(
            clamp_popup(1900.0, 1100.0, 292.0, 420.0, area),
            (1920 - 292 - 8, 1040 - 420 - 8)
        );
        // 期望位为负 → 收到左上边距
        assert_eq!(clamp_popup(-50.0, -50.0, 292.0, 420.0, area), (8, 8));
        // 工作区比窗口小 → 退化贴左上边距（不 panic）
        assert_eq!(clamp_popup(500.0, 500.0, 292.0, 420.0, (0.0, 0.0, 100.0, 100.0)), (8, 8));
    }

    #[test]
    fn tray_popup_prefers_above_anchor_and_flips_below() {
        // 任务栏在底部：anchor 靠近底边 → 弹窗在 anchor 上方 8px、水平居中
        let area = (0.0, 0.0, 1920.0, 1080.0);
        let (x, y) = tray_popup_position((1000.0, 1080.0), (292.0, 420.0), area);
        assert_eq!((x, y), (1000 - 146, 1080 - 420 - 8));
        // 任务栏在顶部（工作区 top=40）：anchor 贴顶 → 上方空间不足翻转到下方 8px
        let area_top_taskbar = (0.0, 40.0, 1920.0, 1080.0);
        let (_, y2) = tray_popup_position((1000.0, 40.0), (292.0, 420.0), area_top_taskbar);
        assert_eq!(y2, 48);
        // 左侧任务栏 + 多显示器负坐标工作区：clamp 进该区（不被钳到 0）
        let area_left = (-1920.0, 0.0, 0.0, 1080.0);
        let (x3, _) = tray_popup_position((-1900.0, 1000.0), (292.0, 420.0), area_left);
        assert_eq!(x3, -1920 + 8);
    }
}
