//! Split from lib.rs: system tray and tray popup (pure move, zero logic change)

use crate::{subscription, AppState};
use tauri::Manager;

// ==================== Tray icons (zap on / zap-off off, black/white adapting to system theme) ====================

/// Tray icons (64px transparent PNG; dark=black glyph for light taskbar, light=white glyph for dark taskbar)
const TRAY_ZAP_DARK: &[u8] = include_bytes!("../../icons/tray-zap-dark.png");
const TRAY_ZAP_LIGHT: &[u8] = include_bytes!("../../icons/tray-zap-light.png");
const TRAY_ZAP_OFF_DARK: &[u8] = include_bytes!("../../icons/tray-zap-off-dark.png");
const TRAY_ZAP_OFF_LIGHT: &[u8] = include_bytes!("../../icons/tray-zap-off-light.png");

/// The tray icon to use under the current system theme.
/// macOS uses a template icon (icon_as_template): the system auto-inverts per menu bar appearance, so always pick the black version;
/// Windows/Linux pick black/white manually from the system theme tracked by the main window.
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

/// Refresh tray icon: proxy running=zap / stopped=zap-off, black/white follows system theme.
pub(crate) fn refresh_tray_icon(app: &tauri::AppHandle) {
    let Some(tray) = app.tray_by_id("anet-tray") else {
        return;
    };
    let proxy_on = app.state::<AppState>().client.proxy_port() > 0;
    let _ = tray.set_icon(Some(tray_icon(app, proxy_on)));
}

/// Tray tooltip live speed (1s): shows ↑/↓ when the kernel is running with traffic, otherwise falls back to static text;
/// platform differences tolerated (set_tooltip failures are silent, no panic).
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

/// Build the system tray (left-click/double-click opens the main window, right-click pops the menu panel; no native OS menu)
pub(crate) fn setup_tray(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

    TrayIconBuilder::with_id("anet-tray")
        .icon(tray_icon(app.handle(), false))
        .icon_as_template(true) // macOS template icon: system auto-inverts per menu bar brightness
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
                    // Left click (including double-click, two single-click events): open main window directly
                    MouseButton::Left => show_main_window(tray.app_handle()),
                    // Right click: tray menu panel
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

/// Show and focus the main window (shared by tray left-click and tray panel)
pub(crate) fn show_main_window(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

// ---- Popup positioning (physical coordinates throughout; clamp_popup / tray_popup_position are pure functions covered by unit tests) ----

/// Clamp the desired rect (ex, ey, w, h) into the work area (left, top, right, bottom) with an 8px margin on all sides.
/// When the work area is smaller than the window, degrades to hugging the top-left margin (min>max clamp defense).
pub(crate) fn clamp_popup(ex: f64, ey: f64, w: f64, h: f64, area: (f64, f64, f64, f64)) -> (i32, i32) {
    const M: f64 = 8.0;
    let (left, top, right, bottom) = area;
    let x = ex.clamp(left + M, (right - w - M).max(left + M));
    let y = ey.clamp(top + M, (bottom - h - M).max(top + M));
    (x.round() as i32, y.round() as i32)
}

/// Desired tray popup position: popup bottom 8px above the anchor, horizontally centered; when space above
/// is insufficient (y beyond the work area top margin) flip to 8px below the anchor; finally clamp into the work area.
/// Correct with multi-monitor and taskbars on any edge (including the macOS top menu bar).
pub(crate) fn tray_popup_position(anchor: (f64, f64), size: (f64, f64), area: (f64, f64, f64, f64)) -> (i32, i32) {
    let (w, h) = size;
    let mut y = anchor.1 - h - 8.0;
    if y < area.1 + 8.0 {
        y = anchor.1 + 8.0;
    }
    clamp_popup(anchor.0 - w / 2.0, y, w, h, area)
}

/// Work area (physical (left, top, right, bottom)) and scale factor of the monitor containing the anchor.
/// Falls back to a huge area when monitor info is unavailable (only guarantees non-negative clamp results).
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

/// "Delayed arming" for blur hide/close listeners: show's first frame immediately fires a Focused(false);
/// a listener attached during build would hide/close the just-shown window on the spot (user sees a flicker, works on second try).
/// So the listener is attached 400ms after show. close=false hides (tray panel reuse semantics), true closes (one-shot windows).
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

/// Show/hide the tray panel (lazily created; auto-hides on blur).
/// Physical coordinates throughout: the anchor comes from the tray event (physical), the work area is physical too;
/// the builder sets no position — after build, set_position in physical coords → show → set_focus, eliminating first-click flicker.
pub(crate) fn toggle_tray_popup(app: &tauri::AppHandle, anchor: tauri::PhysicalPosition<f64>) {
    // Tray events run on the main thread: getters like work_area_at/monitor_from_point/is_visible are
    // channel-blocking (waiting on the event loop), so calling them on the main thread self-deadlocks — move everything to a worker thread.
    let app = app.clone();
    std::thread::spawn(move || {
        toggle_tray_popup_inner(&app, anchor);
    });
}
pub(crate) fn toggle_tray_popup_inner(app: &tauri::AppHandle, anchor: tauri::PhysicalPosition<f64>) {
    const W: f64 = 292.0;
    const H: f64 = 420.0;
    // size × scale = physical pixels: anchor/work area are physical; unconverted logical sizes would place the popup off-screen
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
    .visible(false) // position first, then show — no top-left flicker
    .build()
    else {
        return;
    };
    arm_blur_close(&window, false);
    let _ = window.set_position(tauri::PhysicalPosition::new(x, y));
    let _ = window.show();
    let _ = window.set_focus();
}

/// Tray panel: show main window
#[tauri::command]
pub(crate) fn tray_show_main(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(w) = app.get_webview_window("tray-popup") {
        let _ = w.hide();
    }
    show_main_window(&app);
    Ok(())
}

/// Tray panel: quit the app
#[tauri::command]
pub(crate) fn tray_quit(app: tauri::AppHandle) {
    app.exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clamps_popup_into_work_area() {
        // Work area (0,0)-(1920,1040) (bottom taskbar takes 40)
        let area = (0.0, 0.0, 1920.0, 1040.0);
        // Desired position beyond right/bottom edges → pulled back with an 8px margin
        assert_eq!(
            clamp_popup(1900.0, 1100.0, 292.0, 420.0, area),
            (1920 - 292 - 8, 1040 - 420 - 8)
        );
        // Negative desired position → clamped to the top-left margin
        assert_eq!(clamp_popup(-50.0, -50.0, 292.0, 420.0, area), (8, 8));
        // Work area smaller than window → degrades to top-left margin (no panic)
        assert_eq!(clamp_popup(500.0, 500.0, 292.0, 420.0, (0.0, 0.0, 100.0, 100.0)), (8, 8));
    }

    #[test]
    fn tray_popup_prefers_above_anchor_and_flips_below() {
        // Taskbar at bottom: anchor near the bottom edge → popup 8px above the anchor, horizontally centered
        let area = (0.0, 0.0, 1920.0, 1080.0);
        let (x, y) = tray_popup_position((1000.0, 1080.0), (292.0, 420.0), area);
        assert_eq!((x, y), (1000 - 146, 1080 - 420 - 8));
        // Taskbar at top (work area top=40): anchor at the top → insufficient space above, flips to 8px below
        let area_top_taskbar = (0.0, 40.0, 1920.0, 1080.0);
        let (_, y2) = tray_popup_position((1000.0, 40.0), (292.0, 420.0), area_top_taskbar);
        assert_eq!(y2, 48);
        // Left taskbar + multi-monitor negative-coordinate work area: clamps into that area (not clamped to 0)
        let area_left = (-1920.0, 0.0, 0.0, 1080.0);
        let (x3, _) = tray_popup_position((-1900.0, 1000.0), (292.0, 420.0), area_left);
        assert_eq!(x3, -1920 + 8);
    }
}
