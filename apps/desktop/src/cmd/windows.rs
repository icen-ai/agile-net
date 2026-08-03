//! Split from lib.rs: float ball / bubble notifications / window geometry (pure move, zero logic change)

use crate::{map_err, roles, AppState};
#[cfg(windows)]
use crate::floatball;
use std::sync::atomic::Ordering;
use tauri::{Manager, State};

/// Unified window spec: half the primary monitor's logical width, 4:3 aspect ratio, screen-centered (main window and console alike)
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

// ==================== Float ball window (desktop only) ====================

/// Float ball anchor: physical (x, y) of the ball's visible top-left, ball visible height, work area (x, y, w, h) of its monitor, and scale factor.
pub(crate) type BallAnchor = (f64, f64, f64, (f64, f64, f64, f64), f64);

/// Read the float ball anchor (field semantics see BallAnchor).
/// Uses inner_position/inner_size: outer_* includes DWM invisible borders on Windows (72→170), which would skew menu placement.
/// Returns None when the ball does not exist.
pub(crate) fn ball_anchor(app: &tauri::AppHandle) -> Option<BallAnchor> {
    // Windows native ball: position comes from the floatball static slot (no webview window)
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

/// Float ball bubble notification (shared by existing alert call sites and the float_ball_notify command):
/// singleton float-bubble window + ag-bubble-text event renewal — if the window already exists, only new
/// text is sent; the frontend closes it itself 4s after rendering (window teardown is frontend-driven, no backend cleanup).
/// Goes fully silent (including existing call sites) when the user disables the "float ball notifications" preference.
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
    // ball_anchor/build are channel-blocking calls: this function may be invoked from a main-thread
    // context (sync command), so all window ops go to a worker thread to avoid self-deadlock.
    let app = app.clone();
    std::thread::spawn(move || {
        float_notify_inner(&app, text);
    });
}
/// Pending bubble text: written by float_notify_inner, taken by the float-bubble page via float_bubble_take after load.
/// (Replaces the old emit + 600ms resend: the first-frame webview has no listener attached, dropping the event and leaving a stuck empty bubble)
static BUBBLE_PENDING: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Take the pending text once the float-bubble page is ready (take-and-clear; None = no notification, frontend should close the window immediately).
#[tauri::command]
pub(crate) fn float_bubble_take() -> Option<String> {
    BUBBLE_PENDING.lock().ok()?.take()
}

pub(crate) fn float_notify_inner(app: &tauri::AppHandle, text: String) {
    const W: f64 = 220.0;
    const H: f64 = 96.0;
    // Opaque card (the bubble is a card, no transparent needed; the same-window resize approach was abandoned after Windows transparency failures)
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
    .visible(false) // position first, then show
    .build()
    else {
        return;
    };
    // Position: 10px left of the ball, vertically centered with it, clamped into the ball's work area
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
    // Text goes to the pending slot (old text in the slot is overwritten: the frontend only needs the latest); page fetches it when ready
    if let Ok(mut p) = BUBBLE_PENDING.lock() {
        *p = Some(text);
    }
    let _ = window.show();
}

/// Create the float ball window (idempotent): 72×72 frameless transparent always-on-top, default position
/// offset from the primary monitor's bottom-right corner (primary monitor lookup matches normalize_window_geometry).
#[cfg(desktop)]
#[cfg(all(desktop, windows))]
pub(crate) fn create_float_ball(app: &tauri::AppHandle) -> Result<(), String> {
    // Windows: native layered-window ball (GDI+ rendered, no WebView; eliminates the whole class of transparency/frame/clipping issues)
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

/// Float ball unsupported on mobile (returns unsupported by platform check; keeps the mobile target compiling).
#[cfg(not(desktop))]
pub(crate) fn create_float_ball(_app: &tauri::AppHandle) -> Result<(), String> {
    Err("悬浮球仅支持桌面端".into())
}

/// Float ball toggle: on=create window, off=destroy; persisted + audited (setup restore reads the same field).
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

/// Float ball bubble notification toggle: when false, neither float_notify call sites nor the float_ball_notify command emit.
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

/// Float ball bubble notification channel (frontend main window → float bubble window).
#[tauri::command]
pub(crate) fn float_ball_notify(app: tauri::AppHandle, text: String) -> Result<(), String> {
    float_notify(&app, text);
    Ok(())
}

/// Float ball context menu (separate float-menu window; toggle semantics: closes when already visible).
/// Opaque card (a menu should be opaque anyway, no transparent needed); auto-closes on blur (armed after 400ms).
/// Must be async: ball_anchor's outer_position/outer_size are channel-blocking calls; a sync command on
/// the main thread would self-deadlock (menu never pops up + main window freezes).
#[tauri::command]
pub(crate) async fn float_open_menu(app: tauri::AppHandle) -> Result<(), String> {
    float_open_menu_impl(&app).await
}

/// Shared implementation of menu open/positioning (used by both the command and the native float ball right-click).
pub(crate) async fn float_open_menu_impl(app: &tauri::AppHandle) -> Result<(), String> {
    const W: f64 = 200.0;
    const H: f64 = 320.0; // 268 + outbound mode button group (rule/global/direct)
    // Target position: menu right edge 10px left of the ball, bottom aligned to ball bottom, clamped into the ball's work area
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
        if let Some(p) = position(app) {
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
    .visible(false) // position first, then show
    .build()
    .map_err(map_err)?;
    crate::arm_blur_close(&window, true);
    if let Some(p) = position(app) {
        let _ = window.set_position(p);
    }
    let _ = window.show();
    let _ = window.set_focus();
    Ok(())
}
