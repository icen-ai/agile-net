//! 原生悬浮球（Windows）：WS_EX_LAYERED 逐像素透明分层窗 + GDI+ 绘制。
//! 为什么不用 WebView 画圆：透明合成/DWM 隐形边框/region 裁剪在部分机器上整类失效，
//! 原生分层窗是桌面圆形组件的正解（Rainmeter/TrafficMonitor 同款技术），
//! 顺带省下一个 WebView2 进程（~50MB 内存）。
//! 交互：左键拖拽（松手边缘吸附）/ 单击 Q 弹缩放 / 双击开主窗 / 右键交互菜单；
//! 内容：↓↑ 实时速率（2s 直读内核 TrafficStats，无 IPC），无流量显示闪电标。

#![cfg(windows)]

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicIsize, Ordering};
use std::sync::{Mutex, OnceLock};
use tauri::Manager as _;
use windows_sys::core::w;
use windows_sys::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, POINT, RECT, SIZE, WPARAM};
use windows_sys::Win32::Graphics::GdiPlus::GpPath;
use windows_sys::Win32::Graphics::Gdi::{
    CreateCompatibleDC, CreateDIBSection, DeleteDC, DeleteObject, GetDC, ReleaseDC, SelectObject,
    BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, HBITMAP,
};
use windows_sys::Win32::Graphics::GdiPlus::{
    GdipCreateFont, GdipCreateFontFamilyFromName, GdipCreateFromHDC, GdipCreatePen1,
    GdipCreateSolidFill, GdipCreateStringFormat, GdipDeleteBrush, GdipDeleteFont,
    GdipDeleteFontFamily, GdipDeleteGraphics, GdipDeletePen, GdipDeleteStringFormat,
    GdipDrawEllipse, GdipDrawString, GdipFillEllipse, GdipSetSmoothingMode,
    GdipSetStringFormatAlign, GdipSetStringFormatLineAlign, GdiplusStartup,
    GdiplusStartupInput, GpFont, GpFontFamily, GpGraphics, GpPen, GpSolidFill, GpStringFormat,
    RectF, SmoothingModeAntiAlias, StringAlignmentCenter, UnitPoint,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, GetSystemMetrics, KillTimer, LoadCursorW,
    PostMessageW, PostQuitMessage, RegisterClassExW, SetTimer,
    GetCursorPos, SetWindowPos, SystemParametersInfoW, IDC_ARROW, SM_CXSCREEN,
    SM_CYSCREEN, SPI_GETWORKAREA, SWP_NOACTIVATE, SWP_NOZORDER, ULW_ALPHA, WM_DESTROY,
    GetWindowRect, WM_EXITSIZEMOVE, WM_LBUTTONDBLCLK, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MOUSEMOVE, WM_PAINT,
    WM_RBUTTONUP, WM_TIMER, WM_USER, WNDCLASSEXW, WS_EX_LAYERED, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW,
    WS_EX_TOPMOST, WS_POPUP, WS_VISIBLE,
};
use windows_sys::Win32::Graphics::Gdi::BLENDFUNCTION;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{ReleaseCapture, SetCapture};
use windows_sys::Win32::UI::WindowsAndMessaging::UpdateLayeredWindow;

const BALL_SIZE: i32 = 72; // 逻辑像素（×DPI 得物理）
const TIMER_TRAFFIC: usize = 1;
const TIMER_BOUNCE: usize = 2;
const WM_SNAP: u32 = WM_USER + 41;

static APP: OnceLock<tauri::AppHandle> = OnceLock::new();
static BALL_HWND: AtomicIsize = AtomicIsize::new(0);
static DARK: AtomicBool = AtomicBool::new(false);
static BOUNCE_FRAME: AtomicI32 = AtomicI32::new(0);
/// 左键按下状态：光标起点（屏幕坐标）、球起点、是否已进拖拽。
/// Option::None = 空闲（鼠标未按下）——悬停移动严禁触发拖拽（否则球被光标"吓跑"）
static DOWN_STATE: Mutex<Option<(i32, i32, i32, i32, bool)>> = Mutex::new(None);
static GDIP_TOKEN: OnceLock<usize> = OnceLock::new();

fn gdip_init() {
    GDIP_TOKEN.get_or_init(|| {
        let mut token = 0usize;
        let input = GdiplusStartupInput {
            GdiplusVersion: 1,
            DebugEventCallback: 0,
            SuppressBackgroundThread: 0,
            SuppressExternalCodecs: 0,
        };
        unsafe { GdiplusStartup(&mut token, &input, std::ptr::null_mut()) };
        token
    });
}

/// 主题切换钩子（broadcast_theme 命令调用）：深色系重绘。
pub fn set_dark(dark: bool) {
    DARK.store(dark, Ordering::Relaxed);
    let hwnd: HWND = BALL_HWND.load(Ordering::Relaxed) as HWND;
    if !hwnd.is_null() {
        unsafe { PostMessageW(hwnd, WM_PAINT, 0, 0) };
    }
}

/// 球当前外接矩形（物理）：GetWindowRect 实时读取（拖拽/吸附/重绘永不同步问题根绝），
/// 供菜单/气泡定位（ball_anchor 读取）。
pub fn rect() -> Option<(i32, i32, i32)> {
    let hwnd: HWND = BALL_HWND.load(Ordering::Relaxed) as HWND;
    if hwnd.is_null() {
        return None;
    }
    let mut r: RECT = unsafe { std::mem::zeroed() };
    unsafe {
        if GetWindowRect(hwnd, &mut r) == 0 {
            return None;
        }
    }
    let w = r.right - r.left;
    (w > 0).then_some((r.left, r.top, w))
}

pub fn destroy() {
    let hwnd: HWND = BALL_HWND.swap(0, Ordering::Relaxed) as HWND;
    if !hwnd.is_null() {
        unsafe {
            KillTimer(hwnd, TIMER_TRAFFIC);
            KillTimer(hwnd, TIMER_BOUNCE);
            DestroyWindow(hwnd);
        }
    }
}

pub fn create(app: &tauri::AppHandle) -> Result<(), String> {
    if BALL_HWND.load(Ordering::Relaxed) != 0 {
        return Ok(()); // 幂等
    }
    let _ = APP.set(app.clone());
    gdip_init();
    unsafe {
        let hinst: HINSTANCE = GetModuleHandleW(std::ptr::null());
        let class_name = w!("AgileNetFloatBall");
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: 0,
            lpfnWndProc: Some(wndproc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinst,
            hIcon: std::ptr::null_mut(),
            hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: class_name,
            hIconSm: std::ptr::null_mut(),
        };
        RegisterClassExW(&wc);

        // 初始位置：主工作区右下（96px 上边距，与既有逻辑一致）
        let mut area = RECT {
            left: 0,
            top: 0,
            right: GetSystemMetrics(SM_CXSCREEN),
            bottom: GetSystemMetrics(SM_CYSCREEN),
        };
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &mut area as *mut _ as _, 0);
        // DPI：用主屏 96→实际的缩放（SystemParametersInfo 的 work area 已是物理像素）
        let dpi = 96.0 * primary_scale(app);
        let phys = ((BALL_SIZE as f64) * dpi / 96.0).round() as i32;
        let x = area.right - phys - s_dip(24.0, dpi);
        let y = area.bottom - phys - s_dip(96.0, dpi);

        let hwnd = CreateWindowExW(
            WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_TOPMOST,
            class_name,
            w!("AgileNet"),
            WS_POPUP | WS_VISIBLE,
            x,
            y,
            phys,
            phys,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinst,
            std::ptr::null_mut(),
        );
        if hwnd.is_null() {
            return Err("悬浮球窗口创建失败".into());
        }
        BALL_HWND.store(hwnd as isize, Ordering::Relaxed);
        SetTimer(hwnd, TIMER_TRAFFIC, 2000, None);
        present(hwnd); // 首帧
    }
    Ok(())
}

/// 主屏缩放（tauri primary_monitor；失败按 1.0）
fn primary_scale(app: &tauri::AppHandle) -> f64 {
    app.primary_monitor()
        .ok()
        .flatten()
        .map(|m| m.scale_factor())
        .unwrap_or(1.0)
}

fn s_dip(v: f64, dpi: f64) -> i32 {
    (v * dpi / 96.0).round() as i32
}

/// 球内紧凑速率（无 /s 后缀，单位单字母；56px 球宽约束：≤5 字符）
fn compact_rate(b: u64) -> String {
    const K: u64 = 1024;
    const M: u64 = 1024 * 1024;
    const G: u64 = 1024 * 1024 * 1024;
    if b >= G {
        // G/T 封顶防溢出：球内弦长 ≈53px 逻辑，最长串必须 ≤6 字符（含箭头）
        let v = b as f64 / G as f64;
        if v >= 1024.0 {
            let t = v / 1024.0;
            if t >= 999.0 { "999T".into() } else if t >= 100.0 { format!("{:.0}T", t) } else { format!("{:.1}T", t) }
        } else if v >= 100.0 {
            format!("{:.0}G", v)
        } else {
            format!("{:.1}G", v)
        }
    } else if b >= M {
        let v = b as f64 / M as f64;
        if v >= 100.0 { format!("{:.0}M", v) } else { format!("{:.1}M", v) }
    } else if b >= 100 * K {
        format!("{}K", b / K)
    } else if b >= K {
        format!("{:.1}K", b as f64 / K as f64)
    } else {
        format!("{}", b)
    }
}

fn traffic_text() -> (String, String) {
    let Some(app) = APP.get() else {
        return (String::new(), String::new());
    };
    let Some(state) = app.try_state::<crate::AppState>() else {
        return (String::new(), String::new());
    };
    let t = state.kernel.traffic();
    if t.up_rate == 0 && t.down_rate == 0 {
        return (String::new(), String::new());
    }
    (
        format!("↓{}", compact_rate(t.down_rate)),
        format!("↑{}", compact_rate(t.up_rate)),
    )
}

/// 颜色：深色系切换（token：浅 glass rgba(252,252,252,.85) / 深 rgba(56,54,54,.85)）
fn ball_colors() -> (u32, u32, u32, u32) {
    // (fill, border, text_main, text_sub) ARGB
    if DARK.load(Ordering::Relaxed) {
        (0xD9383836, 0x33FFFFFF, 0xFFEEEEEE, 0xFF9A9A9A)
    } else {
        (0xD9FCFCFC, 0x14000000, 0xFF3C3F43, 0xFF8A8A8A)
    }
}

/// GDI+ 画球到 DIB 并 UpdateLayeredWindow 呈现（逐像素透明）。
fn present(hwnd: HWND) {
    let Some((_x, _y, phys)) = rect() else { return };
    if phys <= 0 {
        return;
    }
    // 弹跳帧缩放（0.88 / 1.06 / 0.97 / 1.0）；拖拽中 0.94（跟手反馈）
    let zoom = if DOWN_STATE.lock().ok().and_then(|s| *s).map(|t| t.4).unwrap_or(false) {
        0.94
    } else {
        let scale_anim = [0.88f32, 1.06, 0.97, 1.0];
        let frame = BOUNCE_FRAME.load(Ordering::Relaxed).clamp(0, 3) as usize;
        scale_anim[frame]
    };
    let ball = (phys as f32 * 0.7778 * zoom).round().max(8.0) as i32; // 56/72
    let off = (phys - ball) / 2;

    unsafe {
        let screen_dc = GetDC(std::ptr::null_mut());
        let mem_dc = CreateCompatibleDC(screen_dc);
        let mut bmi: BITMAPINFO = std::mem::zeroed();
        bmi.bmiHeader = BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: phys,
            biHeight: -phys, // 顶向下
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB,
            ..std::mem::zeroed()
        };
        let mut bits: *mut core::ffi::c_void = std::ptr::null_mut();
        let hbmp: HBITMAP = CreateDIBSection(mem_dc, &bmi, DIB_RGB_COLORS, &mut bits, std::ptr::null_mut(), 0);
        let old = SelectObject(mem_dc, hbmp);
        // DIB 初始化为全 0（全透明）——CreateDIBSection 不保证清零
        if !bits.is_null() {
            std::ptr::write_bytes(bits as *mut u8, 0, (phys * phys * 4) as usize);
        }

        let mut graphics: *mut GpGraphics = std::ptr::null_mut();
        if GdipCreateFromHDC(mem_dc, &mut graphics) == 0 && !graphics.is_null() {
            GdipSetSmoothingMode(graphics, SmoothingModeAntiAlias);
            let (fill, border, tmain, tsub) = ball_colors();
            let (fx, fy, fs) = (off as f32, off as f32, ball as f32);
            // 柔和投影：两层扩散椭圆（GDI+ 无模糊，同心递减模拟）
            let mut shadow: *mut GpSolidFill = std::ptr::null_mut();
            GdipCreateSolidFill(0x24000000, &mut shadow);
            GdipFillEllipse(graphics, shadow as *mut _, fx + 1.0, fy + 3.0, fs, fs);
            GdipDeleteBrush(shadow as *mut _);
            // 球体
            let mut brush: *mut GpSolidFill = std::ptr::null_mut();
            GdipCreateSolidFill(fill, &mut brush);
            GdipFillEllipse(graphics, brush as *mut _, fx, fy, fs, fs);
            GdipDeleteBrush(brush as *mut _);
            // 边框
            let mut pen: *mut GpPen = std::ptr::null_mut();
            GdipCreatePen1(border, 1.0, UnitPoint, &mut pen);
            GdipDrawEllipse(graphics, pen, fx + 0.5, fy + 0.5, fs - 1.0, fs - 1.0);
            GdipDeletePen(pen);

            let (l1, l2) = traffic_text();
            let mut family: *mut GpFontFamily = std::ptr::null_mut();
            GdipCreateFontFamilyFromName(w!("Segoe UI"), std::ptr::null_mut(), &mut family);
            let mut fmt: *mut GpStringFormat = std::ptr::null_mut();
            GdipCreateStringFormat(0, 0, &mut fmt);
            GdipSetStringFormatAlign(fmt, StringAlignmentCenter);
            GdipSetStringFormatLineAlign(fmt, StringAlignmentCenter);
            let dpi_scale = phys as f32 / BALL_SIZE as f32;
            if l1.is_empty() {
                // 无流量：闪电标（简单多边形点）
                draw_bolt(graphics, fx, fy, fs, tsub);
            } else {
                // 上下行对等字号（用户要求）
                draw_text(
                    graphics, family, fmt, &l1, 7.0 * dpi_scale, tmain,
                    RectF { X: fx, Y: fy + fs * 0.22, Width: fs, Height: fs * 0.24 },
                );
                draw_text(
                    graphics, family, fmt, &l2, 7.0 * dpi_scale, tmain,
                    RectF { X: fx, Y: fy + fs * 0.50, Width: fs, Height: fs * 0.24 },
                );
            }
            GdipDeleteStringFormat(fmt);
            GdipDeleteFontFamily(family);
            GdipDeleteGraphics(graphics);
        }

        // UpdateLayeredWindow 呈现（pptDst=NULL：窗口位置由拖拽/吸附独占，重绘不搬窗）
        let size = SIZE { cx: phys, cy: phys };
        let src = POINT { x: 0, y: 0 };
        let blend = BLENDFUNCTION {
            BlendOp: 0, // AC_SRC_OVER
            BlendFlags: 0,
            SourceConstantAlpha: 255,
            AlphaFormat: 1, // AC_SRC_ALPHA
        };
        UpdateLayeredWindow(
            hwnd,
            screen_dc,
            std::ptr::null_mut(),
            &size,
            mem_dc,
            &src,
            0,
            &blend,
            ULW_ALPHA,
        );

        SelectObject(mem_dc, old);
        DeleteObject(hbmp);
        DeleteDC(mem_dc);
        ReleaseDC(std::ptr::null_mut(), screen_dc);
    }
}

fn draw_text(
    g: *mut GpGraphics,
    family: *mut GpFontFamily,
    fmt: *mut GpStringFormat,
    s: &str,
    pt: f32,
    argb: u32,
    rect: RectF,
) {
    unsafe {
        let mut font: *mut GpFont = std::ptr::null_mut();
        if GdipCreateFont(family, pt, 0, UnitPoint, &mut font) != 0 || font.is_null() {
            return;
        }
        let mut brush: *mut GpSolidFill = std::ptr::null_mut();
        GdipCreateSolidFill(argb, &mut brush);
        let wide: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
        GdipDrawString(g, wide.as_ptr(), (wide.len() - 1) as i32, font, &rect, fmt, brush as *mut _);
        GdipDeleteBrush(brush as *mut _);
        GdipDeleteFont(font);
    }
}

/// 闪电标（zap 简化多边形）
fn draw_bolt(g: *mut GpGraphics, fx: f32, fy: f32, fs: f32, argb: u32) {
    use windows_sys::Win32::Graphics::GdiPlus::{GdipCreatePath, GdipDeletePath, GdipFillPath, PointF};
    unsafe {
        let mut path: *mut GpPath = std::ptr::null_mut();
        if GdipCreatePath(0, &mut path) != 0 || path.is_null() {
            return;
        }
        // Lucide zap 轮廓（24 视窗）映射到球内 0.28~0.72 区域
        let m = |vx: f32, vy: f32| PointF {
            X: fx + fs * (0.28 + vx / 24.0 * 0.44),
            Y: fy + fs * (0.28 + vy / 24.0 * 0.44),
        };
        let pts = [
            m(13.0, 2.0),
            m(4.9, 13.2),
            m(11.0, 13.2),
            m(10.1, 21.8),
            m(19.1, 10.8),
            m(13.0, 10.8),
        ];
        windows_sys::Win32::Graphics::GdiPlus::GdipAddPathPolygon(path, pts.as_ptr(), pts.len() as i32);
        let mut brush: *mut GpSolidFill = std::ptr::null_mut();
        GdipCreateSolidFill(argb, &mut brush);
        GdipFillPath(g, brush as *mut _, path);
        GdipDeleteBrush(brush as *mut _);
        GdipDeletePath(path);
    }
}

/// 边缘吸附（松手后）：距左右边 ≤24px 逻辑则贴上
fn snap_edge(hwnd: HWND) {
    unsafe {
        let Some((x, y, phys)) = rect() else { return };
        let mut area: RECT = std::mem::zeroed();
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &mut area as *mut _ as _, 0);
        let dpi = 96.0 * ((phys as f64) / BALL_SIZE as f64);
        let th = s_dip(24.0, dpi);
        let mut nx = x;
        if x - area.left <= th {
            nx = area.left;
        } else if area.right - (x + phys) <= th {
            nx = area.right - phys;
        }
        if nx != x {
            SetWindowPos(hwnd, std::ptr::null_mut(), nx, y, 0, 0, SWP_NOACTIVATE | SWP_NOZORDER | 0x0001 /*SWP_NOSIZE*/);
        }
    }
}

/// 当前球 DPI 缩放（phys/logical）
fn dpi2(_hwnd: HWND) -> f64 {
    rect().map(|(_, _, s)| s as f64 / BALL_SIZE as f64).unwrap_or(1.0)
}

extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_PAINT => {
            present(hwnd);
            return 0;
        }
        WM_TIMER => {
            match wparam {
                TIMER_TRAFFIC => present(hwnd),
                TIMER_BOUNCE => {
                    let f = BOUNCE_FRAME.fetch_add(1, Ordering::Relaxed);
                    if f >= 3 {
                        BOUNCE_FRAME.store(0, Ordering::Relaxed);
                        unsafe { KillTimer(hwnd, TIMER_BOUNCE) };
                    }
                    present(hwnd);
                }
                _ => {}
            }
            return 0;
        }
        WM_LBUTTONDOWN => {
            // 记录光标起点与球起点（屏幕坐标）并捕获鼠标；移动超阈值进拖拽，否则留给单击弹跳
            let mut cur: POINT = unsafe { std::mem::zeroed() };
            unsafe { GetCursorPos(&mut cur) };
            let (bx, by, _) = rect().unwrap_or((0, 0, 0));
            if let Ok(mut st) = DOWN_STATE.lock() {
                *st = Some((cur.x, cur.y, bx, by, false));
            }
            unsafe { SetCapture(hwnd) };
            return 0;
        }
        WM_MOUSEMOVE => {
            // 仅左键按下期间（Some 武装态）处理拖拽；悬停（None）直接放行
            let Some((sx, sy, bx, by, dragging)) = DOWN_STATE.lock().ok().and_then(|s| *s) else {
                return 0;
            };
            let mut cur: POINT = unsafe { std::mem::zeroed() };
            unsafe { GetCursorPos(&mut cur) };
            let (dx, dy) = (cur.x - sx, cur.y - sy);
            if !dragging {
                let th = 4.0 * dpi2(hwnd);
                if (dx * dx + dy * dy) as f64 <= th * th {
                    return 0; // 阈值内：视为潜在单击，不动
                }
                if let Ok(mut st) = DOWN_STATE.lock() {
                    if let Some(t) = st.as_mut() {
                        t.4 = true;
                    }
                }
                present(hwnd); // 进拖拽即刻缩 0.94
            }
            // 手动跟手移动（不依赖 NC drag；重绘不搬窗，互搏根绝）
            unsafe {
                SetWindowPos(
                    hwnd,
                    std::ptr::null_mut(),
                    bx + dx,
                    by + dy,
                    0,
                    0,
                    SWP_NOACTIVATE | SWP_NOZORDER | 0x0001, // SWP_NOSIZE
                )
            };
            return 0;
        }
        WM_LBUTTONUP => {
            let dragging = DOWN_STATE
                .lock()
                .ok()
                .and_then(|mut s| s.take())
                .map(|t| t.4)
                .unwrap_or(false);
            unsafe { ReleaseCapture() };
            if dragging {
                snap_edge(hwnd); // 拖拽结束：边缘吸附
                present(hwnd);   // 还原 1.0 缩放
            } else {
                // 单击：Q 弹缩放动画
                BOUNCE_FRAME.store(0, Ordering::Relaxed);
                unsafe { SetTimer(hwnd, TIMER_BOUNCE, 90, None) };
            }
            return 0;
        }
        WM_LBUTTONDBLCLK => {
            if let Some(app) = APP.get() {
                crate::show_main_window(app);
            }
            return 0;
        }
        WM_RBUTTONUP => {
            if let Some(app) = APP.get() {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = crate::float_open_menu_impl(&app).await;
                });
            }
            return 0;
        }
        WM_EXITSIZEMOVE => {
            snap_edge(hwnd);
            return 0;
        }
        WM_SNAP => {
            snap_edge(hwnd);
            return 0;
        }
        WM_DESTROY => {
            unsafe { PostQuitMessage(0) };
            return 0;
        }
        _ => {}
    }
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 球内弦长约束：紧凑速率连箭头最长 6 字符（≈32px < 53px 逻辑可用宽）
    #[test]
    fn compact_rate_max_six_chars() {
        let cases = [
            (0u64, "0"), (999, "999"), (1023, "1023"), (1536, "1.5K"),
            (102_298, "99.9K"), (100 * 1024, "100K"), (999 * 1024, "999K"),
            (1024 * 1024, "1.0M"), (104_752_742, "99.9M"), (1_073_741_824, "1.0G"),
            (10_737_418_240, "10.0G"), (1_099_511_627_776, "1.0T" /*→1024G? 见断言*/),
        ];
        for (b, expect) in cases {
            if b == 1_099_511_627_776 { continue; } // 1T 档单独断言
            assert_eq!(compact_rate(b), expect, "b={b}");
        }
        // 1TB/s：进 T 档；u64::MAX：钳 999T
        assert_eq!(compact_rate(1_099_511_627_776), "1.0T");
        assert_eq!(compact_rate(u64::MAX), "999T");
        // 全域断言：任意极端值含箭头不超 6 字符
        for &b in &[u64::MAX, 1 << 40, 1 << 50, 1 << 60] {
            let s = format!("↓{}", compact_rate(b));
            assert!(s.chars().count() <= 6, "b={b} s={s}");
        }
    }
}
