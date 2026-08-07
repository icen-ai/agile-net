#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Headless system-proxy restore watchdog mode (spawned detached when we take over the system
    // proxy; restores it if this process dies without disengaging — kill / crash / shutdown)
    #[cfg(windows)]
    if anet_gui_lib::sysproxy_watchdog_main() {
        return;
    }
    anet_gui_lib::run()
}
