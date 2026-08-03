'use strict';
/* Float ball quick menu (float-menu window, 200×268): right-clicking the ball → backend float_open_menu() positions/creates/shows it,
   auto-closed by backend on blur. Window does not auto-close after an action (user may act repeatedly); only 「打开主窗口」「隐藏悬浮球」 close it proactively.
   Init fetches proxy_mode_get / subscription_status / proxy_status / get_role_settings in parallel;
   after each action only locally refresh labels and highlights, never full re-render. Dynamic text always written via textContent (equivalent to esc, injection-proof). */
/* Theme must run on the first line to prevent flash (this script loads synchronously in head, before first paint) */
document.documentElement.dataset.theme = localStorage.getItem('ag_theme') || 'light';

const TAURI = window.__TAURI__;
const invoke = TAURI && TAURI.core ? TAURI.core.invoke : null;
const $ = (id) => document.getElementById(id);

const MODES = ['system', 'local', 'tun'];
const OUTMODES = ['rule', 'global', 'direct'];
let mode = '';            // current proxy mode: system | local | tun
let outMode = 'rule';     // outbound mode: rule | global | direct
let sysOn = false;        // system proxy managed
let subRunning = false;   // subscription proxy running

function win() { return TAURI.window.getCurrentWindow(); }
function setText(id, t) { const el = $(id); if (el && el.textContent !== t) el.textContent = t; }

/* ---------------- Partial rendering ---------------- */
function renderSys() { setText('fm-sys-label', AgI18n.t(sysOn ? 'float.sysStop' : 'float.sysStart')); }
function renderSub() { setText('fm-sub-label', AgI18n.t(subRunning ? 'float.subStop' : 'float.subStart')); }
function renderMode() {
  document.querySelectorAll('#fm-mode button').forEach(b => {
    b.classList.toggle('cur', b.dataset.mode === mode);
  });
  renderOutMode(); // proxy mode affects outbound group availability (TUN pins rule)
}
function renderOutMode() {
  const wrap = $('fm-outmode');
  // TUN (virtual NIC) pins outbound to rule routing; grey out and disable the whole outbound group
  const dis = mode === 'tun';
  wrap.style.opacity = dis ? '.45' : '';
  wrap.style.pointerEvents = dis ? 'none' : '';
  document.querySelectorAll('#fm-outmode button').forEach(b => {
    b.classList.toggle('cur', b.dataset.om === outMode);
  });
}
/* Small note under the proxy-mode group: isErr=false grey (e.g. 「需管理员重启」), isErr=true red error */
function note(text, isErr) {
  const n = $('fm-mode-note');
  if (!text) { n.hidden = true; n.textContent = ''; return; }
  n.hidden = false;
  n.classList.toggle('err', !!isErr);
  n.textContent = text;
}

/* ---------------- Init: four-way parallel fetch ---------------- */
async function initState() {
  const [m, ss, ps, rs] = await Promise.allSettled([
    invoke('proxy_mode_get'),
    invoke('subscription_status'),
    invoke('proxy_status'),
    invoke('get_role_settings'),
  ]);
  const roles = rs.status === 'fulfilled' && rs.value ? rs.value : null;
  const proxy = ps.status === 'fulfilled' && ps.value ? ps.value : null;

  if (m.status === 'fulfilled' && MODES.includes(m.value)) mode = m.value;
  else if (roles) mode = roles.tun_mode ? 'tun' : (roles.system_proxy === false ? 'local' : 'system');

  if (ss.status === 'fulfilled' && ss.value) subRunning = !!ss.value.running;
  else if (roles) subRunning = !!roles.subscription;

  if (roles && typeof roles.system_proxy === 'boolean') sysOn = roles.system_proxy;
  else if (proxy) sysOn = !!proxy.running && mode === 'system'; // fallback inference: proxy running and system mode

  if (roles && OUTMODES.includes(roles.sub_mode)) outMode = roles.sub_mode;

  renderSys();
  renderSub();
  renderMode();
  renderOutMode();
}

/* ---------------- Actions ---------------- */
function bind() {
  $('fm-open').addEventListener('click', async () => {
    try { await invoke('tray_show_main'); } catch (e) {}
    win().close().catch(() => {});
  });

  $('fm-sys').addEventListener('click', async () => {
    try {
      sysOn = !!(await invoke('sysproxy_toggle'));
    } catch (e) {
      // on failure re-fetch the real state
      try { const r = await invoke('get_role_settings'); if (r) sysOn = !!r.system_proxy; } catch (e2) {}
    }
    renderSys();
  });

  $('fm-sub').addEventListener('click', async () => {
    const on = !subRunning;
    try {
      // contract param is on; current impl takes enabled — write both for compat (serde ignores extra keys)
      const st = await invoke('set_subscription_role', { on, enabled: on });
      subRunning = st && typeof st.running === 'boolean' ? st.running : on;
    } catch (e) {
      try { const st = await invoke('subscription_status'); if (st) subRunning = !!st.running; } catch (e2) {}
    }
    renderSub();
  });

  // proxy-mode three-way segmented control (event delegation)
  $('fm-mode').addEventListener('click', async (e) => {
    const b = e.target.closest('button[data-mode]');
    if (!b || b.classList.contains('dis')) return;
    const m = b.dataset.mode;
    if (m === mode) return;
    try {
      const r = await invoke('proxy_mode_set', { mode: m });
      mode = MODES.includes(r) ? r : m;
      note('', false);
      renderMode();
    } catch (err) {
      const msg = String(err || '');
      if (msg.indexOf('NEED_ELEVATION:') === 0) {
        b.classList.add('dis'); // grey out: requires backend restarted with admin elevation
        note(AgI18n.t('float.needAdmin'), false);
      } else {
        note(msg || AgI18n.t('float.switchFailed'), true);
      }
      // re-fetch the real mode so the highlight doesn't stick on an item that never took effect
      try {
        const cur = await invoke('proxy_mode_get');
        if (MODES.includes(cur) && cur !== mode) { mode = cur; renderMode(); }
      } catch (e2) {}
    }
  });

  // outbound-mode three-way segmented control (rule/global/direct, event delegation)
  $('fm-outmode').addEventListener('click', async (e) => {
    const b = e.target.closest('button[data-om]');
    if (!b) return;
    const m = b.dataset.om;
    if (m === outMode) return;
    const prev = outMode;
    outMode = m; // optimistic highlight (mihomo PATCH usually applies instantly); roll back on failure
    renderOutMode();
    try {
      await invoke('set_sub_mode', { mode: m });
      note('', false);
    } catch (err) {
      outMode = prev;
      renderOutMode();
      note(String(err || AgI18n.t('float.switchFailed')), true);
    }
  });

  $('fm-hide').addEventListener('click', async () => {
    try { await invoke('set_float_ball', { on: false }); } catch (e) {}
    win().close().catch(() => {}); // ball gone, menu pointless — close the window directly
  });

  $('fm-quit').addEventListener('click', () => {
    invoke('tray_quit').catch(() => {});
  });
}

/* ---------------- Startup ---------------- */
window.addEventListener('DOMContentLoaded', () => {
  AgI18n.hydrate(document);
  if (!invoke) {
    $('fm-noenv').hidden = false;
    return;
  }
  $('fm-root').hidden = false;
  if (TAURI.event && TAURI.event.listen) {
    TAURI.event.listen('ag-theme', e => { document.documentElement.dataset.theme = e.payload; }).catch(() => {});
  }
  bind();
  initState();
});
