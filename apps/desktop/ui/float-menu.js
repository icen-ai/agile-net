'use strict';
/* 悬浮球快捷菜单（float-menu 窗，200×268）：右键悬浮球由后端 float_open_menu() 定位创建/显示，
   失焦后端自动关闭。操作完成后不自动关窗（用户可能连续操作），仅「打开主窗口」「隐藏悬浮球」主动关窗。
   初始化并行拉 proxy_mode_get / subscription_status / proxy_status / get_role_settings；
   每次操作后仅局部刷新文案与高亮，不整页重渲。动态文本一律 textContent 写入（等价 esc，杜绝注入）。 */
/* 主题须首行执行防闪烁（本脚本在 head 同步加载，先于首次绘制） */
document.documentElement.dataset.theme = localStorage.getItem('ag_theme') || 'light';

const TAURI = window.__TAURI__;
const invoke = TAURI && TAURI.core ? TAURI.core.invoke : null;
const $ = (id) => document.getElementById(id);

const MODES = ['system', 'local', 'tun'];
const OUTMODES = ['rule', 'global', 'direct'];
let mode = '';            // 当前代理方式：system | local | tun
let outMode = 'rule';     // 出站模式：rule | global | direct
let sysOn = false;        // 系统代理托管中
let subRunning = false;   // 订阅代理运行中

function win() { return TAURI.window.getCurrentWindow(); }
function setText(id, t) { const el = $(id); if (el && el.textContent !== t) el.textContent = t; }

/* ---------------- 局部渲染 ---------------- */
function renderSys() { setText('fm-sys-label', sysOn ? '停止系统代理' : '启动系统代理'); }
function renderSub() { setText('fm-sub-label', subRunning ? '停止订阅代理' : '启动订阅代理'); }
function renderMode() {
  document.querySelectorAll('#fm-mode button').forEach(b => {
    b.classList.toggle('cur', b.dataset.mode === mode);
  });
  renderOutMode(); // 代理方式影响出站组可用态（TUN 固定规则）
}
function renderOutMode() {
  const wrap = $('fm-outmode');
  // TUN（虚拟网卡）出站固定规则分流，出站组整体置灰禁点
  const dis = mode === 'tun';
  wrap.style.opacity = dis ? '.45' : '';
  wrap.style.pointerEvents = dis ? 'none' : '';
  document.querySelectorAll('#fm-outmode button').forEach(b => {
    b.classList.toggle('cur', b.dataset.om === outMode);
  });
}
/* 代理方式组小字：isErr=false 灰显（如「需管理员重启」），isErr=true 红显错误 */
function note(text, isErr) {
  const n = $('fm-mode-note');
  if (!text) { n.hidden = true; n.textContent = ''; return; }
  n.hidden = false;
  n.classList.toggle('err', !!isErr);
  n.textContent = text;
}

/* ---------------- 初始化：四路并行拉取 ---------------- */
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
  else if (proxy) sysOn = !!proxy.running && mode === 'system'; // 兜底推断：代理运行且系统模式

  if (roles && OUTMODES.includes(roles.sub_mode)) outMode = roles.sub_mode;

  renderSys();
  renderSub();
  renderMode();
  renderOutMode();
}

/* ---------------- 操作 ---------------- */
function bind() {
  $('fm-open').addEventListener('click', async () => {
    try { await invoke('tray_show_main'); } catch (e) {}
    win().close().catch(() => {});
  });

  $('fm-sys').addEventListener('click', async () => {
    try {
      sysOn = !!(await invoke('sysproxy_toggle'));
    } catch (e) {
      // 失败重取真实状态
      try { const r = await invoke('get_role_settings'); if (r) sysOn = !!r.system_proxy; } catch (e2) {}
    }
    renderSys();
  });

  $('fm-sub').addEventListener('click', async () => {
    const on = !subRunning;
    try {
      // 契约形参为 on；现有实现形参为 enabled——双写兼容（serde 忽略多余键）
      const st = await invoke('set_subscription_role', { on, enabled: on });
      subRunning = st && typeof st.running === 'boolean' ? st.running : on;
    } catch (e) {
      try { const st = await invoke('subscription_status'); if (st) subRunning = !!st.running; } catch (e2) {}
    }
    renderSub();
  });

  // 代理方式三段胶囊（事件委托）
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
        b.classList.add('dis'); // 置灰：需管理员重启后端到权限才可用
        note('需管理员重启', false);
      } else {
        note(msg || '切换失败', true);
      }
      // 重取真实模式，避免高亮停留在未生效项
      try {
        const cur = await invoke('proxy_mode_get');
        if (MODES.includes(cur) && cur !== mode) { mode = cur; renderMode(); }
      } catch (e2) {}
    }
  });

  // 出站模式三段胶囊（规则/全局/直连，事件委托）
  $('fm-outmode').addEventListener('click', async (e) => {
    const b = e.target.closest('button[data-om]');
    if (!b) return;
    const m = b.dataset.om;
    if (m === outMode) return;
    const prev = outMode;
    outMode = m; // 先高亮（mihomo PATCH 通常即时生效），失败回滚
    renderOutMode();
    try {
      await invoke('set_sub_mode', { mode: m });
      note('', false);
    } catch (err) {
      outMode = prev;
      renderOutMode();
      note(String(err || '切换失败'), true);
    }
  });

  $('fm-hide').addEventListener('click', async () => {
    try { await invoke('set_float_ball', { on: false }); } catch (e) {}
    win().close().catch(() => {}); // 球已消失，菜单无存在意义，直接关窗
  });

  $('fm-quit').addEventListener('click', () => {
    invoke('tray_quit').catch(() => {});
  });
}

/* ---------------- 启动 ---------------- */
window.addEventListener('DOMContentLoaded', () => {
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
