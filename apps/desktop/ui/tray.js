'use strict';
/* Tray popup: status area (big speed digits + 60s sparkline) / outbound mode / proxy group quick-switch / connection summary / bottom action row.
   Render discipline: sig-compare all sections, no DOM rewrite when data unchanged; dual polling 1s (speed) + 3s (status/groups/conns),
   paused while window hidden. */
/* Theme must run on the first line to prevent flash (this script loads synchronously in head, before first paint) */
document.documentElement.dataset.theme = localStorage.getItem('ag_theme') || 'light';

const TAURI = window.__TAURI__;
const invoke = TAURI && TAURI.core ? TAURI.core.invoke : null;
const $ = (id) => document.getElementById(id);

function esc(s) {
  return String(s ?? '').replace(/[&<>"'`]/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;'
  }[c]));
}

/* ---------------- State & sigs ---------------- */
const S = {
  running: false, port: 0,          // local proxy
  mode: 'rule', tun: false,         // outbound mode / TUN lock
  pmode: 'system',                  // proxy mode: system | local | tun
  kernel: false,                    // subscription kernel running
  sigStatus: '', sigMode: '', sigPMode: '', sigGroups: '', sigConns: '',
  sigPill: '', sigExit: '',
  openGroup: null, lastGroups: null,  // expanded proxy group (name; only one open at a time) and last group data
  openConns: false,                   // connection summary expanded state (collapsed by default, click header to expand)
  downSig: '', upSig: '',
  up60: [], down60: [],             // 60s rate samples (B/s)
  chart: null,
};

function fmtRate(bps) {
  bps = +bps || 0;
  if (bps >= 1048576) return { num: (bps / 1048576).toFixed(1), unit: 'MB/s' };
  if (bps >= 1024) return { num: (bps / 1024).toFixed(1), unit: 'KB/s' };
  return { num: String(Math.round(bps)), unit: 'B/s' };
}

/* ---------------- Fast polling (1s): live speed + sparkline ---------------- */
async function fastTick() {
  let t = null;
  try { t = await invoke('sub_traffic'); } catch (e) { /* kernel not running etc. */ }
  if (!t) {
    setSpeed('down', null); setSpeed('up', null);
    return;
  }
  setSpeed('down', +t.down_rate || 0);
  setSpeed('up', +t.up_rate || 0);
  S.down60.push(+t.down_rate || 0); if (S.down60.length > 60) S.down60.shift();
  S.up60.push(+t.up_rate || 0); if (S.up60.length > 60) S.up60.shift();
  // AgChart sig-compares internally, no redraw when sig unchanged; rAF-interpolated transition on change
  S.chart = window.AgChart && AgChart.sparkline($('tp-chart'), [
    { name: AgI18n.t('tray.down'), values: S.down60.slice() },
    { name: AgI18n.t('tray.up'), values: S.up60.slice() },
  ]);
}

function setSpeed(kind, bps) {
  const numEl = $(kind === 'down' ? 'tp-down-num' : 'tp-up-num');
  const unitEl = $(kind === 'down' ? 'tp-down-unit' : 'tp-up-unit');
  const sigKey = kind === 'down' ? 'downSig' : 'upSig';
  const r = bps === null ? null : fmtRate(bps);
  const sig = r ? r.num + r.unit : '-';
  if (S[sigKey] === sig) return;
  S[sigKey] = sig;
  numEl.textContent = r ? r.num : '-';
  unitEl.textContent = r ? r.unit : '';
}

/* ---------------- Slow polling (3s): status / mode / proxy groups / connections ---------------- */
async function slowTick() {
  const [stR, roleR, kR, gR, cR, pmR] = await Promise.allSettled([
    invoke('proxy_status'),
    invoke('get_role_settings'),
    invoke('subscription_status'),
    invoke('proxy_groups'),
    invoke('sub_connections'), // new backend command; rejects until landed, empty state fallback
    invoke('proxy_mode_get'),
  ]);
  if (stR.status === 'fulfilled' && stR.value) renderStatus(!!stR.value.running, +stR.value.port || 0);
  if (roleR.status === 'fulfilled' && roleR.value) {
    renderMode(roleR.value.sub_mode || 'rule', !!roleR.value.tun_mode);
  }
  if (pmR.status === 'fulfilled' && typeof pmR.value === 'string') renderPMode(pmR.value);
  if (kR.status === 'fulfilled' && kR.value) { S.kernel = !!kR.value.running; renderSub(); }
  if (gR.status === 'fulfilled') renderGroups(gR.value);
  if (cR.status === 'fulfilled') renderConns(cR.value);
  else renderConns(null);
}

function renderStatus(running, port) {
  const sig = running + '|' + port;
  if (sig === S.sigStatus) return;
  S.sigStatus = sig;
  S.running = running; S.port = port;
  $('tp-toggle-label').textContent = AgI18n.t(running ? 'tray.stopProxy' : 'tray.startProxy');
  $('tp-toggle').classList.toggle('warn', running);
  renderPill(); renderExit();
}

/* Status pill follows the effective takeover state (stopped / system proxy / TUN / local listen),
   merging what used to be three separate signals (pill + hero address + button label) into one */
function renderPill() {
  const key = !S.running ? 'common.stopped'
    : S.pmode === 'system' ? 'tray.pillSystem'
    : S.pmode === 'tun' ? 'tray.pillTun'
    : 'tray.pillLocal';
  const text = AgI18n.t(key);
  if (text === S.sigPill) return;
  S.sigPill = text;
  const pill = $('tp-pill');
  pill.textContent = text;
  pill.classList.toggle('on', S.running);
}

/* Hero sub-line: current egress at a glance — direct / GLOBAL node (global mode) / first Selector group node (rule mode);
   falls back to proxy-off / kernel-off hints when not applicable */
function renderExit() {
  let text;
  if (!S.running) text = AgI18n.t('tray.proxyOff');
  else if (!S.kernel) text = AgI18n.t('tray.kernelOff');
  else if (S.mode === 'direct') text = AgI18n.t('tray.exitNode', { name: AgI18n.t('tray.outDirect') });
  else {
    const px = (S.lastGroups && S.lastGroups.proxies) || {};
    const entry = S.mode === 'global'
      ? ['GLOBAL', px.GLOBAL]
      : Object.entries(px).find(([n, p]) => n !== 'GLOBAL' && p && p.type === 'Selector' && Array.isArray(p.all));
    const now = entry && entry[1] && entry[1].now ? entry[1].now : '';
    text = now ? AgI18n.t('tray.exitNode', { name: now }) : AgI18n.t('tray.noGroups');
  }
  if (text === S.sigExit) return;
  S.sigExit = text;
  const el = $('tp-addr');
  el.textContent = text;
  el.title = text;
}

function renderMode(mode, tun) {
  const sig = mode + '|' + tun;
  if (sig === S.sigMode) return;
  S.sigMode = sig;
  S.mode = mode; S.tun = tun;
  const seg = $('tp-mode');
  seg.classList.toggle('off', tun); // outbound pinned to rule under TUN (backend rejects switching too)
  seg.title = tun ? AgI18n.t('tray.tunLockTip') : '';
  seg.querySelectorAll('button').forEach(b => b.classList.toggle('cur', b.dataset.mode === mode));
  renderExit();
}

/* Proxy mode (system/local/tun) segmented control — aligns tray with float-menu */
function renderPMode(pm) {
  const sig = pm;
  if (sig === S.sigPMode) return;
  S.sigPMode = sig;
  S.pmode = pm;
  $('tp-pmode').querySelectorAll('button').forEach(b => b.classList.toggle('cur', b.dataset.pmode === pm));
  renderPill();
}

/* Subscription kernel icon button: live status dot + hover title */
function renderSub() {
  const btn = $('tp-sub');
  if (!btn) return;
  btn.classList.toggle('on', S.kernel);
  btn.title = AgI18n.t(S.kernel ? 'float.subStop' : 'float.subStart');
  renderExit();
}

/* Proxy groups: Selector groups only; collapsed by default rendering just the group-name row, click .grp-name to expand
   (click again to collapse; only one group open at a time); expanded state kept in S.openGroup and folded into the sig,
   so it survives re-renders triggered by later data changes. Current selection highlighted in the expanded group; click node → select_proxy. */
function renderGroups(d) {
  S.lastGroups = d;
  const px = (d && d.proxies) || {};
  const groups = Object.entries(px)
    .filter(([, p]) => p && Array.isArray(p.all) && p.type === 'Selector')
    .map(([gn, g]) => ({
      name: gn,
      now: g.now || '',
      nodes: g.all.map(n => {
        const p = px[n] || {};
        const hist = (p.history && p.history.length) ? p.history[p.history.length - 1].delay : 0;
        return { name: n, delay: hist, cur: n === g.now };
      }),
    }));
  const sig = S.kernel + '|' + (S.openGroup || '') + '|' + JSON.stringify(groups);
  if (sig === S.sigGroups) return;
  S.sigGroups = sig;
  renderExit(); // egress node may have changed with the group data
  const box = $('tp-groups');
  if (!S.kernel) { box.innerHTML = '<div class="tp-empty">' + AgI18n.t('tray.kernelOff') + '</div>'; return; }
  if (!groups.length) { box.innerHTML = '<div class="tp-empty">' + AgI18n.t('tray.noGroups') + '</div>'; return; }
  box.innerHTML = groups.map(g =>
    '<div class="grp' + (S.openGroup === g.name ? ' open' : '') + '">' +
    '<div class="grp-name" data-g="' + esc(g.name) + '"><span>' + esc(g.name) + '</span>' +
    '<span class="now">' + esc(g.now) + '</span>' +
    '<span class="chev">' + AgIcon('chevron-down', 12) + '</span></div>' +
    (S.openGroup === g.name
      ? g.nodes.map(n =>
          '<div class="tp-node' + (n.cur ? ' cur' : '') + '" data-g="' + esc(g.name) + '" data-n="' + esc(n.name) + '">' +
          '<span class="dot ' + (n.cur ? 'on' : 'off') + '"></span>' +
          '<span class="nm">' + esc(n.name) + '</span>' +
          '<span class="ms">' + (n.delay ? n.delay + 'ms' : '') + '</span></div>'
        ).join('')
      : '') +
    '</div>'
  ).join('');
}

/* Connection summary: collapsed by default (header row + active count only, same as proxy groups); click header to expand the latest 5 */
function renderConns(d) {
  S.lastConns = d;
  const active = (d && Array.isArray(d.active)) ? d.active : [];
  const rows = active.slice(-5).reverse().map(c => {
    const it = c || {};
    const md = it.metadata || {};
    const host = it.host || md.host ||
      (md.destinationIP ? md.destinationIP + (md.destinationPort ? ':' + md.destinationPort : '') : '') || '-';
    const chains = Array.isArray(it.chains) ? it.chains : (Array.isArray(it.chain) ? it.chain : []);
    return { host, end: chains.length ? String(chains[0]) : '' }; // mihomo chains[0] = final egress of the chain
  });
  const sig = (S.openConns ? '1' : '0') + '|' + active.length + '|' + JSON.stringify(rows);
  if (sig === S.sigConns) return;
  S.sigConns = sig;
  $('tp-conn-count').textContent = AgI18n.t('tray.activeCount', { n: active.length });
  const head = $('tp-conns-head');
  if (head) head.classList.toggle('open', !!S.openConns);
  $('tp-conns').innerHTML = !S.openConns
    ? ''
    : (rows.length
      ? rows.map(r =>
          '<div class="tp-conn"><span class="host">' + esc(r.host) + '</span>' +
          (r.end ? '<span class="via">' + esc(r.end) + '</span>' : '') + '</div>'
        ).join('')
      : '<div class="tp-empty">' + AgI18n.t('tray.noConns') + '</div>');
}

/* ---------------- Poll scheduling: pause when hidden ---------------- */
let fastT = 0, slowT = 0;
function startLoops() {
  if (fastT || !invoke) return;
  fastTick(); slowTick();
  fastT = setInterval(fastTick, 1000);
  slowT = setInterval(slowTick, 3000);
}
function stopLoops() {
  clearInterval(fastT); clearInterval(slowT);
  fastT = slowT = 0;
}

/* ---------------- Startup ---------------- */
window.addEventListener('DOMContentLoaded', () => {
  AgI18n.hydrate(document);
  if (!invoke) {
    $('tp-noenv').hidden = false;
    return;
  }
  $('tp-root').hidden = false;
  if (TAURI.event && TAURI.event.listen) {
    TAURI.event.listen('ag-theme', e => { document.documentElement.dataset.theme = e.payload; }).catch(() => {});
  }

  document.addEventListener('visibilitychange', () => { document.hidden ? stopLoops() : startLoops(); });
  startLoops();

  // outbound mode switching (event delegation; optimistic flip, slowTick re-syncs from the truth)
  $('tp-mode').addEventListener('click', async (e) => {
    const b = e.target.closest('button[data-mode]');
    if (!b || S.tun || b.dataset.mode === S.mode) return;
    renderMode(b.dataset.mode, S.tun);
    try { await invoke('set_sub_mode', { mode: b.dataset.mode }); } catch (err) {}
    slowTick();
  });

  // proxy mode switching (system/local/tun — aligns tray with float-menu)
  $('tp-pmode').addEventListener('click', async (e) => {
    const b = e.target.closest('button[data-pmode]');
    if (!b || b.dataset.pmode === S.pmode) return;
    renderPMode(b.dataset.pmode);
    try { await invoke('proxy_mode_set', { mode: b.dataset.pmode }); } catch (err) {}
    slowTick();
  });

  // proxy groups: group-name row expand/collapse (one group at a time, immediate re-render); node row select_proxy (event delegation)
  $('tp-groups').addEventListener('click', async (e) => {
    const head = e.target.closest('.grp-name');
    if (head) {
      S.openGroup = (S.openGroup === head.dataset.g) ? null : head.dataset.g;
      renderGroups(S.lastGroups);
      return;
    }
    const row = e.target.closest('.tp-node');
    if (!row) return;
    try { await invoke('select_proxy', { group: row.dataset.g, name: row.dataset.n }); } catch (err) {}
    slowTick();
  });

  // connection summary: header row click expand/collapse (collapsed by default, immediate re-render)
  $('tp-conns-head').addEventListener('click', () => {
    S.openConns = !S.openConns;
    renderConns(S.lastConns);
  });

  // bottom action row (tray left-click already opens the main panel, no duplicate button here)
  $('tp-quit').addEventListener('click', () => { invoke('tray_quit').catch(() => {}); });
  $('tp-toggle').addEventListener('click', async () => {
    const btn = $('tp-toggle');
    btn.disabled = true;
    try {
      const st = await invoke('proxy_status');
      if (st && st.running) await invoke('stop_proxy');
      else await invoke('start_proxy', { port: 57890 });
    } catch (err) {}
    btn.disabled = false;
    slowTick();
  });
  // subscription kernel toggle (aligns tray with float-menu)
  $('tp-sub').addEventListener('click', async () => {
    const btn = $('tp-sub');
    btn.disabled = true;
    try {
      const on = !S.kernel;
      const st = await invoke('set_subscription_role', { on, enabled: on });
      S.kernel = st && typeof st.running === 'boolean' ? st.running : on;
      renderSub();
    } catch (err) {}
    btn.disabled = false;
    slowTick();
  });
});
