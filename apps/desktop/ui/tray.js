'use strict';
/* 托盘弹窗：状态区（网速大字 + 60s sparkline）/ 出站模式 / 代理组快切 / 连接摘要 / 底部操作行。
   渲染纪律：所有区块签名对比，数据不变不重写 DOM；1s（网速）+ 3s（状态/组/连接）双频轮询，
   窗口不可见时暂停。 */
/* 主题须首行执行防闪烁（本脚本在 head 同步加载，先于首次绘制） */
document.documentElement.dataset.theme = localStorage.getItem('ag_theme') || 'light';

const TAURI = window.__TAURI__;
const invoke = TAURI && TAURI.core ? TAURI.core.invoke : null;
const $ = (id) => document.getElementById(id);

function esc(s) {
  return String(s ?? '').replace(/[&<>"'`]/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;'
  }[c]));
}

/* ---------------- 状态与签名 ---------------- */
const S = {
  running: false, port: 0,          // 本地代理
  mode: 'rule', tun: false,         // 出站模式 / TUN 锁定
  kernel: false,                    // 订阅内核
  sigStatus: '', sigMode: '', sigGroups: '', sigConns: '',
  openGroup: null, lastGroups: null,  // 代理组展开态（组名，同时只展开一组）与最近一次组数据
  downSig: '', upSig: '',
  up60: [], down60: [],             // 60s 速率采样（B/s）
  chart: null,
};

function fmtRate(bps) {
  bps = +bps || 0;
  if (bps >= 1048576) return { num: (bps / 1048576).toFixed(1), unit: 'MB/s' };
  if (bps >= 1024) return { num: (bps / 1024).toFixed(1), unit: 'KB/s' };
  return { num: String(Math.round(bps)), unit: 'B/s' };
}

/* ---------------- 快轮询（1s）：实时网速 + sparkline ---------------- */
async function fastTick() {
  let t = null;
  try { t = await invoke('sub_traffic'); } catch (e) { /* 内核未运行等 */ }
  if (!t) {
    setSpeed('down', null); setSpeed('up', null);
    return;
  }
  setSpeed('down', +t.down_rate || 0);
  setSpeed('up', +t.up_rate || 0);
  S.down60.push(+t.down_rate || 0); if (S.down60.length > 60) S.down60.shift();
  S.up60.push(+t.up_rate || 0); if (S.up60.length > 60) S.up60.shift();
  // AgChart 内部签名对比，签名不变不重绘；变化时 rAF 插值过渡
  S.chart = window.AgChart && AgChart.sparkline($('tp-chart'), [
    { name: '下行', values: S.down60.slice() },
    { name: '上行', values: S.up60.slice() },
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

/* ---------------- 慢轮询（3s）：状态 / 模式 / 代理组 / 连接 ---------------- */
async function slowTick() {
  const [stR, roleR, kR, gR, cR] = await Promise.allSettled([
    invoke('proxy_status'),
    invoke('get_role_settings'),
    invoke('subscription_status'),
    invoke('proxy_groups'),
    invoke('sub_connections'), // 后端新增命令；未落地前 reject，空态兜底
  ]);
  if (stR.status === 'fulfilled' && stR.value) renderStatus(!!stR.value.running, +stR.value.port || 0);
  if (roleR.status === 'fulfilled' && roleR.value) {
    renderMode(roleR.value.sub_mode || 'rule', !!roleR.value.tun_mode);
  }
  if (kR.status === 'fulfilled' && kR.value) S.kernel = !!kR.value.running;
  if (gR.status === 'fulfilled') renderGroups(gR.value);
  if (cR.status === 'fulfilled') renderConns(cR.value);
  else renderConns(null);
}

function renderStatus(running, port) {
  const sig = running + '|' + port;
  if (sig === S.sigStatus) return;
  S.sigStatus = sig;
  S.running = running; S.port = port;
  const pill = $('tp-pill');
  pill.textContent = running ? '运行中' : '已停止';
  pill.classList.toggle('on', running);
  $('tp-addr').textContent = running ? ('本地代理 127.0.0.1:' + port) : '本地代理未启动';
  $('tp-toggle-label').textContent = running ? '停止代理' : '启动代理';
  $('tp-toggle').classList.toggle('warn', running);
}

function renderMode(mode, tun) {
  const sig = mode + '|' + tun;
  if (sig === S.sigMode) return;
  S.sigMode = sig;
  S.mode = mode; S.tun = tun;
  const seg = $('tp-mode');
  seg.classList.toggle('off', tun); // TUN 模式下出站固定规则（后端同样拒绝切换）
  seg.title = tun ? 'TUN 模式下出站固定为规则' : '';
  seg.querySelectorAll('button').forEach(b => b.classList.toggle('cur', b.dataset.mode === mode));
}

/* 代理组：仅列 Selector 组；默认收起只渲染组名行，点击 .grp-name 展开该组（再点收起，
   同时只展开一组）；展开态存 S.openGroup 并并入签名，延迟等数据变化触发重绘后展开态保持。
   展开组内当前选中高亮，点击节点 select_proxy。 */
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
  const box = $('tp-groups');
  if (!S.kernel) { box.innerHTML = '<div class="tp-empty">订阅内核未运行</div>'; return; }
  if (!groups.length) { box.innerHTML = '<div class="tp-empty">无可用代理组</div>'; return; }
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

/* 连接摘要：活跃数 + 最近 5 条（host + 链末节点名；字段做防御性解析） */
function renderConns(d) {
  const active = (d && Array.isArray(d.active)) ? d.active : [];
  const rows = active.slice(-5).reverse().map(c => {
    const it = c || {};
    const md = it.metadata || {};
    const host = it.host || md.host ||
      (md.destinationIP ? md.destinationIP + (md.destinationPort ? ':' + md.destinationPort : '') : '') || '-';
    const chains = Array.isArray(it.chains) ? it.chains : (Array.isArray(it.chain) ? it.chain : []);
    return { host, end: chains.length ? String(chains[0]) : '' }; // mihomo chains[0] = 链末出口
  });
  const sig = active.length + '|' + JSON.stringify(rows);
  if (sig === S.sigConns) return;
  S.sigConns = sig;
  $('tp-conn-count').textContent = '活跃 ' + active.length;
  $('tp-conns').innerHTML = rows.length
    ? rows.map(r =>
        '<div class="tp-conn"><span class="host">' + esc(r.host) + '</span>' +
        (r.end ? '<span class="via">' + esc(r.end) + '</span>' : '') + '</div>'
      ).join('')
    : '<div class="tp-empty">暂无活跃连接</div>';
}

/* ---------------- 轮询调度：不可见暂停 ---------------- */
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

/* ---------------- 启动 ---------------- */
window.addEventListener('DOMContentLoaded', () => {
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

  // 出站模式切换（事件委托）
  $('tp-mode').addEventListener('click', async (e) => {
    const b = e.target.closest('button[data-mode]');
    if (!b || S.tun || b.dataset.mode === S.mode) return;
    try { await invoke('set_sub_mode', { mode: b.dataset.mode }); } catch (err) {}
    slowTick();
  });

  // 代理组：组名行展开/收起（单组展开，立即重绘）；节点行 select_proxy（事件委托）
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

  // 底部操作行
  $('tp-show').addEventListener('click', () => { invoke('tray_show_main').catch(() => {}); });
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
});
