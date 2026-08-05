'use strict';
/* Split out of app.js: subscription proxy / node page / override scripts / TUN / artifact download / drag-drop import (pure move, zero logic change) */

/* ================= Subscription proxy (mihomo sidecar) ================= */
let SUBS = [];
let PROXY_DATA = null;
let PROXY_CACHED = false; // true = kernel not running, showing cached snapshot (read-only)
let CUR_GROUP = null;
/* 「每日选妃」 latency-test state: DELAY_CACHE group -> Map(node -> ms, 0=timeout), refresh badges in place only, no full-group re-render;
   TESTING groups currently testing (button disabled against double-click); TEST_ALL_ON serial test-all in progress */
const DELAY_CACHE = new Map();
const TESTING = new Set();
let TEST_ALL_ON = false;
function getSortMode(g) { return localStorage.getItem('ag_sort_' + g) || 'default'; } // per-group remembered sort mode

/* Dashboard subscription card: active subscription + node count + current node latency (filled once PROXY_DATA ready) */
function updateDashSub() {
  const active = SUBS.find(s => s.active);
  let val, sub;
  if (active) {
    val = active.name;
    sub = AgI18n.t('sub.dashActiveSub', { nodes: active.node_count, subs: SUBS.length });
    const g = PROXY_DATA && CUR_GROUP && PROXY_DATA[CUR_GROUP];
    if (g && g.now) {
      const p = PROXY_DATA[g.now] || {};
      const hist = (p.history && p.history.length) ? p.history[p.history.length - 1].delay : 0;
      sub += AgI18n.t('sub.dashCurrent', { node: g.now }) + (hist ? ' ' + hist + 'ms' : '');
    }
  } else {
    val = SUBS.length ? AgI18n.t('sub.dashCountSubs', { n: SUBS.length }) : AgI18n.t('sub.dashNoSub');
    sub = AgI18n.t(SUBS.length ? 'sub.dashInactiveHint' : 'sub.dashEmptyHint');
  }
  setText('d-sub-val', val);
  setText('d-sub-sub', sub);
}

function fmtDate(ts) { return ts ? new Date(ts * 1000).toLocaleDateString() : ''; }

async function refreshSubs() {
  try { SUBS = await invoke('list_subscriptions'); } catch (e) { SUBS = []; }
  const list = $('subs-list');
  const active = SUBS.find(s => s.active);
  // proxy-sub-desc single-writer rule (web.md §2.2): cached state belongs to refreshGroups,
  // normal state to refreshSubs — never both in one poll cycle
  if (!PROXY_CACHED) {
    $('proxy-sub-desc').textContent = active
      ? AgI18n.t('sub.descActive', { name: active.name, n: active.node_count })
      : AgI18n.t('sub.descActivateFirst');
  }
  updateDashSub();
  if (!SUBS.length) {
    list.innerHTML = '<div class="empty">' + AgI18n.t('sub.emptySubs') + '</div>';
    return;
  }
  list.innerHTML = SUBS.map(s => {
    const used = (s.upload || 0) + (s.download || 0);
    const pct = s.total ? Math.min(100, used / s.total * 100) : 0;
    const cls = pct >= 95 ? 'full' : pct >= 80 ? 'warn' : '';
    const traffic = s.total ? fmtBytes(used) + ' / ' + fmtBytes(s.total) : AgI18n.t('sub.usedOnly', { used: fmtBytes(used) });
    const expire = s.expire ? ' · ' + fmtDate(s.expire) : (s.total ? AgI18n.t('sub.longTerm') : '');
    return '<div class="sub-card' + (s.active ? ' active' : '') + '" data-sub-activate="' + esc(s.id) + '">' +
      '<div class="sub-card-top"><span class="sub-card-title" title="' + esc(s.name) + '">' + esc(s.name) + '</span>' +
      (s.active ? '<span class="sub-badge">' + AgI18n.t('sub.inUse') + '</span>' : '') +
      '<span class="sub-card-actions">' +
      '<button class="ghost small icon-btn" data-sub-update="' + esc(s.id) + '" title="' + AgI18n.t('sub.refreshTitle') + '">' + AgIcon('refresh-cw', 13) + '</button>' +
      '<button class="ghost small icon-btn" data-sub-del="' + esc(s.id) + '" title="' + AgI18n.t('common.delete') + '">' + AgIcon('trash-2', 13) + '</button>' +
      '</span></div>' +
      '<div class="sub-progress"><i class="' + cls + '" style="width:' + pct.toFixed(1) + '%"></i></div>' +
      '<div class="sub-card-meta">' + traffic + expire + '</div>' +
      '<div class="sub-card-sub">' + AgI18n.t('sub.updatedMeta', { ago: fmtAgo(s.updated_at), n: s.node_count }) + '</div>' +
      '</div>';
  }).join('');
}

async function refreshSubStatus() {
  let st;
  try { st = await invoke('subscription_status'); } catch (e) { return; }
  $('sub-status-text').textContent = st.running
    ? AgI18n.t('common.running')
    : (st.installed ? AgI18n.t('sub.installedNotRunning') : (st.supported ? AgI18n.t('sub.notEnabled') : AgI18n.t('sub.unsupported')));
  $('sub-version').textContent = st.version || (st.installed ? AgI18n.t('sub.installed') : '-');
  $('r-sub').checked = st.running;
  // dashboard subscription card toggle & badge sync (same role as the subscription page kernel toggle)
  const d = $('d-sub');
  if (d) d.checked = st.running;
  setHtml('d-sub-badge', st.running ? '<span class="badge b-ok">' + AgI18n.t('common.running') + '</span>' : '<span class="badge b-gray">' + AgI18n.t('sub.notRunning') + '</span>');
  // override script failure alert (sig dedup: same failure set toasts once, resets after recovery)
  const se = st.script_errors || [];
  const seSig = JSON.stringify(se);
  if (se.length && window._scriptErrSig !== seSig) {
    toast(AgI18n.t('sub.scriptFailed', { name: se[0][0], err: se[0][1] }), 'err');
  }
  window._scriptErrSig = se.length ? seSig : '';
  // kernel state flipped: egress path changes, re-probe egress IP now (via mihomo ↔ direct)
  if (window._subRunning !== st.running) {
    window._subRunning = st.running;
    NetProbe.refresh();
  }
  NetProbe.render();
  // sidebar footer rate area flips with kernel run state (running ↔ stopped)
  renderSideFoot();
  Hero.onTraffic(); // hero card curve/readings flip too (fallback to empty state here when sub_traffic errors)
  // refresh proxy page whether kernel runs or not (falls back to cached snapshot when down, for node browsing)
  refreshGroups();
}

/* ---------- Subscription kernel traffic (backend /traffic WS single-task cumulative; frontend 2s polls same source) ----------
   Subscription page kernel card and home subscription card share this module's series; no extra polling;
   rate series follows trackFaninTraffic's delta guard: cumulative regression = kernel restart reset, take as new baseline. */
const SubTraffic = {
  data: null, _last: null, _lastUp: null, _lastDown: null, series: [], rates: { up: 0, down: 0 }, _sig: '',
  async poll() {
    if (HTTP_MODE) return;
    let t;
    try { t = await invoke('sub_traffic'); } catch (e) { return; }
    const total = t.up_total + t.down_total;
    if (this._last !== null) {
      let delta = total - this._last;
      // kernel restart zeroes the counters: the new total is a fresh baseline, not traffic —
      // clamp the reset frame to 0 (same semantics as the direction-rate Math.max(0, …) below)
      if (delta < 0) delta = 0;
      this.series.push(delta);
      if (this.series.length > 90) this.series.shift();
    }
    this._last = total;
    // per-direction rates (2s poll delta feeds sidebar footer; kernel restart zeroes counters → clamp negative delta to 0, never fake rates)
    const dUp = this._lastUp === null ? 0 : Math.max(0, t.up_total - this._lastUp);
    const dDown = this._lastDown === null ? 0 : Math.max(0, t.down_total - this._lastDown);
    this._lastUp = t.up_total;
    this._lastDown = t.down_total;
    this.rates = { up: Math.round(dUp / 2), down: Math.round(dDown / 2) };
    this.data = t;
    this.render();
    renderSideFoot();
    Hero.onTraffic(); // dashboard hero card: rate buffer/curve/today usage (same 2s source, no extra polling)
  },
  render() {
    const t = this.data, show = !!window._subRunning && !!t;
    // visibility first (not gated by change detection)
    const row = $('sub-traffic-row'), spark = $('sub-spark');
    const dtf = $('d-sub-tf'), dspark = $('d-sub-spark');
    [row, spark, dtf, dspark].forEach(el => { if (el) el.style.display = show ? '' : 'none'; });
    const sig = show ? (t.up_total + '/' + t.down_total) : 'off';
    if (sig === this._sig) return; // change detection: totals unchanged, skip redraw
    this._sig = sig;
    if (!show) return;
    const text = '↑ ' + fmtBytes(t.up_total) + ' · ↓ ' + fmtBytes(t.down_total);
    setText('sub-traffic-total', text);
    setText('d-sub-tf', text);
    const series = this.series.length > 1 ? this.series : [0, 0];
    if (spark) AgChart.sparkline(spark, series);
    if (dspark) AgChart.sparkline(dspark, series);
  },
};

/* ---------- Proxy page (「每日选妃」: group batch latency test with streaming badge refresh + delay sort + recommended badge) ----------
   Render discipline: group-tabs / node-grid both sig-compared, no redraw when data unchanged (refreshSubStatus 10s poll calls in);
   test results only write DELAY_CACHE and refresh .lat badges in place (text/class), no full-group re-render;
   after the stagger finishes, reconcile once: apply delay sort and 「推荐」 badge. */
const GROUP_LABELS = { 'AGILE-SUB': 'sub.groupAgileSub' }; // technical name → locale entry key; mihomo built-in GLOBAL group hidden
function proxyGroupList() {
  return Object.entries(PROXY_DATA || {}).filter(([n, p]) =>
    n !== 'GLOBAL' && p.all && ['Selector', 'URLTest', 'Fallback'].includes(p.type));
}
/* Effective node latency: latency-test cache first (0=timeout); URLTest/Fallback groups fall back to latest mihomo history value; null=not tested */
function delayOf(group, node) {
  const m = DELAY_CACHE.get(group);
  if (m && m.has(node)) return m.get(node);
  const g = PROXY_DATA && PROXY_DATA[group];
  if (g && (g.type === 'URLTest' || g.type === 'Fallback')) {
    const p = PROXY_DATA[node] || {};
    if (p.history && p.history.length) return p.history[p.history.length - 1].delay || 0;
  }
  return null;
}
// latency tiers: <300ms good / <800ms mid / else bad; 0 (timeout) and null (not tested) are both na
function latCls(ms) { return ms < 300 ? 'lat-good' : ms < 800 ? 'lat-mid' : 'lat-bad'; }
function latHtml(ms) {
  if (typeof ms === 'number' && ms > 0)
    return '<span class="lat ' + latCls(ms) + '" style="margin-left:auto">' + ms + ' ms</span>';
  return '<span class="lat lat-na" style="margin-left:auto">' + (ms === null ? '—' : AgI18n.t('sub.timeout')) + '</span>';
}
/* 「推荐」 badge: node with lowest tested latency under 500ms (Tailscale-style decide-for-user) */
function bestNode(group) {
  const m = DELAY_CACHE.get(group);
  let best = null, bestMs = 500;
  if (m) m.forEach((ms, name) => { if (ms > 0 && ms < bestMs) { best = name; bestMs = ms; } });
  return best;
}
/* Sort by latency: nodes with valid latency ascending first, no-data/timeout keep original order after (index tiebreak keeps stability); current selection follows naturally */
function sortedNodes(group) {
  const g = PROXY_DATA[group];
  if (getSortMode(group) !== 'delay') return g.all;
  return g.all.map((n, i) => ({ n, i, ms: delayOf(group, n) }))
    .sort((a, b) => {
      const av = a.ms > 0 ? a.ms : Infinity, bv = b.ms > 0 ? b.ms : Infinity;
      return av !== bv ? av - bv : a.i - b.i;
    })
    .map(k => k.n);
}

/* Empty state & degradation: kernel not running (「去开启」 jumps to subscription view, no such entry in HTTP_MODE) / no proxy groups */
function renderProxyEmpty(kind) {
  $('pg-toolbar').style.display = 'none';
  const tabs = $('group-tabs');
  if (tabs.dataset.sig !== '') { tabs.dataset.sig = ''; tabs.innerHTML = ''; }
  const grid = $('node-grid');
  const sig = 'empty-' + kind + (HTTP_MODE ? '-http' : '');
  if (grid.dataset.sig !== sig) {
    grid.dataset.sig = sig;
    grid.innerHTML = kind === 'down'
      ? '<div class="empty-state" style="grid-column:1/-1">' + AgIcon('satellite', 36) +
        '<div class="empty-t">' + AgI18n.t('sub.kernelDown') + '</div>' +
        '<div class="empty-d">' + AgI18n.t('sub.kernelDownDesc') + '</div>' +
        (HTTP_MODE ? '' : '<button class="small" data-goto-sub>' + AgI18n.t('sub.goEnable') + '</button>') + '</div>'
      : '<div class="empty-state" style="grid-column:1/-1">' + AgIcon('orbit', 36) +
        '<div class="empty-t">' + AgI18n.t('sub.noGroups') + '</div>' +
        '<div class="empty-d">' + AgI18n.t('sub.noGroupsDesc') + '</div></div>';
  }
  syncTestUI();
}

async function refreshGroups() {
  let d;
  try { d = await invoke('proxy_groups'); } catch (e) {
    PROXY_CACHED = false;
    PROXY_DATA = null;
    renderProxyEmpty('down');
    updateDashSub();
    return;
  }
  PROXY_CACHED = !!d.cached;
  PROXY_DATA = (d && d.proxies) || {};
  const groups = proxyGroupList();
  if (!groups.length) { renderProxyEmpty('empty'); updateDashSub(); return; }
  if (!CUR_GROUP || !groups.some(([n]) => n === CUR_GROUP)) CUR_GROUP = groups[0][0];
  $('pg-toolbar').style.display = '';
  // group tab sig compare: no redraw when group set and current group unchanged
  const tabs = $('group-tabs');
  const tabSig = JSON.stringify([groups.map(([n]) => n), CUR_GROUP]);
  if (tabs.dataset.sig !== tabSig) {
    tabs.dataset.sig = tabSig;
    tabs.innerHTML = groups.map(([n]) =>
      '<button class="group-tab' + (n === CUR_GROUP ? ' active' : '') + '" data-group-tab="' + esc(n) + '">' + esc(GROUP_LABELS[n] ? AgI18n.t(GROUP_LABELS[n]) : n) + '</button>'
    ).join('');
  }
  // cached state: read-only display, override desc copy (proxy-sub-desc single-writer rule, web.md §2.2: cached belongs here, normal to refreshSubs)
  if (PROXY_CACHED) setText('proxy-sub-desc', AgI18n.t('sub.cachedDesc'));
  syncSortTabs();
  syncTestUI();
  renderNodeGrid();
  updateDashSub();
}

function renderNodeGrid(force) {
  const g = PROXY_DATA && PROXY_DATA[CUR_GROUP];
  if (!g) return;
  const grid = $('node-grid');
  // sig compare: no redraw when proxy data/sort mode unchanged (latency-test badges refresh in place separately; 10s poll must not interrupt streaming writes)
  const sig = JSON.stringify([CUR_GROUP, g.type, g.now, g.all, PROXY_CACHED, getSortMode(CUR_GROUP)]);
  if (!force && grid.dataset.sig === sig) return;
  grid.dataset.sig = sig;
  const best = bestNode(CUR_GROUP);
  grid.innerHTML = sortedNodes(CUR_GROUP).map(n => {
    const p = PROXY_DATA[n] || {};
    const cur = g.now === n;
    return '<div class="snode-card' + (cur ? ' current' : '') + '" data-group="' + esc(CUR_GROUP) + '" data-node="' + esc(n) + '">' +
      '<div class="node-name">' + (cur ? '<span class="node-check">' + AgIcon('check', 11) + '</span>' : '') +
      (best === n ? '<span class="pill pill-ok">' + AgI18n.t('sub.recommended') + '</span>' : '') +
      '<span class="node-name-text" title="' + esc(n) + '">' + esc(n) + '</span></div>' +
      '<div class="node-foot" style="padding-right:0"><span class="node-proto">' + esc(p.type || '') + '</span>' +
      latHtml(delayOf(CUR_GROUP, n)) +
      '</div></div>';
  }).join('');
}

/* Badge-only refresh, no re-render: '…' loading / null not tested (—) / 0 timeout / >0 valid latency */
function writeLat(card, ms) {
  const el = card.querySelector('.lat');
  if (!el) return;
  if (ms === '…') { el.textContent = '…'; el.className = 'lat lat-na'; return; }
  if (typeof ms === 'number' && ms > 0) { el.textContent = ms + ' ms'; el.className = 'lat ' + latCls(ms); return; }
  el.textContent = ms === null ? '—' : AgI18n.t('sub.timeout');
  el.className = 'lat lat-na';
}
function groupCards(group) {
  return [...$('node-grid').querySelectorAll('.snode-card')].filter(c => c.dataset.group === group);
}

/* Latency-test button state: hidden in HTTP_MODE (CMD_MAP lacks this command) and cached state; disabled + spinner while running (anti double-click, learned from competitor complaints) */
let _testUiKey = '';
function syncTestUI() {
  const bAll = $('btn-test-all'), bGrp = $('btn-test-group');
  const grpBusy = TESTING.has(CUR_GROUP);
  const key = [HTTP_MODE, PROXY_CACHED, TEST_ALL_ON, grpBusy].join('|');
  if (key === _testUiKey) return;
  _testUiKey = key;
  const hide = HTTP_MODE || PROXY_CACHED;
  bAll.style.display = hide ? 'none' : '';
  bGrp.style.display = hide ? 'none' : '';
  bGrp.disabled = grpBusy || TEST_ALL_ON;
  bAll.disabled = TEST_ALL_ON;
  bGrp.innerHTML = grpBusy ? '<span class="spinner"></span>' + AgI18n.t('sub.testing') : AgIcon('zap', 13) + AgI18n.t('sub.test');
  bAll.innerHTML = TEST_ALL_ON ? '<span class="spinner"></span>' + AgI18n.t('sub.testingAll') : AgIcon('gauge', 14) + AgI18n.t('sub.testAll');
}
function syncSortTabs() {
  const cur = getSortMode(CUR_GROUP);
  document.querySelectorAll('#sort-tabs .agtab').forEach(t => t.classList.toggle('active', t.dataset.sort === cur));
}

/* Group batch latency test (sub_test_group: delay=0 means timeout, returns sorted by valid latency ascending, 0 at tail):
   on click set all group badges to 「…」 loading; results written in 30ms stagger in returned order, simulating streaming row-by-row refresh
   (mihomo returns all at once; frontend fakes the row-by-row feel); on failure roll badges back to cached/history values, no full-group re-render. */
async function testGroupDelay(group) {
  if (!group || TESTING.has(group) || PROXY_CACHED || HTTP_MODE) return false;
  TESTING.add(group);
  syncTestUI();
  groupCards(group).forEach(c => writeLat(c, '…'));
  let results;
  try {
    results = await invoke('sub_test_group', { group });
  } catch (e) {
    groupCards(group).forEach(c => writeLat(c, delayOf(group, c.dataset.node)));
    TESTING.delete(group);
    syncTestUI();
    toast(friendlyError(e), 'err');
    return false;
  }
  let m = DELAY_CACHE.get(group);
  if (!m) { m = new Map(); DELAY_CACHE.set(group, m); }
  results.forEach(r => m.set(r.name, r.delay));
  results.forEach((r, i) => {
    setTimeout(() => {
      const card = $('node-grid').querySelector('[data-group="' + CSS.escape(group) + '"][data-node="' + CSS.escape(r.name) + '"]');
      if (card) writeLat(card, r.delay);
    }, i * 30);
  });
  TESTING.delete(group);
  syncTestUI();
  // after the stagger finishes, reconcile once: apply delay sort and 「推荐」 badge (if current group still shown)
  setTimeout(() => { if (CUR_GROUP === group && PROXY_DATA && PROXY_DATA[group]) renderNodeGrid(true); }, results.length * 30 + 60);
  return true;
}

/* Test all: iterate groups serially (avoid hammering the kernel with concurrency), abort on first group failure; button spinner + disabled while running */
async function testAllGroups() {
  if (TEST_ALL_ON || PROXY_CACHED || HTTP_MODE) return;
  const groups = proxyGroupList();
  if (!groups.length) return;
  TEST_ALL_ON = true;
  syncTestUI();
  for (const [name] of groups) { if (!(await testGroupDelay(name))) break; }
  TEST_ALL_ON = false;
  syncTestUI();
}

function openSubModal() {
  $('sub-name').value = ''; $('sub-url').value = ''; $('sub-err').textContent = '';
  $('sub-modal').style.display = 'flex';
  $('sub-url').focus();
}

/* ---------- Override scripts (JS: main(config) pipeline; drag sort + per-script toggle + dry run) ---------- */
let SUB_SCRIPTS = [];
let SCRIPT_EDIT_ID = null; // null = new
let SCRIPT_DRAG_ID = null;
function scriptTemplate() {
  return `const main = (config) => {
  // ${AgI18n.t('sub.tplComment')}
  config.proxies = config.proxies || [];
  config.proxies.push({
    name: "${AgI18n.t('sub.tplProxyName')}", type: "ss",
    server: "example.com", port: 8388,
    cipher: "aes-128-gcm", password: "${AgI18n.t('sub.tplPassword')}"
  });
  config.rules = config.rules || [];
  config.rules.unshift("DOMAIN-SUFFIX,example.com,${AgI18n.t('sub.tplProxyName')}");
  return config;
};`;
}

async function refreshSubScripts() {
  try { SUB_SCRIPTS = await invoke('list_sub_scripts'); } catch (e) { SUB_SCRIPTS = []; }
  const sig = JSON.stringify(SUB_SCRIPTS.map(s => [s.id, s.name, s.enabled, s.order]));
  const list = $('scripts-list');
  if (!SUB_SCRIPTS.length) {
    if (list.dataset.sig !== 'empty') { list.dataset.sig = 'empty'; list.innerHTML = '<div class="empty">' + AgI18n.t('sub.emptyScripts') + '</div>'; }
    return;
  }
  if (list.dataset.sig === sig) return; // change detection: content unchanged, skip redraw (avoid poll interrupting an active drag)
  list.dataset.sig = sig;
  list.innerHTML = SUB_SCRIPTS.map(s =>
    '<div class="script-row" draggable="true" data-script-row="' + esc(s.id) + '">' +
    '<span class="script-grip" title="' + AgI18n.t('sub.dragSort') + '">' + AgIcon('grip-vertical', 14) + '</span>' +
    '<span class="script-name" title="' + esc(s.name) + '">' + esc(s.name) + '</span>' +
    '<span class="script-state">' + (s.enabled ? '' : AgI18n.t('common.disabled')) + '</span>' +
    '<label class="switch"><input type="checkbox" data-script-toggle="' + esc(s.id) + '"' + (s.enabled ? ' checked' : '') + '><span class="slider"></span></label>' +
    '<button class="ghost small icon-btn" data-script-edit="' + esc(s.id) + '" title="' + AgI18n.t('common.edit') + '">' + AgIcon('pencil', 13) + '</button>' +
    '<button class="ghost small icon-btn" data-script-del="' + esc(s.id) + '" title="' + AgI18n.t('common.delete') + '">' + AgIcon('trash-2', 13) + '</button>' +
    '</div>'
  ).join('');
}

function openScriptModal(id) {
  const sc = id ? SUB_SCRIPTS.find(s => s.id === id) : null;
  SCRIPT_EDIT_ID = sc ? sc.id : null;
  $('script-modal-title').textContent = AgI18n.t(sc ? 'sub.scriptEdit' : 'sub.scriptNew');
  $('script-name').value = sc ? sc.name : '';
  $('script-code').value = sc ? sc.code : scriptTemplate();
  $('script-err').textContent = '';
  $('script-test-result').textContent = '';
  $('script-modal').style.display = 'flex';
  $('script-name').focus();
}

function initSubScripts() {
  $('btn-add-script').onclick = () => openScriptModal(null);
  $('script-cancel').onclick = () => { $('script-modal').style.display = 'none'; };
  $('script-test').onclick = async () => {
    const code = $('script-code').value;
    const btn = $('script-test');
    btn.disabled = true;
    $('script-test-result').textContent = AgI18n.t('sub.scriptTesting');
    $('script-test-result').classList.remove('sm-err');
    try {
      const msg = await invoke('test_sub_script', { code });
      $('script-test-result').textContent = msg;
    } catch (err) {
      $('script-test-result').textContent = friendlyError(err);
      $('script-test-result').classList.add('sm-err');
    } finally {
      btn.disabled = false;
    }
  };
  $('script-ok').onclick = async () => {
    const name = $('script-name').value.trim();
    const code = $('script-code').value;
    if (!code.trim()) { $('script-err').textContent = AgI18n.t('sub.scriptCodeEmpty'); return; }
    const btn = $('script-ok');
    btn.disabled = true;
    $('script-err').textContent = '';
    try {
      if (SCRIPT_EDIT_ID) {
        await invoke('update_sub_script', { id: SCRIPT_EDIT_ID, name, code });
        toast(AgI18n.t('sub.scriptSaved'), 'ok');
      } else {
        await invoke('add_sub_script', { name, code });
        toast(AgI18n.t('sub.scriptCreated'), 'ok');
      }
      $('script-modal').style.display = 'none';
      refreshSubScripts();
    } catch (err) {
      $('script-err').textContent = friendlyError(err);
    } finally {
      btn.disabled = false;
    }
  };
  const list = $('scripts-list');
  list.addEventListener('click', async (e) => {
    const btn = e.target.closest('button');
    if (!btn) return;
    try {
      if (btn.dataset.scriptEdit) {
        openScriptModal(btn.dataset.scriptEdit);
      } else if (btn.dataset.scriptDel) {
        if (btn.dataset.confirm === '1') {
          await invoke('remove_sub_script', { id: btn.dataset.scriptDel });
          toast(AgI18n.t('sub.scriptDeleted'), 'ok');
          refreshSubScripts();
          return;
        }
        btn.dataset.confirm = '1';
        const old = btn.innerHTML;
        btn.innerHTML = '<span style="font-size:11px">' + AgI18n.t('common.confirm') + '</span>';
        setTimeout(() => { if (btn.isConnected) { btn.dataset.confirm = ''; btn.innerHTML = old; } }, 2500);
      }
    } catch (err) { toast(friendlyError(err), 'err'); }
  });
  list.addEventListener('change', async (e) => {
    const cb = e.target.closest('input[data-script-toggle]');
    if (!cb) return;
    try {
      await invoke('set_sub_script_enabled', { id: cb.dataset.scriptToggle, enabled: cb.checked });
      toast(AgI18n.t(cb.checked ? 'sub.scriptEnabled' : 'sub.scriptDisabled'), 'ok');
      refreshSubScripts();
    } catch (err) { cb.checked = !cb.checked; toast(friendlyError(err), 'err'); }
  });
  /* HTML5 drag sort: submit reorder command with new order after drop */
  list.addEventListener('dragstart', (e) => {
    const row = e.target.closest('[data-script-row]');
    if (!row) return;
    SCRIPT_DRAG_ID = row.dataset.scriptRow;
    row.classList.add('dragging');
    e.dataTransfer.effectAllowed = 'move';
  });
  list.addEventListener('dragend', () => {
    SCRIPT_DRAG_ID = null;
    list.querySelectorAll('.script-row').forEach(r => r.classList.remove('dragging', 'drop-before', 'drop-after'));
  });
  list.addEventListener('dragover', (e) => {
    if (!SCRIPT_DRAG_ID) return;
    const row = e.target.closest('[data-script-row]');
    if (!row || row.dataset.scriptRow === SCRIPT_DRAG_ID) return;
    e.preventDefault(); // preventDefault required to allow drop
    e.dataTransfer.dropEffect = 'move';
    const rect = row.getBoundingClientRect();
    const before = e.clientY < rect.top + rect.height / 2;
    list.querySelectorAll('.script-row').forEach(r => r.classList.remove('drop-before', 'drop-after'));
    row.classList.add(before ? 'drop-before' : 'drop-after');
  });
  list.addEventListener('drop', async (e) => {
    if (!SCRIPT_DRAG_ID) return;
    const row = e.target.closest('[data-script-row]');
    if (!row || row.dataset.scriptRow === SCRIPT_DRAG_ID) return;
    e.preventDefault();
    const rect = row.getBoundingClientRect();
    const before = e.clientY < rect.top + rect.height / 2;
    const ids = SUB_SCRIPTS.map(s => s.id).filter(id => id !== SCRIPT_DRAG_ID);
    let idx = ids.indexOf(row.dataset.scriptRow);
    if (!before) idx += 1;
    ids.splice(idx, 0, SCRIPT_DRAG_ID);
    try {
      await invoke('reorder_sub_scripts', { ids });
      refreshSubScripts();
    } catch (err) { toast(friendlyError(err), 'err'); }
  });
}

function initSubscription() {
  $('btn-add-sub').onclick = openSubModal;
  $('sub-cancel').onclick = () => { $('sub-modal').style.display = 'none'; };
  $('sub-paste').onclick = async () => {
    try { $('sub-url').value = await navigator.clipboard.readText(); } catch (e) { toast(AgI18n.t('sub.clipboardErr'), 'err'); }
  };
  $('sub-url').addEventListener('keydown', e => { if (e.key === 'Enter') $('sub-ok').click(); });
  $('sub-ok').onclick = async () => {
    const url = $('sub-url').value.trim();
    if (!url) { $('sub-err').textContent = AgI18n.t('sub.urlRequired'); return; }
    const btn = $('sub-ok');
    btn.disabled = true;
    btn.textContent = AgI18n.t('sub.fetching');
    $('sub-err').textContent = '';
    try {
      const sub = await invoke('add_subscription', { name: $('sub-name').value.trim(), url });
      $('sub-modal').style.display = 'none';
      toast(AgI18n.t('sub.added', { n: sub.node_count }), 'ok');
      refreshSubs();
    } catch (err) {
      $('sub-err').textContent = friendlyError(err);
    } finally {
      btn.disabled = false;
      btn.textContent = AgI18n.t('sub.fetchAdd');
    }
  };
  $('subs-list').addEventListener('click', async (e) => {
    const btn = e.target.closest('button');
    if (btn) {
      e.stopPropagation();
      try {
        if (btn.dataset.subUpdate) {
          btn.disabled = true;
          const sub = await invoke('update_subscription', { id: btn.dataset.subUpdate });
          toast(AgI18n.t('sub.refreshed', { n: sub.node_count }), 'ok');
          refreshSubs(); refreshGroups();
        } else if (btn.dataset.subDel) {
          if (btn.dataset.confirm === '1') {
            await invoke('remove_subscription', { id: btn.dataset.subDel });
            toast(AgI18n.t('sub.deleted'), 'ok');
            refreshSubs(); refreshSubStatus();
            return;
          }
          btn.dataset.confirm = '1';
          const old = btn.innerHTML;
          btn.innerHTML = '<span style="font-size:11px">' + AgI18n.t('common.confirm') + '</span>';
          setTimeout(() => { if (btn.isConnected) { btn.dataset.confirm = ''; btn.innerHTML = old; } }, 2500);
        }
      } catch (err) { toast(friendlyError(err), 'err'); btn.disabled = false; }
      return;
    }
    // card body click = single-select activate
    const card = e.target.closest('[data-sub-activate]');
    if (card && !card.classList.contains('active')) {
      try {
        const sub = await invoke('set_active_subscription', { id: card.dataset.subActivate });
        toast(AgI18n.t('sub.activated', { name: sub.name }), 'ok');
        refreshSubs(); refreshSubStatus();
      } catch (err) { toast(friendlyError(err), 'err'); }
    }
  });

  /* Kernel role toggle (subscription page r-sub and dashboard d-sub dual entries share this logic; checked synced centrally by refreshSubStatus) */
  const subToggle = async (e) => {
    const on = e.target.checked;
    const el = e.target;
    el.disabled = true;
    try {
      if (on && !SUBS.length) {
        el.checked = false;
        toast(AgI18n.t('sub.addFirst'), 'err');
        openSubModal();
        return;
      }
      await invoke('set_subscription_role', { enabled: on });
      toast(AgI18n.t(on ? 'sub.roleOn' : 'sub.roleOff'), 'ok');
      refreshSubStatus();
    } catch (err) {
      el.checked = !on;
      if (on && String(err).indexOf('NEED_DOWNLOAD:') === 0) {
        /* kernel not installed: backend already auto-started download; auto-retry enabling after done */
        handleNeedDownload(async () => {
          try {
            await invoke('set_subscription_role', { enabled: true });
            toast(AgI18n.t('sub.roleOn'), 'ok');
            refreshSubStatus();
          } catch (e2) { toast(friendlyError(e2), 'err'); }
        });
      } else {
        toast(friendlyError(err), 'err');
      }
    } finally {
      el.disabled = false;
    }
  };
  $('r-sub').onchange = subToggle;
  $('d-sub').onchange = subToggle;
  /* Outbound mode: persist on switch, hot-swap in controller while kernel runs (backend PATCH /configs) */
  $('sub-mode').onchange = async (e) => {
    const prev = e.target.dataset.prev || 'rule';
    try {
      await invoke('set_sub_mode', { mode: e.target.value });
      e.target.dataset.prev = e.target.value;
      if (window._rolesCache) window._rolesCache.sub_mode = e.target.value;
      const label = { rule: AgI18n.t('sub.modeRule'), global: AgI18n.t('sub.modeGlobal'), direct: AgI18n.t('sub.modeDirect') }[e.target.value] || e.target.value;
      toast(AgI18n.t('sub.modeSwitched', { mode: label }), 'ok');
    } catch (err) {
      e.target.value = prev;
      agSelectRefresh(e.target);
      toast(friendlyError(err), 'err');
    }
  };
  initSubScripts();

  /* Proxy page events */
  $('group-tabs').addEventListener('click', (e) => {
    const tab = e.target.closest('[data-group-tab]');
    if (!tab) return;
    CUR_GROUP = tab.dataset.groupTab;
    refreshGroups();
  });
  $('sort-tabs').addEventListener('click', (e) => {
    const t = e.target.closest('[data-sort]');
    if (!t || !CUR_GROUP) return;
    localStorage.setItem('ag_sort_' + CUR_GROUP, t.dataset.sort);
    syncSortTabs();
    renderNodeGrid(true);
  });
  $('btn-test-group').onclick = () => testGroupDelay(CUR_GROUP);
  $('btn-test-all').onclick = () => testAllGroups();
  $('node-grid').addEventListener('click', async (e) => {
    if (e.target.closest('[data-goto-sub]')) { switchView('subscription'); return; }
    const card = e.target.closest('.snode-card');
    if (!card) return;
    if (PROXY_CACHED) { toast(AgI18n.t('sub.cachedOnly'), 'err'); return; }
    try {
      await invoke('select_proxy', { group: card.dataset.group, name: card.dataset.node });
      // reflect selection locally at once (incl. check-mark move); once g.now synced, 10s poll sig naturally triggers redraw
      if (PROXY_DATA && PROXY_DATA[card.dataset.group]) PROXY_DATA[card.dataset.group].now = card.dataset.node;
      document.querySelectorAll('.snode-card').forEach(c => {
        c.classList.toggle('current', c === card);
        const chk = c.querySelector('.node-check');
        if (c === card && !chk) c.querySelector('.node-name').insertAdjacentHTML('afterbegin', '<span class="node-check">' + AgIcon('check', 11) + '</span>');
        if (c !== card && chk) chk.remove();
      });
      toast(AgI18n.t('sub.switchedTo', { name: card.dataset.node }), 'ok');
    } catch (err) { toast(friendlyError(err), 'err'); }
  });
}

/* ---------- Subscription feature install/activate (settings page) ---------- */
async function refreshSubFeature() {
  let st;
  try { st = await invoke('subscription_status'); } catch (e) { return; }
  const statusEl = $('sub-install-status');
  const installBtn = $('btn-install-kernel');
  if (!st.supported) {
    statusEl.textContent = AgI18n.t('sub.unsupported');
    installBtn.disabled = true;
    $('btn-activate-sub').disabled = true;
    return;
  }
  statusEl.textContent = st.installed ? (st.version ? AgI18n.t('sub.installedVersion', { ver: st.version }) : AgI18n.t('sub.installed')) : AgI18n.t('sub.notInstalled');
  installBtn.innerHTML = AgIcon('download', 13) + ' ' + AgI18n.t(st.installed ? 'sub.redownloadKernel' : 'sub.downloadKernel');
  $('btn-activate-sub').disabled = !st.installed;
}
function initSubFeature() {
  /* Download & install kernel: backend returns once background download starts; progress shown on subscription page download card; refresh install state on completion */
  $('btn-install-kernel').onclick = async (e) => {
    const btn = e.target.closest('button');
    btn.disabled = true;
    try {
      await invoke('install_kernel');
      handleNeedDownload(() => { refreshSubFeature(); });
    } catch (err) { toast(friendlyError(err), 'err'); }
    finally { btn.disabled = false; }
  };
  /* Manual install: user downloads the official file themselves, gives full path; written to disk only after pinned-version/hash check passes */
  $('btn-manual-kernel').onclick = () => openDlManual('kernel');
  $('btn-activate-sub').onclick = async () => {
    try {
      await invoke('activate_subscription_feature', { enabled: true });
      applySubFeature(true);
      toast(AgI18n.t('sub.featureActivated'), 'ok');
      switchView('subscription');
    } catch (err) { toast(friendlyError(err), 'err'); }
  };
  $('btn-deactivate-sub').onclick = async () => {
    try {
      await invoke('activate_subscription_feature', { enabled: false });
      applySubFeature(false);
      toast(AgI18n.t('sub.featureDeactivated'), 'ok');
    } catch (err) { toast(friendlyError(err), 'err'); }
  };
}

/* ================= TUN mode (anet in front, FlClash behind; Windows x64, admin required) =================
   State polled from backend tun_status (inside the 10s main poll); all rendering via change detection (setText/sig dedup);
   toggle/upstream address/elevation modal events bound explicitly, no inline handlers. */
let TUN_ON = false;
let TUN_SUPPORTED = true;
let TUN_UPSTREAM = '127.0.0.1:7890';

function warnTunUpstream(st) {
  if (st && st.upstream_ok === false) {
    toast(AgI18n.t('tun.upstreamUnreachable', { addr: st.upstream }), 'err');
  }
}

function applyTunStatus(st) {
  TUN_ON = !!st.enabled;
  if (window._rolesCache) window._rolesCache.tun_mode = TUN_ON; // Hero current-mode summary sync (one place covers onchange/retry/10s poll)
  TUN_SUPPORTED = !!st.supported;
  if (st.upstream) TUN_UPSTREAM = st.upstream;
  // one-shot give-up notice (insufficient privilege/start failure fell back to normal mode; backend clears on read, toast once only)
  if (st.notice) toast(st.notice, 'err');
  const toggle = $('tun-mode');
  toggle.checked = TUN_ON;
  toggle.disabled = !TUN_SUPPORTED;
  setText('tun-status-text', !TUN_SUPPORTED ? AgI18n.t('sub.unsupported') : (TUN_ON ? (st.running ? AgI18n.t('common.running') : AgI18n.t('tun.kernelNotRunning')) : AgI18n.t('sub.notEnabled')));
  // state line: running / insufficient privilege / upstream unreachable
  let stateTxt = '-';
  if (!TUN_SUPPORTED) stateTxt = AgI18n.t('tun.onlyWin64');
  else if (TUN_ON) {
    if (!st.admin) stateTxt = AgI18n.t('tun.needAdmin');
    else if (st.upstream_ok === false) stateTxt = AgI18n.t('tun.upstreamBad');
    else if (st.running) stateTxt = AgI18n.t('tun.runningManaged');
    else stateTxt = AgI18n.t('tun.kernelNotRunning');
  }
  setText('tun-state', stateTxt);
  // mutual exclusion (§2.5): outbound mode pinned to rule under TUN (global/direct would bypass anet routing)
  const modeSel = $('sub-mode');
  if (modeSel.disabled !== TUN_ON) { modeSel.disabled = TUN_ON; agSelectRefresh(modeSel); }
  // Dynamic Island alert for unreachable upstream (sig dedup: same address toasts once, resets after recovery)
  if (TUN_ON && st.upstream_ok === false && window._tunWarnSig !== st.upstream) {
    window._tunWarnSig = st.upstream;
    warnTunUpstream(st);
  }
  if (!(TUN_ON && st.upstream_ok === false)) window._tunWarnSig = '';
}

async function refreshTun() {
  let st;
  try { st = await invoke('tun_status'); } catch (e) { return; }
  applyTunStatus(st);
}

function openTunElevateModal() {
  $('tun-elevate-err').textContent = '';
  $('tun-elevate-modal').style.display = 'flex';
}

function initTun() {
  /* TUN toggle: non-admin → backend returns NEED_ELEVATION, show elevation dialog (not a plain toast) */
  $('tun-mode').onchange = async (e) => {
    const on = e.target.checked;
    const el = e.target;
    el.disabled = true;
    try {
      const st = await invoke('set_tun_mode', { enabled: on });
      applyTunStatus(st);
      if (on) {
        toast(AgI18n.t('tun.onToast'), 'ok');
        warnTunUpstream(st);
      } else {
        toast(AgI18n.t('tun.offToast'), 'ok');
      }
    } catch (err) {
      el.checked = !on;
      if (String(err).indexOf('NEED_ELEVATION:') === 0) openTunElevateModal();
      else if (on && String(err).indexOf('NEED_DOWNLOAD:') === 0) {
        /* kernel/wintun not installed: backend already auto-started download; auto-retry enabling TUN after done */
        handleNeedDownload(async () => {
          try {
            const st2 = await invoke('set_tun_mode', { enabled: true });
            applyTunStatus(st2);
            toast(AgI18n.t('tun.onToast'), 'ok');
            warnTunUpstream(st2);
          } catch (e2) { toast(friendlyError(e2), 'err'); refreshTun(); }
        });
      }
      else toast(friendlyError(err), 'err');
    } finally {
      el.disabled = !TUN_SUPPORTED;
    }
  };

  /* External upstream address (agedit inline edit; backend strict validation: loopback only, ports 57890/57892/59292 forbidden) */
  bindInlineEdit($('tun-upstream'), {
    get: () => TUN_UPSTREAM,
    validate: (v) => /^\S+:\d+$/.test(v) ? null : AgI18n.t('tun.addrFormat'),
    set: async (v) => {
      const st = await invoke('set_tun_upstream', { addr: v });
      TUN_UPSTREAM = v;
      applyTunStatus(st);
      toast(AgI18n.t('tun.upstreamSaved'), 'ok');
      warnTunUpstream(st);
    },
  });

  /* Elevation modal: confirm → runas relaunch (process exits, nothing after); cancel → audit declined */
  $('tun-elevate-cancel').onclick = async () => {
    $('tun-elevate-modal').style.display = 'none';
    try { await invoke('tun_elevation_declined'); } catch (e) {}
  };
  $('tun-elevate-ok').onclick = async (e) => {
    const btn = e.target.closest('button');
    btn.disabled = true;
    try {
      await invoke('tun_relaunch_elevated');
    } catch (err) {
      btn.disabled = false;
      $('tun-elevate-err').textContent = friendlyError(err);
    }
  };
}

/* ================= Artifact download management (mihomo kernel / wintun; progress card + manual install + hash confirm) =================
   Backend dl_state 2s poll (same slot as SubTraffic); state machine idle/downloading/done/failed.
   Enable action hitting NEED_DOWNLOAD: backend already auto-started download, frontend shows download card and records the original action,
   auto-retries once on done; failed left to user decision (retry/manual install/cancel). All rendering via sig change detection. */
const DL_LABEL = { kernel: 'sub.dlKernel', wintun: 'sub.dlWintun' };
function dlLabel(a) { return DL_LABEL[a] ? AgI18n.t(DL_LABEL[a]) : a; }
/* Official download pages (pinned versions see subscription.rs MIHOMO_VERSION / WINTUN_VERSION, keep in sync on upgrade) */
const DL_OFFICIAL = {
  kernel: 'https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.29',
  wintun: 'https://www.wintun.net/',
};
let _dlSig = '';       // render sig (change detection)
let _dlRetry = null;   // original enable action to auto-retry after download/manual install completes
let _dlDoneSeen = '';  // consumed done sig (prevents duplicate retry)
let _dlManualArtifact = 'kernel';

async function pollDl() {
  if (HTTP_MODE) return;
  let st;
  try { st = await invoke('dl_state'); } catch (e) { return; }
  renderDlCard(st);
  if (st.phase === 'downloading') _dlDoneSeen = ''; // new download round started, reset done-consumed mark
  if (st.phase === 'done') {
    const sig = 'done:' + st.artifact;
    if (_dlDoneSeen !== sig) {
      _dlDoneSeen = sig;
      toast(AgI18n.t('sub.dlDone', { name: dlLabel(st.artifact) }), 'ok');
      const retry = _dlRetry; _dlRetry = null;
      if (retry) retry();
    }
  }
}

function renderDlCard(st) {
  const card = $('dl-card');
  if (!card) return;
  const show = st.phase === 'downloading' || st.phase === 'failed';
  if (!show) {
    if (card.style.display !== 'none') { card.style.display = 'none'; _dlSig = ''; }
    return;
  }
  const sig = JSON.stringify(st);
  if (sig === _dlSig) return; // change detection: progress unchanged, skip redraw
  _dlSig = sig;
  card.style.display = '';
  const label = dlLabel(st.artifact);
  const downloading = st.phase === 'downloading';
  setText('dl-title', downloading ? AgI18n.t('sub.dlDownloading', { name: label }) : AgI18n.t('sub.dlFailed', { name: label }));
  $('dl-cancel-x').style.display = downloading ? '' : 'none';
  const bar = $('dl-progress').firstElementChild;
  if (downloading) {
    const pct = st.total ? Math.min(100, st.downloaded / st.total * 100) : 0;
    bar.style.width = pct.toFixed(1) + '%';
    const sizeTxt = st.total
      ? fmtBytes(st.downloaded) + ' / ' + fmtBytes(st.total) + '（' + pct.toFixed(0) + '%）'
      : AgI18n.t('sub.dlSizeUnknown', { size: fmtBytes(st.downloaded) });
    setText('dl-detail', sizeTxt + ' · ' + (st.mirror || AgI18n.t('sub.dlConnecting')));
  } else {
    bar.style.width = '0%';
    setText('dl-detail', AgI18n.t('sub.dlFailHint'));
  }
  $('dl-err').style.display = downloading ? 'none' : '';
  setText('dl-err', downloading ? '' : (st.reason || AgI18n.t('sub.dlFail')));
  $('dl-actions').style.display = downloading ? 'none' : 'flex';
  if (!downloading) $('dl-manual').dataset.artifact = st.artifact;
}

/* Enable action hits NEED_DOWNLOAD: toast + jump to subscription page to show download card + register auto-retry on completion */
function handleNeedDownload(retry) {
  _dlRetry = retry;
  toast(AgI18n.t('sub.dlAutoStart'), 'ok');
  switchView('subscription');
  pollDl();
}

function openDlManual(artifact) {
  _dlManualArtifact = artifact;
  const k = artifact === 'kernel';
  setText('dl-manual-title', AgI18n.t('sub.dlManualTitle', { name: dlLabel(artifact) }));
  setText('dl-manual-hint', AgI18n.t(k ? 'sub.dlManualHintKernel' : 'sub.dlManualHintWintun'));
  const inp = $('dl-manual-path');
  inp.value = '';
  inp.placeholder = AgI18n.t(k ? 'sub.dlManualPhKernel' : 'sub.dlManualPhWintun');
  $('dl-manual-err').textContent = '';
  $('dl-manual-modal').style.display = 'flex';
  inp.focus();
}

async function submitDlManual(allowMismatch) {
  const path = $('dl-manual-path').value.trim();
  if (!path) { $('dl-manual-err').textContent = AgI18n.t('sub.dlPathRequired'); return; }
  const btn = $('dl-manual-ok');
  btn.disabled = true;
  $('dl-manual-err').textContent = '';
  try {
    const res = await invoke('dl_install_manual', { artifact: _dlManualArtifact, path, allowMismatch: !!allowMismatch });
    if (res.result === 'installed') {
      $('dl-manual-modal').style.display = 'none';
      $('dl-mismatch-modal').style.display = 'none';
      toast(AgI18n.t('sub.dlInstalled', { name: DL_LABEL[_dlManualArtifact] ? AgI18n.t(DL_LABEL[_dlManualArtifact]) : AgI18n.t('sub.dlArtifact') }), 'ok');
      refreshSubFeature(); refreshSubStatus();
      const retry = _dlRetry; _dlRetry = null;
      if (retry) retry();
    } else if (res.result === 'hash_mismatch') {
      // pinned version/hash mismatch or unverifiable: state risk explicitly, force-install only after user confirms
      setText('dl-mm-version', res.expect_version || '-');
      setText('dl-mm-hash', (res.actual_hash || '').slice(0, 12) + '…');
      $('dl-mismatch-modal').style.display = 'flex';
    }
  } catch (err) {
    $('dl-manual-err').textContent = friendlyError(err);
  } finally {
    btn.disabled = false;
  }
}

function initDl() {
  /* Download card: cancel (while downloading) / retry / manual install / cancel (give up after failure) */
  $('dl-cancel-x').onclick = async () => {
    _dlRetry = null;
    try { await invoke('dl_cancel'); } catch (e) {}
    pollDl();
  };
  $('dl-retry').onclick = async () => {
    const artifact = $('dl-manual').dataset.artifact || 'kernel';
    try { await invoke('dl_start', { artifact }); pollDl(); }
    catch (err) { toast(friendlyError(err), 'err'); }
  };
  $('dl-manual').onclick = () => openDlManual($('dl-manual').dataset.artifact || 'kernel');
  $('dl-dismiss').onclick = async () => {
    _dlRetry = null;
    try { await invoke('dl_cancel'); } catch (e) {}
    pollDl();
  };
  /* Manual install modal */
  $('dl-manual-cancel').onclick = () => { $('dl-manual-modal').style.display = 'none'; };
  $('dl-manual-open').onclick = () => { invoke('open_url', { url: DL_OFFICIAL[_dlManualArtifact] }).catch(() => {}); };
  $('dl-manual-path').addEventListener('keydown', e => { if (e.key === 'Enter') $('dl-manual-ok').click(); });
  $('dl-manual-ok').onclick = () => submitDlManual(false);
  /* Hash mismatch confirm modal: use anyway = re-invoke with allow_mismatch; give up = back to manual install modal */
  $('dl-mm-cancel').onclick = () => { $('dl-mismatch-modal').style.display = 'none'; };
  $('dl-mm-ok').onclick = () => submitDlManual(true);
}

/* ================= Drag-drop subscription import (Tauri window-level file drag; dropping .yaml/.yml on the window imports into the subscription list) =================
   Desktop only (HTTP_MODE/Android skip listeners); subscription list card dashed highlight while hovering (element.style + var token). */
function initSubDragImport() {
  if (!TAURI || !TAURI.event || /Android/i.test(navigator.userAgent)) return;
  const card = $('subs-list').closest('.card');
  const hot = (on) => {
    card.style.outline = on ? '2px dashed var(--accent)' : '';
    card.style.outlineOffset = on ? '-6px' : '';
  };
  TAURI.event.listen('tauri://drag-enter', () => hot(true));
  TAURI.event.listen('tauri://drag-over', () => hot(true));
  TAURI.event.listen('tauri://drag-leave', () => hot(false));
  TAURI.event.listen('tauri://drag-drop', async (e) => {
    hot(false);
    const paths = (e.payload && e.payload.paths) || [];
    const p = paths.find(x => /\.(yaml|yml)$/i.test(x));
    if (!p) { toast(AgI18n.t('sub.dragHintToast'), 'err'); return; }
    try {
      const sub = await invoke('import_local_subscription', { path: p });
      toast(AgI18n.t('sub.imported', { n: sub.node_count }), 'ok');
      refreshSubs();
    } catch (err) { toast(friendlyError(err), 'err'); }
  });
}

/* i18n: force re-render of this domain on language switch (sigs cleared, so change detection can't block old-language copy) */
AgI18n.onChange(() => {
  _testUiKey = ''; _dlSig = '';
  const tabs = $('group-tabs'); if (tabs) tabs.dataset.sig = '';
  const grid = $('node-grid'); if (grid) grid.dataset.sig = '';
  const sl = $('scripts-list'); if (sl) sl.dataset.sig = '';
  refreshSubs(); refreshSubStatus(); refreshSubScripts(); refreshSubFeature(); refreshTun(); pollDl();
});
