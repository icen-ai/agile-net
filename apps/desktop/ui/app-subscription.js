'use strict';
/* 从 app.js 拆分：订阅代理 / 节点页 / 覆写脚本 / TUN / 制品下载 / 拖拽导入（纯搬运，零逻辑变更） */

/* ================= 订阅代理（mihomo sidecar） ================= */
let SUBS = [];
let PROXY_DATA = null;
let PROXY_CACHED = false; // true = 内核未运行，展示缓存快照（只读）
let CUR_GROUP = null;
/* 「每日选妃」测速状态：DELAY_CACHE group -> Map(node -> ms，0=超时)，只就地刷徽标不触发整组重渲染；
   TESTING 进行中的组（按钮禁用防重复点击）；TEST_ALL_ON 串行全部测速中 */
const DELAY_CACHE = new Map();
const TESTING = new Set();
let TEST_ALL_ON = false;
function getSortMode(g) { return localStorage.getItem('ag_sort_' + g) || 'default'; } // 每组记忆排序方式

/* 仪表盘订阅卡：激活订阅 + 节点数 + 当前节点延迟（PROXY_DATA 就绪后补充） */
function updateDashSub() {
  const active = SUBS.find(s => s.active);
  let val, sub;
  if (active) {
    val = active.name;
    sub = active.node_count + ' 节点 · 共 ' + SUBS.length + ' 个订阅';
    const g = PROXY_DATA && CUR_GROUP && PROXY_DATA[CUR_GROUP];
    if (g && g.now) {
      const p = PROXY_DATA[g.now] || {};
      const hist = (p.history && p.history.length) ? p.history[p.history.length - 1].delay : 0;
      sub += ' · 当前 ' + g.now + (hist ? ' ' + hist + 'ms' : '');
    }
  } else {
    val = SUBS.length ? SUBS.length + ' 个订阅' : '未添加订阅';
    sub = SUBS.length ? '未激活，点卡片进订阅页激活' : '点卡片进订阅页添加';
  }
  setText('d-sub-val', val);
  setText('d-sub-sub', sub);
}

function fmtDate(ts) { return ts ? new Date(ts * 1000).toLocaleDateString() : ''; }

async function refreshSubs() {
  try { SUBS = await invoke('list_subscriptions'); } catch (e) { SUBS = []; }
  const list = $('subs-list');
  const active = SUBS.find(s => s.active);
  $('proxy-sub-desc').textContent = active
    ? '当前激活：' + active.name + '（' + active.node_count + ' 节点）— 点击卡片切换，「测速」批量测延迟'
    : '请先在「订阅」页激活一个订阅';
  updateDashSub();
  if (!SUBS.length) {
    list.innerHTML = '<div class="empty">尚未添加订阅</div>';
    return;
  }
  list.innerHTML = SUBS.map(s => {
    const used = (s.upload || 0) + (s.download || 0);
    const pct = s.total ? Math.min(100, used / s.total * 100) : 0;
    const cls = pct >= 95 ? 'full' : pct >= 80 ? 'warn' : '';
    const traffic = s.total ? fmtBytes(used) + ' / ' + fmtBytes(s.total) : fmtBytes(used) + ' 已用';
    const expire = s.expire ? ' · ' + fmtDate(s.expire) : (s.total ? ' · 长期有效' : '');
    return '<div class="sub-card' + (s.active ? ' active' : '') + '" data-sub-activate="' + esc(s.id) + '">' +
      '<div class="sub-card-top"><span class="sub-card-title" title="' + esc(s.name) + '">' + esc(s.name) + '</span>' +
      (s.active ? '<span class="sub-badge">使用中</span>' : '') +
      '<span class="sub-card-actions">' +
      '<button class="ghost small icon-btn" data-sub-update="' + esc(s.id) + '" title="刷新订阅">' + AgIcon('refresh-cw', 13) + '</button>' +
      '<button class="ghost small icon-btn" data-sub-del="' + esc(s.id) + '" title="删除">' + AgIcon('trash-2', 13) + '</button>' +
      '</span></div>' +
      '<div class="sub-progress"><i class="' + cls + '" style="width:' + pct.toFixed(1) + '%"></i></div>' +
      '<div class="sub-card-meta">' + traffic + expire + '</div>' +
      '<div class="sub-card-sub">' + fmtAgo(s.updated_at) + '更新 · ' + s.node_count + ' 节点</div>' +
      '</div>';
  }).join('');
}

async function refreshSubStatus() {
  let st;
  try { st = await invoke('subscription_status'); } catch (e) { return; }
  $('sub-status-text').textContent = st.running
    ? '运行中'
    : (st.installed ? '已安装，未运行' : (st.supported ? '未开启' : '当前平台不支持'));
  $('sub-version').textContent = st.version || (st.installed ? '已安装' : '-');
  $('r-sub').checked = st.running;
  // 仪表盘订阅卡开关与徽标同步（与订阅页内核开关同一角色）
  const d = $('d-sub');
  if (d) d.checked = st.running;
  setHtml('d-sub-badge', st.running ? '<span class="badge b-ok">运行中</span>' : '<span class="badge b-gray">未运行</span>');
  // 覆写脚本失败告警（签名去重：同一组失败只弹一次，恢复后重置）
  const se = st.script_errors || [];
  const seSig = JSON.stringify(se);
  if (se.length && window._scriptErrSig !== seSig) {
    toast('覆写脚本「' + se[0][0] + '」执行失败已跳过：' + se[0][1], 'err');
  }
  window._scriptErrSig = se.length ? seSig : '';
  // 内核状态翻转：出口路径随之变化，立刻重探出口 IP（经 mihomo ↔ 直连）
  if (window._subRunning !== st.running) {
    window._subRunning = st.running;
    NetProbe.refresh();
  }
  NetProbe.render();
  // 侧栏底部速率区随内核运行态翻转（运行↔未运行）
  renderSideFoot();
  Hero.onTraffic(); // 英雄卡曲线/读数同步翻转（sub_traffic 报错时此处兜底切空态）
  // 无论内核是否运行都刷新代理页（未运行时回落缓存快照，方便查看节点情况）
  refreshGroups();
}

/* ---------- 订阅内核流量（后端 /traffic WS 单任务累计，前端 2s 轮询同一数据源） ----------
   订阅页内核卡与首页订阅卡共用本模块序列，不另起轮询；
   速率序列照 trackFaninTraffic 的 delta 保护：累计倒退 = 内核重启清零，按新基准。 */
const SubTraffic = {
  data: null, _last: null, _lastUp: null, _lastDown: null, series: [], rates: { up: 0, down: 0 }, _sig: '',
  async poll() {
    if (HTTP_MODE) return;
    let t;
    try { t = await invoke('sub_traffic'); } catch (e) { return; }
    const total = t.up_total + t.down_total;
    if (this._last !== null) {
      let delta = total - this._last;
      if (delta < 0) delta = total;
      this.series.push(delta);
      if (this.series.length > 90) this.series.shift();
    }
    this._last = total;
    // 分向速率（2s 轮询差分供侧栏底部；内核重启计数归零 → 负差钳 0，速率不造假）
    const dUp = this._lastUp === null ? 0 : Math.max(0, t.up_total - this._lastUp);
    const dDown = this._lastDown === null ? 0 : Math.max(0, t.down_total - this._lastDown);
    this._lastUp = t.up_total;
    this._lastDown = t.down_total;
    this.rates = { up: Math.round(dUp / 2), down: Math.round(dDown / 2) };
    this.data = t;
    this.render();
    renderSideFoot();
    Hero.onTraffic(); // 中控台英雄卡：速率缓冲/曲线/今日已用（同一 2s 数据源，不另起轮询）
  },
  render() {
    const t = this.data, show = !!window._subRunning && !!t;
    // 显隐先行（不受变更检测拦截）
    const row = $('sub-traffic-row'), spark = $('sub-spark');
    const dtf = $('d-sub-tf'), dspark = $('d-sub-spark');
    [row, spark, dtf, dspark].forEach(el => { if (el) el.style.display = show ? '' : 'none'; });
    const sig = show ? (t.up_total + '/' + t.down_total) : 'off';
    if (sig === this._sig) return; // 变更检测：总量未变不重绘
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

/* ---------- 代理页（「每日选妃」：组批量测速流式刷徽标 + 延迟排序 + 推荐徽标） ----------
   渲染纪律：group-tabs / node-grid 均签名对比，数据不变不重绘（refreshSubStatus 10s 轮询会调进来）；
   测速结果只写 DELAY_CACHE 并就地刷 .lat 徽标（text/class），不触发整组重渲染；
   阶梯收尾后 reconcile 一次，应用延迟排序与「推荐」徽标。 */
const GROUP_LABELS = { 'AGILE-SUB': '订阅节点' }; // 技术名 → 友好名；mihomo 内置 GLOBAL 组隐藏
function proxyGroupList() {
  return Object.entries(PROXY_DATA || {}).filter(([n, p]) =>
    n !== 'GLOBAL' && p.all && ['Selector', 'URLTest', 'Fallback'].includes(p.type));
}
/* 节点有效延迟：测速缓存优先（0=超时）；URLTest/Fallback 组回落 mihomo history 最近值；null=未测速 */
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
// 延迟分档：<300ms good / <800ms mid / 其余 bad；0（超时）与 null（未测速）均为 na
function latCls(ms) { return ms < 300 ? 'lat-good' : ms < 800 ? 'lat-mid' : 'lat-bad'; }
function latHtml(ms) {
  if (typeof ms === 'number' && ms > 0)
    return '<span class="lat ' + latCls(ms) + '" style="margin-left:auto">' + ms + ' ms</span>';
  return '<span class="lat lat-na" style="margin-left:auto">' + (ms === null ? '—' : '超时') + '</span>';
}
/* 「推荐」徽标：测速后延迟最低且 <500ms 的节点（Tailscale 式替用户决策） */
function bestNode(group) {
  const m = DELAY_CACHE.get(group);
  let best = null, bestMs = 500;
  if (m) m.forEach((ms, name) => { if (ms > 0 && ms < bestMs) { best = name; bestMs = ms; } });
  return best;
}
/* 按延迟排序：有有效延迟的升序在前，无数据/超时保持原顺序在后（下标 tiebreak 保稳定）；当前选中顺其自然 */
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

/* 空态与降级：内核未运行（「去开启」跳订阅视图，HTTP_MODE 无此入口）/ 无代理组 */
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
        '<div class="empty-t">订阅内核未运行</div>' +
        '<div class="empty-d">开启订阅代理角色后，这里会列出可切换的节点</div>' +
        (HTTP_MODE ? '' : '<button class="small" data-goto-sub>去开启</button>') + '</div>'
      : '<div class="empty-state" style="grid-column:1/-1">' + AgIcon('orbit', 36) +
        '<div class="empty-t">暂无代理组，检查订阅配置</div>' +
        '<div class="empty-d">订阅可能未包含节点，或尚未刷新成功</div></div>';
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
  // 组页签签名对比：组集合与当前组不变不重绘
  const tabs = $('group-tabs');
  const tabSig = JSON.stringify([groups.map(([n]) => n), CUR_GROUP]);
  if (tabs.dataset.sig !== tabSig) {
    tabs.dataset.sig = tabSig;
    tabs.innerHTML = groups.map(([n]) =>
      '<button class="group-tab' + (n === CUR_GROUP ? ' active' : '') + '" data-group-tab="' + esc(n) + '">' + esc(GROUP_LABELS[n] || n) + '</button>'
    ).join('');
  }
  // 缓存态：只读展示，覆盖说明文案（正常态文案由 refreshSubs 维护）
  if (PROXY_CACHED) setText('proxy-sub-desc', '订阅内核未运行，以下为最近缓存节点（测速与切换不可用）');
  syncSortTabs();
  syncTestUI();
  renderNodeGrid();
  updateDashSub();
}

function renderNodeGrid(force) {
  const g = PROXY_DATA && PROXY_DATA[CUR_GROUP];
  if (!g) return;
  const grid = $('node-grid');
  // 签名对比：代理数据/排序方式不变不重绘（测速徽标就地单独刷，10s 轮询不打断流式写入）
  const sig = JSON.stringify([CUR_GROUP, g.type, g.now, g.all, PROXY_CACHED, getSortMode(CUR_GROUP)]);
  if (!force && grid.dataset.sig === sig) return;
  grid.dataset.sig = sig;
  const best = bestNode(CUR_GROUP);
  grid.innerHTML = sortedNodes(CUR_GROUP).map(n => {
    const p = PROXY_DATA[n] || {};
    const cur = g.now === n;
    return '<div class="snode-card' + (cur ? ' current' : '') + '" data-group="' + esc(CUR_GROUP) + '" data-node="' + esc(n) + '">' +
      '<div class="node-name">' + (cur ? '<span class="node-check">' + AgIcon('check', 11) + '</span>' : '') +
      (best === n ? '<span class="pill pill-ok">推荐</span>' : '') +
      '<span class="node-name-text" title="' + esc(n) + '">' + esc(n) + '</span></div>' +
      '<div class="node-foot" style="padding-right:0"><span class="node-proto">' + esc(p.type || '') + '</span>' +
      latHtml(delayOf(CUR_GROUP, n)) +
      '</div></div>';
  }).join('');
}

/* 只刷徽标不重渲染：'…' 加载态 / null 未测速（—）/ 0 超时 / >0 有效延迟 */
function writeLat(card, ms) {
  const el = card.querySelector('.lat');
  if (!el) return;
  if (ms === '…') { el.textContent = '…'; el.className = 'lat lat-na'; return; }
  if (typeof ms === 'number' && ms > 0) { el.textContent = ms + ' ms'; el.className = 'lat ' + latCls(ms); return; }
  el.textContent = ms === null ? '—' : '超时';
  el.className = 'lat lat-na';
}
function groupCards(group) {
  return [...$('node-grid').querySelectorAll('.snode-card')].filter(c => c.dataset.group === group);
}

/* 测速按钮态：HTTP_MODE（CMD_MAP 无此命令）与缓存态隐藏；进行中禁用 + 转圈（防重复点击，竞品投诉教训） */
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
  bGrp.innerHTML = grpBusy ? '<span class="spinner"></span>测速中' : AgIcon('zap', 13) + '测速';
  bAll.innerHTML = TEST_ALL_ON ? '<span class="spinner"></span>测速中…' : AgIcon('gauge', 14) + '全部测速';
}
function syncSortTabs() {
  const cur = getSortMode(CUR_GROUP);
  document.querySelectorAll('#sort-tabs .agtab').forEach(t => t.classList.toggle('active', t.dataset.sort === cur));
}

/* 组批量测速（sub_test_group：delay=0 表超时，返回已按有效延迟升序、0 排尾）：
   点击即把全组徽标置「…」加载态；结果按返回顺序 30ms 阶梯写入，模拟流式逐行刷新
   （mihomo 一次性返回，前端做出逐行感）；失败回滚徽标为缓存/历史值，不整组重渲染。 */
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
  // 阶梯收尾后 reconcile 一次：应用延迟排序与「推荐」徽标（当前组仍在展示时）
  setTimeout(() => { if (CUR_GROUP === group && PROXY_DATA && PROXY_DATA[group]) renderNodeGrid(true); }, results.length * 30 + 60);
  return true;
}

/* 全部测速：串行遍历所有组（避免并发打爆内核），任一组失败即中止；进行中按钮转圈禁用 */
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

/* ---------- 覆写脚本（JS：main(config) 管线；拖拽排序 + 独立开关 + 试跑） ---------- */
let SUB_SCRIPTS = [];
let SCRIPT_EDIT_ID = null; // null = 新建
let SCRIPT_DRAG_ID = null;
const SCRIPT_TEMPLATE = `const main = (config) => {
  // config 为订阅生成的内核配置对象，修改后返回
  config.proxies = config.proxies || [];
  config.proxies.push({
    name: "自建", type: "ss",
    server: "example.com", port: 8388,
    cipher: "aes-128-gcm", password: "密码"
  });
  config.rules = config.rules || [];
  config.rules.unshift("DOMAIN-SUFFIX,example.com,自建");
  return config;
};`;

async function refreshSubScripts() {
  try { SUB_SCRIPTS = await invoke('list_sub_scripts'); } catch (e) { SUB_SCRIPTS = []; }
  const sig = JSON.stringify(SUB_SCRIPTS.map(s => [s.id, s.name, s.enabled, s.order]));
  const list = $('scripts-list');
  if (!SUB_SCRIPTS.length) {
    if (list.dataset.sig !== 'empty') { list.dataset.sig = 'empty'; list.innerHTML = '<div class="empty">尚未添加脚本</div>'; }
    return;
  }
  if (list.dataset.sig === sig) return; // 变更检测：内容未变不重绘（避免拖拽中被轮询打断）
  list.dataset.sig = sig;
  list.innerHTML = SUB_SCRIPTS.map(s =>
    '<div class="script-row" draggable="true" data-script-row="' + esc(s.id) + '">' +
    '<span class="script-grip" title="拖拽排序">' + AgIcon('grip-vertical', 14) + '</span>' +
    '<span class="script-name" title="' + esc(s.name) + '">' + esc(s.name) + '</span>' +
    '<span class="script-state">' + (s.enabled ? '' : '已停用') + '</span>' +
    '<label class="switch"><input type="checkbox" data-script-toggle="' + esc(s.id) + '"' + (s.enabled ? ' checked' : '') + '><span class="slider"></span></label>' +
    '<button class="ghost small icon-btn" data-script-edit="' + esc(s.id) + '" title="编辑">' + AgIcon('pencil', 13) + '</button>' +
    '<button class="ghost small icon-btn" data-script-del="' + esc(s.id) + '" title="删除">' + AgIcon('trash-2', 13) + '</button>' +
    '</div>'
  ).join('');
}

function openScriptModal(id) {
  const sc = id ? SUB_SCRIPTS.find(s => s.id === id) : null;
  SCRIPT_EDIT_ID = sc ? sc.id : null;
  $('script-modal-title').textContent = sc ? '编辑脚本' : '新建脚本';
  $('script-name').value = sc ? sc.name : '';
  $('script-code').value = sc ? sc.code : SCRIPT_TEMPLATE;
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
    $('script-test-result').textContent = '试跑中…';
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
    if (!code.trim()) { $('script-err').textContent = '脚本代码不能为空'; return; }
    const btn = $('script-ok');
    btn.disabled = true;
    $('script-err').textContent = '';
    try {
      if (SCRIPT_EDIT_ID) {
        await invoke('update_sub_script', { id: SCRIPT_EDIT_ID, name, code });
        toast('脚本已保存', 'ok');
      } else {
        await invoke('add_sub_script', { name, code });
        toast('脚本已创建', 'ok');
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
          toast('脚本已删除', 'ok');
          refreshSubScripts();
          return;
        }
        btn.dataset.confirm = '1';
        const old = btn.innerHTML;
        btn.innerHTML = '<span style="font-size:11px">确认</span>';
        setTimeout(() => { if (btn.isConnected) { btn.dataset.confirm = ''; btn.innerHTML = old; } }, 2500);
      }
    } catch (err) { toast(friendlyError(err), 'err'); }
  });
  list.addEventListener('change', async (e) => {
    const cb = e.target.closest('input[data-script-toggle]');
    if (!cb) return;
    try {
      await invoke('set_sub_script_enabled', { id: cb.dataset.scriptToggle, enabled: cb.checked });
      toast(cb.checked ? '脚本已启用' : '脚本已停用', 'ok');
      refreshSubScripts();
    } catch (err) { cb.checked = !cb.checked; toast(friendlyError(err), 'err'); }
  });
  /* HTML5 拖拽排序：drop 后按新顺序提交 reorder 命令 */
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
    e.preventDefault(); // 必须 preventDefault 才允许 drop
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
    try { $('sub-url').value = await navigator.clipboard.readText(); } catch (e) { toast('无法读取剪贴板', 'err'); }
  };
  $('sub-url').addEventListener('keydown', e => { if (e.key === 'Enter') $('sub-ok').click(); });
  $('sub-ok').onclick = async () => {
    const url = $('sub-url').value.trim();
    if (!url) { $('sub-err').textContent = '请粘贴订阅地址'; return; }
    const btn = $('sub-ok');
    btn.disabled = true;
    btn.textContent = '拉取校验中…';
    $('sub-err').textContent = '';
    try {
      const sub = await invoke('add_subscription', { name: $('sub-name').value.trim(), url });
      $('sub-modal').style.display = 'none';
      toast('订阅已添加（' + sub.node_count + ' 节点）', 'ok');
      refreshSubs();
    } catch (err) {
      $('sub-err').textContent = friendlyError(err);
    } finally {
      btn.disabled = false;
      btn.textContent = '拉取并添加';
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
          toast('订阅已刷新（' + sub.node_count + ' 节点）', 'ok');
          refreshSubs(); refreshGroups();
        } else if (btn.dataset.subDel) {
          if (btn.dataset.confirm === '1') {
            await invoke('remove_subscription', { id: btn.dataset.subDel });
            toast('订阅已删除', 'ok');
            refreshSubs(); refreshSubStatus();
            return;
          }
          btn.dataset.confirm = '1';
          const old = btn.innerHTML;
          btn.innerHTML = '<span style="font-size:11px">确认</span>';
          setTimeout(() => { if (btn.isConnected) { btn.dataset.confirm = ''; btn.innerHTML = old; } }, 2500);
        }
      } catch (err) { toast(friendlyError(err), 'err'); btn.disabled = false; }
      return;
    }
    // 卡片主体点击 = 单选激活
    const card = e.target.closest('[data-sub-activate]');
    if (card && !card.classList.contains('active')) {
      try {
        const sub = await invoke('set_active_subscription', { id: card.dataset.subActivate });
        toast('已激活 ' + sub.name, 'ok');
        refreshSubs(); refreshSubStatus();
      } catch (err) { toast(friendlyError(err), 'err'); }
    }
  });

  /* 内核角色开关（订阅页 r-sub 与仪表盘 d-sub 双入口同一逻辑，checked 由 refreshSubStatus 统一同步） */
  const subToggle = async (e) => {
    const on = e.target.checked;
    const el = e.target;
    el.disabled = true;
    try {
      if (on && !SUBS.length) {
        el.checked = false;
        toast('请先添加订阅', 'err');
        openSubModal();
        return;
      }
      await invoke('set_subscription_role', { enabled: on });
      toast(on ? '订阅代理已开启（内核运行中）' : '订阅代理已关闭', 'ok');
      refreshSubStatus();
    } catch (err) {
      el.checked = !on;
      if (on && String(err).indexOf('NEED_DOWNLOAD:') === 0) {
        /* 内核未安装：后端已自动开始下载；done 后自动重试开启 */
        handleNeedDownload(async () => {
          try {
            await invoke('set_subscription_role', { enabled: true });
            toast('订阅代理已开启（内核运行中）', 'ok');
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
  /* 出站模式：切换即持久化，内核运行中控制器热切（后端 PATCH /configs） */
  $('sub-mode').onchange = async (e) => {
    const prev = e.target.dataset.prev || 'rule';
    try {
      await invoke('set_sub_mode', { mode: e.target.value });
      e.target.dataset.prev = e.target.value;
      if (window._rolesCache) window._rolesCache.sub_mode = e.target.value;
      const label = { rule: '规则', global: '全局', direct: '直连' }[e.target.value] || e.target.value;
      toast('出站模式已切换为 ' + label, 'ok');
    } catch (err) {
      e.target.value = prev;
      agSelectRefresh(e.target);
      toast(friendlyError(err), 'err');
    }
  };
  initSubScripts();

  /* 代理页事件 */
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
    if (PROXY_CACHED) { toast('订阅内核未运行，仅展示缓存节点', 'err'); return; }
    try {
      await invoke('select_proxy', { group: card.dataset.group, name: card.dataset.node });
      // 本地即时报选中态（含对勾搬迁）；g.now 同步后 10s 轮询签名自然触发重绘
      if (PROXY_DATA && PROXY_DATA[card.dataset.group]) PROXY_DATA[card.dataset.group].now = card.dataset.node;
      document.querySelectorAll('.snode-card').forEach(c => {
        c.classList.toggle('current', c === card);
        const chk = c.querySelector('.node-check');
        if (c === card && !chk) c.querySelector('.node-name').insertAdjacentHTML('afterbegin', '<span class="node-check">' + AgIcon('check', 11) + '</span>');
        if (c !== card && chk) chk.remove();
      });
      toast('已切换到 ' + card.dataset.node, 'ok');
    } catch (err) { toast(friendlyError(err), 'err'); }
  });
}

/* ---------- 订阅功能安装/激活（设置页） ---------- */
async function refreshSubFeature() {
  let st;
  try { st = await invoke('subscription_status'); } catch (e) { return; }
  const statusEl = $('sub-install-status');
  const installBtn = $('btn-install-kernel');
  if (!st.supported) {
    statusEl.textContent = '当前平台不支持';
    installBtn.disabled = true;
    $('btn-activate-sub').disabled = true;
    return;
  }
  statusEl.textContent = st.installed ? (st.version ? '已安装（' + st.version + '）' : '已安装') : '未安装';
  installBtn.innerHTML = AgIcon('download', 13) + (st.installed ? ' 重新下载内核' : ' 下载并安装内核');
  $('btn-activate-sub').disabled = !st.installed;
}
function initSubFeature() {
  /* 下载并安装内核：后端开始后台下载即返回；进度在订阅页下载卡展示，完成后刷新安装状态 */
  $('btn-install-kernel').onclick = async (e) => {
    const btn = e.target.closest('button');
    btn.disabled = true;
    try {
      await invoke('install_kernel');
      handleNeedDownload(() => { refreshSubFeature(); });
    } catch (err) { toast(friendlyError(err), 'err'); }
    finally { btn.disabled = false; }
  };
  /* 手动安装：用户自行下载官方文件，给完整路径，钉值校验通过才落盘 */
  $('btn-manual-kernel').onclick = () => openDlManual('kernel');
  $('btn-activate-sub').onclick = async () => {
    try {
      await invoke('activate_subscription_feature', { enabled: true });
      applySubFeature(true);
      toast('订阅功能已激活', 'ok');
      switchView('subscription');
    } catch (err) { toast(friendlyError(err), 'err'); }
  };
  $('btn-deactivate-sub').onclick = async () => {
    try {
      await invoke('activate_subscription_feature', { enabled: false });
      applySubFeature(false);
      toast('订阅功能已停用', 'ok');
    } catch (err) { toast(friendlyError(err), 'err'); }
  };
}

/* ================= TUN 模式（anet 在前 FlClash 在后；Windows x64，需管理员） =================
   状态由后端 tun_status 轮询（10s 主轮询内），渲染全部走变更检测（setText/签名去重）；
   开关/上游地址/提权弹窗事件显式绑定，无内联事件。 */
let TUN_ON = false;
let TUN_SUPPORTED = true;
let TUN_UPSTREAM = '127.0.0.1:7890';

function warnTunUpstream(st) {
  if (st && st.upstream_ok === false) {
    toast('外部上游 ' + st.upstream + ' 不可达：FlClash 未运行或端口不符，未命中流量将失败', 'err');
  }
}

function applyTunStatus(st) {
  TUN_ON = !!st.enabled;
  if (window._rolesCache) window._rolesCache.tun_mode = TUN_ON; // Hero 当前模式摘要同步（onchange/重试/10s 轮询一处覆盖）
  TUN_SUPPORTED = !!st.supported;
  if (st.upstream) TUN_UPSTREAM = st.upstream;
  // 放弃开启的一次性提示（权限不足/启动失败回退普通模式；后端读取即清除，仅弹一次）
  if (st.notice) toast(st.notice, 'err');
  const toggle = $('tun-mode');
  toggle.checked = TUN_ON;
  toggle.disabled = !TUN_SUPPORTED;
  setText('tun-status-text', !TUN_SUPPORTED ? '当前平台不支持' : (TUN_ON ? (st.running ? '运行中' : '内核未运行') : '未开启'));
  // 状态行：运行中 / 权限不足 / 上游不可达
  let stateTxt = '-';
  if (!TUN_SUPPORTED) stateTxt = 'TUN 仅支持 Windows x64';
  else if (TUN_ON) {
    if (!st.admin) stateTxt = '权限不足（需管理员）';
    else if (st.upstream_ok === false) stateTxt = '上游不可达（未命中流量将失败）';
    else if (st.running) stateTxt = '运行中（系统代理已托管 57890）';
    else stateTxt = '内核未运行';
  }
  setText('tun-state', stateTxt);
  // 互斥（§2.5）：TUN 下出站模式固定 rule（global/direct 会绕过 anet 分流）
  const modeSel = $('sub-mode');
  if (modeSel.disabled !== TUN_ON) { modeSel.disabled = TUN_ON; agSelectRefresh(modeSel); }
  // 上游不可达灵动岛告警（签名去重：同一地址只弹一次，恢复后重置）
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
  /* TUN 开关：非管理员 → 后端返回 NEED_ELEVATION，弹提权对话框（不直接 toast） */
  $('tun-mode').onchange = async (e) => {
    const on = e.target.checked;
    const el = e.target;
    el.disabled = true;
    try {
      const st = await invoke('set_tun_mode', { enabled: on });
      applyTunStatus(st);
      if (on) {
        toast('TUN 模式已开启（系统代理已托管 127.0.0.1:57890）', 'ok');
        warnTunUpstream(st);
      } else {
        toast('TUN 模式已关闭', 'ok');
      }
    } catch (err) {
      el.checked = !on;
      if (String(err).indexOf('NEED_ELEVATION:') === 0) openTunElevateModal();
      else if (on && String(err).indexOf('NEED_DOWNLOAD:') === 0) {
        /* 内核/wintun 未安装：后端已自动开始下载；done 后自动重试开启 TUN */
        handleNeedDownload(async () => {
          try {
            const st2 = await invoke('set_tun_mode', { enabled: true });
            applyTunStatus(st2);
            toast('TUN 模式已开启（系统代理已托管 127.0.0.1:57890）', 'ok');
            warnTunUpstream(st2);
          } catch (e2) { toast(friendlyError(e2), 'err'); refreshTun(); }
        });
      }
      else toast(friendlyError(err), 'err');
    } finally {
      el.disabled = !TUN_SUPPORTED;
    }
  };

  /* 外部上游地址（agedit 行内编辑；后端严格校验：仅回环，严禁 57890/57892/59292） */
  bindInlineEdit($('tun-upstream'), {
    get: () => TUN_UPSTREAM,
    validate: (v) => /^\S+:\d+$/.test(v) ? null : '地址格式应为 ip:port（如 127.0.0.1:7890）',
    set: async (v) => {
      const st = await invoke('set_tun_upstream', { addr: v });
      TUN_UPSTREAM = v;
      applyTunStatus(st);
      toast('外部上游已保存', 'ok');
      warnTunUpstream(st);
    },
  });

  /* 提权弹窗：确认 → runas 拉起重启（进程退出，无需后续）；取消 → 审计 declined */
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

/* ================= 制品下载管理（mihomo 内核 / wintun；进度卡 + 手动安装 + 哈希确认） =================
   后端 dl_state 2s 轮询（与 SubTraffic 同槽）；状态机 idle/downloading/done/failed。
   开启动作遇 NEED_DOWNLOAD：后端已自动开始下载，前端展示下载卡并记下原动作，
   done 自动重试一次；failed 由用户决策（重试/手动安装/取消）。渲染全部走签名变更检测。 */
const DL_LABEL = { kernel: '订阅内核', wintun: 'wintun 组件' };
/* 官方下载页（版本钉值见 subscription.rs MIHOMO_VERSION / WINTUN_VERSION，升级时同步） */
const DL_OFFICIAL = {
  kernel: 'https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.29',
  wintun: 'https://www.wintun.net/',
};
let _dlSig = '';       // 渲染签名（变更检测）
let _dlRetry = null;   // 下载/手动安装完成后自动重试的原开启动作
let _dlDoneSeen = '';  // 已消费的 done 签名（防重复重试）
let _dlManualArtifact = 'kernel';

async function pollDl() {
  if (HTTP_MODE) return;
  let st;
  try { st = await invoke('dl_state'); } catch (e) { return; }
  renderDlCard(st);
  if (st.phase === 'downloading') _dlDoneSeen = ''; // 新一轮下载开始，重置 done 消费标记
  if (st.phase === 'done') {
    const sig = 'done:' + st.artifact;
    if (_dlDoneSeen !== sig) {
      _dlDoneSeen = sig;
      toast(DL_LABEL[st.artifact] + ' 下载安装完成', 'ok');
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
  if (sig === _dlSig) return; // 变更检测：进度未变不重绘
  _dlSig = sig;
  card.style.display = '';
  const label = DL_LABEL[st.artifact] || st.artifact;
  const downloading = st.phase === 'downloading';
  setText('dl-title', downloading ? '正在下载' + label : label + ' 下载失败');
  $('dl-cancel-x').style.display = downloading ? '' : 'none';
  const bar = $('dl-progress').firstElementChild;
  if (downloading) {
    const pct = st.total ? Math.min(100, st.downloaded / st.total * 100) : 0;
    bar.style.width = pct.toFixed(1) + '%';
    const sizeTxt = st.total
      ? fmtBytes(st.downloaded) + ' / ' + fmtBytes(st.total) + '（' + pct.toFixed(0) + '%）'
      : fmtBytes(st.downloaded) + '（大小未知）';
    setText('dl-detail', sizeTxt + ' · ' + (st.mirror || '连接中…'));
  } else {
    bar.style.width = '0%';
    setText('dl-detail', '可重试下载，或从官方渠道自行下载后手动安装');
  }
  $('dl-err').style.display = downloading ? 'none' : '';
  setText('dl-err', downloading ? '' : (st.reason || '下载失败'));
  $('dl-actions').style.display = downloading ? 'none' : 'flex';
  if (!downloading) $('dl-manual').dataset.artifact = st.artifact;
}

/* 开启动作遇 NEED_DOWNLOAD：提示 + 跳订阅页展示下载卡 + 登记完成后自动重试 */
function handleNeedDownload(retry) {
  _dlRetry = retry;
  toast('制品未安装，正在后台下载（进度见下载卡）', 'ok');
  switchView('subscription');
  pollDl();
}

function openDlManual(artifact) {
  _dlManualArtifact = artifact;
  const k = artifact === 'kernel';
  setText('dl-manual-title', '手动安装' + (DL_LABEL[artifact] || artifact));
  setText('dl-manual-hint', k
    ? '支持官方 zip/gz 包（推荐，可对钉校验）或裸 mihomo 二进制（无法对钉，需确认风险）'
    : '支持官方 wintun zip 包或 wintun.dll（Clash 系客户端通常自带同版本 dll）');
  const inp = $('dl-manual-path');
  inp.value = '';
  inp.placeholder = k ? 'D:\\dl\\mihomo-windows-amd64-compatible-v1.19.29.zip' : 'D:\\dl\\wintun-0.14.1.zip 或 wintun.dll';
  $('dl-manual-err').textContent = '';
  $('dl-manual-modal').style.display = 'flex';
  inp.focus();
}

async function submitDlManual(allowMismatch) {
  const path = $('dl-manual-path').value.trim();
  if (!path) { $('dl-manual-err').textContent = '请填写文件完整路径'; return; }
  const btn = $('dl-manual-ok');
  btn.disabled = true;
  $('dl-manual-err').textContent = '';
  try {
    const res = await invoke('dl_install_manual', { artifact: _dlManualArtifact, path, allowMismatch: !!allowMismatch });
    if (res.result === 'installed') {
      $('dl-manual-modal').style.display = 'none';
      $('dl-mismatch-modal').style.display = 'none';
      toast((DL_LABEL[_dlManualArtifact] || '制品') + ' 已安装', 'ok');
      refreshSubFeature(); refreshSubStatus();
      const retry = _dlRetry; _dlRetry = null;
      if (retry) retry();
    } else if (res.result === 'hash_mismatch') {
      // 钉值对不上/无法对钉：明示风险，用户确认才强装
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
  /* 下载卡：取消（下载中）/ 重试 / 手动安装 / 取消（失败后放弃） */
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
  /* 手动安装弹窗 */
  $('dl-manual-cancel').onclick = () => { $('dl-manual-modal').style.display = 'none'; };
  $('dl-manual-open').onclick = () => { invoke('open_url', { url: DL_OFFICIAL[_dlManualArtifact] }).catch(() => {}); };
  $('dl-manual-path').addEventListener('keydown', e => { if (e.key === 'Enter') $('dl-manual-ok').click(); });
  $('dl-manual-ok').onclick = () => submitDlManual(false);
  /* 哈希不符确认弹窗：仍然使用 = 带 allow_mismatch 重调；放弃 = 回手动安装弹窗 */
  $('dl-mm-cancel').onclick = () => { $('dl-mismatch-modal').style.display = 'none'; };
  $('dl-mm-ok').onclick = () => submitDlManual(true);
}

/* ================= 拖拽导入订阅（Tauri 窗口级文件拖拽；.yaml/.yml 落窗即导入到订阅列表） =================
   桌面端专属（HTTP_MODE/Android 跳过监听）；悬拖期间订阅列表卡虚线高亮（element.style + var token）。 */
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
    if (!p) { toast('请拖入 .yaml / .yml 订阅文件', 'err'); return; }
    try {
      const sub = await invoke('import_local_subscription', { path: p });
      toast('订阅已导入（' + sub.node_count + ' 节点）', 'ok');
      refreshSubs();
    } catch (err) { toast(friendlyError(err), 'err'); }
  });
}
