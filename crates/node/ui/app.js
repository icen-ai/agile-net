'use strict';
/* ================= 图标 =================
   共享图标表 apps/desktop/ui/icons.js 经 /ui/icons.js 服务（AgIcon/AgIconHydrate，AGENTS.md §6）；
   本端保留 ic 别名兼容既有调用，不再本地维护图标表。 */
const ic = AgIcon;

/* ================= ag-select 统一自定义下拉（共享组件，样式在 /ui/components.css） =================
   渐进增强：原生 select 保留为数据/逻辑载体（视觉隐藏），自定义 UI 与其双向同步——
   选择自定义项 = 写回 sel.value 并 dispatch change（冒泡，既有绑定照常触发）；
   程序化改选项/值后调 agSelectRefresh(sel) 刷新标签；sel.disabled 同步禁用态。
   弹出层 fixed 挂 body（避开模态 overflow 裁剪，z-index 高于模态），点击外部 / Esc / 滚动 / 缩放关闭。 */
let agselOpen = null; // 当前打开的下拉 {root, btn, pop, cleanup}（全局同时只开一个）

function agSelClose() {
  if (!agselOpen) return;
  const o = agselOpen; agselOpen = null;
  o.root.classList.remove('open');
  o.btn.setAttribute('aria-expanded', 'false');
  o.pop.remove();
  o.cleanup();
}

/* 标签与禁用态同步（增强/打开/选择/refresh 时调用） */
function agSelSyncLabel(sel) {
  const root = sel._agsel; if (!root) return;
  const opt = sel.options[sel.selectedIndex];
  root.querySelector('.agsel-label').textContent = opt ? opt.textContent : '';
  root.querySelector('.agsel-btn').disabled = sel.disabled;
}

/* 打开时重建选项列表（天然兼容动态选项变更）并定位弹出层 */
function agSelOpenPop(sel, root, btn) {
  const pop = document.createElement('div');
  pop.className = 'agsel-pop';
  pop.setAttribute('role', 'listbox');
  [...sel.options].forEach((o, i) => {
    const d = document.createElement('div');
    d.className = 'agsel-opt' + (i === sel.selectedIndex ? ' sel' : '');
    d.setAttribute('role', 'option');
    d.setAttribute('aria-selected', i === sel.selectedIndex ? 'true' : 'false');
    d.textContent = o.textContent;
    d.addEventListener('click', () => {
      sel.selectedIndex = i;
      agSelSyncLabel(sel);
      agSelClose();
      sel.dispatchEvent(new Event('change', { bubbles: true }));
    });
    pop.appendChild(d);
  });
  document.body.appendChild(pop);
  root.classList.add('open');
  btn.setAttribute('aria-expanded', 'true');
  // 定位：默认按钮下方，下方空间不足翻上方；右缘越界则左移
  const r = btn.getBoundingClientRect();
  pop.style.minWidth = r.width + 'px';
  const pw = pop.offsetWidth;
  pop.style.left = Math.max(8, Math.min(r.left, window.innerWidth - pw - 8)) + 'px';
  const below = window.innerHeight - r.bottom - 8, above = r.top - 8;
  if (below >= 160 || below >= above) {
    pop.style.top = (r.bottom + 4) + 'px';
    pop.style.maxHeight = Math.max(120, Math.min(260, below - 4)) + 'px';
  } else {
    pop.style.bottom = (window.innerHeight - r.top + 4) + 'px';
    pop.style.maxHeight = Math.max(120, Math.min(260, above - 4)) + 'px';
  }
  const cur = pop.querySelector('.agsel-opt.sel');
  if (cur) cur.scrollIntoView({ block: 'nearest' });
  const onDocDown = (e) => { if (!pop.contains(e.target) && !root.contains(e.target)) agSelClose(); };
  const onKey = (e) => { if (e.key === 'Escape') { agSelClose(); btn.focus(); } };
  const onScroll = (e) => { if (!pop.contains(e.target)) agSelClose(); };
  const onResize = () => agSelClose();
  document.addEventListener('pointerdown', onDocDown, true);
  document.addEventListener('keydown', onKey, true);
  document.addEventListener('scroll', onScroll, true);
  window.addEventListener('resize', onResize);
  agselOpen = { root, btn, pop, cleanup() {
    document.removeEventListener('pointerdown', onDocDown, true);
    document.removeEventListener('keydown', onKey, true);
    document.removeEventListener('scroll', onScroll, true);
    window.removeEventListener('resize', onResize);
  } };
}

/* 扫描 root 内未增强的 select 并增强（幂等）；innerHTML 渲染出入口之后调用 */
function agSelectEnhance(root) {
  (root || document).querySelectorAll('select:not([data-agsel])').forEach(sel => {
    sel.dataset.agsel = '1';
    sel.classList.add('agsel-src');
    sel.setAttribute('aria-hidden', 'true');
    sel.tabIndex = -1;
    const wrap = document.createElement('span');
    wrap.className = 'agsel' + (sel.classList.contains('small') ? ' agsel-sm' : '');
    if (sel.style.width) wrap.style.width = sel.style.width;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'agsel-btn';
    btn.setAttribute('aria-haspopup', 'listbox');
    btn.setAttribute('aria-expanded', 'false');
    btn.innerHTML = '<span class="agsel-label"></span>' + ic('chevron-down', 14);
    wrap.appendChild(btn);
    sel.parentNode.insertBefore(wrap, sel.nextSibling);
    sel._agsel = wrap;
    btn.addEventListener('click', () => {
      if (sel.disabled) return;
      if (agselOpen && agselOpen.root === wrap) { agSelClose(); return; }
      agSelClose();
      agSelOpenPop(sel, wrap, btn);
    });
    // 外部代码直接改值并派发 change 时同步标签
    sel.addEventListener('change', () => agSelSyncLabel(sel));
    agSelSyncLabel(sel);
  });
}

/* 程序化改选项/值/disabled 后刷新自定义 UI（未增强时安全 no-op） */
function agSelectRefresh(sel) { if (sel && sel._agsel) agSelSyncLabel(sel); }

/* ================= ag-tabs 横向页签条（共享组件，样式在 /ui/components.css） =================
   结构：<div class="agtabs"><div class="agtabs-pill"><button class="agtab" data-agtab="k">…
         面板 = 与页签条同容器内的直属 [data-agpanel="k"]；点击置 active 并显示对应面板。
   纯显隐切换不重渲染（轮询签名检测不受影响）；onSwitch(key) 供页面同步状态。 */
function agTabsBind(bar, onSwitch) {
  const scope = bar.parentElement;
  const apply = (key, fire) => {
    bar.querySelectorAll('.agtab').forEach(t => t.classList.toggle('active', t.dataset.agtab === key));
    scope.querySelectorAll(':scope > [data-agpanel]').forEach(p => { p.hidden = p.dataset.agpanel !== key; });
    if (fire && onSwitch) onSwitch(key);
  };
  bar.querySelectorAll('.agtab').forEach(t => { t.onclick = () => apply(t.dataset.agtab, true); });
  const cur = bar.querySelector('.agtab.active') || bar.querySelector('.agtab');
  if (cur) apply(cur.dataset.agtab, false);
}

/* ================= 基础设施 =================
   $ / esc / ahelp 走共享基础工具 /ui/agutil.js（AGENTS.md §6），本端不再保留本地副本 */
const S = {
  access: localStorage.getItem('ag_access') || '',
  refresh: localStorage.getItem('ag_refresh') || '',
  view: 'dashboard',
  page: { accounts: 1, groups: 1, rules: 1, audit: 1 },
  size: { accounts: 10, groups: 10, rules: 10, audit: 15 },
  filter: { accounts: '', accountsEnabled: '', accountsGroup: '', rules: '', rulesType: '', auditAction: '' },
  faninTab: 'listen',   // 扇入页当前页签：listen | peers | tokens
  faninQuery: '',       // 扇入页搜索词：连接/令牌两页签共享（一脉相承，切页签保留）
  groups: [],
  timers: [],
  ws: null,
};

function fmtBytes(n) {
  n = Number(n) || 0;
  if (n >= (1<<30)) return (n/(1<<30)).toFixed(2) + ' GB';
  if (n >= (1<<20)) return (n/(1<<20)).toFixed(2) + ' MB';
  if (n >= 1024) return (n/1024).toFixed(1) + ' KB';
  return n + ' B';
}
function fmtUptime(s) {
  s = Number(s)||0;
  const d = Math.floor(s/86400), h = Math.floor(s%86400/3600), m = Math.floor(s%3600/60);
  return (d? d+'天 ':'') + (h? h+'时 ':'') + m + '分';
}
function toast(msg, type) {
  // 内嵌进 GUI 时通知统一走外壳灵动岛（避免新旧两套通知组件并存）
  if (window.parent !== window) {
    try {
      window.parent.postMessage({ type: 'ag-toast', msg: String(msg), kind: type || 'info' }, '*');
      return;
    } catch (e) { /* postMessage 不可用时回退本地 toast */ }
  }
  const el = document.createElement('div');
  el.className = 'toast ' + (type||'');
  el.textContent = msg;
  $('toasts').appendChild(el);
  setTimeout(() => el.remove(), 3600);
}
async function copyText(text) {
  try { await navigator.clipboard.writeText(text); toast('已复制到剪贴板', 'ok'); }
  catch(e) { toast('复制失败', 'err'); }
}

/* ================= API 客户端（自动续期） ================= */
async function apiRaw(method, path, body) {
  const opt = { method, headers: {} };
  if (S.access) opt.headers['Authorization'] = 'Bearer ' + S.access;
  if (body !== undefined) {
    opt.headers['Content-Type'] = 'application/json';
    opt.body = JSON.stringify(body);
  }
  return fetch(path, opt);
}
async function refreshSession() {
  if (!S.refresh) return false;
  const res = await fetch('/api/v1/auth/refresh', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ refresh_token: S.refresh })
  });
  if (!res.ok) return false;
  const j = await res.json();
  if (j.code !== 0) return false;
  S.access = j.data.access_token;
  if (j.data.refresh_token) { S.refresh = j.data.refresh_token; localStorage.setItem('ag_refresh', S.refresh); }
  localStorage.setItem('ag_access', S.access);
  return true;
}
async function api(method, path, body, retried) {
  let res = await apiRaw(method, path, body);
  if (res.status === 401 && !retried && await refreshSession()) {
    res = await apiRaw(method, path, body);
  }
  if (res.status === 401) { doLogout(); throw new Error('登录已过期'); }
  let j;
  try { j = await res.json(); } catch(e) { throw new Error('服务响应异常: HTTP ' + res.status); }
  if (j.code !== 0) throw new Error(j.message || ('错误码 ' + j.code));
  return j.data;
}

/* ================= 模态框 ================= */
function openModal(title, bodyHtml, actions) {
  const root = $('modal-root');
  root.innerHTML = '';
  const mask = document.createElement('div');
  mask.className = 'modal-mask';
  mask.onclick = (e) => { if (e.target === mask) closeModal(); };
  const modal = document.createElement('div');
  modal.className = 'modal';
  modal.innerHTML = '<h3>' + esc(title) + '</h3>' + bodyHtml;
  const bar = document.createElement('div');
  bar.className = 'actions';
  (actions || [{label:'关闭', kind:'ghost', fn: closeModal}]).forEach(a => {
    const b = document.createElement('button');
    b.textContent = a.label;
    if (a.kind) b.className = a.kind;
    b.onclick = a.fn;
    bar.appendChild(b);
  });
  modal.appendChild(bar);
  mask.appendChild(modal);
  root.appendChild(mask);
  agSelectEnhance(modal);
}
function closeModal() { $('modal-root').innerHTML = ''; }
function confirmAction(text, onYes) {
  openModal('确认操作', '<p style="color:var(--dim)">' + esc(text) + '</p>', [
    {label:'取消', kind:'ghost', fn: closeModal},
    {label:'确认执行', kind:'danger', fn: async () => { closeModal(); await onYes(); }},
  ]);
}

/* ================= 登录/登出 ================= */
async function doLogin() {
  const u = $('login-user').value.trim(), p = $('login-pass').value;
  $('login-err').textContent = '';
  if (!u || !p) { $('login-err').textContent = '请输入用户名和密码'; return; }
  try {
    const res = await fetch('/api/v1/auth/login', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({username: u, password: p})
    });
    const j = await res.json();
    if (j.code !== 0) { $('login-err').textContent = j.message || '登录失败'; return; }
    S.access = j.data.access_token; S.refresh = j.data.refresh_token || '';
    localStorage.setItem('ag_access', S.access);
    localStorage.setItem('ag_refresh', S.refresh);
    enterApp();
  } catch(e) { $('login-err').textContent = '网络错误'; }
}
async function doLogout() {
  try { await api('POST', '/api/v1/auth/logout', { refresh_token: S.refresh }); } catch(e) {}
  S.access = ''; S.refresh = '';
  localStorage.removeItem('ag_access');
  localStorage.removeItem('ag_refresh');
  if (S.ws) { try { S.ws.close(); } catch(e){} S.ws = null; }
  S.timers.forEach(clearInterval); S.timers = [];
  $('app').style.display = 'none';
  $('login-view').style.display = 'flex';
}

async function enterApp() {
  $('login-view').style.display = 'none';
  $('app').style.display = 'block';
  try {
    const me = await api('GET', '/api/v1/auth/me');
    $('me-info').innerHTML = ic('user', 14) + ' ' + esc(me.username) + ' <span class="badge b-info">' + esc(me.role) + '</span>';
  } catch(e) { return; }
  await loadGroupsCache();
  switchView(S.view || 'dashboard');
}

/* ================= 视图路由 ================= */
function switchView(v) {
  S.view = v;
  S.timers.forEach(clearInterval); S.timers = [];
  document.querySelectorAll('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.view === v));
  const fn = ({dashboard: renderDashboard, accounts: renderAccounts, groups: renderGroups,
    rules: renderRules, fanin: renderFanIn, connectors: renderConnectors, audit: renderAudit, settings: renderSettings})[v] || renderDashboard;
  fn();
}
async function loadGroupsCache() {
  try { const d = await api('GET', '/api/v1/admin/groups?page_size=100'); S.groups = d.items || []; } catch(e) { S.groups = []; }
  // 组缓存刷新后同步现存自定义下拉标签（选项列表随各渲染入口重建）
  document.querySelectorAll('select[data-agsel]').forEach(agSelectRefresh);
}
function groupName(id) {
  const g = S.groups.find(g => g.id === id);
  return g ? g.name : (id || '-');
}
/* 代理模式文案（客户端代理槽位 mode：system=系统代理 / local=本地代理） */
function proxyModeText(m) { return ({ system: '系统代理', local: '本地代理' })[m] || m || ''; }
function pager(viewKey, total) {
  const page = S.page[viewKey], size = S.size[viewKey];
  const pages = Math.max(1, Math.ceil(total / size));
  return '<div class="pager"><span>共 ' + total + ' 条 · ' + page + '/' + pages + ' 页</span>' +
    '<button class="ghost small" ' + (page<=1?'disabled':'') + ' data-pager="' + viewKey + '" data-delta="-1">上一页</button>' +
    '<button class="ghost small" ' + (page>=pages?'disabled':'') + ' data-pager="' + viewKey + '" data-delta="1">下一页</button></div>';
}
function shortId(id) { return esc(String(id||'').substring(0,8)); }

/* ================= 动态内容事件委托 =================
   动态 HTML 一律 data-* 标记、document 层统一分派（替代内联 onclick/onchange，对齐桌面端 CSP 约束）；
   委托挂在 document，innerHTML 轮询重写不影响绑定。点击动作用 data-act，变更动作用 data-act-chg。 */
const ACT_CLICK = {
  'copy': b => copyText(b.dataset.copy),
  'show-qr': b => showQr(b.dataset.id),
  'acc-reset': b => resetAccountPwd(b.dataset.id, b.dataset.name),
  'acc-toggle': b => toggleAccount(b.dataset.id, b.dataset.enabled === 'true'),
  'acc-del': b => delAccount(b.dataset.id, b.dataset.name),
  'grp-detail': b => openGroupDetail(b.dataset.id),
  'grp-bind': b => openBindRules(b.dataset.id, b.dataset.name),
  'grp-edit': b => openEditGroup(b.dataset.id, b.dataset.name, b.dataset.remark || ''),
  'grp-del': b => delGroup(b.dataset.id, b.dataset.name, Number(b.dataset.count || 0)),
  'rule-edit': b => openEditRule(b.dataset.id, b.dataset.type, b.dataset.value, b.dataset.resolve === 'true', b.dataset.remark || ''),
  'rule-del': b => delRule(b.dataset.id, b.dataset.value, Number(b.dataset.count || 0)),
  'tok-edit': b => openEditToken(b.dataset.id, b.dataset.group || '', b.dataset.expose === 'true', b.dataset.scope),
  'tok-del': b => delToken(b.dataset.id),
  'conn-edit': b => openEditConnector(b.dataset.id),
  'conn-toggle': b => toggleConnector(b.dataset.id, b.dataset.enabled === 'true'),
  'conn-del': b => delConnector(b.dataset.id, b.dataset.name),
  'admin-del': b => delAdmin(b.dataset.id, b.dataset.name),
};
const ACT_CHANGE = {
  'tok-expose': el => toggleExpose(el.dataset.id, el.checked),
  'tok-scope': el => setScope(el.dataset.id, el.value),
};
document.addEventListener('click', (e) => {
  const p = e.target.closest('[data-pager]');
  if (p) {
    if (p.disabled) return;
    const key = p.dataset.pager;
    S.page[key] += Number(p.dataset.delta);
    ({ accounts: renderAccounts, groups: renderGroups, rules: renderRules, audit: renderAudit }[key] || (() => {}))();
    return;
  }
  const b = e.target.closest('[data-act]');
  if (!b) return;
  const fn = ACT_CLICK[b.dataset.act];
  if (fn) fn(b);
});
document.addEventListener('change', (e) => {
  const el = e.target.closest('[data-act-chg]');
  if (!el) return;
  const fn = ACT_CHANGE[el.dataset.actChg];
  if (fn) fn(el);
});

/* ================= 概览 ================= */
async function renderDashboard() {
  $('view').innerHTML = '<div class="page-title">' + ic('layout-dashboard', 20) + '<span id="dash-title">端点概览</span></div><div class="page-desc">运行状态、连接拓扑与流量统计</div>' +
    '<div class="stat-grid" id="dash-stats"></div>' +
    '<div class="tf-grid" id="dash-tf">' +
      tfCard('fanin', '扇入流量', 'fanin') +
      tfCard('fanout', '扇出流量', 'connectors') +
      tfCard('transit', '中继途径', 'fanin') +
    '</div>' +
    '<div class="card"><h3>流量趋势（24h，按小时）</h3><div class="chart-wrap" id="traffic-chart"></div></div>' +
    '<div class="card"><h3>实时事件</h3><div id="events-list" class="mono" style="max-height:180px;overflow-y:auto;color:var(--dim)">连接事件中…</div></div>';
  // 卡片点击跳转（事件委托：容器常驻，load 重写 innerHTML 不影响绑定；embed 模式同链路）
  const gotoView = (e) => {
    const card = e.target.closest('[data-goto]');
    if (card) switchView(card.dataset.goto);
  };
  $('dash-stats').onclick = gotoView;
  $('dash-tf').onclick = gotoView;

  async function load() {
    try {
      const st = await api('GET', '/api/v1/admin/node/status');
      // 标题栏跟随端点名称（Tauri 控制台窗口）
      const tbt = document.querySelector('.tb-title');
      if (tbt && st.node_name) tbt.textContent = st.node_name;
      const tt = $('dash-title'), tname = (st.node_name || '端点') + ' 概览';
      if (tt && tt.textContent !== tname) tt.textContent = tname;
      const L = st.roles.listener, CS = st.roles.connectors || [], P = st.proxy, A = st.accounts;
      const statusText = { connected: '已连接', connecting: '连接中', reconnecting: '重连中', disconnected: '已断开' };
      const fanoutSub = CS.length
        ? CS.map(c => '<div class="mono">' + esc(c.upstream) + ' <span class="badge ' +
            (c.status === 'connected' ? 'b-ok' : (c.status === 'disconnected' ? 'b-off' : 'b-warn')) + '">' +
            esc(statusText[c.status] || c.status) + '</span></div>').join('')
        : '-';
      // 本地代理副行：有 mode（客户端代理槽位）→ 模式 + listen；否则节点 proxy_listen 旧口径
      const proxySub = P.mode
        ? esc(proxyModeText(P.mode)) + (P.enabled && P.listen ? ' · ' + esc(P.listen) : '')
        : (P.enabled ? esc(P.listen) + ' · 活跃 ' + (P.active_connections||0) + ' · 规则 ' + (P.rule_count||0) : '规则 ' + (P.rule_count||0));
      let cards =
        statCard('端点名称', esc(st.node_name), 'v' + esc(st.version) + ' · 运行 ' + fmtUptime(st.uptime), 'settings') +
        statCard('Relay 监听（扇入）', L.enabled ? '<span class="badge b-ok">启用</span>' : '<span class="badge b-off">未启用</span>',
          L.enabled ? esc(L.addr) + ' · 扇入 ' + (L.connected_connectors||0) + ' 端点 · 在线客户端 ' + (L.online_clients||0) : '-', 'fanin') +
        statCard('扇出连接', CS.length ? '<span class="badge b-ok">' + CS.length + ' 条</span>' : '<span class="badge b-off">未扇出</span>', fanoutSub, 'connectors') +
        statCard('本地代理', P.enabled ? '<span class="badge b-ok">启用</span>' : '<span class="badge b-off">未启用</span>', proxySub, 'settings') +
        statCard('客户端账号', (A.total||0) + ' 个', '在线 ' + (A.online||0) + ' · 禁用 ' + (A.disabled||0), 'accounts') +
        statCard('系统资源', (st.system.memory_mb||0) + ' MB', 'CPU ' + (st.system.cpu_usage||0).toFixed(1) + '% · 总内存 ' + (st.system.total_memory_mb||0) + ' MB');
      if (L.enabled && (L.peers||[]).length) {
        cards += statCard('在线扇入端点', (L.peers||[]).map(p => '<div class="mono"><span class="dot on"></span>' + esc(p) + '</div>').join(''), '');
      }
      $('dash-stats').innerHTML = cards;
      // 三张流量卡：扇入（今日 + 24h 趋势）/ 扇出（汇总 + 逐条明细）/ 中继途径（汇总 + pairs）
      updateTfCards(st);
    } catch(e) { toast(e.message, 'err'); }

    try {
      const t = await api('GET', '/api/v1/admin/node/stats?period=24h&group_by=time');
      const pts = t.points || [];
      AgChart.line($('traffic-chart'), {
        x: pts.map(p => p.time),
        series: [
          { name: 'RX', values: pts.map(p => p.bytes_rx) },
          { name: 'TX', values: pts.map(p => p.bytes_tx) },
        ],
        fmtY: fmtBytes,
        fmtX: h => String(h || '').slice(11, 16),
        empty: '暂无流量数据',
      });
    } catch(e) {}
  }
  function statCard(k, v, sub, view) {
    return '<div class="stat' + (view ? ' link' : '') + '"' + (view ? ' data-goto="' + view + '"' : '') +
      '><div class="k">' + k + '</div><div class="v">' + v + '</div><div class="sub">' + sub + '</div></div>';
  }
  await load();
  S.timers.push(setInterval(load, 15000));

  // WebSocket 实时事件
  try {
    if (S.ws) { S.ws.close(); S.ws = null; }
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(proto + '://' + location.host + '/api/v1/admin/node/events');
    S.ws = ws;
    // 升级后首条消息认证（token 不进 URL，避免落入访问日志/浏览器历史）
    ws.onopen = () => { try { ws.send(S.access); } catch(e) {} };
    ws.onmessage = (ev) => {
      try {
        const e = JSON.parse(ev.data);
        const list = $('events-list');
        if (!list) return;
        if (list.textContent.includes('连接事件中')) list.innerHTML = '';
        const line = document.createElement('div');
        line.textContent = '[' + (e.time||'').substring(11,19) + '] ' + e.type + ' ' + JSON.stringify(e.data||{});
        list.prepend(line);
        while (list.children.length > 50) list.lastChild.remove();
      } catch(err) {}
    };
    ws.onclose = () => { const l = $('events-list'); if (l && S.view === 'dashboard') l.innerHTML = '<span style="color:var(--dim2)">事件通道已断开（15s 后随概览刷新重连）</span>'; };
  } catch(e) {}
}

/* ================= 流量卡（扇入/扇出/中继途径；sparkline 用共享组件 AgChart） =================
   数据源：status 契约 st.roles.fanout_traffic / st.roles.transit / st.traffic_24h，
   扇入今日合计由 traffic_24h.fanin 按本地日期聚合；契约字段缺失（旧端点）时优雅降级为「-」。
   变更检测：数字/明细区各自签名对比，图表签名在 AgChart 内部，均不变更不重写。 */
function tfCard(key, title, gotoView) {
  return '<div class="card tf-card link" data-goto="' + gotoView + '"><h3>' + title + '</h3>' +
    '<div class="tf-nums" id="tf-' + key + '-nums"></div>' +
    '<div class="tf-spark" id="tf-' + key + '-spark"></div>' +
    '<div class="tf-detail" id="tf-' + key + '-detail"></div></div>';
}
function tfNums(key, up, down, scope) {
  const el = $('tf-' + key + '-nums'); if (!el) return;
  const html = (up == null)
    ? '<div class="n"><div class="k">暂无数据</div></div>'
    : '<div class="n"><div class="k">下行' + scope + '</div><div class="v">' + fmtBytes(down) + '</div></div>' +
      '<div class="n"><div class="k">上行' + scope + '</div><div class="v">' + fmtBytes(up) + '</div></div>';
  if (el.dataset.sig !== html) { el.dataset.sig = html; el.innerHTML = html; }
}
function tfSpark(key, points) {
  const el = $('tf-' + key + '-spark'); if (!el) return;
  const pts = Array.isArray(points) ? points : [];
  AgChart.sparkline(el, [
    { name: '下行', values: pts.map(p => +p.down || 0) },
    { name: '上行', values: pts.map(p => +p.up || 0) },
  ]);
}
function tfDetail(key, rows) {
  const el = $('tf-' + key + '-detail'); if (!el) return;
  const html = rows.length
    ? rows.slice(0, 5).map(r =>
        '<div class="row"><span class="l">' + esc(r.l) + '</span><span class="v mono">' + esc(r.v) + '</span></div>').join('') +
      (rows.length > 5 ? '<div class="row"><span class="l">…等 ' + rows.length + ' 条</span><span></span></div>' : '')
    : '<div class="row"><span class="l" style="color:var(--dim2)">暂无数据</span></div>';
  if (el.dataset.sig !== html) { el.dataset.sig = html; el.innerHTML = html; }
}
/* 今日合计：hour 为 "YYYY-MM-DD HH:00" 本地时间字符串，按本地日期前缀过滤 */
function tfTodaySum(points) {
  const d = new Date();
  const pfx = d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
  let up = 0, down = 0;
  (points || []).forEach(p => {
    if (String(p.hour || '').slice(0, 10) === pfx) { up += +p.up || 0; down += +p.down || 0; }
  });
  return { up, down };
}
function tfUpDown(up, down) { return '↑ ' + fmtBytes(up) + ' · ↓ ' + fmtBytes(down); }
function updateTfCards(st) {
  const R = st.roles || {}, T24 = st.traffic_24h || {};
  // 扇入：今日 up/down + 24h 趋势；明细 = 当前各扇入对端累计（peer_traffic）
  const fi = Array.isArray(T24.fanin) ? tfTodaySum(T24.fanin) : null;
  tfNums('fanin', fi ? fi.up : null, fi ? fi.down : 0, '（今日）');
  tfSpark('fanin', T24.fanin);
  tfDetail('fanin', ((R.listener || {}).peer_traffic || []).map(p => ({
    l: p.node_id, v: tfUpDown(p.bytes_up, p.bytes_down),
  })));
  // 扇出：fanout_traffic 汇总 + 逐条 connector 明细
  const fo = Array.isArray(R.fanout_traffic) ? R.fanout_traffic : null;
  let foUp = 0, foDown = 0;
  (fo || []).forEach(c => { foUp += +c.bytes_up || 0; foDown += +c.bytes_down || 0; });
  tfNums('fanout', fo ? foUp : null, foDown, '（累计）');
  tfSpark('fanout', T24.fanout);
  tfDetail('fanout', (fo || []).map(c => ({ l: c.name, v: tfUpDown(c.bytes_up, c.bytes_down) })));
  // 中继途径：transit 汇总 + pairs（起始端 → 结束端；主权域边界内仅相邻两跳可见）
  const tr = R.transit || null;
  tfNums('transit', tr ? +tr.bytes_up || 0 : null, tr ? +tr.bytes_down || 0 : 0, '（累计）');
  tfSpark('transit', T24.transit);
  tfDetail('transit', ((tr && tr.pairs) || []).map(p => ({
    l: (p.from || '?') + ' → ' + (p.to || '?'), v: tfUpDown(p.bytes_up, p.bytes_down),
  })));
}

/* ================= 客户端账号 ================= */
async function renderAccounts() {
  $('view').innerHTML = '<div class="page-title">' + ic('users', 20) + '客户端账号</div><div class="page-desc">账号即客户端身份凭据，密码由服务端生成（sk- 48 位强随机），仅创建/重置时展示一次</div>' +
    '<div class="toolbar">' +
      '<input id="acc-q" placeholder="搜索账号/备注" value="' + esc(S.filter.accounts) + '">' +
      '<select id="acc-group">' +
        '<option value="">全部权限组</option>' +
        S.groups.map(g => '<option value="' + esc(g.id) + '" ' + (S.filter.accountsGroup===g.id?'selected':'') + '>' + esc(g.name) + '</option>').join('') +
      '</select>' +
      '<select id="acc-enabled">' +
        '<option value="">全部状态</option>' +
        '<option value="true" ' + (S.filter.accountsEnabled==='true'?'selected':'') + '>启用</option>' +
        '<option value="false" ' + (S.filter.accountsEnabled==='false'?'selected':'') + '>禁用</option>' +
      '</select>' +
      '<div class="spacer"></div>' +
      '<button id="acc-create">' + ic('plus', 15) + '新建账号</button>' +
    '</div>' +
    '<div class="card table-wrap"><table><thead><tr><th>账号</th><th>权限组</th><th>在线</th><th>状态</th><th>最后在线</th><th>备注</th><th>操作</th></tr></thead><tbody id="acc-body"></tbody></table><div id="acc-pager"></div></div>';
  agSelectEnhance($('view'));
  $('acc-q').oninput = (e) => { S.filter.accounts = e.target.value; S.page.accounts = 1; renderAccounts(); };
  $('acc-group').onchange = (e) => { S.filter.accountsGroup = e.target.value; S.page.accounts = 1; renderAccounts(); };
  $('acc-enabled').onchange = (e) => { S.filter.accountsEnabled = e.target.value; S.page.accounts = 1; renderAccounts(); };
  $('acc-create').onclick = openCreateAccount;
  await loadAccounts();
  S.timers.push(setInterval(loadAccounts, 20000));
}
async function loadAccounts() {
  const body = $('acc-body'); if (!body) return;
  let url = '/api/v1/admin/accounts?page=' + S.page.accounts + '&page_size=' + S.size.accounts;
  if (S.filter.accounts) url += '&q=' + encodeURIComponent(S.filter.accounts);
  if (S.filter.accountsGroup) url += '&group_id=' + encodeURIComponent(S.filter.accountsGroup);
  if (S.filter.accountsEnabled) url += '&enabled=' + S.filter.accountsEnabled;
  try {
    const d = await api('GET', url);
    body.innerHTML = (d.items||[]).map(a =>
      '<tr><td><b>' + esc(a.username) + '</b>' + (a.admin_console ? ' <span class="badge b-info">可管理</span>' : '') + '<div class="mono" style="color:var(--dim2)">' + shortId(a.id) + '</div></td>' +
      '<td>' + esc(a.group_name || groupName(a.group_id)) + '</td>' +
      '<td><span class="dot ' + (a.online?'on':'off') + '"></span>' + (a.online?'在线':'离线') + '</td>' +
      '<td>' + (a.enabled ? '<span class="badge b-ok">启用</span>' : '<span class="badge b-off">禁用</span>') + '</td>' +
      '<td style="color:var(--dim)">' + esc(a.last_seen_at || '从未') + '</td>' +
      '<td style="color:var(--dim)">' + esc(a.remark || '-') + '</td>' +
      '<td style="white-space:nowrap">' +
        '<button class="ghost small" data-act="acc-reset" data-id="' + esc(a.id) + '" data-name="' + esc(a.username) + '">重置密码</button> ' +
        '<button class="ghost small" data-act="acc-toggle" data-id="' + esc(a.id) + '" data-enabled="' + !a.enabled + '">' + (a.enabled?'禁用':'启用') + '</button> ' +
        '<button class="danger small" data-act="acc-del" data-id="' + esc(a.id) + '" data-name="' + esc(a.username) + '">删除</button>' +
      '</td></tr>'
    ).join('') || '<tr><td colspan="7" class="empty">暂无账号</td></tr>';
    $('acc-pager').innerHTML = pager('accounts', d.total||0);
  } catch(e) { toast(e.message, 'err'); }
}
function openCreateAccount() {
  if (!S.groups.length) { toast('请先创建权限组', 'err'); return; }
  openModal('新建客户端账号',
    '<label>账号名（3-32 位字母数字_-）</label><input id="na-user" style="width:100%">' +
    '<label>权限组</label><select id="na-group" style="width:100%">' +
      S.groups.map(g => '<option value="' + esc(g.id) + '">' + esc(g.name) + '</option>').join('') + '</select>' +
    '<label>备注</label><input id="na-remark" style="width:100%">' +
    '<label class="chk" style="display:flex;align-items:center;gap:6px;margin-top:8px"><input type="checkbox" id="na-admin"> 同时授予管理权限（生成管理版接入链接）</label>' +
    '<div class="hint" id="na-admin-warn" style="color:var(--danger-text);display:none">' + ic('triangle-alert', 13) + ' 持管理版接入链接者可经控制台通道管理本端点（规则/账号/令牌同管理员），签发将记入审计。仅发给可信管理员。</div>',
    [
      {label:'取消', kind:'ghost', fn: closeModal},
      {label:'创建', fn: async () => {
        const username = $('na-user').value.trim(), group_id = $('na-group').value, remark = $('na-remark').value.trim();
        const admin_console = $('na-admin').checked;
        try {
          const d = await api('POST', '/api/v1/admin/accounts', {username, group_id, remark, admin_console});
          showAccountSecret('账号创建成功 — 请立即保存凭据', d.username, d.password, d.connect_url, d.id, admin_console);
          loadAccounts();
        } catch(e) { toast(e.message, 'err'); }
      }},
    ]);
  $('na-admin').onchange = (e) => { $('na-admin-warn').style.display = e.target.checked ? 'block' : 'none'; };
}
function showAccountSecret(title, username, password, connectUrl, accountId, isAdminLink) {
  openModal(title,
    (isAdminLink ? '<div class="hint" style="color:var(--danger-text);margin-bottom:8px">' + ic('triangle-alert', 13) + ' 这是管理版接入链接：持链接者可管理本端点，请按管理员凭据级别保管与分发</div>' : '') +
    '<div class="kv"><span class="k">账号</span><span><b>' + esc(username) + '</b></span></div>' +
    '<div class="kv"><span class="k">密码</span><span class="mono">' + esc(password) + ' <button class="ghost small" data-act="copy" data-copy="' + esc(password) + '">' + ic('copy', 13) + '复制</button></span></div>' +
    '<div class="secret-box"><div style="color:var(--dim);font-size:12px;margin-bottom:4px">接入链接（客户端导入）</div><span class="mono">' + esc(connectUrl) + '</span></div>' +
    '<div class="actions" style="justify-content:flex-start;margin-top:10px"><button class="ghost small" data-act="copy" data-copy="' + esc(connectUrl) + '">' + ic('copy', 13) + '复制接入链接</button>' +
    '<button class="ghost small" data-act="show-qr" data-id="' + esc(accountId) + '">' + ic('qr-code', 13) + '显示二维码</button></div>' +
    '<div class="qr-box" id="qr-box"></div>' +
    '<div class="hint" style="color:var(--warn)">' + ic('triangle-alert', 13) + ' 密码与接入链接仅本次展示，10 分钟内可打开二维码</div>',
    [{label:'我已保存', fn: closeModal}]);
}
async function showQr(accountId) {
  try {
    const res = await fetch('/api/v1/admin/accounts/' + accountId + '/qrcode', { headers: { 'Authorization': 'Bearer ' + S.access } });
    if (!res.ok) { toast('二维码已过期（仅创建/重置后 10 分钟可取）', 'err'); return; }
    const svg = await res.text();
    $('qr-box').innerHTML = svg;
  } catch(e) { toast(e.message, 'err'); }
}
async function resetAccountPwd(id, username) {
  confirmAction('确定重置账号 ' + username + ' 的密码？旧密码与旧令牌立即失效。', async () => {
    try {
      const d = await api('POST', '/api/v1/admin/accounts/' + id + '/reset-password');
      showAccountSecret('密码已重置 — 请立即保存', username, d.password, d.connect_url, id);
    } catch(e) { toast(e.message, 'err'); }
  });
}
async function toggleAccount(id, enabled) {
  try {
    await api('PUT', '/api/v1/admin/accounts/' + id, { enabled });
    toast(enabled ? '已启用' : '已禁用（令牌已吊销）', 'ok');
    loadAccounts();
  } catch(e) { toast(e.message, 'err'); }
}
async function delAccount(id, username) {
  confirmAction('确定删除账号 ' + username + '？其全部凭据与连接将失效。', async () => {
    try { await api('DELETE', '/api/v1/admin/accounts/' + id); toast('已删除', 'ok'); loadAccounts(); }
    catch(e) { toast(e.message, 'err'); }
  });
}

/* ================= 权限组 ================= */
async function renderGroups() {
  $('view').innerHTML = '<div class="page-title">' + ic('shield', 20) + '权限组</div><div class="page-desc">权限组是规则与账号的桥梁：账号所属组决定其可访问的内网资源</div>' +
    '<div class="toolbar"><input id="grp-q" placeholder="搜索名称/备注" value="' + esc(S.filter.groups||'') + '">' +
    '<div class="spacer"></div><button id="grp-create">' + ic('plus', 15) + '新建权限组</button></div>' +
    '<div class="card table-wrap"><table><thead><tr><th>名称</th><th>规则数</th><th>账号数</th><th>备注</th><th>操作</th></tr></thead><tbody id="grp-body"></tbody></table><div id="grp-pager"></div></div>';
  $('grp-q').oninput = (e) => { S.filter.groups = e.target.value; S.page.groups = 1; renderGroups(); };
  $('grp-create').onclick = openCreateGroup;
  await loadGroups();
}
async function loadGroups() {
  const body = $('grp-body'); if (!body) return;
  let url = '/api/v1/admin/groups?page=' + S.page.groups + '&page_size=' + S.size.groups;
  if (S.filter.groups) url += '&q=' + encodeURIComponent(S.filter.groups);
  try {
    const d = await api('GET', url);
    body.innerHTML = (d.items||[]).map(g =>
      '<tr><td><b>' + esc(g.name) + '</b><div class="mono" style="color:var(--dim2)">' + shortId(g.id) + '</div></td>' +
      '<td><span class="badge b-info">' + g.rule_count + '</span></td>' +
      '<td><span class="badge b-info">' + g.account_count + '</span></td>' +
      '<td style="color:var(--dim)">' + esc(g.remark || '-') + '</td>' +
      '<td style="white-space:nowrap">' +
        '<button class="ghost small" data-act="grp-detail" data-id="' + esc(g.id) + '">详情</button> ' +
        '<button class="ghost small" data-act="grp-bind" data-id="' + esc(g.id) + '" data-name="' + esc(g.name) + '">绑定规则</button> ' +
        '<button class="ghost small" data-act="grp-edit" data-id="' + esc(g.id) + '" data-name="' + esc(g.name) + '" data-remark="' + esc(g.remark||'') + '">编辑</button> ' +
        '<button class="danger small" data-act="grp-del" data-id="' + esc(g.id) + '" data-name="' + esc(g.name) + '" data-count="' + g.account_count + '">删除</button>' +
      '</td></tr>'
    ).join('') || '<tr><td colspan="5" class="empty">暂无权限组</td></tr>';
    $('grp-pager').innerHTML = pager('groups', d.total||0);
    S.groups = d.items || S.groups;
  } catch(e) { toast(e.message, 'err'); }
}
function openCreateGroup() {
  openModal('新建权限组',
    '<label>名称（1-64 字符，唯一）</label><input id="ng-name" style="width:100%">' +
    '<label>备注</label><input id="ng-remark" style="width:100%">',
    [
      {label:'取消', kind:'ghost', fn: closeModal},
      {label:'创建', fn: async () => {
        try {
          await api('POST', '/api/v1/admin/groups', { name: $('ng-name').value.trim(), remark: $('ng-remark').value.trim() });
          closeModal(); toast('已创建', 'ok'); loadGroupsCache(); loadGroups();
        } catch(e) { toast(e.message, 'err'); }
      }},
    ]);
}
function openEditGroup(id, name, remark) {
  openModal('编辑权限组',
    '<label>名称</label><input id="eg-name" style="width:100%" value="' + esc(name) + '">' +
    '<label>备注</label><input id="eg-remark" style="width:100%" value="' + esc(remark) + '">',
    [
      {label:'取消', kind:'ghost', fn: closeModal},
      {label:'保存', fn: async () => {
        try {
          await api('PUT', '/api/v1/admin/groups/' + id, { name: $('eg-name').value.trim(), remark: $('eg-remark').value.trim() });
          closeModal(); toast('已保存', 'ok'); loadGroupsCache(); loadGroups();
        } catch(e) { toast(e.message, 'err'); }
      }},
    ]);
}
async function openGroupDetail(id) {
  try {
    const [g, d] = await Promise.all([
      api('GET', '/api/v1/admin/groups/' + id),
      api('GET', '/api/v1/admin/groups/' + id + '/detail'),
    ]);
    openModal('权限组详情 — ' + g.name,
      '<h3 style="margin:10px 0 6px">关联规则（' + (g.rules||[]).length + '）</h3>' +
      ((g.rules||[]).map(r => '<div class="kv"><span class="mono">' + esc(r.value) + '</span><span class="badge b-info">' + esc(r.type) + '</span></div>').join('') || '<div class="empty">无</div>') +
      '<h3 style="margin:14px 0 6px">组内账号（' + (d.accounts||[]).length + '）</h3>' +
      ((d.accounts||[]).map(a => '<div class="kv"><span>' + esc(a.username) + '</span><span>' + (a.enabled?'<span class="badge b-ok">启用</span>':'<span class="badge b-off">禁用</span>') + '</span></div>').join('') || '<div class="empty">无</div>') +
      '<h3 style="margin:14px 0 6px">扇入令牌（' + (d.relay_tokens||[]).length + '）</h3>' +
      ((d.relay_tokens||[]).map(t => '<div class="kv"><span class="mono">' + esc(t.token_prefix) + '</span><span style="color:var(--dim)">' + esc(t.remark || '-') + '</span></div>').join('') || '<div class="empty">无</div>') +
      '<h3 style="margin:14px 0 6px">扇出对端（' + (d.connectors||[]).length + '）</h3>' +
      ((d.connectors||[]).map(c => '<div class="kv"><span><b>' + esc(c.name) + '</b> <span class="mono" style="color:var(--dim);font-size:12px">' + esc(c.upstream_addr) + '</span></span><span>' + (c.enabled?'<span class="badge b-ok">启用</span>':'<span class="badge b-off">禁用</span>') + '</span></div>').join('') || '<div class="empty">无</div>'));
  } catch(e) { toast(e.message, 'err'); }
}
async function openBindRules(id, name) {
  try {
    const [detail, all] = await Promise.all([
      api('GET', '/api/v1/admin/groups/' + id),
      api('GET', '/api/v1/admin/rules?page_size=100'),
    ]);
    const bound = new Set((detail.rules||[]).map(r => r.id));
    openModal('绑定规则 — ' + name,
      '<div class="rule-check">' +
      (all.items||[]).map(r =>
        '<label><input type="checkbox" class="bind-rule" value="' + esc(r.id) + '" ' + (bound.has(r.id)?'checked':'') + '>' +
        '<span class="mono">' + esc(r.value) + '</span><span class="badge b-info">' + esc(r.type) + '</span>' +
        (r.remark ? '<span style="color:var(--dim)">' + esc(r.remark) + '</span>' : '') + '</label>'
      ).join('') || '<div class="empty">暂无规则，请先在「路由规则」中创建</div>' + '</div>',
      [
        {label:'取消', kind:'ghost', fn: closeModal},
        {label:'保存绑定', fn: async () => {
          const ids = [...document.querySelectorAll('.bind-rule:checked')].map(c => c.value);
          try {
            await api('PUT', '/api/v1/admin/groups/' + id + '/rules', { rule_ids: ids });
            closeModal(); toast('绑定已更新（配置版本已递增）', 'ok'); loadGroups();
          } catch(e) { toast(e.message, 'err'); }
        }},
      ]);
  } catch(e) { toast(e.message, 'err'); }
}
async function delGroup(id, name, accountCount) {
  const forceNote = accountCount > 0 ? '（组下仍有 ' + accountCount + ' 个账号，强制删除将一并删除！）' : '';
  openModal('删除权限组',
    '<p style="color:var(--dim)">确定删除权限组 <b>' + esc(name) + '</b>？' + esc(forceNote) + '</p>',
    [
      {label:'取消', kind:'ghost', fn: closeModal},
      ...(accountCount > 0 ? [{label:'强制删除', kind:'danger', fn: async () => {
        closeModal();
        try { await api('DELETE', '/api/v1/admin/groups/' + id + '?force=true'); toast('已强制删除', 'ok'); loadGroupsCache(); loadGroups(); }
        catch(e) { toast(e.message, 'err'); }
      }}] : []),
      {label:'删除', kind:'danger', fn: async () => {
        closeModal();
        try { await api('DELETE', '/api/v1/admin/groups/' + id); toast('已删除', 'ok'); loadGroupsCache(); loadGroups(); }
        catch(e) { toast(e.message, 'err'); }
      }},
    ]);
}

/* ================= 路由规则 ================= */
async function renderRules() {
  $('view').innerHTML = '<div class="page-title">' + ic('route', 20) + '路由规则</div><div class="page-desc">CIDR 网段与域名规则，经权限组分配给账号；变更即时生效并推送客户端</div>' +
    '<div class="toolbar">' +
      '<input id="rule-q" placeholder="搜索匹配值/备注" value="' + esc(S.filter.rules) + '">' +
      '<select id="rule-type">' +
        '<option value="">全部类型</option>' +
        '<option value="ip-cidr" ' + (S.filter.rulesType==='ip-cidr'?'selected':'') + '>ip-cidr</option>' +
        '<option value="host" ' + (S.filter.rulesType==='host'?'selected':'') + '>host</option>' +
      '</select>' +
      '<div class="spacer"></div>' +
      '<button class="ghost" id="rule-batch">批量导入</button>' +
      '<button id="rule-create">' + ic('plus', 15) + '新建规则</button>' +
    '</div>' +
    '<div class="card table-wrap"><table><thead><tr><th>类型</th><th>匹配值</th><th>解析</th><th>引用组</th><th>备注</th><th>操作</th></tr></thead><tbody id="rule-body"></tbody></table><div id="rule-pager"></div></div>';
  agSelectEnhance($('view'));
  $('rule-q').oninput = (e) => { S.filter.rules = e.target.value; S.page.rules = 1; renderRules(); };
  $('rule-type').onchange = (e) => { S.filter.rulesType = e.target.value; S.page.rules = 1; renderRules(); };
  $('rule-batch').onclick = openBatchImport;
  $('rule-create').onclick = openCreateRule;
  await loadRules();
}
async function loadRules() {
  const body = $('rule-body'); if (!body) return;
  let url = '/api/v1/admin/rules?page=' + S.page.rules + '&page_size=' + S.size.rules;
  if (S.filter.rules) url += '&q=' + encodeURIComponent(S.filter.rules);
  if (S.filter.rulesType) url += '&type=' + S.filter.rulesType;
  try {
    const d = await api('GET', url);
    body.innerHTML = (d.items||[]).map(r =>
      '<tr><td><span class="badge b-info">' + esc(r.type) + '</span></td>' +
      '<td class="mono"><b>' + esc(r.value) + '</b></td>' +
      '<td>' + (r.resolve ? '<span class="badge b-warn">是</span>' : '<span style="color:var(--dim2)">否</span>') + '</td>' +
      '<td>' + (r.group_count || 0) + '</td>' +
      '<td style="color:var(--dim)">' + esc(r.remark || '-') + '</td>' +
      '<td style="white-space:nowrap">' +
        '<button class="ghost small" data-act="rule-edit" data-id="' + esc(r.id) + '" data-type="' + esc(r.type) + '" data-value="' + esc(r.value) + '" data-resolve="' + r.resolve + '" data-remark="' + esc(r.remark||'') + '">编辑</button> ' +
        '<button class="danger small" data-act="rule-del" data-id="' + esc(r.id) + '" data-value="' + esc(r.value) + '" data-count="' + (r.group_count||0) + '">删除</button>' +
      '</td></tr>'
    ).join('') || '<tr><td colspan="6" class="empty">暂无规则</td></tr>';
    $('rule-pager').innerHTML = pager('rules', d.total||0);
  } catch(e) { toast(e.message, 'err'); }
}
function ruleFormHtml(t, v, resolve, remark) {
  // “写入系统 hosts” 仅 host 类型有意义：非 host 类型隐藏该开关（新建态切换类型时联动）
  return '<label>类型</label><select id="rf-type" style="width:100%" ' + (t?'disabled':'') + '>' +
      '<option value="ip-cidr" ' + (t==='ip-cidr'?'selected':'') + '>ip-cidr（网段，如 10.12.0.0/16）</option>' +
      '<option value="host" ' + (t==='host'?'selected':'') + '>host（域名，如 git.internal 或 *.dev.internal）</option>' +
    '</select>' +
    '<label>匹配值</label><input id="rf-value" style="width:100%" value="' + esc(v||'') + '" placeholder="10.12.0.0/16 或 git.internal">' +
    '<label id="rf-resolve-row" style="display:' + (t === 'host' ? 'flex' : 'none') + ';gap:8px;align-items:center;margin-top:10px"><input type="checkbox" id="rf-resolve" ' + (resolve?'checked':'') + '> host 需要客户端写入系统 hosts</label>' +
    '<label>备注</label><input id="rf-remark" style="width:100%" value="' + esc(remark||'') + '">';
}
function openCreateRule() {
  openModal('新建路由规则', ruleFormHtml('', '', false, ''), [
    {label:'取消', kind:'ghost', fn: closeModal},
    {label:'创建', fn: async () => {
      try {
        await api('POST', '/api/v1/admin/rules', {
          type: $('rf-type').value, value: $('rf-value').value.trim(),
          resolve: $('rf-resolve').checked, remark: $('rf-remark').value.trim(),
        });
        closeModal(); toast('已创建', 'ok'); loadRules();
      } catch(e) { toast(e.message, 'err'); }
    }},
  ]);
  $('rf-type').addEventListener('change', () => {
    $('rf-resolve-row').style.display = $('rf-type').value === 'host' ? 'flex' : 'none';
  });
}
function openEditRule(id, type, value, resolve, remark) {
  openModal('编辑规则（类型不可改）', ruleFormHtml(type, value, resolve, remark), [
    {label:'取消', kind:'ghost', fn: closeModal},
    {label:'保存', fn: async () => {
      try {
        await api('PUT', '/api/v1/admin/rules/' + id, {
          value: $('rf-value').value.trim(), resolve: $('rf-resolve').checked, remark: $('rf-remark').value.trim(),
        });
        closeModal(); toast('已保存', 'ok'); loadRules();
      } catch(e) { toast(e.message, 'err'); }
    }},
  ]);
}
async function delRule(id, value, groupCount) {
  if (groupCount > 0) {
    openModal('规则被引用',
      '<p style="color:var(--dim)">规则 <span class="mono">' + esc(value) + '</span> 被 ' + groupCount + ' 个权限组引用，强制删除将解除全部引用。</p>',
      [
        {label:'取消', kind:'ghost', fn: closeModal},
        {label:'强制删除', kind:'danger', fn: async () => {
          closeModal();
          try { await api('DELETE', '/api/v1/admin/rules/' + id + '?force=true'); toast('已强制删除', 'ok'); loadRules(); }
          catch(e) { toast(e.message, 'err'); }
        }},
      ]);
  } else {
    confirmAction('确定删除规则 ' + value + '？', async () => {
      try { await api('DELETE', '/api/v1/admin/rules/' + id); toast('已删除', 'ok'); loadRules(); }
      catch(e) { toast(e.message, 'err'); }
    });
  }
}
function openBatchImport() {
  openModal('批量导入规则',
    '<label>规则 JSON 数组（每行一个对象亦可）</label>' +
    '<textarea id="bi-text" style="width:100%;height:160px" class="mono" placeholder=\'[{"type":"ip-cidr","value":"10.12.0.0/16","remark":"办公网"},{"type":"host","value":"git.internal","resolve":true}]\'></textarea>' +
    '<label>冲突处理</label><select id="bi-mode" style="width:100%"><option value="skip">skip — 跳过重复</option><option value="overwrite">overwrite — 覆盖备注等字段</option><option value="error">error — 有重复即全部拒绝</option></select>',
    [
      {label:'取消', kind:'ghost', fn: closeModal},
      {label:'导入', fn: async () => {
        let rules;
        try {
          const text = $('bi-text').value.trim();
          try { rules = JSON.parse(text); }
          catch(e) {
            rules = text.split('\n').map(l => l.trim()).filter(Boolean).map(l => JSON.parse(l));
          }
          if (!Array.isArray(rules)) throw new Error('格式错误');
        } catch(e) { toast('JSON 解析失败: ' + e.message, 'err'); return; }
        try {
          const d = await api('POST', '/api/v1/admin/rules/batch', { rules, on_conflict: $('bi-mode').value });
          closeModal();
          toast('导入完成：新建 ' + d.created + ' · 跳过 ' + d.skipped + ' · 更新 ' + d.updated + (d.errors.length ? ' · 错误 ' + d.errors.length : ''), d.errors.length ? 'err' : 'ok');
          loadRules();
        } catch(e) { toast(e.message, 'err'); }
      }},
    ]);
}

/* ================= 扇入（谁连着本端点：监听 / 连接 / 令牌） ================= */
/* 列表最近数据缓存：轮询签名检测外，搜索过滤与页签切换直接复用（不重新拉取） */
let FANIN_PEERS = [];
let FANIN_TOKENS = [];
async function renderFanIn() {
  const tab = S.faninTab;
  $('view').innerHTML = '<div class="page-title">' + ic('orbit', 20) + '扇入</div><div class="page-desc">谁连着本端点：扇入监听状态、在线扇入连接与扇入令牌管理</div>' +
    '<div class="agtabs" id="fanin-tabs">' +
      '<div class="agtabs-pill">' +
        '<button class="agtab' + (tab === 'listen' ? ' active' : '') + '" data-agtab="listen">监听</button>' +
        '<button class="agtab' + (tab === 'peers' ? ' active' : '') + '" data-agtab="peers">连接</button>' +
        '<button class="agtab' + (tab === 'tokens' ? ' active' : '') + '" data-agtab="tokens">令牌</button>' +
      '</div>' +
      '<div class="agtabs-tools"><input id="fanin-q" style="width:230px" placeholder="搜索连接 / 令牌（同词联动过滤）" value="' + esc(S.faninQuery) + '"' + (tab === 'listen' ? ' hidden' : '') + '></div>' +
    '</div>' +
    '<div data-agpanel="listen"><div class="card"><h3>扇入监听</h3><div id="fanin-listener"></div></div></div>' +
    '<div data-agpanel="peers" hidden><div class="card"><h3>扇入连接</h3><div class="table-wrap"><table><thead><tr><th>对端 node_id</th><th>上行</th><th>下行</th></tr></thead><tbody id="fanin-peers"></tbody></table></div></div></div>' +
    '<div data-agpanel="tokens" hidden><div class="card"><h3>扇入令牌' + ahelp('令牌 = 允许对端扇入本端点的预共享密钥（psk_ 48 位）；服务端只存哈希，全文仅创建时展示一次') + '</h3>' +
      '<div class="toolbar"><div class="spacer"></div><button id="tok-create">' + ic('plus', 15) + '生成令牌</button></div>' +
      '<div class="table-wrap"><table><thead><tr><th>前缀</th><th>权限组</th><th>带宽配额</th><th>备注</th><th>暴露控制面</th><th>最近使用</th><th>创建时间</th><th>操作</th></tr></thead><tbody id="tok-body"></tbody></table></div></div></div>';
  agTabsBind($('fanin-tabs'), (k) => {
    S.faninTab = k;
    $('fanin-q').hidden = (k === 'listen');
  });
  $('tok-create').onclick = openCreateToken;
  // 连接/令牌一脉相承的相关搜索：输入即过滤两表，切页签搜索词保留并各自生效
  $('fanin-q').oninput = (e) => {
    S.faninQuery = e.target.value;
    renderFaninPeers();
    renderFaninTokens();
  };
  await Promise.all([loadFaninStatus(), loadTokens()]);
  S.timers.push(setInterval(loadFaninStatus, 10000));
}
/* 监听卡 + 连接表同源于 roles.listener：单次拉取、单签名变更检测（不变不重写 DOM） */
async function loadFaninStatus() {
  const box = $('fanin-listener'); if (!box) return;
  let L;
  try { L = (await api('GET', '/api/v1/admin/node/status')).roles.listener; }
  catch(e) { toast(e.message, 'err'); return; }
  L = L || { enabled: false };
  const sig = JSON.stringify(L);
  if (sig === box.dataset.sig) return;
  box.dataset.sig = sig;
  if (!L.enabled) {
    box.innerHTML = '<div class="empty">扇入监听未开启：对端端点与客户端均无法连入。请在服务端配置中启用 relay listener 后，此处展示监听地址与连接概况。</div>';
  } else {
    box.innerHTML =
      '<div class="kv"><span class="k">监听地址</span><span class="mono">' + esc(L.addr || '-') + '</span></div>' +
      '<div class="kv"><span class="k">TLS</span><span>' + (L.tls ? '<span class="badge b-ok">已启用</span>' : '<span class="badge b-off">未启用</span>') + '</span></div>' +
      '<div class="kv"><span class="k">扇入端点</span><span>' + (L.connected_connectors || 0) + ' 个已连接</span></div>' +
      '<div class="kv"><span class="k">在线客户端</span><span>' + (L.online_clients || 0) + ' 个</span></div>';
  }
  const traffic = L.enabled ? (L.peer_traffic || []) : [];
  const peers = L.enabled ? (L.peers || []) : [];
  // peers 有而 traffic 缺失的补 0（流量计数为启动以来累计）
  const rows = traffic.slice();
  const seen = new Set(traffic.map(t => t.node_id));
  peers.filter(p => !seen.has(p)).forEach(p => rows.push({ node_id: p, bytes_up: 0, bytes_down: 0 }));
  FANIN_PEERS = rows;
  renderFaninPeers();
}
function renderFaninPeers() {
  const body = $('fanin-peers'); if (!body) return;
  const q = S.faninQuery.trim().toLowerCase();
  const rows = q ? FANIN_PEERS.filter(t => (t.node_id || '').toLowerCase().includes(q)) : FANIN_PEERS;
  body.innerHTML = rows.map(t =>
    '<tr><td class="mono"><span class="dot on"></span>' + esc(t.node_id) + '</td>' +
    '<td class="mono">' + fmtBytes(t.bytes_up) + '</td>' +
    '<td class="mono">' + fmtBytes(t.bytes_down) + '</td></tr>'
  ).join('') || '<tr><td colspan="3" class="empty">' + (q ? '无匹配的扇入连接' : '暂无扇入连接') + '</td></tr>';
}
async function loadTokens() {
  const body = $('tok-body'); if (!body) return;
  try {
    const d = await api('GET', '/api/v1/admin/node/relay-tokens');
    FANIN_TOKENS = d.items || [];
    renderFaninTokens();
  } catch(e) { toast(e.message, 'err'); }
}
/* 令牌过滤维度：前缀 / 备注 / 组名（与连接表共用同一搜索词） */
function renderFaninTokens() {
  const body = $('tok-body'); if (!body) return;
  const q = S.faninQuery.trim().toLowerCase();
  const items = q ? FANIN_TOKENS.filter(t =>
    (t.token_prefix || '').toLowerCase().includes(q) ||
    (t.remark || '').toLowerCase().includes(q) ||
    (t.group_id && (t.group_name || groupName(t.group_id)).toLowerCase().includes(q))
  ) : FANIN_TOKENS;
  body.innerHTML = items.map(t =>
    '<tr><td class="mono">' + esc(t.token_prefix) + '</td>' +
    '<td>' + (t.group_id ? esc(t.group_name || groupName(t.group_id)) : '<span style="color:var(--dim2)">不收敛</span>') + '</td>' +
    '<td class="mono">' + (t.rate_limit_kbps ? esc(t.rate_limit_kbps) + ' KB/s' : '<span style="color:var(--dim2)">不限</span>') + '</td>' +
    '<td>' + esc(t.remark || '-') + '</td>' +
    '<td><label class="chk" style="display:flex;align-items:center;gap:5px"><input type="checkbox" data-act-chg="tok-expose" data-id="' + esc(t.id) + '"' + (t.expose_control ? ' checked' : '') +
      '><span style="font-size:12px">允许管理</span></label>' +
      (t.expose_control ? '<select class="ghost small" data-act-chg="tok-scope" data-id="' + esc(t.id) + '">' +
        ['ro','rules','full'].map(sc => '<option value="' + sc + '" ' + (t.control_scope === sc ? 'selected' : '') + '>' + ({ro:'只读',rules:'规则',full:'全权'})[sc] + '</option>').join('') + '</select>' : '') + '</td>' +
    '<td style="color:var(--dim)">' + esc(t.last_used_at || '未使用') + '</td>' +
    '<td style="color:var(--dim)">' + esc(t.created_at) + '</td>' +
    '<td style="white-space:nowrap"><button class="ghost small" data-act="tok-edit" data-id="' + esc(t.id) + '" data-group="' + esc(t.group_id||'') + '" data-expose="' + t.expose_control + '" data-scope="' + esc(t.control_scope) + '">编辑</button> ' +
    '<button class="danger small" data-act="tok-del" data-id="' + esc(t.id) + '">吊销</button></td></tr>'
  ).join('') || '<tr><td colspan="8" class="empty">' + (q ? '无匹配的扇入令牌' : '暂无扇入令牌') + '</td></tr>';
  agSelectEnhance(body);
}
async function toggleExpose(id, on) {
  try {
    const cur = (await api('GET', '/api/v1/admin/node/relay-tokens')).items.find(t => t.id === id);
    await api('PUT', '/api/v1/admin/node/relay-tokens/' + id, { expose_control: on, control_scope: (cur && cur.control_scope) || 'full' });
    toast(on ? '已允许该扇入中继管理本端点（变更已记审计）' : '已关闭控制面暴露', 'ok');
    loadTokens();
  } catch(e) { toast(e.message, 'err'); loadTokens(); }
}
async function setScope(id, scope) {
  try {
    await api('PUT', '/api/v1/admin/node/relay-tokens/' + id, { expose_control: true, control_scope: scope });
    toast('授权档位已更新', 'ok');
  } catch(e) { toast(e.message, 'err'); }
}
function openCreateToken() {
  openModal('生成扇入令牌',
    '<label>备注（如：分公司跳板机）</label><input id="nt-remark" style="width:100%">' +
    '<label>权限组（留空 = 不收敛，放行一切）</label><select id="nt-group" style="width:100%">' +
      '<option value="">不收敛（放行一切）</option>' +
      S.groups.map(g => '<option value="' + esc(g.id) + '">' + esc(g.name) + '</option>').join('') + '</select>' +
    '<label>带宽配额 KB/s（留空 = 不限速）</label><input id="nt-rate" type="number" min="1" placeholder="如 10240（= 10 MB/s）" style="width:100%">' +
    '<div class="hint">限制该令牌整条链路的读写总速率（数据面令牌桶节流，超限自然降速不断流）</div>' +
    '<label class="chk" style="display:flex;align-items:center;gap:6px;margin-top:8px"><input type="checkbox" id="nt-expose"> 允许该扇入中继管理本端点（暴露控制面，默认关）</label>' +
    '<div id="nt-expose-opts" style="display:none;margin:6px 0">' +
      '<label>授权档位</label><select id="nt-scope" style="width:100%">' +
        '<option value="ro">只读（仅查看状态/配置）</option>' +
        '<option value="rules">可改规则（只读 + 规则增删改）</option>' +
        '<option value="full" selected>全权（等同管理员）</option>' +
      '</select>' +
      '<div class="hint" style="color:var(--danger-text)">' + ic('triangle-alert', 13) + ' 扇入端点持该令牌即可换取本端点管理会话（零开通），签发与换取均记审计；吊销令牌即全线回收。</div>' +
    '</div>',
    [
      {label:'取消', kind:'ghost', fn: closeModal},
      {label:'生成', fn: async () => {
        try {
          const rateVal = parseInt($('nt-rate').value, 10);
          const d = await api('POST', '/api/v1/admin/node/relay-tokens', {
            remark: $('nt-remark').value.trim(),
            expose_control: $('nt-expose').checked,
            control_scope: $('nt-scope').value,
            group_id: $('nt-group').value || null,
            rate_limit_kbps: rateVal > 0 ? rateVal : null,
          });
          openModal('令牌已生成 — 仅此一次展示',
            '<div class="secret-box"><span class="mono">' + esc(d.token) + '</span></div>' +
            '<div class="actions" style="justify-content:flex-start;margin-top:10px"><button class="ghost small" data-act="copy" data-copy="' + esc(d.token) + '">' + ic('copy', 13) + '复制令牌</button></div>' +
            '<div class="hint" style="color:var(--warn)">' + ic('triangle-alert', 13) + ' 请立即保存，服务端只存哈希，无法找回</div>',
            [{label:'我已保存', fn: () => { closeModal(); loadTokens(); }}]);
        } catch(e) { toast(e.message, 'err'); }
      }},
    ]);
  $('nt-expose').onchange = (e) => { $('nt-expose-opts').style.display = e.target.checked ? 'block' : 'none'; };
}
async function delToken(id) {
  confirmAction('确定吊销该令牌？使用它的扇入端点将在断开后无法重连。', async () => {
    try { await api('DELETE', '/api/v1/admin/node/relay-tokens/' + id); toast('已吊销', 'ok'); loadTokens(); }
    catch(e) { toast(e.message, 'err'); }
  });
}
/* 编辑收敛组：PUT 三态语义（缺省=不变 / null=不收敛 / 字符串=挂组），
   编辑为用户显式选择故总是送出；暴露控制面在列表直接改（不送 group_id=不变） */
function openEditToken(id, groupId, exposeControl, controlScope, rateKbps) {
  openModal('编辑扇入令牌',
    '<label>权限组（选「不收敛」= 放行一切）</label><select id="et-group" style="width:100%">' +
      '<option value="">不收敛（放行一切）</option>' +
      S.groups.map(g => '<option value="' + esc(g.id) + '" ' + (groupId===g.id?'selected':'') + '>' + esc(g.name) + '</option>').join('') + '</select>' +
    '<label>带宽配额 KB/s（清空 = 不限速）</label><input id="et-rate" type="number" min="1" value="' + (rateKbps > 0 ? rateKbps : '') + '" placeholder="不限" style="width:100%">' +
    '<div class="hint">配额变更对新建会话即时生效（在线会话不断连，重连后生效）；变更收敛组后在线对端将被踢断，重连即按新组收敛（记审计）</div>',
    [
      {label:'取消', kind:'ghost', fn: closeModal},
      {label:'保存', fn: async () => {
        try {
          const rateVal = parseInt($('et-rate').value, 10);
          await api('PUT', '/api/v1/admin/node/relay-tokens/' + id, {
            expose_control: exposeControl, control_scope: controlScope,
            group_id: $('et-group').value || null,
            rate_limit_kbps: rateVal > 0 ? rateVal : null,
          });
          closeModal(); toast('已保存', 'ok'); loadTokens();
        } catch(e) { toast(e.message, 'err'); }
      }},
    ]);
}

/* ================= 扇出（对端连接） ================= */
const CONN_STATUS = { connected: '已连接', connecting: '连接中', reconnecting: '重连中', disconnected: '已断开' };
function connStatusBadge(st) {
  return '<span class="badge ' + (st === 'connected' ? 'b-ok' : (st === 'disconnected' ? 'b-off' : 'b-warn')) + '">' +
    esc(CONN_STATUS[st] || st || '未知') + '</span>';
}
async function renderConnectors() {
  $('view').innerHTML = '<div class="page-title">' + ic('git-fork', 20) + '扇出</div><div class="page-desc">本端点主动连出的对端隧道</div>' +
    '<div class="toolbar"><div class="spacer"></div><button id="conn-create">' + ic('plus', 15) + '新建扇出</button></div>' +
    '<div class="card table-wrap"><table><thead><tr><th>名称</th><th>上游地址</th><th>权限组</th><th>状态</th><th>启用</th><th>备注</th><th>操作</th></tr></thead><tbody id="conn-body"></tbody></table></div>';
  $('conn-create').onclick = openCreateConnector;
  await loadConnectors();
  S.timers.push(setInterval(loadConnectors, 5000));
}
async function loadConnectors() {
  const body = $('conn-body'); if (!body) return;
  try {
    const d = await api('GET', '/api/v1/admin/connectors');
    const items = d.items || [];
    // 轮询变更检测：签名一致不重写 DOM（避免频闪）
    const sig = JSON.stringify(items);
    if (sig === body.dataset.sig) return;
    body.dataset.sig = sig;
    body.innerHTML = items.map(c => {
      const adv = (c.advertise || '').split(',').filter(Boolean).join(' · ');
      return '<tr><td><b>' + esc(c.name) + '</b><div class="mono" style="color:var(--dim2)">' + (c.token_prefix ? esc(c.token_prefix) : shortId(c.id)) + '</div></td>' +
      '<td class="mono">' + esc(c.upstream_addr) + (adv ? '<div style="color:var(--dim2);font-size:12px">' + esc(adv) + '</div>' : '') + '</td>' +
      '<td>' + (c.group_id ? esc(c.group_name || groupName(c.group_id)) : '<span style="color:var(--dim2)">不收敛</span>') + '</td>' +
      '<td>' + connStatusBadge(c.state) + '</td>' +
      '<td>' + (c.enabled ? '<span class="badge b-ok">启用</span>' : '<span class="badge b-off">禁用</span>') + '</td>' +
      '<td style="color:var(--dim)">' + esc(c.remark || '-') + '</td>' +
      '<td style="white-space:nowrap">' +
        '<button class="ghost small" data-act="conn-edit" data-id="' + esc(c.id) + '">编辑</button> ' +
        '<button class="ghost small" data-act="conn-toggle" data-id="' + esc(c.id) + '" data-enabled="' + !c.enabled + '">' + (c.enabled ? '禁用' : '启用') + '</button> ' +
        '<button class="danger small" data-act="conn-del" data-id="' + esc(c.id) + '" data-name="' + esc(c.name) + '">删除</button>' +
      '</td></tr>';
    }).join('') || '<tr><td colspan="7" class="empty">暂无扇出对端</td></tr>';
  } catch(e) { toast(e.message, 'err'); }
}
function connectorFormHtml(c) {
  c = c || {};
  return '<label>名称（1-64 字符，唯一）</label><input id="cf-name" style="width:100%" value="' + esc(c.name||'') + '">' +
    '<label>上游地址（host:port）</label><input id="cf-addr" class="mono" style="width:100%" value="' + esc(c.upstream_addr||'') + '" placeholder="peer.example.com:54430">' +
    '<label>扇出 token（对端签发，加密落库不回显）</label><input id="cf-token" type="password" class="mono" style="width:100%" autocomplete="off" placeholder="' + (c.id ? '留空 = 保留原 token' : '对端签发的 psk_ 令牌') + '">' +
    '<label>SNI 主机名（可选）</label><input id="cf-sni" class="mono" style="width:100%" value="' + esc(c.sni_hostname||'') + '">' +
    '<label class="chk" style="display:flex;align-items:center;gap:6px;margin-top:8px"><input type="checkbox" id="cf-insecure" ' + (c.insecure?'checked':'') + '> 跳过 TLS 证书校验（insecure，仅调试用）</label>' +
    '<label>路由再发布 advertise（每行一条 CIDR/域名，可空）</label><textarea id="cf-advertise" class="mono" style="width:100%;height:90px" placeholder="10.12.0.0/16&#10;git.internal">' + esc((c.advertise||'').split(',').filter(Boolean).join('\n')) + '</textarea>' +
    '<label>权限组（留空 = 不收敛，放行一切）</label><select id="cf-group" style="width:100%">' +
      '<option value="">不收敛（放行一切）</option>' +
      S.groups.map(g => '<option value="' + esc(g.id) + '" ' + (c.group_id===g.id?'selected':'') + '>' + esc(g.name) + '</option>').join('') + '</select>' +
    '<label>备注</label><input id="cf-remark" style="width:100%" value="' + esc(c.remark||'') + '">';
}
function connectorFormBody() {
  return {
    name: $('cf-name').value.trim(),
    upstream_addr: $('cf-addr').value.trim(),
    sni_hostname: $('cf-sni').value.trim(),
    insecure: $('cf-insecure').checked,
    advertise: $('cf-advertise').value.split('\n').map(s => s.trim()).filter(Boolean),
    group_id: $('cf-group').value || null,
    remark: $('cf-remark').value.trim(),
  };
}
function openCreateConnector() {
  openModal('新建扇出', connectorFormHtml(), [
    {label:'取消', kind:'ghost', fn: closeModal},
    {label:'创建', fn: async () => {
      const body = connectorFormBody();
      const token = $('cf-token').value.trim();
      if (!body.name || !body.upstream_addr || !token) { toast('名称、上游地址与 token 必填', 'err'); return; }
      try {
        await api('POST', '/api/v1/admin/connectors', { ...body, token });
        closeModal(); toast('已创建（隧道开始连接）', 'ok'); loadConnectors();
      } catch(e) { toast(e.message, 'err'); }
    }},
  ]);
}
async function openEditConnector(id) {
  let c;
  try { c = ((await api('GET', '/api/v1/admin/connectors')).items||[]).find(x => x.id === id); }
  catch(e) { toast(e.message, 'err'); return; }
  if (!c) { toast('扇出对端不存在', 'err'); return; }
  openModal('编辑扇出', connectorFormHtml(c), [
    {label:'取消', kind:'ghost', fn: closeModal},
    {label:'保存', fn: async () => {
      const body = connectorFormBody();
      const token = $('cf-token').value.trim();
      if (!body.name || !body.upstream_addr) { toast('名称与上游地址必填', 'err'); return; }
      try {
        // PUT 为全量替换：token 留空=保留原值；证书路径表单不暴露，透传原值防被清空
        await api('PUT', '/api/v1/admin/connectors/' + id, {
          ...body, token: token || null,
          ca_cert_path: c.ca_cert_path || '', pinned_cert_path: c.pinned_cert_path || '',
        });
        closeModal(); toast('已保存（隧道已按新配置重建）', 'ok'); loadConnectors();
      } catch(e) { toast(e.message, 'err'); }
    }},
  ]);
}
async function toggleConnector(id, enabled) {
  try {
    await api('POST', '/api/v1/admin/connectors/' + id + (enabled ? '/enable' : '/disable'));
    toast(enabled ? '已启用（开始连接）' : '已禁用（隧道已断开）', 'ok');
    loadConnectors();
  } catch(e) { toast(e.message, 'err'); }
}
async function delConnector(id, name) {
  confirmAction('确定删除扇出 ' + name + '？隧道将立即断开且配置不再保留。', async () => {
    try { await api('DELETE', '/api/v1/admin/connectors/' + id); toast('已删除', 'ok'); loadConnectors(); }
    catch(e) { toast(e.message, 'err'); }
  });
}

/* ================= 审计日志 ================= */
async function renderAudit() {
  $('view').innerHTML = '<div class="page-title">' + ic('scroll-text', 20) + '审计日志</div><div class="page-desc">全部敏感操作留痕：登录、增删改、启停、重置、吊销</div>' +
    '<div class="toolbar">' +
      '<select id="audit-action">' +
        '<option value="">全部动作</option>' +
        ['admin.login','admin.init','rule.create','rule.update','rule.delete','rule.batch_import',
         'group.create','group.update','group.delete','group.update_rules',
         'account.create','account.update','account.delete','account.reset_password','account.enable','account.disable',
         'relay_token.create','relay_token.delete','relay_token.expose_control','relay_token.set_group',
         'connector.create','connector.update','connector.delete','connector.enable','connector.disable',
         'account.issue_admin_link','admin.console_access','admin.session_via_relay','node.update_settings'].map(a =>
          '<option value="' + a + '" ' + (S.filter.auditAction===a?'selected':'') + '>' + a + '</option>').join('') +
      '</select>' +
    '</div>' +
    '<div class="card table-wrap"><table><thead><tr><th>时间</th><th>操作人</th><th>动作</th><th>目标</th><th>详情</th><th>来源 IP</th></tr></thead><tbody id="audit-body"></tbody></table><div id="audit-pager"></div></div>';
  agSelectEnhance($('view'));
  $('audit-action').onchange = (e) => { S.filter.auditAction = e.target.value; S.page.audit = 1; renderAudit(); };
  await loadAudit();
}
async function loadAudit() {
  const body = $('audit-body'); if (!body) return;
  let url = '/api/v1/admin/audit-logs?page=' + S.page.audit + '&page_size=' + S.size.audit;
  if (S.filter.auditAction) url += '&action=' + S.filter.auditAction;
  try {
    const d = await api('GET', url);
    body.innerHTML = (d.items||[]).map(l =>
      '<tr><td style="color:var(--dim);white-space:nowrap">' + esc((l.created_at||'').replace('T',' ').replace('Z','')) + '</td>' +
      '<td><b>' + esc(l.operator || '-') + '</b></td>' +
      '<td><span class="badge b-info mono">' + esc(l.action) + '</span></td>' +
      '<td class="mono" style="color:var(--dim)">' + esc(l.target ? shortId(l.target) : '-') + '</td>' +
      '<td style="color:var(--dim);max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(l.detail || '-') + '</td>' +
      '<td class="mono" style="color:var(--dim)">' + esc(l.ip || '-') + '</td></tr>'
    ).join('') || '<tr><td colspan="6" class="empty">暂无审计日志</td></tr>';
    $('audit-pager').innerHTML = pager('audit', d.total||0);
  } catch(e) { toast(e.message, 'err'); }
}

/* ================= 节点设置 ================= */
async function renderSettings() {
  // 分区：服务端信息（名称/公网地址/运行信息）→ 管理面（管理员/我的密码）→ 系统日志；仅重排分组，元素 id 全部保留
  $('view').innerHTML = '<div class="page-title">' + ic('settings', 20) + '端点设置</div><div class="page-desc">服务端信息、管理面账号与系统日志</div>' +
    '<div class="card"><h3>服务端信息</h3>' +
      '<label>端点名称</label><div style="display:flex;gap:10px"><input id="set-name" style="flex:1"><button id="set-name-save">保存</button></div>' +
      '<label>公网接入地址（connect_url 与隧道端点主机名）</label><div style="display:flex;gap:10px"><input id="set-host" style="flex:1" placeholder="cdn.example.com"><button id="set-host-save">保存</button></div>' +
      '<div id="set-info" style="margin-top:14px"></div>' +
    '</div>' +
    '<div class="card"><h3>管理员</h3>' +
      '<div class="table-wrap"><table><thead><tr><th>用户名</th><th>创建时间</th><th>操作</th></tr></thead><tbody id="admin-body"></tbody></table></div>' +
      '<div class="toolbar" style="margin-top:12px"><input id="na-user" placeholder="新管理员用户名"><input id="na-pass" type="password" placeholder="密码（≥10位含大小写数字）"><button id="admin-create">' + ic('plus', 15) + '新建管理员</button></div>' +
    '</div>' +
    '<div class="card"><h3>修改我的密码</h3>' +
      '<label>旧密码</label><input id="pw-old" type="password" style="width:280px">' +
      '<label>新密码（≥10 位，含大小写字母与数字）</label><input id="pw-new" type="password" style="width:280px">' +
      '<div style="margin-top:12px"><button id="pw-change">修改密码（修改后需重新登录）</button></div>' +
    '</div>' +
    '<div class="card"><h3>最近系统日志</h3><div id="set-logs" class="mono" style="max-height:300px;overflow-y:auto;color:var(--dim);font-size:12px"></div></div>';
  $('set-name-save').onclick = saveNodeName;
  $('set-host-save').onclick = savePublicHost;
  $('admin-create').onclick = createAdmin;
  $('pw-change').onclick = changePassword;
  try {
    const st = await api('GET', '/api/v1/admin/node/status');
    $('set-name').value = st.node_name || '';
    $('set-info').innerHTML =
      kv('版本', 'v' + st.version) + kv('运行时长', fmtUptime(st.uptime)) +
      kv('Relay 监听（扇入）', st.roles.listener.enabled ? st.roles.listener.addr : '未启用') +
      kv('扇出连接', (st.roles.connectors || []).length
        ? st.roles.connectors.map(c => esc(c.upstream) + '（' + esc(c.status) + '）').join(' · ')
        : '未扇出') +
      kv('本地代理', (st.proxy.mode ? proxyModeText(st.proxy.mode) + ' · ' : '') + (st.proxy.enabled ? st.proxy.listen : '未启用')) +
      (st.cert_fingerprint
        ? '<div class="kv"><span class="k">证书指纹 (SHA-256)</span><span class="mono" style="font-size:11px;word-break:break-all">' + esc(st.cert_fingerprint) +
          ' <button class="ghost small" data-act="copy" data-copy="' + esc(st.cert_fingerprint) + '">' + ic('copy', 13) + '复制</button></span></div>'
        : '');
  } catch(e) { toast(e.message, 'err'); }
  try {
    const conf = await api('GET', '/api/v1/admin/admins');
    $('admin-body').innerHTML = (conf.items||[]).map(a =>
      '<tr><td><b>' + esc(a.username) + '</b></td><td style="color:var(--dim)">' + esc(a.created_at) + '</td>' +
      '<td><button class="danger small" data-act="admin-del" data-id="' + esc(a.id) + '" data-name="' + esc(a.username) + '">删除</button></td></tr>'
    ).join('') || '<tr><td colspan="3" class="empty">无</td></tr>';
  } catch(e) {}
  try {
    const d = await api('GET', '/api/v1/admin/node/logs?limit=100');
    $('set-logs').innerHTML = (d.items||[]).map(l =>
      '<div>[' + esc((l.time||'').substring(11,23)) + '] <span style="color:' + (l.level==='error'?'var(--danger)':l.level==='warn'?'var(--warn)':'var(--dim)') + '">' + esc(l.level) + '</span> ' + esc(l.message) + '</div>'
    ).join('') || '<div class="empty">暂无日志</div>';
  } catch(e) {}
  function kv(k, v) { return '<div class="kv"><span class="k">' + esc(k) + '</span><span>' + esc(v) + '</span></div>'; }
}
async function saveNodeName() {
  try {
    await api('PUT', '/api/v1/admin/node/settings', { node_name: $('set-name').value.trim() });
    toast('已保存', 'ok');
  } catch(e) { toast(e.message, 'err'); }
}
async function savePublicHost() {
  try {
    await api('PUT', '/api/v1/admin/node/settings', { public_host: $('set-host').value.trim() });
    toast('公网地址已更新（新签发的接入链接立即生效）', 'ok');
  } catch(e) { toast(e.message, 'err'); }
}
async function createAdmin() {
  const username = $('na-user').value.trim(), password = $('na-pass').value;
  if (!username || !password) { toast('请填写用户名与密码', 'err'); return; }
  try {
    await api('POST', '/api/v1/admin/admins', { username, password });
    toast('管理员已创建', 'ok');
    $('na-user').value = ''; $('na-pass').value = '';
    renderSettings();
  } catch(e) { toast(e.message, 'err'); }
}
async function delAdmin(id, username) {
  confirmAction('确定删除管理员 ' + username + '？其会话将立即失效。', async () => {
    try { await api('DELETE', '/api/v1/admin/admins/' + id); toast('已删除', 'ok'); renderSettings(); }
    catch(e) { toast(e.message, 'err'); }
  });
}
async function changePassword() {
  const old_password = $('pw-old').value, new_password = $('pw-new').value;
  if (!old_password || !new_password) { toast('请填写旧密码与新密码', 'err'); return; }
  try {
    await api('PUT', '/api/v1/auth/password', { old_password, new_password });
    toast('密码已修改，请重新登录', 'ok');
    setTimeout(doLogout, 1200);
  } catch(e) { toast(e.message, 'err'); }
}

/* ================= 主题切换 ================= */
function applyTheme() {
  const t = localStorage.getItem('ag_theme') || 'light';
  document.documentElement.dataset.theme = t;
  const btn = $('theme-btn');
  if (btn) btn.innerHTML = ic(t === 'dark' ? 'sun' : 'moon', 14) + (t === 'dark' ? '浅色' : '深色');
  const lb = $('login-theme-btn');
  if (lb) lb.innerHTML = ic(t === 'dark' ? 'sun' : 'moon', 15);
}
function toggleTheme() {
  localStorage.setItem('ag_theme', (localStorage.getItem('ag_theme') || 'light') === 'dark' ? 'light' : 'dark');
  applyTheme();
}

/* ================= 启动 ================= */
window.addEventListener('DOMContentLoaded', async () => {
  AgIconHydrate();
  applyTheme();
  // 静态元素事件绑定（HTML 一律不写内联事件属性，对齐桌面端 CSP 约束）
  $('login-btn').onclick = doLogin;
  $('login-theme-btn').onclick = toggleTheme;
  $('theme-btn').onclick = toggleTheme;
  $('logout-btn').onclick = doLogout;
  document.querySelectorAll('.nav-item[data-view]').forEach(n => { n.onclick = () => switchView(n.dataset.view); });
  // Tauri 控制台窗口：显示自定义标题栏（无边框窗口），接 window 控制与主题广播
  if (window.__TAURI__) {
    document.body.classList.add('tb-mode');
    $('titlebar').style.display = 'flex';
    const tbt0 = document.querySelector('.tb-title');
    if (tbt0) tbt0.textContent = document.title;
    try {
      const cw = window.__TAURI__.window.getCurrentWindow();
      $('tb-min').onclick = () => cw.minimize();
      $('tb-max').onclick = () => cw.toggleMaximize();
      $('tb-close').onclick = () => cw.close();
      window.__TAURI__.event.listen('ag-theme', e => {
        try { localStorage.setItem('ag_theme', e.payload); applyTheme(); } catch(_) {}
      });
    } catch(_) {}
  }
  // 侧栏收起（持久化；对齐桌面 GUI 的图标模式）
  if (localStorage.getItem('ag_admin_sidebar') === 'collapsed') document.body.classList.add('collapsed');
  $('btn-collapse').onclick = () => {
    const c = document.body.classList.toggle('collapsed');
    localStorage.setItem('ag_admin_sidebar', c ? 'collapsed' : '');
  };
  // 主窗内嵌桥：导航与主题经 postMessage 驱动（跨源安全白名单）
  window.addEventListener('message', e => {
    const d = e.data || {};
    if (d.type === 'ag-theme' && (d.theme === 'dark' || d.theme === 'light')) {
      try { localStorage.setItem('ag_theme', d.theme); applyTheme(); } catch(_) {}
    }
    if (d.type === 'ag-nav' && {dashboard:1,accounts:1,groups:1,rules:1,fanin:1,connectors:1,audit:1,settings:1}[d.view]) {
      switchView(d.view);
    }
  });
  $('login-pass').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
  $('login-user').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
  // 控制台通道票据自举：#boot=<ticket> → 换取管理会话（一次性，换取即失效）
  const boot = location.hash.match(/#boot=([A-Za-z0-9_-]+)/);
  if (boot) {
    history.replaceState(null, '', location.pathname);
    try {
      const res = await fetch('/api/v1/auth/admin-bootstrap', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ ticket: boot[1] })
      });
      const j = await res.json();
      if (j.code === 0) {
        S.access = j.data.access_token; S.refresh = j.data.refresh_token || '';
        localStorage.setItem('ag_access', S.access);
        localStorage.setItem('ag_refresh', S.refresh);
        toast('已通过管理票据登录', 'ok');
      } else {
        toast(j.message || '管理票据无效或已过期', 'err');
      }
    } catch(e) { toast('管理票据换取失败', 'err'); }
  }
  if (S.access) { enterApp(); }
});
