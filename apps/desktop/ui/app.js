'use strict';
/* 双传输 invoke 桥：Tauri 窗口内走 IPC；浏览器（Web 远程面）走 HTTP REST。
   REST 端点与命令一一映射（服务端见 crates/client/src/api.rs），信封 {code,data}/{code,message}。 */
const TAURI = window.__TAURI__ || null;
const HTTP_MODE = !TAURI;
let httpToken = localStorage.getItem('ag_web_token') || '';

const CMD_MAP = {
  list_nodes:        ['GET', '/api/v1/nodes'],
  connect_node:      ['POST', '/api/v1/nodes', a => a.input],
  disconnect_node:   ['POST', '/api/v1/nodes/disconnect', a => ({ node_id: a.nodeId })],
  list_credentials:  ['GET', '/api/v1/credentials'],
  delete_credential: ['DELETE', a => '/api/v1/credentials?key=' + encodeURIComponent(a.key)],
  export_credential: ['GET', a => '/api/v1/credentials/export?confirm=true&key=' + encodeURIComponent(a.key)],
  set_rule_paused:   ['POST', '/api/v1/nodes/paused-rules/toggle', a => ({ node_id: a.nodeId, rule_key: a.ruleKey, paused: a.paused })],
  get_paused_rules:  ['GET', a => '/api/v1/nodes/paused-rules?node_id=' + encodeURIComponent(a.nodeId)],
  set_paused_rules:  ['PUT', '/api/v1/nodes/paused-rules', a => ({ node_id: a.nodeId, keys: a.keys })],
  start_proxy:       ['POST', '/api/v1/proxy/start', a => ({ port: a.port })],
  stop_proxy:        ['POST', '/api/v1/proxy/stop'],
  proxy_status:      ['GET', '/api/v1/proxy/status'],
  parse_connect_url: ['POST', '/api/v1/parse-connect-url', a => ({ url: a.url })],
};

async function httpInvoke(cmd, args) {
  const spec = CMD_MAP[cmd];
  if (!spec) throw new Error('该操作不支持 Web 远程调用');
  const method = spec[0], path = spec[1], bodyFn = spec[2];
  const url = typeof path === 'function' ? path(args || {}) : path;
  const headers = { 'Authorization': 'Bearer ' + httpToken };
  if (bodyFn) headers['Content-Type'] = 'application/json';
  const resp = await fetch(url, {
    method,
    headers,
    body: bodyFn ? JSON.stringify(bodyFn(args || {})) : undefined,
  });
  if (resp.status === 401) {
    localStorage.removeItem('ag_web_token');
    httpToken = '';
    showLogin();
    throw new Error('未登录或会话已过期');
  }
  const json = await resp.json().catch(() => ({}));
  if (json.code !== 0) throw new Error(json.message || ('请求失败 (code ' + json.code + ')'));
  return json.data;
}

const invoke = TAURI ? TAURI.core.invoke : httpInvoke;

/* ================= 原生化：屏蔽 WebView 浏览器行为（仅 Tauri 窗口；浏览器远程面不受影响） ================= */
if (TAURI) {
  // 右键菜单 / 拖拽
  document.addEventListener('contextmenu', e => e.preventDefault());
  document.addEventListener('dragstart', e => e.preventDefault());
  // F12 / DevTools / 查看源码 / 刷新 / 打印 / 缩放 等浏览器快捷键
  document.addEventListener('keydown', e => {
    const k = e.key.toLowerCase();
    const devCombo = e.ctrlKey && e.shiftKey && ['i', 'j', 'c'].includes(k);
    const zoomCombo = e.ctrlKey && ['=', '-', '0', '+'].includes(e.key);
    if (e.key === 'F12' || e.key === 'F5' || devCombo || zoomCombo ||
        (e.ctrlKey && ['u', 'r', 'p'].includes(k))) e.preventDefault();
  });
  // Ctrl + 滚轮缩放
  document.addEventListener('wheel', e => { if (e.ctrlKey) e.preventDefault(); }, { passive: false });
  // 关闭表单自动填充 / 拼写检查等浏览器提示
  window.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('input, textarea, select').forEach(el => {
      el.setAttribute('autocomplete', 'off');
      el.setAttribute('spellcheck', 'false');
      el.setAttribute('autocorrect', 'off');
      el.setAttribute('autocapitalize', 'off');
    });
  });
}

/* ---- Web 远程面登录 ---- */
function showLogin() {
  $('login-modal').style.display = 'flex';
  const p = $('login-pass');
  if (p) p.focus();
}
async function webLogin() {
  const pass = $('login-pass').value;
  if (!pass) return;
  try {
    const resp = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: pass }),
    });
    const json = await resp.json();
    if (json.code !== 0) { toast(json.message || '登录失败', 'err'); return; }
    httpToken = json.data.access_token;
    localStorage.setItem('ag_web_token', httpToken);
    location.reload();
  } catch (e) {
    toast('无法连接管理服务', 'err');
  }
}
const $ = (id) => document.getElementById(id);

const PREFS = {
  get autoproxy() { return localStorage.getItem('ag_autoproxy') !== '0'; },
  set autoproxy(v) { localStorage.setItem('ag_autoproxy', v ? '1' : '0'); },
  get autoreconnect() { return localStorage.getItem('ag_autoreconnect') !== '0'; },
  set autoreconnect(v) { localStorage.setItem('ag_autoreconnect', v ? '1' : '0'); },
};

/* ================= i18n & 主题 ================= */
const I18N = {
  zh: {
    'st-connected': '已连接', 'st-connecting': '连接中', 'st-reconnecting': '重连中', 'st-disconnected': '已断开',
    'st-unreachable': '不可达', 'st-degraded': '部分网络不可达',
    'banner-degraded': '端点 {name} 网络不可达，正在自动重连…',
    'banner-down': '端点 {name} 已离线，其网段当前不可达',
    'proxy-running': '代理运行中', 'proxy-stopped': '代理未启动',
    'reconnecting-nodes': '正在自动重连 {n} 个已保存端点…',
    'connected-toast': '已连接 {name}（下发规则 {n} 条）',
    'proxy-on': '代理已启动', 'proxy-off': '代理已停止',
    'btn-start-proxy': '启动代理', 'btn-stop-proxy': '停止代理',
    'err-need-url': '请粘贴接入链接', 'err-bad-url': '链接格式不正确，应以 agilenet://connect? 开头',
    'clip-ok': '已识别剪贴板中的接入链接', 'clip-none': '剪贴板中没有接入链接', 'clip-fail': '无法读取剪贴板',
    'disconnected': '已断开', 'no-nodes': '尚未连接端点', 'no-rules': '无生效规则', 'no-creds': '无保存的凭据',
  },
  en: {
    'st-connected': 'Connected', 'st-connecting': 'Connecting', 'st-reconnecting': 'Reconnecting', 'st-disconnected': 'Disconnected',
    'st-unreachable': 'Unreachable', 'st-degraded': 'Some networks unreachable',
    'banner-degraded': 'Node {name} unreachable, reconnecting…',
    'banner-down': 'Node {name} is offline; its networks are unreachable',
    'proxy-running': 'Proxy running', 'proxy-stopped': 'Proxy stopped',
    'reconnecting-nodes': 'Reconnecting {n} saved nodes…',
    'connected-toast': 'Connected {name} ({n} rules)',
    'proxy-on': 'Proxy started', 'proxy-off': 'Proxy stopped',
    'btn-start-proxy': 'Start Proxy', 'btn-stop-proxy': 'Stop Proxy',
    'err-need-url': 'Please paste a connect URL', 'err-bad-url': 'Invalid URL: must start with agilenet://connect?',
    'clip-ok': 'Connect URL detected in clipboard', 'clip-none': 'No connect URL in clipboard', 'clip-fail': 'Cannot read clipboard',
    'disconnected': 'Disconnected', 'no-nodes': 'No nodes connected', 'no-rules': 'No active rules', 'no-creds': 'No saved credentials',
  },
};
let LANG = localStorage.getItem('ag_lang') || 'zh';
const T = (k) => (I18N[LANG] && I18N[LANG][k]) || I18N.zh[k] || k;
function applyLanguage() { LANG = localStorage.getItem('ag_lang') || 'zh'; refreshNodes(true); refreshProxy(); }
function applyTheme() {
  document.documentElement.dataset.theme = localStorage.getItem('ag_theme') || 'light';
}
// 解析即应用，避免首帧浅色闪烁（与 wiki / 控制台行为一致）
applyTheme();

function esc(s) {
  return String(s ?? '').replace(/[&<>"'`]/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','`':'&#96;'
  }[c]));
}

/* ================= 灵动岛（状态 + 通知 + 异常详情） =================
   形变原则：容器显式宽高动画（overflow:hidden 全程包裹内容），
   旧内容即刻退场、新内容延迟淡入——任何中间帧都不会出现内容溢出岛体。 */
const Island = {
  timer: null, canExpand: false, detailNodes: [], current: 'bar', _t1: null, _t2: null,
  init() {
    $('island-bar').onclick = () => { if (this.canExpand) this.toggleDetail(); };
  },
  _parts() { return { bar: $('island-bar'), msg: $('island-msg'), detail: $('island-detail') }; },
  /** 显式尺寸形变：先量后动、先形后内容（苹果式弹簧）；bar 在 detail 展开/收起间常显 */
  morph(showPart) {
    const el = $('island');
    const parts = this._parts();
    const prev = this.current;
    const same = showPart === prev;
    // 1. 冻结当前渲染尺寸（可从过渡中任意帧打断续接）
    const cw = el.offsetWidth, ch = el.offsetHeight;
    el.style.width = cw + 'px'; el.style.height = ch + 'px';
    // 2. 切换内容布局：detail 态 = bar + 详情共存；新出现的部分占位但不可见
    const barPersist = (showPart === 'detail' && prev === 'bar') || (showPart === 'bar' && prev === 'detail');
    if (!same) {
      for (const [k, p] of Object.entries(parts)) {
        const show = k === showPart || (showPart === 'detail' && k === 'bar');
        p.style.display = show ? (k === 'detail' ? 'block' : 'flex') : 'none';
        p.style.visibility = (show && k === showPart && !(k === 'bar' && barPersist)) ? 'hidden' : '';
      }
    }
    // 3. 量取目标尺寸（临时 auto，同帧内完成不回绘）
    el.style.transition = 'none';
    el.style.width = ''; el.style.height = '';
    const tw = el.offsetWidth, th = el.offsetHeight;
    el.style.width = cw + 'px'; el.style.height = ch + 'px';
    void el.offsetHeight;
    el.style.transition = '';
    // 4. 弹性形变至目标尺寸
    requestAnimationFrame(() => { el.style.width = tw + 'px'; el.style.height = th + 'px'; });
    el.classList.toggle('expanded', showPart !== 'bar');
    el.dataset.state = showPart;  // 三态梯度配色：bar 常驻 / msg 轻梯度 / detail 强梯度
    // 5. 形变过半 → 新内容淡入（模糊+微位移消散）；bar 持续可见的场景无淡出淡入
    clearTimeout(this._t1); clearTimeout(this._t2);
    if (!same && !(showPart === 'bar' && barPersist)) {
      this._t1 = setTimeout(() => {
        const target = parts[showPart];
        target.style.visibility = '';
        target.classList.remove('island-part');
        void target.offsetWidth;
        target.classList.add('island-part');
      }, 200);
    }
    // 6. 收尾释放显式尺寸（回到自适应）
    this._t2 = setTimeout(() => { el.style.width = ''; el.style.height = ''; }, 520);
    this.current = showPart;
  },
  /** 常态状态条。mode: on | off | warn */
  setStatus(mode, text, detailNodes) {
    const t = $('proxy-text');
    const changed = t.textContent !== text;
    if (changed) t.textContent = text;
    const cls = 'dot ' + (mode === 'warn' ? 'warn' : mode);
    if ($('proxy-dot').className !== cls) $('proxy-dot').className = cls;
    this.detailNodes = detailNodes || [];
    this.canExpand = mode === 'warn' && this.detailNodes.length > 0;
    $('island').classList.toggle('warn', mode === 'warn');
    if (!this.canExpand && this.current === 'detail') this.morph('bar');
    else if (this.current === 'detail') this.renderDetail();
    else if (changed && this.current === 'bar') this.morph('bar');  // 文本变长变短也弹性过渡
  },
  /** 瞬时通知（弹性弹出，自动收回） */
  notify(msg, type) {
    clearTimeout(this.timer);
    const m = $('island-msg');
    const ic = type === 'err' ? 'triangle-alert' : (type === 'ok' ? 'check' : 'info');
    m.innerHTML = '<span class="msg-ic">' + AgIcon(ic, 13) + '</span><span>' + esc(msg) + '</span>';
    m.className = 'island-msg ' + (type || 'info');
    this.morph('msg');
    const el = $('island');
    el.classList.remove('pop'); void el.offsetWidth; el.classList.add('pop');
    this.timer = setTimeout(() => this.morph('bar'), 3400);
  },
  toggleDetail() {
    if (this.current === 'detail') { this.morph('bar'); return; }
    this.renderDetail();
    this.morph('detail');
  },
  renderDetail() {
    $('island-detail').innerHTML = '<div class="dt-title">以下端点当前不可达，其网段流量不会进入隧道：</div>' +
      this.detailNodes.map(n =>
        '<div class="island-row"><span class="dot off"></span><b>' + esc(n.node_name) + '</b>' +
        '<span class="mono">' + esc(n.addr) + '</span><span class="st">' + esc(statusText(n.status)) + '</span></div>'
      ).join('');
  },
  hideDetail() { if (this.current === 'detail') this.morph('bar'); },
};
function toast(msg, type) { Island.notify(msg, type); }

/** 把底层错误翻译成用户友好的中文提示 */
function friendlyError(e) {
  const s = String(e);
  if (/login failed|401|invalid username|invalid_credentials/i.test(s)) return '账号或密码错误，请核对接入信息';
  if (/tunnel_token|not a client/i.test(s)) return '该账号不是客户端账号，请向管理员确认';
  if (/certificate|tls|TLS|certificate verify/i.test(s)) return '证书校验失败：请检查证书固定配置，或仅在受信网络开启 insecure';
  if (/timed out|timeout|deadline/i.test(s)) return '连接超时：端点不可达或网络受限';
  if (/ConnectionRefused|refused|10061/i.test(s)) return '无法连接端点：地址/端口错误或端点未启动';
  if (/dns|resolve|lookup/i.test(s)) return '域名解析失败：请检查端点地址';
  if (/account disabled/i.test(s)) return '账号已被禁用，请联系管理员';
  return s.length > 120 ? s.slice(0, 120) + '…' : s;
}

/* ================= 空状态引导 ================= */
function updateOnboarding(nodes) {
  const empty = !nodes || nodes.length === 0;
  $('onboarding').style.display = empty ? 'block' : 'none';
  $('quick-card').style.display = empty ? 'none' : 'block';
  $('creds-card').style.display = (window._creds && Object.keys(window._creds).length) ? 'block' : 'none';
}

/* ================= 列表过滤（搜索） ================= */
const FILTERS = { nodes: '', creds: '', rules: '' };
function bindSearch() {
  document.querySelectorAll('.search-toggle').forEach(btn => {
    btn.onclick = () => {
      const key = btn.dataset.search;
      const row = $('search-' + key);
      const input = row.querySelector('input');
      if (row.hidden) { row.hidden = false; input.focus(); }
      else { row.hidden = true; input.value = ''; setFilter(key, ''); }
    };
  });
  ['nodes', 'creds', 'rules'].forEach(key => {
    $('search-' + key).querySelector('input').oninput = (e) => setFilter(key, e.target.value);
  });
}
function setFilter(key, v) {
  FILTERS[key] = v.trim().toLowerCase();
  if (key === 'nodes') renderNodeList(window._nodes || []);
  if (key === 'rules') renderMergedRules(window._nodes || []);
  if (key === 'creds') renderCredList(window._credsRaw || [], window._nodeStatus || {});
}

/* ================= 节点管理 ================= */
let lastNodesSig = null;
const restoredPaused = new Set();

async function refreshNodes(force) {
  let nodes = [];
  try {
    nodes = await invoke('list_nodes');
  } catch (e) { toast(friendlyError(e), 'err'); updateOnboarding([]); return; }
  window._nodes = nodes;
  window._nodeStatus = Object.fromEntries(nodes.map(n => [n.node_id, n.status]));
  refreshAdminEntry();
  await restorePaused(nodes);
  const sig = JSON.stringify(nodes);
  if (force || sig !== lastNodesSig) {
    lastNodesSig = sig;
    await loadPaused(nodes);
    renderNodeList(nodes);
    renderMergedRules(nodes);
  }
  updateOnboarding(nodes);
}
function statusText(s) {
  if (s === 'Connected') return T('st-connected');
  if (s === 'Connecting') return T('st-connecting');
  if (s === 'Reconnecting') return T('st-reconnecting');
  return T('st-disconnected');
}
function statusBadgeHtml(s) {
  if (s === 'Connected') return '<span class="badge b-ok">' + T('st-connected') + '</span>';
  if (s === 'Connecting') return '<span class="badge b-warn"><span class="pulse"></span>' + T('st-connecting') + '</span>';
  if (s === 'Reconnecting') return '<span class="badge b-warn"><span class="pulse"></span>' + T('st-reconnecting') + '</span>';
  return '<span class="badge b-off">' + T('st-disconnected') + '</span>';
}
function renderNodeList(nodes) {
  const list = $('nodes-list');
  const f = FILTERS.nodes;
  const shown = !f ? nodes : nodes.filter(n =>
    n.node_name.toLowerCase().includes(f) || n.addr.toLowerCase().includes(f) || statusText(n.status).includes(f));
  if (!shown.length) {
    list.innerHTML = '<div class="empty">' + (f ? '无匹配结果' : T('no-nodes')) + '</div>';
    return;
  }
  list.innerHTML = shown.map(n =>
    '<div class="node-card' + (n.status === 'Connected' || n.status === 'Connecting' || n.status === 'Reconnecting' ? '' : ' down') + '"><div class="info">' +
    '<div class="name">' + esc(n.node_name) + (n.username ? ' <span class="dim">· ' + esc(n.username) + '</span>' : '') + ' ' + statusBadgeHtml(n.status) + (n.admin_console ? ' <span class="badge b-info">可管理</span>' : '') + '</div>' +
    '<div class="addr mono">' + esc(n.addr) + ' · 规则 ' + (n.rules || []).length + ' 条 · 配置 v' + n.config_version + '</div>' +
    ((n.manageable || []).length
      ? '<div class="addr" style="margin-top:4px">可管理上游：' + n.manageable.map(m =>
          '<span class="badge b-info">' + esc(m.node_name) + '</span>' +
          (!HTTP_MODE ? ' <button class="ghost small" data-act="upconsole" data-id="' + esc(n.node_id) + '" data-up="' + esc(m.node_name) + '">' + AgIcon('monitor', 12) + ' 管理</button>' : '')
        ).join(' ') + '</div>'
      : '') +
    '</div><div class="card-actions">' +
    (n.admin_console && n.status === 'Connected' && !HTTP_MODE
      ? '<button class="ghost small" data-act="console" data-id="' + esc(n.node_id) + '">' + AgIcon('monitor', 13) + ' 管理此端点</button>' : '') +
    '<button class="danger small" data-act="disconnect" data-id="' + esc(n.node_id) + '">断开</button></div></div>'
  ).join('');
}

/* ---- 路由合并视图（可暂停单条规则） ---- */
function ruleKey(r) { return (r.type + ':' + r.value).toLowerCase(); }
async function loadPaused(nodes) {
  const map = {};
  for (const n of nodes) {
    try { map[n.node_id] = new Set(await invoke('get_paused_rules', { nodeId: n.node_id })); }
    catch (e) { map[n.node_id] = new Set(); }
  }
  window._paused = map;
}
async function restorePaused(nodes) {
  let saved;
  try { saved = JSON.parse(localStorage.getItem('ag_paused_rules') || '{}'); } catch (e) { return; }
  for (const n of nodes) {
    if (restoredPaused.has(n.node_id)) continue;
    restoredPaused.add(n.node_id);
    const keys = saved[n.node_id];
    if (keys && keys.length) {
      try { await invoke('set_paused_rules', { nodeId: n.node_id, keys }); } catch (e) {}
    }
  }
}
function persistPaused() {
  const out = {};
  for (const [k, set] of Object.entries(window._paused || {})) out[k] = [...set];
  localStorage.setItem('ag_paused_rules', JSON.stringify(out));
}
function renderMergedRules(nodes) {
  const f = FILTERS.rules;
  const pausedMap = window._paused || {};
  const rows = [];
  for (const n of nodes) {
    const dot = n.status === 'Connected' ? 'ok' : (n.status === 'Disconnected' ? 'down' : 'warn');
    const pset = pausedMap[n.node_id] || new Set();
    for (const r of (n.rules || [])) {
      const key = ruleKey(r);
      if (f && !(r.value.toLowerCase().includes(f) || r.type.toLowerCase().includes(f) || n.node_name.toLowerCase().includes(f))) continue;
      const paused = pset.has(key);
      rows.push('<tr class="' + (paused ? 'rule-paused' : '') + '"><td><span class="rdot ' + dot + '"></span><span class="badge b-ok">' + esc(r.type) + '</span></td>' +
        '<td class="mono">' + esc(r.value) + '</td>' +
        '<td style="color:var(--dim)">' + esc(n.node_name) + '</td>' +
        '<td><label class="switch"><input type="checkbox" data-node="' + esc(n.node_id) + '" data-rule="' + esc(key) + '"' + (paused ? '' : ' checked') + '><span class="slider"></span></label></td></tr>');
    }
  }
  $('rules-body').innerHTML = rows.join('') || '<tr><td colspan="4" class="empty">' + (f ? '无匹配结果' : T('no-rules')) + '</td></tr>';
}
async function toggleRule(nodeId, key, paused) {
  try {
    await invoke('set_rule_paused', { nodeId, ruleKey: key, paused });
    const map = window._paused || (window._paused = {});
    const set = map[nodeId] || (map[nodeId] = new Set());
    if (paused) set.add(key); else set.delete(key);
    persistPaused();
    const tr = document.querySelector('input[data-node][data-rule="' + CSS.escape(key) + '"]');
    if (tr) tr.closest('tr').classList.toggle('rule-paused', paused);
    toast(paused ? '已暂停该规则（立即生效）' : '已恢复该规则', 'ok');
  } catch (e) {
    toast(friendlyError(e), 'err');
    refreshNodes(true);
  }
}

async function disconnectNode(nodeId) {
  try {
    await invoke('disconnect_node', { nodeId });
    toast(T('disconnected'), 'ok');
    refreshNodes(true);
    refreshCreds();
    refreshProxy();
  } catch (e) { toast(friendlyError(e), 'err'); }
}

/** 带加载状态的连接执行 */
async function connectWith(input, btn) {
  let originalText = null;
  if (btn) {
    originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>连接中…';
  }
  try {
    const st = await invoke('connect_node', { input });
    toast(T('connected-toast').replace('{name}', st.node_name).replace('{n}', st.rules.length), 'ok');
    // 连接成功后按需自动启动代理
    if (PREFS.autoproxy) {
      try {
        const ps = await invoke('proxy_status');
        if (!ps.running) {
          const port = parseInt($('proxy-port').value || '57890', 10);
          await invoke('start_proxy', { port });
        }
      } catch (e) { /* 代理自启失败不阻塞连接 */ }
    }
    refreshNodes(true);
    refreshCreds();
    refreshProxy();
    return true;
  } catch (e) {
    toast(friendlyError(e), 'err');
    return false;
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = originalText;
    }
  }
}

/* ================= 管理端模式（内嵌 iframe 承载管理 SPA；不开子窗口） ================= */
let ADMIN = null; // { label, url, origin }

const curTheme = () => localStorage.getItem('ag_theme') || 'light';

async function enterAdmin(nodeId, upstream, label) {
  let url;
  try {
    url = await invoke('console_url', { nodeId: nodeId || null, upstream: upstream || null, theme: curTheme() });
  } catch (e) { toast(friendlyError(e), 'err'); return; }
  ADMIN = { label, url, origin: new URL(url).origin };
  $('admin-frame').src = url;
  document.querySelector('.content').classList.add('admin-mode');
  $('nav-client').style.display = 'none';
  $('nav-admin').style.display = 'flex';
  document.querySelectorAll('.view').forEach(s => { s.hidden = s.id !== 'view-admin'; });
  adminNavActivate('dashboard');
  toast('已进入管理端：' + label, 'ok');
}

function exitAdmin() {
  if (!ADMIN) return;
  $('admin-frame').src = 'about:blank';
  ADMIN = null;
  document.querySelector('.content').classList.remove('admin-mode');
  $('nav-admin').style.display = 'none';
  $('nav-client').style.display = 'flex';
  switchView('connect');
}

function adminNavActivate(v) {
  document.querySelectorAll('#nav-admin .nav-item[data-aview]').forEach(n =>
    n.classList.toggle('active', n.dataset.aview === v));
  if (ADMIN) {
    const f = $('admin-frame');
    if (f && f.contentWindow) f.contentWindow.postMessage({ type: 'ag-nav', view: v }, ADMIN.origin);
  }
}

/** 标题栏管理端入口：本机服务端恒第一，可管理端点/上游按名称排序；无项置灰 */
async function refreshAdminEntry() {
  const items = [];
  try {
    const st = await invoke('server_status');
    if (st && st.running) items.push({ kind: 'local', label: '本机服务端', sub: '内嵌端点' });
  } catch (e) {}
  const nodes = window._nodes || [];
  const remotes = [];
  for (const n of nodes) {
    if (n.admin_console && n.status === 'Connected') {
      remotes.push({ kind: 'node', id: n.node_id, label: n.node_name + (n.username ? ' · ' + n.username : ''), sub: n.addr });
    }
    for (const m of (n.manageable || [])) {
      if (n.status === 'Connected') {
        remotes.push({ kind: 'up', id: n.node_id, up: m.node_name, label: m.node_name, sub: '上游 · 经 ' + n.node_name });
      }
    }
  }
  remotes.sort((a, b) => a.label.localeCompare(b.label, 'zh'));
  items.push(...remotes);
  const btn = $('btn-admin');
  btn.classList.toggle('disabled', !items.length);
  const menu = $('admin-menu');
  menu.innerHTML = items.length
    ? items.map((it, i) =>
        '<button data-aitem="' + i + '">' + AgIcon('fingerprint', 13) + '<span class="aitem-label">' + esc(it.label) + '</span><span class="aitem-sub">' + esc(it.sub) + '</span></button>'
      ).join('')
    : '<button disabled>暂无可管理端点</button>';
  menu._items = items;
}

function initAdminMode() {
  $('nav-admin-back').onclick = exitAdmin;
  document.querySelectorAll('#nav-admin .nav-item[data-aview]').forEach(n => {
    n.onclick = () => adminNavActivate(n.dataset.aview);
  });
  const menu = $('admin-menu');
  $('btn-admin').onclick = (e) => {
    e.stopPropagation();
    if ($('btn-admin').classList.contains('disabled')) return;
    menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
  };
  document.addEventListener('click', (e) => {
    if (!e.target.closest('#admin-menu') && !e.target.closest('#btn-admin')) menu.style.display = 'none';
    const btn = e.target.closest('#admin-menu [data-aitem]');
    if (!btn) return;
    menu.style.display = 'none';
    const it = (menu._items || [])[+btn.dataset.aitem];
    if (!it) return;
    if (it.kind === 'local') enterAdmin(null, null, it.label);
    else if (it.kind === 'node') enterAdmin(it.id, null, it.label);
    else enterAdmin(it.id, it.up, it.label);
  });
}

/* ================= 控制台通道（管理此端点 / 可管理上游；内嵌进主窗口） ================= */
async function openNodeConsole(nodeId) {
  const n = (window._nodes || []).find(x => x.node_id === nodeId);
  const label = n ? n.node_name + (n.username ? ' · ' + n.username : '') : nodeId;
  await enterAdmin(nodeId, null, label);
}
async function openUpstreamConsole(nodeId, upstream) {
  await enterAdmin(nodeId, upstream, upstream);
}

/* ================= 接入链接导入 ================= */
async function importUrl(url, btn) {
  url = (url || '').trim();
  if (!url) { toast(T('err-need-url'), 'err'); return; }
  if (!url.startsWith('agilenet://connect?')) { toast(T('err-bad-url'), 'err'); return; }
  try {
    const input = await invoke('parse_connect_url', { url });
    if (input.admin) toast('该链接为管理版：连接后可在端点卡片管理此端点', 'info');
    await connectWith(input, btn);
  } catch (e) { toast(friendlyError(e), 'err'); }
}

async function pasteFromClipboard() {
  try {
    const text = await navigator.clipboard.readText();
    if (text && text.trim().startsWith('agilenet://connect?')) {
      $('connect-url-hero') && ($('connect-url-hero').value = text.trim());
      $('connect-url') && ($('connect-url').value = text.trim());
      toast(T('clip-ok'), 'ok');
      await importUrl(text, null);
    } else {
      toast(T('clip-none'), 'err');
    }
  } catch (e) {
    toast(T('clip-fail'), 'err');
  }
}

/* ================= 代理控制 ================= */
async function refreshProxy() {
  try {
    const st = await invoke('proxy_status');
    const nodes = await invoke('list_nodes').catch(() => []);
    const degraded = nodes.filter(n => n.status !== 'Connected');
    let mode, text;
    if (nodes.length && degraded.length) {
      mode = 'warn';
      text = T('st-degraded') + '（' + degraded.length + '）';
    } else if (st.running) {
      mode = 'on';
      text = T('proxy-running') + ' 127.0.0.1:' + st.port;
    } else {
      mode = 'off';
      text = T('proxy-stopped');
    }
    Island.setStatus(mode, text, degraded);
    const btnText = st.running ? T('btn-stop-proxy') : T('btn-start-proxy');
    if ($('btn-proxy-toggle').textContent !== btnText) $('btn-proxy-toggle').textContent = btnText;
    const hint = st.running
      ? (CUR_PROXY_MODE === 'system'
        ? '已接管系统代理 127.0.0.1:' + st.port + '，浏览器即开即用'
        : '本地代理运行中，应用手动指向 127.0.0.1:' + st.port + ' 即可')
      : '';
    if ($('proxy-hint').textContent !== hint) $('proxy-hint').textContent = hint;
  } catch (e) {}
}
async function toggleProxy() {
  try {
    const st = await invoke('proxy_status');
    if (st.running) {
      await invoke('stop_proxy');
      toast(T('proxy-off'), 'ok');
    } else {
      const port = parseInt($('proxy-port').value || '57890', 10);
      const actual = await invoke('start_proxy', { port });
      toast(T('proxy-on') + ' 127.0.0.1:' + actual, 'ok');
    }
    refreshProxy();
  } catch (e) { toast(friendlyError(e), 'err'); }
}

/* ================= 已保存凭据（管理：连接/断开/导出/删除） ================= */
async function refreshCreds() {
  try {
    const creds = await invoke('list_credentials');
    window._credsRaw = creds;
    window._creds = Object.fromEntries(creds);
    renderCredList(creds, window._nodeStatus || {});
    invoke('list_nodes').then(nodes => updateOnboarding(nodes)).catch(() => {});
  } catch (e) {}
}
function renderCredList(creds, statusMap) {
  const list = $('creds-list');
  const f = FILTERS.creds;
  const shown = !f ? creds : creds.filter(([key, c]) =>
    c.username.toLowerCase().includes(f) || c.addr.toLowerCase().includes(f) || key.toLowerCase().includes(f));
  if (!shown.length) {
    list.innerHTML = '<div class="empty">' + (f ? '无匹配结果' : T('no-creds')) + '</div>';
    return;
  }
  list.innerHTML = shown.map(([key, c]) => {
    const st = statusMap[key];
    const badge = st ? statusBadgeHtml(st) : '<span class="badge b-gray">未连接</span>';
    const mainBtn = st === 'Connected'
      ? '<button class="ghost small" data-act="disconnect" data-key="' + esc(key) + '">断开</button>'
      : '<button class="ghost small" data-act="reconnect" data-key="' + esc(key) + '">' + (st ? '重连' : '连接') + '</button>';
    const epName = key.includes('@') ? key.slice(0, key.indexOf('@')) : key;
    return '<div class="node-card"><div class="info">' +
      '<div class="name">' + esc(epName) + ' <span class="dim">· ' + esc(c.username) + '</span> ' + badge + '</div>' +
      '<div class="addr mono">' + esc(c.addr) + (c.insecure ? ' · <span class="badge b-warn">insecure</span>' : '') + '</div>' +
      '</div><div class="card-actions">' + mainBtn +
      '<button class="ghost small icon-btn" title="导出接入链接（复制到剪贴板）" data-act="export" data-key="' + esc(key) + '">' + AgIcon('share-2', 13) + '</button>' +
      '<button class="danger small icon-btn" title="删除该凭据" data-act="delcred" data-key="' + esc(key) + '">' + AgIcon('trash-2', 13) + '</button>' +
      '</div></div>';
  }).join('');
}
async function reconnectSaved(key, btn) {
  const c = (window._creds || {})[key];
  if (!c) return;
  await connectWith({
    addr: c.addr, username: c.username, password: c.password,
    insecure: c.insecure, pinned_cert_path: null, pinned_fingerprint: c.pinned_fingerprint || null,
    manage_hosts: false, save_credential: true,
  }, btn || null);
}
async function exportCred(key) {
  // 凭据导出含明文密码：Web 远程面需二次确认
  if (HTTP_MODE && !window.confirm('导出的接入链接包含明文密码，确定导出到剪贴板吗？')) return;
  try {
    const url = await invoke('export_credential', { key });
    await navigator.clipboard.writeText(url);
    toast('接入链接已复制到剪贴板（含明文密码，谨慎分享）', 'ok');
  } catch (e) { toast(friendlyError(e), 'err'); }
}
async function deleteCred(key, btn) {
  if (btn.dataset.confirm === '1') {
    try {
      await invoke('delete_credential', { key });
      toast('已删除保存的端点', 'ok');
      refreshCreds();
    } catch (e) { toast(friendlyError(e), 'err'); }
    return;
  }
  btn.dataset.confirm = '1';
  const old = btn.innerHTML;
  btn.innerHTML = '<span style="font-size:11px">确认</span>';
  setTimeout(() => { if (btn.isConnected) { btn.dataset.confirm = ''; btn.innerHTML = old; } }, 2500);
}

/* ================= 三路角色开关 ================= */
let pwdResolver = null;

/** 强制设置管理密码弹窗（Promise 化；取消 resolve null） */
function askPassword(opts) {
  return new Promise((resolve) => {
    $('pwd-title').innerHTML = AgIcon('shield', 16) + ' ' + esc(opts.title);
    $('pwd-desc').textContent = opts.desc;
    $('pwd-user-row').style.display = opts.showUser ? 'block' : 'none';
    $('pwd-pass').value = ''; $('pwd-pass2').value = '';
    $('pwd-modal').style.display = 'flex';
    $('pwd-pass').focus();
    pwdResolver = resolve;
  });
}
function closePwdModal(result) {
  $('pwd-modal').style.display = 'none';
  if (pwdResolver) { const r = pwdResolver; pwdResolver = null; r(result); }
}
function applyClientRole(on) {
  $('role-banner').style.display = on ? 'none' : 'flex';
}
async function refreshServerPanel() {
  let st = null;
  try { st = await invoke('server_status'); } catch (e) { return; }
  window._serverStatus = st;
  const on = $('r-server').checked || st.running;
  $('server-panel').style.display = on ? 'block' : 'none';
  $('sv-api').textContent = st.api_addr || '-';
  $('sv-relay').textContent = st.relay_addr || '-';
}
function refreshWebPanel() {
  const on = $('r-web').checked;
  $('web-panel').style.display = on ? 'block' : 'none';
  $('web-status').textContent = on ? '监听地址保存后生效；浏览器访问需输入管理密码' : '';
}
async function initRoles() {
  let settings = { client: true, server: false, web: false, web_listen: '127.0.0.1:59291' };
  try { settings = await invoke('get_role_settings'); } catch (e) {}
  $('r-client').checked = settings.client;
  $('r-server').checked = settings.server;
  $('r-web').checked = settings.web;
  $('s-unified').checked = settings.subscription_unified !== false;
  applySubFeature(!!settings.subscription_feature);
  $('web-listen').value = settings.web_listen;
  applyClientRole(settings.client);
  refreshServerPanel();
  refreshWebPanel();

  $('r-client').onchange = async (e) => {
    try {
      await invoke('set_client_role', { enabled: e.target.checked });
      applyClientRole(e.target.checked);
      toast(e.target.checked ? '客户端角色已开启' : '客户端角色已停用（已断开全部端点）', 'ok');
      if (e.target.checked) { refreshNodes(true); refreshProxy(); refreshCreds(); }
    } catch (err) {
      e.target.checked = !e.target.checked;
      toast(friendlyError(err), 'err');
    }
  };

  $('r-server').onchange = async (e) => {
    const on = e.target.checked;
    try {
      if (on) {
        // 首开强制设管理密码
        const st = await invoke('server_status');
        if (!st.has_admin) {
          e.target.checked = false;
          const cred = await askPassword({
            title: '设置服务端管理密码',
            desc: '首开服务端角色须先设置内嵌端点管理员，该密码用于登录控制台。',
            showUser: true,
          });
          if (!cred) return;
          await invoke('init_server_admin', { username: cred.user, password: cred.pass });
          e.target.checked = true;
          toast('管理员已创建', 'ok');
        }
      }
      await invoke('set_server_role', { enabled: on });
      await refreshServerPanel();
      refreshAdminEntry();
      toast(on ? '服务端角色已开启（内嵌端点运行中）' : '服务端角色已关闭', 'ok');
    } catch (err) {
      e.target.checked = false;
      toast(friendlyError(err), 'err');
      refreshServerPanel();
    }
  };

  $('r-web').onchange = async (e) => {
    const on = e.target.checked;
    try {
      if (on && !(await invoke('has_web_password'))) {
        e.target.checked = false;
        const cred = await askPassword({
          title: '设置 Web 远程面管理密码',
          desc: '开启 Web 远程面前须先设置管理密码；从浏览器访问本机管理界面时需输入。',
          showUser: false,
        });
        if (!cred) return;
        await invoke('set_web_password', { password: cred.pass });
        e.target.checked = true;
        toast('管理密码已设置', 'ok');
      }
      await invoke('set_web_role', { enabled: on, listen: $('web-listen').value.trim() || null });
      refreshWebPanel();
      toast(on ? 'Web 远程面已开启' : 'Web 远程面已关闭', 'ok');
    } catch (err) {
      e.target.checked = !on;
      toast(friendlyError(err), 'err');
    }
  };

  $('btn-web-listen-save').onclick = async () => {
    try {
      await invoke('set_web_role', { enabled: $('r-web').checked, listen: $('web-listen').value.trim() });
      toast('监听地址已保存', 'ok');
    } catch (err) { toast(friendlyError(err), 'err'); }
  };

  $('btn-open-console').onclick = () => enterAdmin(null, null, '本机服务端');

  // 上游中继（路由再发布）配置
  const sc = settings.server_connector || null;
  if (sc) {
    $('sc-upstream').value = sc.upstream_addr || '';
    $('sc-token').value = sc.token || '';
    $('sc-sni').value = sc.sni_hostname || 'cdn.cloudflare.com';
    $('sc-insecure').checked = !!sc.insecure;
    $('sc-status').textContent = '已配置，内嵌端点将作为下游接入 ' + sc.upstream_addr;
  }
  $('btn-sc-save').onclick = async () => {
    const cfg = {
      upstream_addr: $('sc-upstream').value.trim(),
      token: $('sc-token').value.trim(),
      sni_hostname: $('sc-sni').value.trim() || 'cdn.cloudflare.com',
      insecure: $('sc-insecure').checked,
    };
    if (!cfg.upstream_addr || !cfg.token) { toast('请填写上游地址与 Relay Token', 'err'); return; }
    try {
      await invoke('set_server_connector', { config: cfg });
      $('sc-status').textContent = '已配置，内嵌端点将作为下游接入 ' + cfg.upstream_addr;
      toast('上游中继已保存（客户端隧道规则将转售给下游）', 'ok');
    } catch (err) { toast(friendlyError(err), 'err'); }
  };
  $('btn-sc-clear').onclick = async () => {
    try {
      await invoke('set_server_connector', { config: null });
      $('sc-upstream').value = ''; $('sc-token').value = '';
      $('sc-status').textContent = '';
      toast('已清除上游中继配置', 'ok');
    } catch (err) { toast(friendlyError(err), 'err'); }
  };

  $('pwd-cancel').onclick = () => closePwdModal(null);
  $('pwd-ok').onclick = () => {
    const user = $('pwd-user').value.trim();
    const p1 = $('pwd-pass').value, p2 = $('pwd-pass2').value;
    if ($('pwd-user-row').style.display !== 'none' && !user) { toast('请填写管理员账号', 'err'); return; }
    if (p1.length < 10) { toast('管理密码至少 10 位', 'err'); return; }
    if (p1 !== p2) { toast('两次输入的密码不一致', 'err'); return; }
    closePwdModal({ user, pass: p1 });
  };
}

/* ================= 订阅代理（mihomo sidecar） ================= */
let SUBS = [];
let PROXY_DATA = null;
let PROXY_CACHED = false; // true = 内核未运行，展示缓存快照（只读）
let CUR_GROUP = null;

/** 功能入口可见性（安装激活后侧栏出现「订阅/代理」） */
function applySubFeature(on) {
  document.querySelectorAll('.nav-item.sub-feature').forEach(n => { n.style.display = on ? '' : 'none'; });
  $('btn-activate-sub').style.display = on ? 'none' : '';
  $('btn-deactivate-sub').style.display = on ? '' : 'none';
}

function fmtBytes(n) {
  if (!n) return '0B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (v >= 100 ? v.toFixed(0) : v.toFixed(1)) + u[i];
}
function fmtDate(ts) { return ts ? new Date(ts * 1000).toLocaleDateString() : ''; }
function fmtAgo(ts) {
  if (!ts) return '未刷新';
  const d = Date.now() / 1000 - ts;
  if (d < 3600) return Math.max(1, Math.floor(d / 60)) + ' 分钟前';
  if (d < 86400) return Math.floor(d / 3600) + ' 小时前';
  if (d < 86400 * 30) return Math.floor(d / 86400) + ' 天前';
  return Math.floor(d / 86400 / 30) + ' 个月前';
}

async function refreshSubs() {
  try { SUBS = await invoke('list_subscriptions'); } catch (e) { SUBS = []; }
  const list = $('subs-list');
  const active = SUBS.find(s => s.active);
  $('proxy-sub-desc').textContent = active
    ? '当前激活：' + active.name + '（' + active.node_count + ' 节点）— 点击卡片切换，点闪电图标单点测速'
    : '请先在「订阅」页激活一个订阅';
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
  // 无论内核是否运行都刷新代理页（未运行时回落缓存快照，方便查看节点情况）
  refreshGroups();
}

/* ---------- 代理页 ---------- */
async function refreshGroups() {
  let d;
  try { d = await invoke('proxy_groups'); } catch (e) {
    PROXY_CACHED = false;
    $('group-tabs').innerHTML = '';
    $('node-grid').innerHTML = '<div class="empty">订阅内核未运行，且暂无节点缓存</div>';
    return;
  }
  PROXY_CACHED = !!d.cached;
  PROXY_DATA = (d && d.proxies) || {};
  // 隐藏 mihomo 内置 GLOBAL 组；技术名映射为友好名
  const GROUP_LABELS = { 'AGILE-SUB': '订阅节点' };
  const groups = Object.entries(PROXY_DATA).filter(([n, p]) =>
    n !== 'GLOBAL' && p.all && ['Selector', 'URLTest', 'Fallback'].includes(p.type));
  if (!groups.length) {
    $('group-tabs').innerHTML = '';
    $('node-grid').innerHTML = '<div class="empty">暂无节点（请到「订阅」页刷新订阅）</div>';
    return;
  }
  if (!CUR_GROUP || !groups.some(([n]) => n === CUR_GROUP)) CUR_GROUP = groups[0][0];
  $('group-tabs').innerHTML = groups.map(([n]) =>
    '<button class="group-tab' + (n === CUR_GROUP ? ' active' : '') + '" data-group-tab="' + esc(n) + '">' + esc(GROUP_LABELS[n] || n) + '</button>'
  ).join('');
  // 缓存态：只读展示，隐藏测速入口并给出说明
  if (PROXY_CACHED) {
    $('proxy-sub-desc').textContent = '订阅内核未运行，以下为最近缓存节点（测速与切换不可用）';
  }
  $('btn-test-all').style.display = PROXY_CACHED ? 'none' : '';
  renderNodeGrid();
}

function renderNodeGrid() {
  const g = PROXY_DATA && PROXY_DATA[CUR_GROUP];
  if (!g) return;
  $('node-grid').innerHTML = g.all.map(n => {
    const p = PROXY_DATA[n] || {};
    const hist = (p.history && p.history.length) ? p.history[p.history.length - 1].delay : 0;
    const cur = g.now === n;
    return '<div class="node-card' + (cur ? ' current' : '') + '" data-group="' + esc(CUR_GROUP) + '" data-node="' + esc(n) + '">' +
      '<div class="node-name">' + (cur ? '<span class="node-check">' + AgIcon('check', 11) + '</span>' : '') +
      '<span class="node-name-text" title="' + esc(n) + '">' + esc(n) + '</span></div>' +
      '<div class="node-foot"><span class="node-proto">' + esc(p.type || '') + '</span>' +
      '<span class="node-delay' + (hist ? ' ok' : '') + '">' + (hist ? hist + ' ms' : '') + '</span>' +
      (PROXY_CACHED ? '' : '<button class="node-test" data-test="' + esc(n) + '" title="测速">' + AgIcon('zap', 13) + '</button>') +
      '</div></div>';
  }).join('');
}

// provider 节点无单节点测速 API，后端仍是整组并发测（耗时相同），但单点只更新本卡片
async function testNode(btn) {
  const card = btn.closest('.node-card');
  const delayEl = card.querySelector('.node-delay');
  delayEl.textContent = '…';
  delayEl.className = 'node-delay';
  let map;
  try {
    map = await invoke('test_delay', { group: CUR_GROUP });
  } catch (e) {
    delayEl.textContent = '超时';
    delayEl.className = 'node-delay bad';
    toast(friendlyError(e), 'err');
    return;
  }
  const ms = map[card.dataset.node];
  if (ms) {
    delayEl.textContent = ms + ' ms';
    delayEl.className = 'node-delay ok';
  } else {
    delayEl.textContent = '超时';
    delayEl.className = 'node-delay bad';
  }
}

async function testGroup() {
  const cards = [...$('node-grid').querySelectorAll('.node-card')];
  if (!cards.length) return;
  cards.forEach(c => {
    const el = c.querySelector('.node-delay');
    el.textContent = '…';
    el.className = 'node-delay';
  });
  let map;
  try {
    map = await invoke('test_delay', { group: CUR_GROUP });
  } catch (e) {
    cards.forEach(c => {
      const el = c.querySelector('.node-delay');
      el.textContent = '超时';
      el.className = 'node-delay bad';
    });
    toast(friendlyError(e), 'err');
    return;
  }
  cards.forEach(c => {
    const el = c.querySelector('.node-delay');
    const ms = map[c.dataset.node];
    if (ms) {
      el.textContent = ms + ' ms';
      el.className = 'node-delay ok';
    } else {
      el.textContent = '超时';
      el.className = 'node-delay bad';
    }
  });
}

function openSubModal() {
  $('sub-name').value = ''; $('sub-url').value = ''; $('sub-err').textContent = '';
  $('sub-modal').style.display = 'flex';
  $('sub-url').focus();
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

  /* 内核角色开关（订阅页内核卡） */
  $('r-sub').onchange = async (e) => {
    const on = e.target.checked;
    e.target.disabled = true;
    try {
      if (on && !SUBS.length) {
        e.target.checked = false;
        toast('请先添加订阅', 'err');
        openSubModal();
        return;
      }
      await invoke('set_subscription_role', { enabled: on });
      toast(on ? '订阅代理已开启（内核运行中）' : '订阅代理已关闭', 'ok');
      refreshSubStatus();
    } catch (err) {
      e.target.checked = !on;
      toast(friendlyError(err), 'err');
    } finally {
      e.target.disabled = false;
    }
  };
  $('s-unified').onchange = async (e) => {
    try {
      await invoke('set_subscription_unified', { enabled: e.target.checked });
      toast(e.target.checked ? '统一出口已开启（57890 单端口）' : '统一出口已关闭', 'ok');
    } catch (err) { e.target.checked = !e.target.checked; toast(friendlyError(err), 'err'); }
  };

  /* 代理页事件 */
  $('group-tabs').addEventListener('click', (e) => {
    const tab = e.target.closest('[data-group-tab]');
    if (!tab) return;
    CUR_GROUP = tab.dataset.groupTab;
    refreshGroups();
  });
  $('node-grid').addEventListener('click', async (e) => {
    const testBtn = e.target.closest('.node-test');
    if (testBtn) {
      e.stopPropagation();
      testNode(testBtn);
      return;
    }
    const card = e.target.closest('.node-card');
    if (!card) return;
    if (PROXY_CACHED) { toast('订阅内核未运行，仅展示缓存节点', 'err'); return; }
    try {
      await invoke('select_proxy', { group: card.dataset.group, name: card.dataset.node });
      document.querySelectorAll('.node-card').forEach(c => c.classList.toggle('current', c === card));
      toast('已切换到 ' + card.dataset.node, 'ok');
    } catch (err) { toast(friendlyError(err), 'err'); }
  });
  $('btn-test-all').onclick = async () => {
    const btns = [...$('node-grid').querySelectorAll('.node-test')];
    if (!btns.length) return;
    toast('正在测速（' + btns.length + ' 个节点）…', 'ok');
    await testGroup();
  };
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
  $('btn-install-kernel').onclick = async (e) => {
    const btn = e.target.closest('button');
    btn.disabled = true;
    const old = btn.innerHTML;
    btn.innerHTML = AgIcon('download', 13) + ' 下载校验中…';
    try {
      await invoke('install_kernel');
      toast('内核安装完成', 'ok');
      refreshSubFeature();
    } catch (err) { toast(friendlyError(err), 'err'); }
    finally { btn.disabled = false; btn.innerHTML = old; }
  };
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

/* ================= 系统代理托管 ================= */
let _spConflict = false;
let CUR_PROXY_MODE = 'system'; // system=接管系统代理（默认） / local=仅监听端口
async function refreshSysproxy() {
  let st;
  try { st = await invoke('sysproxy_status'); } catch (e) { return; }
  CUR_PROXY_MODE = st.managed ? 'system' : 'local';
  document.querySelectorAll('#proxy-mode .group-tab').forEach(b =>
    b.classList.toggle('active', b.dataset.proxyMode === CUR_PROXY_MODE));
  const banner = $('sysproxy-banner');
  if (st.managed && st.conflict) {
    banner.style.display = 'flex';
    $('sysproxy-banner-text').textContent = '系统代理已被外部修改（当前 ' + (st.current || '未启用') + '，期望 ' + st.expected + '）';
    if (!_spConflict) { _spConflict = true; toast('系统代理已被外部修改，可在「连接」页收回', 'err'); }
  } else {
    banner.style.display = 'none';
    _spConflict = false;
  }
}
function initSysproxy() {
  $('proxy-mode').addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-proxy-mode]');
    if (!btn || btn.classList.contains('active')) return;
    try {
      if (btn.dataset.proxyMode === 'system') {
        // 代理未启动则先按当前端口启动（后端 set_system_proxy 亦会兜底拉起）
        const st = await invoke('proxy_status');
        if (!st.running) {
          const port = parseInt($('proxy-port').value || '57890', 10);
          await invoke('start_proxy', { port });
        }
        await invoke('set_system_proxy', { enabled: true });
        toast('已切换到系统代理（自动接管系统流量）', 'ok');
      } else {
        await invoke('set_system_proxy', { enabled: false });
        toast('已切换到本地代理（手动指向 127.0.0.1:' + ($('proxy-port').value || '57890') + '）', 'ok');
      }
      refreshSysproxy();
      refreshProxy();
    } catch (err) { toast(friendlyError(err), 'err'); }
  });
  $('btn-sysproxy-reclaim').onclick = async () => {
    try { await invoke('reclaim_sysproxy'); toast('已收回系统代理', 'ok'); refreshSysproxy(); }
    catch (err) { toast(friendlyError(err), 'err'); }
  };
}

/* ================= 设置 ================= */
async function loadSettings() {
  $('s-autoproxy').checked = PREFS.autoproxy;
  $('s-autoreconnect').checked = PREFS.autoreconnect;
  try {
    $('s-autostart').checked = await invoke('get_autostart');
  } catch (e) {}

  $('s-autoproxy').onchange = (e) => { PREFS.autoproxy = e.target.checked; };
  $('s-autoreconnect').onchange = (e) => { PREFS.autoreconnect = e.target.checked; };
  $('s-autostart').onchange = async (e) => {
    try {
      await invoke('set_autostart', { enabled: e.target.checked });
      toast(e.target.checked ? '已开启开机自启' : '已关闭开机自启', 'ok');
    } catch (err) {
      e.target.checked = !e.target.checked;
      toast(friendlyError(err), 'err');
    }
  };
}

/* ================= 标题栏（折叠 / 更多菜单 / 关于） ================= */
const LINKS = {
  docs: 'https://anet.icen.ai',
  issue: 'https://github.com/icen-ai/agile-net/issues',
  update: 'https://github.com/icen-ai/agile-net/releases',
  github: 'https://github.com/icen-ai/agile-net',
};
function openLink(url) {
  if (TAURI) { TAURI.core.invoke('open_url', { url }).catch(() => {}); }
  else window.open(url, '_blank', 'noopener');
}
function initTitlebarExtra() {
  // 侧栏折叠（记忆）
  if (localStorage.getItem('ag_sidebar') === 'collapsed') document.body.classList.add('collapsed');
  $('btn-collapse').onclick = () => {
    const collapsed = document.body.classList.toggle('collapsed');
    localStorage.setItem('ag_sidebar', collapsed ? 'collapsed' : '');
  };
  // 更多菜单（点外部关闭）
  const menu = $('more-menu');
  $('btn-more').onclick = (e) => {
    e.stopPropagation();
    menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
  };
  document.addEventListener('click', (e) => {
    if (!e.target.closest('#more-menu') && !e.target.closest('#btn-more')) menu.style.display = 'none';
  });
  // 菜单与关于弹窗动作
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-more]');
    if (!btn) return;
    const act = btn.dataset.more;
    menu.style.display = 'none';
    if (act === 'about') {
      $('about-modal').style.display = 'flex';
    } else if (LINKS[act]) {
      openLink(LINKS[act]);
    }
  });
  $('about-close').onclick = () => { $('about-modal').style.display = 'none'; };
}

/* ================= 视图导航 & 窗口控制 ================= */
function switchView(v) {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.view === v));
  document.querySelectorAll('.view').forEach(s => { s.hidden = s.id !== 'view-' + v; });
  if (v === 'nodes' || v === 'routes') refreshNodes();
  if (v === 'connect') refreshCreds();
  if (v === 'subscription') { refreshSubs(); refreshSubStatus(); }
  if (v === 'proxy') { refreshSubs(); refreshGroups(); }
  if (v === 'settings') { refreshSysproxy(); refreshSubFeature(); }
}
function initTitlebar() {
  if (!TAURI || !TAURI.window) return;
  const win = TAURI.window.getCurrentWindow();
  $('tb-min').onclick = () => win.minimize();
  $('tb-max').onclick = () => win.toggleMaximize();
  $('tb-close').onclick = () => win.close();
}

/* ================= 启动 ================= */
function toggleManual(open) {
  const f = $('manual-form');
  const show = open === true ? true : f.style.display === 'none';
  f.style.display = show ? 'block' : 'none';
  $('manual-arrow').innerHTML = AgIcon(show ? 'chevron-down' : 'chevron-right', 13);
}

window.addEventListener('DOMContentLoaded', async () => {
  Island.init();
  bindSearch();
  document.querySelectorAll('#nav-client .nav-item').forEach(n => n.onclick = () => switchView(n.dataset.view));
  initAdminMode();

  // 浏览器模式（Web 远程面）：隐藏本机专属 UI，未登录先出登录框
  if (HTTP_MODE) {
    document.body.classList.add('http-mode');
    const rc = $('roles-card'); if (rc) rc.style.display = 'none';
    const as = $('s-autostart'); if (as) { const l = as.closest('label'); if (l) l.style.display = 'none'; }
    const sp = $('proxy-mode'); if (sp) sp.style.display = 'none';
    const subNav = document.querySelector('.nav-item[data-view="subscription"]');
    if (subNav) subNav.style.display = 'none';
    // 管理端控制台为本机专属能力（票据/转发器仅 loopback），Web 远程面隐藏入口
    $('btn-admin').style.display = 'none';
    $('login-ok').onclick = webLogin;
    $('login-pass').addEventListener('keydown', e => { if (e.key === 'Enter') webLogin(); });
    if (!httpToken) { showLogin(); return; }
  }

  // 卸载：仅桌面端（Windows 安装版）展示；浏览器远程面与 Android 隐藏
  const unCard = $('btn-uninstall') && $('btn-uninstall').closest('.card');
  if (HTTP_MODE || /Android/i.test(navigator.userAgent)) {
    if (unCard) unCard.style.display = 'none';
  } else {
    $('btn-uninstall').onclick = () => { $('uninstall-modal').style.display = 'flex'; };
    $('un-cancel').onclick = () => { $('uninstall-modal').style.display = 'none'; };
    $('un-ok').onclick = async () => {
      const prefs = $('un-prefs').checked;
      $('un-ok').disabled = true;
      $('un-ok').textContent = '正在卸载…';
      if (prefs) localStorage.clear();
      try {
        await invoke('uninstall_app', {
          options: {
            credentials: $('un-creds').checked,
            serverData: $('un-server').checked,
            prefs,
            audit: $('un-audit').checked,
          },
        });
        // 后端随即退出进程并拉起系统卸载程序，此处无需再处理
      } catch (err) {
        $('un-ok').disabled = false;
        $('un-ok').textContent = '卸载';
        $('uninstall-modal').style.display = 'none';
        toast(friendlyError(err), 'err');
      }
    };
  }

  initTitlebar();
  initTitlebarExtra();
  if (TAURI && TAURI.app) { TAURI.app.getVersion().then(v => { const el = $('ver'); if (el) el.textContent = v; const av = $('about-ver'); if (av) av.textContent = v; }).catch(() => {}); }
  $('btn-import').onclick = (e) => importUrl($('connect-url').value, e.target);
  $('btn-import-hero').onclick = (e) => importUrl($('connect-url-hero').value, e.target);
  $('btn-paste').onclick = pasteFromClipboard;
  $('link-paste').onclick = pasteFromClipboard;
  $('link-manual').onclick = () => toggleManual(true);
  $('manual-toggle').onclick = () => toggleManual();
  $('connect-url').addEventListener('keydown', e => { if (e.key === 'Enter') $('btn-import').click(); });
  $('connect-url-hero').addEventListener('keydown', e => { if (e.key === 'Enter') $('btn-import-hero').click(); });
  $('connect-url-hero').focus();
  $('btn-connect').onclick = () => {
    const addr = $('m-addr').value.trim(), user = $('m-user').value.trim(), pass = $('m-pass').value;
    if (!addr || !user || !pass) { toast('请填写完整信息', 'err'); return; }
    connectWith({
      addr, username: user, password: pass,
      insecure: $('m-insecure').checked,
      pinned_cert_path: $('m-pin').value.trim() || null,
      manage_hosts: $('m-hosts').checked,
      save_credential: $('m-save').checked,
    }, $('btn-connect'));
  };
  $('btn-proxy-toggle').onclick = toggleProxy;
  $('btn-refresh').onclick = () => { refreshNodes(true); refreshProxy(); };

  // 列表动作事件委托（CSP 禁止内联 onclick）
  $('nodes-list').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-act]');
    if (!btn) return;
    if (btn.dataset.act === 'disconnect') disconnectNode(btn.dataset.id);
    if (btn.dataset.act === 'console') openNodeConsole(btn.dataset.id);
    if (btn.dataset.act === 'upconsole') openUpstreamConsole(btn.dataset.id, btn.dataset.up);
  });
  $('creds-list').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-act]');
    if (!btn) return;
    const key = btn.dataset.key;
    if (btn.dataset.act === 'reconnect') reconnectSaved(key, btn);
    if (btn.dataset.act === 'disconnect') disconnectNode(key);
    if (btn.dataset.act === 'export') exportCred(key);
    if (btn.dataset.act === 'delcred') deleteCred(key, btn);
  });
  $('rules-body').addEventListener('change', (e) => {
    const cb = e.target.closest('input[data-rule]');
    if (cb) toggleRule(cb.dataset.node, cb.dataset.rule, !cb.checked);
  });

  await loadSettings();
  await initRoles();
  initSubscription();
  initSubFeature();
  refreshSubFeature();
  initSysproxy();
  refreshSubs();
  refreshSubStatus();
  refreshSysproxy();
  $('s-lang').value = localStorage.getItem('ag_lang') || 'zh';
  $('s-theme').value = localStorage.getItem('ag_theme') || 'light';
  $('s-lang').onchange = (e) => { localStorage.setItem('ag_lang', e.target.value); applyLanguage(); };
  $('s-theme').onchange = (e) => {
    localStorage.setItem('ag_theme', e.target.value);
    applyTheme();
    invoke('broadcast_theme', { theme: e.target.value }).catch(() => {});
    // 管理端 iframe 同步（跨源 postMessage）
    if (ADMIN) {
      const f = $('admin-frame');
      if (f && f.contentWindow) f.contentWindow.postMessage({ type: 'ag-theme', theme: e.target.value }, ADMIN.origin);
    }
  };
  applyTheme();
  refreshNodes(true);
  refreshProxy();
  await refreshCreds();

  // 启动时自动重连已保存节点
  if (PREFS.autoreconnect && window._creds) {
    const keys = Object.keys(window._creds);
    if (keys.length) {
      toast(T('reconnecting-nodes').replace('{n}', keys.length), 'ok');
      for (const key of keys) {
        await reconnectSaved(key, null);
      }
    }
  }

  setInterval(() => { refreshNodes(); refreshProxy(); refreshSubStatus(); refreshSysproxy(); }, 10000);
});
