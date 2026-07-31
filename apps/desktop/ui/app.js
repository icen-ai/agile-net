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
    'banner-degraded': '节点 {name} 网络不可达，正在自动重连…',
    'banner-down': '节点 {name} 已离线，其网段当前不可达',
    'proxy-running': '代理运行中', 'proxy-stopped': '代理未启动',
    'reconnecting-nodes': '正在自动重连 {n} 个已保存节点…',
    'connected-toast': '已连接 {name}（下发规则 {n} 条）',
    'proxy-on': '代理已启动', 'proxy-off': '代理已停止',
    'btn-start-proxy': '启动代理', 'btn-stop-proxy': '停止代理',
    'err-need-url': '请粘贴接入链接', 'err-bad-url': '链接格式不正确，应以 agilenet://connect? 开头',
    'clip-ok': '已识别剪贴板中的接入链接', 'clip-none': '剪贴板中没有接入链接', 'clip-fail': '无法读取剪贴板',
    'disconnected': '已断开', 'no-nodes': '尚未连接节点', 'no-rules': '无生效规则', 'no-creds': '无保存的凭据',
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
    $('island-detail').innerHTML = '<div class="dt-title">以下节点当前不可达，其网段流量不会进入隧道：</div>' +
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
  if (/timed out|timeout|deadline/i.test(s)) return '连接超时：节点不可达或网络受限';
  if (/ConnectionRefused|refused|10061/i.test(s)) return '无法连接节点：地址/端口错误或节点未启动';
  if (/dns|resolve|lookup/i.test(s)) return '域名解析失败：请检查节点地址';
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
    '<div class="name">' + esc(n.node_name) + ' ' + statusBadgeHtml(n.status) + '</div>' +
    '<div class="addr mono">' + esc(n.addr) + ' · 规则 ' + (n.rules || []).length + ' 条 · 配置 v' + n.config_version + '</div>' +
    '</div><button class="danger small" data-act="disconnect" data-id="' + esc(n.node_id) + '">断开</button></div>'
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

/* ================= 接入链接导入 ================= */
async function importUrl(url, btn) {
  url = (url || '').trim();
  if (!url) { toast(T('err-need-url'), 'err'); return; }
  if (!url.startsWith('agilenet://connect?')) { toast(T('err-bad-url'), 'err'); return; }
  try {
    const input = await invoke('parse_connect_url', { url });
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
    const hint = st.running ? '系统/应用代理指向 127.0.0.1:' + st.port + ' 即可' : '';
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
    return '<div class="node-card"><div class="info">' +
      '<div class="name">' + esc(c.username) + ' ' + badge + '</div>' +
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
      toast('已删除保存的节点', 'ok');
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
  $('web-listen').value = settings.web_listen;
  applyClientRole(settings.client);
  refreshServerPanel();
  refreshWebPanel();

  $('r-client').onchange = async (e) => {
    try {
      await invoke('set_client_role', { enabled: e.target.checked });
      applyClientRole(e.target.checked);
      toast(e.target.checked ? '客户端角色已开启' : '客户端角色已停用（已断开全部节点）', 'ok');
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
            desc: '首开服务端角色须先设置内嵌节点管理员，该密码用于登录控制台。',
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
      toast(on ? '服务端角色已开启（内嵌节点运行中）' : '服务端角色已关闭', 'ok');
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

  $('btn-open-console').onclick = async () => {
    try { await invoke('open_console'); }
    catch (err) { toast(friendlyError(err), 'err'); }
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

/* ================= 视图导航 & 窗口控制 ================= */
function switchView(v) {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.view === v));
  document.querySelectorAll('.view').forEach(s => { s.hidden = s.id !== 'view-' + v; });
  if (v === 'nodes' || v === 'routes') refreshNodes();
  if (v === 'connect') refreshCreds();
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
  document.querySelectorAll('.nav-item').forEach(n => n.onclick = () => switchView(n.dataset.view));

  // 浏览器模式（Web 远程面）：隐藏本机专属 UI，未登录先出登录框
  if (HTTP_MODE) {
    document.body.classList.add('http-mode');
    const rc = $('roles-card'); if (rc) rc.style.display = 'none';
    const as = $('s-autostart'); if (as) { const l = as.closest('label'); if (l) l.style.display = 'none'; }
    $('login-ok').onclick = webLogin;
    $('login-pass').addEventListener('keydown', e => { if (e.key === 'Enter') webLogin(); });
    if (!httpToken) { showLogin(); return; }
  }

  initTitlebar();
  if (TAURI && TAURI.app) { TAURI.app.getVersion().then(v => { const el = $('ver'); if (el) el.textContent = v; }).catch(() => {}); }
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
    if (btn && btn.dataset.act === 'disconnect') disconnectNode(btn.dataset.id);
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
  $('s-lang').value = localStorage.getItem('ag_lang') || 'zh';
  $('s-theme').value = localStorage.getItem('ag_theme') || 'light';
  $('s-lang').onchange = (e) => { localStorage.setItem('ag_lang', e.target.value); applyLanguage(); };
  $('s-theme').onchange = (e) => { localStorage.setItem('ag_theme', e.target.value); applyTheme(); };
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

  setInterval(() => { refreshNodes(); refreshProxy(); }, 10000);
});
