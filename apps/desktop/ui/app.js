'use strict';
// Tauri IPC 桥（v2：window.__TAURI__.core.invoke）；纯浏览器预览时提供空数据桩
const TAURI = window.__TAURI__ || null;
const invoke = TAURI ? TAURI.core.invoke : (cmd) => {
  const mock = { list_nodes: [], list_credentials: [], proxy_status: { running: false, port: 7890 }, get_autostart: false };
  return cmd in mock ? Promise.resolve(mock[cmd]) : Promise.resolve(null);
};
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
function applyLanguage() { LANG = localStorage.getItem('ag_lang') || 'zh'; refreshNodes(); refreshProxy(); }
function applyTheme() {
  document.documentElement.dataset.theme = localStorage.getItem('ag_theme') || 'light';
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"'`]/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','`':'&#96;'
  }[c]));
}
function toast(msg, type) {
  const el = document.createElement('div');
  el.className = 'toast ' + (type || '');
  el.textContent = msg;
  $('toasts').appendChild(el);
  setTimeout(() => el.remove(), 3600);
}

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

/* ================= 节点管理 ================= */
async function refreshNodes() {
  let nodes = [];
  try {
    nodes = await invoke('list_nodes');
    const list = $('nodes-list');
    if (!nodes.length) {
      list.innerHTML = '<div class="empty">尚未连接节点</div>';
    } else {
      list.innerHTML = nodes.map(n =>
        '<div class="node-card"><div class="info">' +
        '<div class="name">' + esc(n.node_name) + ' ' + statusBadgeHtml(n.status) + '</div>' +
        '<div class="addr mono">' + esc(n.addr) + ' · 规则 ' + (n.rules || []).length + ' 条 · 配置 v' + n.config_version + '</div>' +
        '</div>' +
        '<button class="danger small" onclick="disconnectNode(\'' + esc(n.node_id) + '\')">断开</button></div>'
      ).join('');
    }
    renderMergedRules(nodes);
  } catch (e) { toast(friendlyError(e), 'err'); }
  updateOnboarding(nodes);
}
function statusBadgeHtml(s) {
  if (s === 'Connected') return '<span class="badge b-ok">已连接</span>';
  if (s === 'Connecting') return '<span class="badge b-warn"><span class="pulse"></span>连接中</span>';
  if (s === 'Reconnecting') return '<span class="badge b-warn"><span class="pulse"></span>重连中</span>';
  return '<span class="badge b-off">已断开</span>';
}
function renderMergedRules(nodes) {
  const rows = [];
  for (const n of nodes) {
    const dot = n.status === 'Connected' ? 'ok' : (n.status === 'Disconnected' ? 'down' : 'warn');
    for (const r of (n.rules || [])) {
      rows.push('<tr><td><span class="rdot ' + dot + '"></span><span class="badge b-ok">' + esc(r.type) + '</span></td>' +
        '<td class="mono">' + esc(r.value) + '</td>' +
        '<td style="color:var(--dim)">' + esc(n.node_name) + '</td></tr>');
    }
  }
  $('rules-body').innerHTML = rows.join('') || '<tr><td colspan="3" class="empty">' + T('no-rules') + '</td></tr>';
}

async function disconnectNode(nodeId) {
  try {
    await invoke('disconnect_node', { nodeId });
    toast('已断开', 'ok');
    refreshNodes();
    refreshCreds();
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
          const port = parseInt($('proxy-port').value || '7890', 10);
          await invoke('start_proxy', { port });
        }
      } catch (e) { /* 代理自启失败不阻塞连接 */ }
    }
    refreshNodes();
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
    $('proxy-dot').className = 'dot ' + (st.running ? 'on' : 'off');
    $('proxy-text').textContent = st.running ? (T('proxy-running') + ' 127.0.0.1:' + st.port) : T('proxy-stopped');
    $('btn-proxy-toggle').textContent = st.running ? T('btn-stop-proxy') : T('btn-start-proxy');
    $('proxy-hint').textContent = st.running ? '系统/应用代理指向 127.0.0.1:' + st.port + ' 即可' : '';
    // 顶栏徽章：有节点降级时黄色提示
    const nodes = await invoke('list_nodes').catch(() => []);
    const degraded = nodes.some(n => n.status !== 'Connected');
    if (nodes.length && degraded) {
      $('proxy-dot').className = 'dot on';
      $('proxy-dot').style.background = 'var(--warn)';
      $('proxy-text').textContent = T('st-degraded');
    } else {
      $('proxy-dot').style.background = '';
    }
  } catch (e) {}
}
async function toggleProxy() {
  try {
    const st = await invoke('proxy_status');
    if (st.running) {
      await invoke('stop_proxy');
      toast('代理已停止', 'ok');
    } else {
      const port = parseInt($('proxy-port').value || '7890', 10);
      const actual = await invoke('start_proxy', { port });
      toast('代理已启动 127.0.0.1:' + actual, 'ok');
    }
    refreshProxy();
  } catch (e) { toast(friendlyError(e), 'err'); }
}

/* ================= 已保存凭据 ================= */
async function refreshCreds() {
  try {
    const creds = await invoke('list_credentials');
    window._creds = Object.fromEntries(creds);
    const list = $('creds-list');
    if (!creds.length) {
      list.innerHTML = '<div class="empty">无保存的凭据</div>';
    } else {
      list.innerHTML = creds.map(([key, c]) =>
        '<div class="node-card"><div class="info">' +
        '<div class="name">' + esc(c.username) + '</div>' +
        '<div class="addr mono">' + esc(c.addr) + (c.insecure ? ' · <span class="badge b-warn">insecure</span>' : '') + '</div>' +
        '</div><button class="ghost small" onclick=\'reconnectSaved(' + JSON.stringify(key) + ', this)\'>重新连接</button></div>'
      ).join('');
    }
    invoke('list_nodes').then(nodes => updateOnboarding(nodes)).catch(() => {});
  } catch (e) {}
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
  document.querySelectorAll('.nav-item').forEach(n => n.onclick = () => switchView(n.dataset.view));
  initTitlebar();
  if (TAURI && TAURI.app) { TAURI.app.getVersion().then(v => { const el = $('ver'); if (el) el.textContent = v; }).catch(() => {}); }
  $('btn-import').onclick = (e) => importUrl($('connect-url').value, e.target);
  $('btn-import-hero').onclick = (e) => importUrl($('connect-url-hero').value, e.target);
  $('btn-paste').onclick = pasteFromClipboard;
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
  $('btn-refresh').onclick = refreshNodes;

  await loadSettings();
  $('s-lang').value = localStorage.getItem('ag_lang') || 'zh';
  $('s-theme').value = localStorage.getItem('ag_theme') || 'light';
  $('s-lang').onchange = (e) => { localStorage.setItem('ag_lang', e.target.value); applyLanguage(); };
  $('s-theme').onchange = (e) => { localStorage.setItem('ag_theme', e.target.value); applyTheme(); };
  applyTheme();
  refreshNodes();
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
