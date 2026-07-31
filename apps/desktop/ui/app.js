'use strict';
// Tauri IPC 桥（v2：window.__TAURI__.core.invoke）
const invoke = window.__TAURI__.core.invoke;
const $ = (id) => document.getElementById(id);

const PREFS = {
  get autoproxy() { return localStorage.getItem('ag_autoproxy') !== '0'; },
  set autoproxy(v) { localStorage.setItem('ag_autoproxy', v ? '1' : '0'); },
  get autoreconnect() { return localStorage.getItem('ag_autoreconnect') !== '0'; },
  set autoreconnect(v) { localStorage.setItem('ag_autoreconnect', v ? '1' : '0'); },
};

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
  $('rules-card').style.display = empty ? 'none' : 'block';
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
    for (const r of (n.rules || [])) {
      rows.push('<tr><td><span class="badge b-ok">' + esc(r.type) + '</span></td>' +
        '<td class="mono">' + esc(r.value) + '</td>' +
        '<td style="color:var(--dim)">' + esc(n.node_name) + '</td></tr>');
    }
  }
  $('rules-body').innerHTML = rows.join('') || '<tr><td colspan="3" class="empty">无生效规则</td></tr>';
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
    toast('已连接 ' + st.node_name + '（下发规则 ' + st.rules.length + ' 条）', 'ok');
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
  if (!url) { toast('请粘贴接入链接', 'err'); return; }
  if (!url.startsWith('agilenet://connect?')) { toast('链接格式不正确，应以 agilenet://connect? 开头', 'err'); return; }
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
      toast('已识别剪贴板中的接入链接', 'ok');
      await importUrl(text, null);
    } else {
      toast('剪贴板中没有接入链接', 'err');
    }
  } catch (e) {
    toast('无法读取剪贴板', 'err');
  }
}

/* ================= 代理控制 ================= */
async function refreshProxy() {
  try {
    const st = await invoke('proxy_status');
    $('proxy-dot').className = 'dot ' + (st.running ? 'on' : 'off');
    $('proxy-text').textContent = st.running ? ('代理运行中 127.0.0.1:' + st.port) : '代理未启动';
    $('btn-proxy-toggle').textContent = st.running ? '停止代理' : '启动代理';
    $('proxy-hint').textContent = st.running ? '系统/应用代理指向 127.0.0.1:' + st.port + ' 即可' : '';
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

/* ================= 启动 ================= */
function toggleManual(open) {
  const f = $('manual-form');
  const show = open === true ? true : f.style.display === 'none';
  f.style.display = show ? 'block' : 'none';
  $('manual-arrow').textContent = show ? '▾' : '▸';
}

window.addEventListener('DOMContentLoaded', async () => {
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
  refreshNodes();
  refreshProxy();
  await refreshCreds();

  // 启动时自动重连已保存节点
  if (PREFS.autoreconnect && window._creds) {
    const keys = Object.keys(window._creds);
    if (keys.length) {
      toast('正在自动重连 ' + keys.length + ' 个已保存节点…', 'ok');
      for (const key of keys) {
        await reconnectSaved(key, null);
      }
    }
  }

  setInterval(() => { refreshNodes(); refreshProxy(); }, 10000);
});
