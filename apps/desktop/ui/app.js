'use strict';
// Tauri IPC 桥（v2：window.__TAURI__.core.invoke）
const invoke = window.__TAURI__.core.invoke;
const $ = (id) => document.getElementById(id);

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
function toggleManual() {
  const f = $('manual-form');
  const open = f.style.display === 'none';
  f.style.display = open ? 'block' : 'none';
  $('manual-arrow').textContent = open ? '▾' : '▸';
}

/* ================= 节点管理 ================= */
async function refreshNodes() {
  try {
    const nodes = await invoke('list_nodes');
    const list = $('nodes-list');
    if (!nodes.length) {
      list.innerHTML = '<div class="empty">尚未连接节点</div>';
    } else {
      list.innerHTML = nodes.map(n =>
        '<div class="node-card"><div class="info">' +
        '<div class="name">' + esc(n.node_name) + ' <span class="badge ' + statusBadge(n.status) + '">' + statusText(n.status) + '</span></div>' +
        '<div class="addr mono">' + esc(n.addr) + ' · 规则 ' + (n.rules || []).length + ' 条 · 配置 v' + n.config_version + '</div>' +
        '</div>' +
        '<button class="danger small" onclick="disconnectNode(\'' + esc(n.node_id) + '\')">断开</button></div>'
      ).join('');
    }
    renderMergedRules(nodes);
  } catch (e) { toast(String(e), 'err'); }
}
function statusBadge(s) {
  return s === 'Connected' ? 'b-ok' : (s === 'Reconnecting' || s === 'Connecting') ? 'b-warn' : 'b-off';
}
function statusText(s) {
  return ({ Connected: '已连接', Connecting: '连接中', Reconnecting: '重连中', Disconnected: '已断开' })[s] || s;
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
  } catch (e) { toast(String(e), 'err'); }
}

async function connectWith(input) {
  try {
    const st = await invoke('connect_node', { input });
    toast('已连接 ' + st.node_name + '（规则 ' + st.rules.length + ' 条）', 'ok');
    refreshNodes();
    refreshCreds();
  } catch (e) { toast('连接失败: ' + String(e), 'err'); }
}

/* ================= 代理控制 ================= */
async function refreshProxy() {
  try {
    const st = await invoke('proxy_status');
    $('proxy-dot').className = 'dot ' + (st.running ? 'on' : 'off');
    $('proxy-text').textContent = st.running ? ('代理运行中 127.0.0.1:' + st.port) : '代理未启动';
    $('btn-proxy-toggle').textContent = st.running ? '停止代理' : '启动代理';
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
  } catch (e) { toast(String(e), 'err'); }
}

/* ================= 已保存凭据 ================= */
async function refreshCreds() {
  try {
    const creds = await invoke('list_credentials');
    const list = $('creds-list');
    if (!creds.length) {
      list.innerHTML = '<div class="empty">无保存的凭据</div>';
      return;
    }
    list.innerHTML = creds.map(([key, c]) =>
      '<div class="node-card"><div class="info">' +
      '<div class="name">' + esc(c.username) + '</div>' +
      '<div class="addr mono">' + esc(c.addr) + (c.insecure ? ' · <span class="badge b-warn">insecure</span>' : '') + '</div>' +
      '</div><button class="ghost small" onclick=\'reconnectSaved(' + JSON.stringify(key) + ')\'>重新连接</button></div>'
    ).join('');
    window._creds = Object.fromEntries(creds);
  } catch (e) {}
}
async function reconnectSaved(key) {
  const c = (window._creds || {})[key];
  if (!c) return;
  connectWith({
    addr: c.addr, username: c.username, password: c.password,
    insecure: c.insecure, pinned_cert_path: null, manage_hosts: false, save_credential: true,
  });
}

/* ================= 事件绑定 ================= */
window.addEventListener('DOMContentLoaded', () => {
  $('btn-import').onclick = async () => {
    const url = $('connect-url').value.trim();
    if (!url) { toast('请粘贴接入链接', 'err'); return; }
    try {
      const input = await invoke('parse_connect_url', { url });
      await connectWith(input);
    } catch (e) { toast(String(e), 'err'); }
  };
  $('btn-connect').onclick = () => {
    const addr = $('m-addr').value.trim(), user = $('m-user').value.trim(), pass = $('m-pass').value;
    if (!addr || !user || !pass) { toast('请填写完整信息', 'err'); return; }
    connectWith({
      addr, username: user, password: pass,
      insecure: $('m-insecure').checked,
      pinned_cert_path: $('m-pin').value.trim() || null,
      manage_hosts: $('m-hosts').checked,
      save_credential: $('m-save').checked,
    });
  };
  $('btn-proxy-toggle').onclick = toggleProxy;
  $('btn-refresh').onclick = refreshNodes;

  refreshNodes();
  refreshProxy();
  refreshCreds();
  setInterval(() => { refreshNodes(); refreshProxy(); }, 10000);
});
