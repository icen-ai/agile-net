'use strict';
/* 托盘弹窗逻辑：状态刷新 / 代理开关 / 订阅节点快切（hover 展开层级列表） */
const TAURI = window.__TAURI__;
const invoke = TAURI.core.invoke;
const $ = (id) => document.getElementById(id);

function esc(s) {
  return String(s ?? '').replace(/[&<>"'`]/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','`':'&#96;'
  }[c]));
}

let GROUP = null;   // 当前组名
let NOW = null;     // 当前节点
let expanded = false;

async function refresh() {
  // 本地代理状态
  try {
    const st = await invoke('proxy_status');
    $('tp-dot').className = 'dot ' + (st.running ? 'on' : 'off');
    $('tp-status').textContent = st.running ? '代理运行中 · ' + st.port : '代理未启动';
    $('tp-proxy-state').textContent = st.running ? '点击停止' : '点击启动';
  } catch (e) {}
  // 订阅内核与当前节点
  try {
    const kst = await invoke('subscription_status');
    if (!kst.running) {
      $('tp-node-cur').textContent = '内核未运行';
      renderNodes([]);
      return;
    }
    const d = await invoke('proxy_groups');
    const px = (d && d.proxies) || {};
    const groups = Object.entries(px).filter(([, p]) => p.all && ['Selector', 'URLTest', 'Fallback'].includes(p.type));
    if (!groups.length) {
      $('tp-node-cur').textContent = '无节点';
      renderNodes([]);
      return;
    }
    const [gn, g] = groups[0];
    GROUP = gn; NOW = g.now;
    $('tp-node-cur').textContent = g.now || '-';
    renderNodes(g.all.map(n => {
      const p = px[n] || {};
      const hist = (p.history && p.history.length) ? p.history[p.history.length - 1].delay : 0;
      return { name: n, delay: hist, current: n === g.now };
    }));
  } catch (e) {
    $('tp-node-cur').textContent = '-';
  }
}

function renderNodes(nodes) {
  const box = $('tp-nodes');
  if (!expanded) { box.style.display = 'none'; return; }
  box.style.display = 'block';
  box.innerHTML = nodes.length
    ? nodes.map(n =>
        '<div class="tp-node' + (n.current ? ' current' : '') + '" data-node="' + esc(n.name) + '">' +
        '<span class="dot ' + (n.current ? 'on' : 'off') + '"></span>' +
        '<span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(n.name) + '</span>' +
        '<span class="st">' + (n.delay ? n.delay + 'ms' : '') + '</span></div>'
      ).join('')
    : '<div class="tp-empty">订阅内核未运行或无节点</div>';
}

function toggleNodes(open) {
  expanded = open === true ? true : !expanded;
  $('tp-nodes-row').classList.toggle('open', expanded);
  refresh();
}

window.addEventListener('DOMContentLoaded', () => {
  refresh();
  setInterval(refresh, 5000);

  $('tp-proxy').onclick = async () => {
    try {
      const st = await invoke('proxy_status');
      if (st.running) await invoke('stop_proxy');
      else await invoke('start_proxy', { port: 57890 });
    } catch (e) {}
    refresh();
  };
  // hover 展开层级（进入行展开，离开整区收起）
  $('tp-nodes-row').addEventListener('mouseenter', () => toggleNodes(true));
  document.querySelector('.tp').addEventListener('mouseleave', () => { if (expanded) toggleNodes(false); });
  $('tp-nodes-row').onclick = () => toggleNodes();
  $('tp-nodes').addEventListener('click', async (e) => {
    const row = e.target.closest('.tp-node');
    if (!row || !GROUP) return;
    try {
      await invoke('select_proxy', { group: GROUP, name: row.dataset.node });
      NOW = row.dataset.node;
      refresh();
    } catch (err) {}
  });
  $('tp-show').onclick = () => invoke('tray_show_main').catch(() => {});
  $('tp-quit').onclick = () => invoke('tray_quit').catch(() => {});
});
