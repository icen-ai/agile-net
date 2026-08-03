'use strict';
/* 启动装配（拆分后保留）：Web 远程面登录 / applySubFeature / 标题栏 / 视图导航与窗口控制 / 启动序列。
   域代码见 app-core.js / app-views.js / app-subscription.js / app-hero.js / app-logs.js / app-settings.js（纯搬运，零逻辑变更） */

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

/** 功能入口可见性（安装激活后侧栏出现「订阅/代理」；仪表盘订阅卡切引导态） */
function applySubFeature(on) {
  document.querySelectorAll('.nav-item.sub-feature').forEach(n => { n.style.display = on ? '' : 'none'; });
  $('btn-activate-sub').style.display = on ? 'none' : '';
  $('btn-deactivate-sub').style.display = on ? '' : 'none';
  const body = $('d-sub-body'), guide = $('d-sub-guide'), sw = $('d-sub-switch');
  if (body) body.style.display = on ? '' : 'none';
  if (guide) guide.style.display = on ? 'none' : '';
  if (sw) sw.style.display = on ? '' : 'none';
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
let CUR_VIEW = 'connect';
function switchView(v) {
  if (CUR_VIEW === 'logs' && v !== 'logs') LogsView.stop(); // 离开日志页即停轮询
  CUR_VIEW = v;
  document.querySelectorAll('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.view === v));
  document.querySelectorAll('#bnav .bnav-item').forEach(n => n.classList.toggle('active', n.dataset.view === v));
  document.querySelectorAll('.view').forEach(s => { s.hidden = s.id !== 'view-' + v; });
  if (v === 'connect') { refreshNodes(); refreshProxy(); renderDashFanout(); NetProbe.render(); Hero.tick10s(); }
  if (v === 'nodes') { refreshNodes(true); refreshCreds(); }
  if (v === 'routes') { refreshNodes(); refreshCustomRules(); refreshCombos(); }
  if (v === 'upstreams') refreshUpstreams();
  if (v === 'subscription') { refreshSubs(); refreshSubStatus(); refreshSubScripts(); SubTraffic.poll(); }
  if (v === 'proxy') { refreshSubs(); refreshGroups(); }
  if (v === 'logs') LogsView.enter();
  if (v === 'settings') { refreshSysproxy(); refreshSubFeature(); loadSyncConfig(); }
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
  document.querySelectorAll('#bnav .bnav-item').forEach(n => n.onclick = () => switchView(n.dataset.view));
  initAdminMode();
  initUpstreams();
  initRules();
  initLogs();

  // 浏览器模式（Web 远程面）：本机专属卡片/开关经 .local-only 隐藏，未登录先出登录框
  if (HTTP_MODE) {
    document.body.classList.add('http-mode');
    const as = $('s-autostart'); if (as) { const l = as.closest('label'); if (l) l.style.display = 'none'; }
    const sp = $('proxy-mode'); if (sp) sp.style.display = 'none';
    const subNav = document.querySelector('.nav-item[data-view="subscription"]');
    if (subNav) subNav.style.display = 'none';
    // 日志视图（订阅内核可观测）与本机专属设置项为桌面端能力，Web 远程面隐藏
    const logsNav = document.querySelector('.nav-item[data-view="logs"]');
    if (logsNav) logsNav.style.display = 'none';
    // 窄屏底部导航含日志等桌面端入口，Web 远程面整体隐藏（内联 none 覆盖 ≤720px 断点的 flex）
    $('bnav').style.display = 'none';
    ['row-sysproxy-lock', 'row-doctor', 'row-float-ball', 'row-notify-float', 'row-reduce-effects', 'sync-card'].forEach(id => {
      const r = $(id); if (r) r.style.display = 'none';
    });
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
    // 桌面悬浮球为桌面端窗口能力，Android 同步隐藏（气泡通知行随行联动隐藏）
    const fb = $('row-float-ball'); if (fb) fb.style.display = 'none';
    const nf = $('row-notify-float'); if (nf) nf.style.display = 'none';
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
  $('link-manual').onclick = () => { switchView('nodes'); toggleManual(true); };
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
  $('d-proxy').onchange = toggleProxy;
  $('btn-net-refresh').onclick = () => { NetProbe.refresh(true); NetProbe.refreshLan(); };
  // 仪表盘卡片：点非开关/按钮区跳对应页面（开关经 change 事件自行处理）
  $('dash-grid').addEventListener('click', (e) => {
    if (e.target.closest('.switch, button, input, select, a, .group-tabs')) return;
    const card = e.target.closest('[data-goto]');
    if (card) switchView(card.dataset.goto);
  });
  $('btn-refresh').onclick = () => { refreshNodes(true); refreshCreds(); refreshProxy(); };

  // 列表动作事件委托（CSP 禁止内联 onclick）
  $('creds-list').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-act]');
    if (!btn) return;
    const key = btn.dataset.key;
    if (btn.dataset.act === 'reconnect') reconnectSaved(key, btn);
    if (btn.dataset.act === 'disconnect') disconnectNode(key);
    if (btn.dataset.act === 'export') exportCred(key);
    if (btn.dataset.act === 'delcred') deleteCred(key, btn);
    if (btn.dataset.act === 'console') openNodeConsole(btn.dataset.id);
  });
  $('rules-body').addEventListener('change', (e) => {
    const cb = e.target.closest('input[data-rule]');
    if (cb) toggleRule(cb.dataset.node, cb.dataset.rule, !cb.checked);
  });

  await loadSettings();
  await initRoles();
  initHero();        // 中控台英雄卡（总开关/曲线/摘要；须晚于 initRoles 的 r-client 初值）
  Onboarding.init(); // 新手检查单（dismissed/done 标记在则整卡不渲染）
  initInlineEdits();
  initSubscription();
  initSubDragImport();
  initSubFeature();
  refreshSubFeature();
  initSysproxy();
  initTun();
  initDl();
  refreshSubs();
  refreshSubStatus();
  refreshSubScripts();
  refreshSysproxy();
  refreshTun();
  $('s-lang').value = localStorage.getItem('ag_lang') || 'zh';
  $('s-theme').value = localStorage.getItem('ag_theme') || 'light';
  agSelectEnhance(document);
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
  renderDashFanout();
  NetProbe.refresh();
  NetProbe.refreshLan();
  refreshCustomRules();
  refreshCombos();
  await refreshCreds();

  // 启动时自动重连已保存的扇入
  if (PREFS.autoreconnect && window._creds) {
    const keys = Object.keys(window._creds);
    if (keys.length) {
      toast(T('reconnecting-nodes').replace('{n}', keys.length), 'ok');
      for (const key of keys) {
        await reconnectSaved(key, null);
      }
    }
  }

  setInterval(() => { refreshNodes(); refreshProxy(); refreshSubStatus(); refreshSysproxy(); refreshTun(); renderDashFanout(); refreshCustomRules(); refreshCombos(); Hero.tick10s(); }, 10000);
  // 订阅内核流量 + 制品下载状态 2s 轮询（sub_traffic 读 Atomic 快照、dl_state 读内存状态，廉价；内部变更检测不重绘）
  setInterval(() => { SubTraffic.poll(); pollDl(); }, 2000);
  // 出口 IP 探测 30s 轮询（结果带签名对比，不变不重绘）
  setInterval(() => { NetProbe.refresh(); }, 30000);
});
