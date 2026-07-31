//! Web 管理后台单页应用 (Admin Web UI)
//!
//! 企业级单文件 SPA：概览 / 账号 / 权限组 / 规则 / 令牌 / 审计 / 设置。
//! - 全部动态内容经 esc() 转义渲染，杜绝存储型 XSS
//! - access_token 过期自动用 refresh_token 续期
//! - 创建账号/令牌仅在弹窗中展示一次明文 + 一键复制 + SVG 二维码
//! - 附带安全响应头（CSP / X-Frame-Options 等）
//! - 图标统一为内置 Lucide 内联 SVG（仅收录用到的图标），严禁文字表情
//! - 视觉 token 对齐 Cindy 桌面端设计（docs/architecture/ui-design.md）

use axum::{
    Router,
    http::{HeaderValue, header},
    response::{Html, IntoResponse},
    routing::get,
};

const ADMIN_HTML: &str = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AgileNet 控制台</title>
<style>
:root {
  --bg: #EDEDED; --bg2: #F4F4F4; --panel: #F8F8F8; --panel2: #FFFFFF;
  --border: #DCDFE3; --border2: #C9CDD3;
  --text: #3C3F43; --text-strong: #2E3237; --dim: #686B72; --dim2: #8C8E94;
  --accent: #3C3F43; --accent2: #2E3237; --accent-fg: #FCFCFC;
  --link: #1D4ED8; --ring: #417CDD;
  --ok: #15803D; --warn: #B45309; --danger: #DC2626;
  --ok-bg: rgba(21,128,61,.10); --warn-bg: rgba(180,83,9,.12); --danger-bg: rgba(220,38,38,.10);
  --danger-border: rgba(220,38,38,.35);
  --chip: #F1F1F1; --hover: #E2E2E2;
  --row-border: #E7E8EA; --row-hover: rgba(0,0,0,.028);
  --shadow: 0 12px 40px rgba(0,0,0,.14);
  --radius: 12px;
}
html[data-theme="dark"] {
  --bg: #2A2828; --bg2: #2F2D2D; --panel: #312F2F; --panel2: #3A3838;
  --border: #434343; --border2: #504F4F;
  --text: #D4D4D4; --text-strong: #EEEEEE; --dim: #9A9DA3; --dim2: #6F6F6F;
  --accent: #EEEEEE; --accent2: #E2E2E2; --accent-fg: #252222;
  --link: #7DA8F8; --ring: #417CDD;
  --ok: #4ADE80; --warn: #FBBF24; --danger: #F87171;
  --ok-bg: rgba(74,222,128,.12); --warn-bg: rgba(251,191,36,.12); --danger-bg: rgba(248,113,113,.12);
  --danger-border: rgba(248,113,113,.35);
  --chip: #2F2D2D; --hover: #3A3838;
  --row-border: #3B3939; --row-hover: rgba(255,255,255,.04);
  --shadow: 0 12px 40px rgba(0,0,0,.5);
}
* { box-sizing: border-box; margin: 0; padding: 0; }
html,body { height: 100%; }
body { background: var(--bg); color: var(--text); font: 14px/1.55 -apple-system, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif; }
button { font: inherit; cursor: pointer; border: none; border-radius: 8px; padding: 7px 14px; background: var(--accent); color: var(--accent-fg); transition: background .15s, border-color .15s; display: inline-flex; align-items: center; justify-content: center; gap: 6px; }
button:hover { background: var(--accent2); }
button.ghost { background: var(--panel2); border: 1px solid var(--border); color: var(--text); }
button.ghost:hover { background: var(--chip); border-color: var(--border2); }
button.danger { background: transparent; border: 1px solid var(--danger-border); color: var(--danger); }
button.danger:hover { background: var(--danger-bg); }
button.small { padding: 4px 10px; font-size: 12px; border-radius: 7px; }
button:disabled { opacity: .5; cursor: not-allowed; }
input, select, textarea { font: inherit; background: var(--panel2); border: 1px solid var(--border); color: var(--text); border-radius: 8px; padding: 8px 12px; outline: none; transition: border-color .15s, box-shadow .15s; }
input:focus, select:focus, textarea:focus { border-color: var(--ring); box-shadow: 0 0 0 3px rgba(65,124,221,.18); }
label { display: block; color: var(--dim); font-size: 12px; margin: 12px 0 4px; }
code, .mono { font-family: ui-monospace, "Cascadia Code", Consolas, monospace; font-size: 12.5px; }
a { color: var(--link); text-decoration: none; }
.ic { vertical-align: -2px; flex-shrink: 0; }
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-thumb { background: rgba(0,0,0,.16); border: 3px solid transparent; border-radius: 999px; background-clip: content-box; }
::-webkit-scrollbar-thumb:hover { background: rgba(0,0,0,.30); border: 3px solid transparent; background-clip: content-box; }
::-webkit-scrollbar-track, ::-webkit-scrollbar-corner { background: transparent; }
html[data-theme="dark"] ::-webkit-scrollbar-thumb { background: rgba(255,255,255,.16); border: 3px solid transparent; background-clip: content-box; }
html[data-theme="dark"] ::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,.30); border: 3px solid transparent; background-clip: content-box; }

#app { display: none; height: 100vh; }
.shell { display: flex; height: 100vh; }
.sidebar { width: 232px; display: flex; flex-direction: column; padding: 18px 12px; flex-shrink: 0; }
.brand { display: flex; align-items: center; gap: 9px; padding: 2px 10px 20px; font-size: 16px; font-weight: 700; color: var(--text-strong); letter-spacing: .2px; }
.logo { display: inline-flex; width: 26px; height: 26px; border-radius: 8px; background: var(--accent); color: var(--accent-fg); align-items: center; justify-content: center; }
.logo svg { display: block; }
.nav-item { display: flex; align-items: center; gap: 10px; padding: 8px 12px; border-radius: 8px; color: var(--dim); cursor: pointer; margin-bottom: 2px; user-select: none; font-size: 13.5px; transition: background .12s, color .12s; }
.nav-item:hover { background: var(--hover); color: var(--text-strong); }
.nav-item.active { background: var(--accent); color: var(--accent-fg); font-weight: 600; }
.sidebar-footer { margin-top: auto; border-top: 1px solid var(--border); padding: 12px 10px 4px; color: var(--dim); font-size: 12px; }
.main { flex: 1; overflow-y: auto; padding: 26px 30px; }
.page-title { font-size: 19px; font-weight: 700; margin-bottom: 4px; color: var(--text-strong); display: flex; align-items: center; gap: 9px; }
.page-desc { color: var(--dim2); font-size: 13px; margin-bottom: 20px; }

.card { background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); padding: 18px; margin-bottom: 16px; }
.card h3 { font-size: 13.5px; font-weight: 600; margin-bottom: 12px; color: var(--text-strong); display: flex; align-items: center; gap: 8px; }
.stat-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(210px, 1fr)); gap: 14px; margin-bottom: 16px; }
.stat { background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); padding: 14px 16px; }
.stat .k { color: var(--dim2); font-size: 12px; }
.stat .v { font-size: 20px; font-weight: 600; margin-top: 5px; color: var(--text-strong); font-variant-numeric: tabular-nums; }
.stat .sub { color: var(--dim2); font-size: 11.5px; margin-top: 3px; }

table { width: 100%; border-collapse: collapse; }
th { text-align: left; color: var(--dim2); font-weight: 500; font-size: 12px; padding: 8px 10px; border-bottom: 1px solid var(--border); white-space: nowrap; position: sticky; top: 0; background: var(--panel); z-index: 1; }
td { padding: 10px; border-bottom: 1px solid var(--row-border); vertical-align: middle; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: var(--row-hover); }
.table-wrap { overflow-x: auto; }
.empty { text-align: center; color: var(--dim2); padding: 28px 0; }

.badge { display: inline-flex; align-items: center; gap: 5px; padding: 2px 10px; border-radius: 999px; font-size: 11px; font-weight: 600; }
.b-ok { background: var(--ok-bg); color: var(--ok); }
.b-off { background: var(--danger-bg); color: var(--danger); }
.b-warn { background: var(--warn-bg); color: var(--warn); }
.b-info { background: var(--chip); color: var(--dim); }
.dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
.dot.on { background: var(--ok); }
.dot.off { background: var(--border2); }

.toolbar { display: flex; gap: 10px; align-items: center; margin-bottom: 14px; flex-wrap: wrap; }
.toolbar .spacer { flex: 1; }
.toolbar input, .toolbar select { min-width: 150px; }
.pager { display: flex; gap: 8px; align-items: center; justify-content: flex-end; margin-top: 12px; color: var(--dim); font-size: 12px; }

.modal-mask { position: fixed; inset: 0; background: rgba(20,20,20,.38); display: flex; align-items: center; justify-content: center; z-index: 200; backdrop-filter: blur(3px); }
.modal { background: var(--panel2); border: 1px solid var(--border); border-radius: 14px; width: 520px; max-width: 94vw; max-height: 88vh; overflow-y: auto; padding: 22px; box-shadow: var(--shadow); }
.modal h3 { font-size: 15px; margin-bottom: 6px; color: var(--text-strong); }
.modal .actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px; }
.modal .hint { color: var(--dim2); font-size: 12px; margin-top: 2px; }
.secret-box { background: var(--panel); border: 1px dashed var(--border2); border-radius: 8px; padding: 12px; margin-top: 12px; word-break: break-all; }
.rule-check { max-height: 220px; overflow-y: auto; border: 1px solid var(--border); border-radius: 8px; padding: 8px; background: var(--panel2); }
.rule-check label { display: flex; gap: 8px; align-items: center; margin: 4px 0; color: var(--text); font-size: 13px; }

#toasts { position: fixed; top: 18px; right: 18px; z-index: 300; display: flex; flex-direction: column; gap: 8px; }
.toast { background: var(--panel2); border: 1px solid var(--border); border-left: 3px solid var(--accent); border-radius: 10px; padding: 10px 16px; min-width: 240px; box-shadow: 0 8px 28px rgba(0,0,0,.12); animation: slidein .18s ease; font-size: 13px; }
.toast.ok { border-left-color: var(--ok); }
.toast.err { border-left-color: var(--danger); }
@keyframes slidein { from { transform: translateX(30px); opacity: 0; } to { transform: none; opacity: 1; } }

#login-view { display: flex; height: 100vh; align-items: center; justify-content: center; }
.login-card { background: var(--panel2); border: 1px solid var(--border); border-radius: 16px; padding: 34px; width: 360px; box-shadow: var(--shadow); }
.login-card .logo { width: 40px; height: 40px; border-radius: 11px; margin-bottom: 14px; }
.login-card h1 { color: var(--text-strong); font-size: 19px; margin-bottom: 4px; }
.login-card p { color: var(--dim2); font-size: 13px; margin-bottom: 18px; }
.login-card input { width: 100%; margin-bottom: 10px; padding: 10px 12px; }
.login-card button { width: 100%; padding: 10px; font-weight: 600; }
.login-err { color: var(--danger); font-size: 12px; min-height: 18px; margin-top: 8px; }

.qr-box { text-align: center; margin-top: 14px; }
.qr-box svg { width: 200px; height: 200px; background: #fff; padding: 8px; border-radius: 8px; }
.chart-wrap { position: relative; height: 220px; }
canvas.chart { width: 100%; height: 220px; }
.kv { display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px dashed var(--row-border); font-size: 13px; }
.kv .k { color: var(--dim); }
</style>
</head>
<body>
<div id="toasts"></div>
<div id="modal-root"></div>

<div id="login-view">
  <div class="login-card">
    <div class="logo"><i data-ic="zap" data-sz="22"></i></div>
    <h1>AgileNet</h1>
    <p>企业级网络穿透与代理链路由 · 管理控制台</p>
    <input id="login-user" type="text" placeholder="用户名" autocomplete="username">
    <input id="login-pass" type="password" placeholder="密码" autocomplete="current-password">
    <button id="login-btn" onclick="doLogin()">登 录</button>
    <div class="login-err" id="login-err"></div>
  </div>
</div>

<div id="app">
<div class="shell">
  <aside class="sidebar">
    <div class="brand"><span class="logo"><i data-ic="zap" data-sz="15"></i></span>AgileNet</div>
    <div class="nav-item" data-view="dashboard" onclick="switchView('dashboard')"><i data-ic="layout-dashboard"></i>概览</div>
    <div class="nav-item" data-view="accounts" onclick="switchView('accounts')"><i data-ic="users"></i>客户端账号</div>
    <div class="nav-item" data-view="groups" onclick="switchView('groups')"><i data-ic="shield"></i>权限组</div>
    <div class="nav-item" data-view="rules" onclick="switchView('rules')"><i data-ic="route"></i>路由规则</div>
    <div class="nav-item" data-view="tokens" onclick="switchView('tokens')"><i data-ic="key-round"></i>Relay 令牌</div>
    <div class="nav-item" data-view="audit" onclick="switchView('audit')"><i data-ic="scroll-text"></i>审计日志</div>
    <div class="nav-item" data-view="settings" onclick="switchView('settings')"><i data-ic="settings"></i>节点设置</div>
    <div class="sidebar-footer">
      <div id="me-info">-</div>
      <div style="margin-top:8px;display:flex;gap:6px">
        <button class="ghost small" onclick="toggleTheme()" id="theme-btn"></button>
        <button class="ghost small" onclick="doLogout()"><i data-ic="log-out" data-sz="13"></i>退出登录</button>
      </div>
    </div>
  </aside>
  <main class="main" id="view"></main>
</div>
</div>

<script>
'use strict';
/* ================= 图标（Lucide 内联 SVG，仅收录用到的图标） ================= */
const ICONS = {
  'zap': '<path d="M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z"/>',
  'layout-dashboard': '<rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/>',
  'users': '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
  'shield': '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>',
  'route': '<circle cx="6" cy="19" r="3"/><path d="M9 19h8.5a3.5 3.5 0 0 0 0-7h-11a3.5 3.5 0 0 1 0-7H15"/><circle cx="18" cy="5" r="3"/>',
  'key-round': '<path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/>',
  'scroll-text': '<path d="M15 12h-5"/><path d="M15 8h-5"/><path d="M19 17V5a2 2 0 0 0-2-2H4"/><path d="M8 21h12a2 2 0 0 0 2-2v-1a1 1 0 0 0-1-1H11a1 1 0 0 0-1 1v1a2 2 0 1 1-4 0V5a2 2 0 1 0-4 0v2a1 1 0 0 0 1 1h3"/>',
  'settings': '<path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/>',
  'sun': '<circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/>',
  'moon': '<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/>',
  'log-out': '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/>',
  'plus': '<path d="M5 12h14"/><path d="M12 5v14"/>',
  'copy': '<rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>',
  'qr-code': '<rect width="5" height="5" x="3" y="3" rx="1"/><rect width="5" height="5" x="16" y="3" rx="1"/><rect width="5" height="5" x="3" y="16" rx="1"/><path d="M21 16h-3a2 2 0 0 0-2 2v3"/><path d="M21 21v.01"/><path d="M12 7v3a2 2 0 0 1-2 2H4"/><path d="M3 12h.01"/><path d="M12 3h.01"/><path d="M12 16v.01"/><path d="M16 12h1"/><path d="M21 12v.01"/><path d="M12 21v-1"/>',
  'triangle-alert': '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
  'user': '<path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
};
function ic(name, size) {
  const s = size || 16;
  return '<svg class="ic" width="' + s + '" height="' + s + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + (ICONS[name] || '') + '</svg>';
}
/* 静态 HTML 中的 <i data-ic="name" data-sz="n"> 占位符替换为内联 SVG */
function hydrateIcons() {
  document.querySelectorAll('[data-ic]').forEach(el => {
    const span = document.createElement('span');
    span.innerHTML = ic(el.dataset.ic, el.dataset.sz ? +el.dataset.sz : 16);
    el.replaceWith(span.firstChild);
  });
}

/* ================= 基础设施 ================= */
const $ = (id) => document.getElementById(id);
const S = {
  access: localStorage.getItem('ag_access') || '',
  refresh: localStorage.getItem('ag_refresh') || '',
  view: 'dashboard',
  page: { accounts: 1, groups: 1, rules: 1, audit: 1 },
  size: { accounts: 10, groups: 10, rules: 10, audit: 15 },
  filter: { accounts: '', accountsEnabled: '', accountsGroup: '', rules: '', rulesType: '', auditAction: '' },
  groups: [],
  timers: [],
  ws: null,
};

function esc(s) {
  return String(s ?? '').replace(/[&<>"'`]/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','`':'&#96;'
  }[c]));
}
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
    rules: renderRules, tokens: renderTokens, audit: renderAudit, settings: renderSettings})[v] || renderDashboard;
  fn();
}
async function loadGroupsCache() {
  try { const d = await api('GET', '/api/v1/admin/groups?page_size=100'); S.groups = d.items || []; } catch(e) { S.groups = []; }
}
function groupName(id) {
  const g = S.groups.find(g => g.id === id);
  return g ? g.name : (id || '-');
}
function pager(viewKey, total, reload) {
  const page = S.page[viewKey], size = S.size[viewKey];
  const pages = Math.max(1, Math.ceil(total / size));
  return '<div class="pager"><span>共 ' + total + ' 条 · ' + page + '/' + pages + ' 页</span>' +
    '<button class="ghost small" ' + (page<=1?'disabled':'') + ' onclick="S.page.' + viewKey + '--;' + reload + '()">上一页</button>' +
    '<button class="ghost small" ' + (page>=pages?'disabled':'') + ' onclick="S.page.' + viewKey + '++;' + reload + '()">下一页</button></div>';
}
function shortId(id) { return esc(String(id||'').substring(0,8)); }

/* ================= 概览 ================= */
async function renderDashboard() {
  $('view').innerHTML = '<div class="page-title">' + ic('layout-dashboard', 20) + '节点概览</div><div class="page-desc">运行状态、连接拓扑与流量统计</div>' +
    '<div class="stat-grid" id="dash-stats"></div>' +
    '<div class="card"><h3>流量趋势（24h，按小时）</h3><div class="chart-wrap"><canvas class="chart" id="traffic-chart"></canvas></div></div>' +
    '<div class="card"><h3>实时事件</h3><div id="events-list" class="mono" style="max-height:180px;overflow-y:auto;color:var(--dim)">连接事件中…</div></div>';

  async function load() {
    try {
      const st = await api('GET', '/api/v1/admin/node/status');
      const L = st.roles.listener, C = st.roles.connector, P = st.proxy, A = st.accounts;
      $('dash-stats').innerHTML =
        statCard('节点名称', esc(st.node_name), 'v' + esc(st.version) + ' · 运行 ' + fmtUptime(st.uptime)) +
        statCard('Relay 监听', L.enabled ? '<span class="badge b-ok">启用</span>' : '<span class="badge b-off">未启用</span>',
          L.enabled ? esc(L.addr) + ' · 下游 ' + (L.connected_connectors||0) + ' 节点 · 在线客户端 ' + (L.online_clients||0) : '-') +
        statCard('上游连接', C.enabled ? esc(C.status) : '<span class="badge b-off">未启用</span>', C.enabled ? esc(C.upstream) : '-') +
        statCard('本地代理', P.enabled ? '<span class="badge b-ok">启用</span>' : '<span class="badge b-off">未启用</span>',
          P.enabled ? esc(P.listen) + ' · 活跃 ' + (P.active_connections||0) + ' · 规则 ' + (P.rule_count||0) : '规则 ' + (P.rule_count||0)) +
        statCard('客户端账号', (A.total||0) + ' 个', '在线 ' + (A.online||0) + ' · 禁用 ' + (A.disabled||0)) +
        statCard('系统资源', (st.system.memory_mb||0) + ' MB', 'CPU ' + (st.system.cpu_usage||0).toFixed(1) + '% · 总内存 ' + (st.system.total_memory_mb||0) + ' MB');
      if (L.enabled && (L.peers||[]).length) {
        $('dash-stats').innerHTML += statCard('在线下游节点', (L.peers||[]).map(p => '<div class="mono"><span class="dot on"></span>' + esc(p) + '</div>').join(''), '');
      }
    } catch(e) { toast(e.message, 'err'); }

    try {
      const t = await api('GET', '/api/v1/admin/node/stats?period=24h&group_by=time');
      drawChart($('traffic-chart'), t.points || []);
    } catch(e) {}
  }
  function statCard(k, v, sub) {
    return '<div class="stat"><div class="k">' + k + '</div><div class="v">' + v + '</div><div class="sub">' + sub + '</div></div>';
  }
  await load();
  S.timers.push(setInterval(load, 15000));

  // WebSocket 实时事件
  try {
    if (S.ws) { S.ws.close(); S.ws = null; }
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(proto + '://' + location.host + '/api/v1/admin/node/events?token=' + encodeURIComponent(S.access));
    S.ws = ws;
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

function drawChart(canvas, points) {
  if (!canvas) return;
  const cs = getComputedStyle(document.documentElement);
  const cDim = cs.getPropertyValue('--dim2').trim() || '#8C8E94';
  const cRx = cs.getPropertyValue('--ring').trim() || '#417CDD';
  const ctx = canvas.getContext('2d');
  const W = canvas.width = canvas.offsetWidth * 2;
  const H = canvas.height = canvas.offsetHeight * 2;
  ctx.clearRect(0, 0, W, H);
  if (!points.length) {
    ctx.fillStyle = cDim; ctx.font = '24px sans-serif';
    ctx.fillText('暂无流量数据', 20, H/2);
    return;
  }
  const tx = points.map(p => p.bytes_tx), rx = points.map(p => p.bytes_rx);
  const max = Math.max(1, ...tx, ...rx);
  const pad = 30;
  function drawLine(vals, color) {
    ctx.strokeStyle = color; ctx.lineWidth = 3; ctx.beginPath();
    vals.forEach((v, i) => {
      const x = pad + i * (W - 2*pad) / Math.max(1, vals.length - 1);
      const y = H - pad - (v / max) * (H - 2*pad);
      i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
    });
    ctx.stroke();
  }
  drawLine(rx, cRx);
  drawLine(tx, cDim);
  ctx.fillStyle = cDim; ctx.font = '20px sans-serif';
  ctx.fillText('RX ' + fmtBytes(rx.reduce((a,b)=>a+b,0)) + '（蓝）  TX ' + fmtBytes(tx.reduce((a,b)=>a+b,0)) + '（灰）', pad, 26);
}

/* ================= 客户端账号 ================= */
async function renderAccounts() {
  $('view').innerHTML = '<div class="page-title">' + ic('users', 20) + '客户端账号</div><div class="page-desc">账号即客户端身份凭据，密码由服务端生成（sk- 48 位强随机），仅创建/重置时展示一次</div>' +
    '<div class="toolbar">' +
      '<input id="acc-q" placeholder="搜索账号/备注" value="' + esc(S.filter.accounts) + '" oninput="S.filter.accounts=this.value;S.page.accounts=1;renderAccounts()">' +
      '<select onchange="S.filter.accountsGroup=this.value;S.page.accounts=1;renderAccounts()">' +
        '<option value="">全部权限组</option>' +
        S.groups.map(g => '<option value="' + esc(g.id) + '" ' + (S.filter.accountsGroup===g.id?'selected':'') + '>' + esc(g.name) + '</option>').join('') +
      '</select>' +
      '<select onchange="S.filter.accountsEnabled=this.value;S.page.accounts=1;renderAccounts()">' +
        '<option value="">全部状态</option>' +
        '<option value="true" ' + (S.filter.accountsEnabled==='true'?'selected':'') + '>启用</option>' +
        '<option value="false" ' + (S.filter.accountsEnabled==='false'?'selected':'') + '>禁用</option>' +
      '</select>' +
      '<div class="spacer"></div>' +
      '<button onclick="openCreateAccount()">' + ic('plus', 15) + '新建账号</button>' +
    '</div>' +
    '<div class="card table-wrap"><table><thead><tr><th>账号</th><th>权限组</th><th>在线</th><th>状态</th><th>最后在线</th><th>备注</th><th>操作</th></tr></thead><tbody id="acc-body"></tbody></table><div id="acc-pager"></div></div>';
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
      '<tr><td><b>' + esc(a.username) + '</b><div class="mono" style="color:var(--dim2)">' + shortId(a.id) + '</div></td>' +
      '<td>' + esc(a.group_name || groupName(a.group_id)) + '</td>' +
      '<td><span class="dot ' + (a.online?'on':'off') + '"></span>' + (a.online?'在线':'离线') + '</td>' +
      '<td>' + (a.enabled ? '<span class="badge b-ok">启用</span>' : '<span class="badge b-off">禁用</span>') + '</td>' +
      '<td style="color:var(--dim)">' + esc(a.last_seen_at || '从未') + '</td>' +
      '<td style="color:var(--dim)">' + esc(a.remark || '-') + '</td>' +
      '<td style="white-space:nowrap">' +
        '<button class="ghost small" onclick="resetAccountPwd(\'' + esc(a.id) + '\',\'' + esc(a.username) + '\')">重置密码</button> ' +
        '<button class="ghost small" onclick="toggleAccount(\'' + esc(a.id) + '\',' + !a.enabled + ')">' + (a.enabled?'禁用':'启用') + '</button> ' +
        '<button class="danger small" onclick="delAccount(\'' + esc(a.id) + '\',\'' + esc(a.username) + '\')">删除</button>' +
      '</td></tr>'
    ).join('') || '<tr><td colspan="7" class="empty">暂无账号</td></tr>';
    $('acc-pager').innerHTML = pager('accounts', d.total||0, 'renderAccounts');
  } catch(e) { toast(e.message, 'err'); }
}
function openCreateAccount() {
  if (!S.groups.length) { toast('请先创建权限组', 'err'); return; }
  openModal('新建客户端账号',
    '<label>账号名（3-32 位字母数字_-）</label><input id="na-user" style="width:100%">' +
    '<label>权限组</label><select id="na-group" style="width:100%">' +
      S.groups.map(g => '<option value="' + esc(g.id) + '">' + esc(g.name) + '</option>').join('') + '</select>' +
    '<label>备注</label><input id="na-remark" style="width:100%">' +
    '<div class="hint">密码由服务端自动生成（sk- 48 位强随机），创建后仅展示一次</div>',
    [
      {label:'取消', kind:'ghost', fn: closeModal},
      {label:'创建', fn: async () => {
        const username = $('na-user').value.trim(), group_id = $('na-group').value, remark = $('na-remark').value.trim();
        try {
          const d = await api('POST', '/api/v1/admin/accounts', {username, group_id, remark});
          showAccountSecret('账号创建成功 — 请立即保存凭据', d.username, d.password, d.connect_url, d.id);
          loadAccounts();
        } catch(e) { toast(e.message, 'err'); }
      }},
    ]);
}
function showAccountSecret(title, username, password, connectUrl, accountId) {
  openModal(title,
    '<div class="kv"><span class="k">账号</span><span><b>' + esc(username) + '</b></span></div>' +
    '<div class="kv"><span class="k">密码</span><span class="mono">' + esc(password) + ' <button class="ghost small" onclick="copyText(\'' + esc(password) + '\')">' + ic('copy', 13) + '复制</button></span></div>' +
    '<div class="secret-box"><div style="color:var(--dim);font-size:12px;margin-bottom:4px">接入链接（客户端导入）</div><span class="mono">' + esc(connectUrl) + '</span></div>' +
    '<div class="actions" style="justify-content:flex-start;margin-top:10px"><button class="ghost small" onclick="copyText(\'' + esc(connectUrl) + '\')">' + ic('copy', 13) + '复制接入链接</button>' +
    '<button class="ghost small" onclick="showQr(\'' + esc(accountId) + '\')">' + ic('qr-code', 13) + '显示二维码</button></div>' +
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
    '<div class="toolbar"><input placeholder="搜索名称/备注" value="' + esc(S.filter.groups||'') + '" oninput="S.filter.groups=this.value;S.page.groups=1;renderGroups()">' +
    '<div class="spacer"></div><button onclick="openCreateGroup()">' + ic('plus', 15) + '新建权限组</button></div>' +
    '<div class="card table-wrap"><table><thead><tr><th>名称</th><th>规则数</th><th>账号数</th><th>备注</th><th>操作</th></tr></thead><tbody id="grp-body"></tbody></table><div id="grp-pager"></div></div>';
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
        '<button class="ghost small" onclick="openGroupDetail(\'' + esc(g.id) + '\')">详情</button> ' +
        '<button class="ghost small" onclick="openBindRules(\'' + esc(g.id) + '\',\'' + esc(g.name) + '\')">绑定规则</button> ' +
        '<button class="ghost small" onclick="openEditGroup(\'' + esc(g.id) + '\',\'' + esc(g.name) + '\',\'' + esc(g.remark||'') + '\')">编辑</button> ' +
        '<button class="danger small" onclick="delGroup(\'' + esc(g.id) + '\',\'' + esc(g.name) + '\',' + g.account_count + ')">删除</button>' +
      '</td></tr>'
    ).join('') || '<tr><td colspan="5" class="empty">暂无权限组</td></tr>';
    $('grp-pager').innerHTML = pager('groups', d.total||0, 'renderGroups');
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
    const g = await api('GET', '/api/v1/admin/groups/' + id);
    openModal('权限组详情 — ' + g.name,
      '<h3 style="margin:10px 0 6px">关联规则（' + (g.rules||[]).length + '）</h3>' +
      ((g.rules||[]).map(r => '<div class="kv"><span class="mono">' + esc(r.value) + '</span><span class="badge b-info">' + esc(r.type) + '</span></div>').join('') || '<div class="empty">无</div>') +
      '<h3 style="margin:14px 0 6px">组内账号（' + (g.accounts||[]).length + '）</h3>' +
      ((g.accounts||[]).map(a => '<div class="kv"><span>' + esc(a.username) + '</span><span>' + (a.enabled?'<span class="badge b-ok">启用</span>':'<span class="badge b-off">禁用</span>') + '</span></div>').join('') || '<div class="empty">无</div>'));
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
      '<input placeholder="搜索匹配值/备注" value="' + esc(S.filter.rules) + '" oninput="S.filter.rules=this.value;S.page.rules=1;renderRules()">' +
      '<select onchange="S.filter.rulesType=this.value;S.page.rules=1;renderRules()">' +
        '<option value="">全部类型</option>' +
        '<option value="ip-cidr" ' + (S.filter.rulesType==='ip-cidr'?'selected':'') + '>ip-cidr</option>' +
        '<option value="host" ' + (S.filter.rulesType==='host'?'selected':'') + '>host</option>' +
      '</select>' +
      '<div class="spacer"></div>' +
      '<button class="ghost" onclick="openBatchImport()">批量导入</button>' +
      '<button onclick="openCreateRule()">' + ic('plus', 15) + '新建规则</button>' +
    '</div>' +
    '<div class="card table-wrap"><table><thead><tr><th>类型</th><th>匹配值</th><th>解析</th><th>引用组</th><th>备注</th><th>操作</th></tr></thead><tbody id="rule-body"></tbody></table><div id="rule-pager"></div></div>';
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
        '<button class="ghost small" onclick="openEditRule(\'' + esc(r.id) + '\',\'' + esc(r.type) + '\',\'' + esc(r.value) + '\',' + r.resolve + ',\'' + esc(r.remark||'') + '\')">编辑</button> ' +
        '<button class="danger small" onclick="delRule(\'' + esc(r.id) + '\',\'' + esc(r.value) + '\',' + (r.group_count||0) + ')">删除</button>' +
      '</td></tr>'
    ).join('') || '<tr><td colspan="6" class="empty">暂无规则</td></tr>';
    $('rule-pager').innerHTML = pager('rules', d.total||0, 'renderRules');
  } catch(e) { toast(e.message, 'err'); }
}
function ruleFormHtml(t, v, resolve, remark) {
  return '<label>类型</label><select id="rf-type" style="width:100%" ' + (t?'disabled':'') + '>' +
      '<option value="ip-cidr" ' + (t==='ip-cidr'?'selected':'') + '>ip-cidr（网段，如 10.12.0.0/16）</option>' +
      '<option value="host" ' + (t==='host'?'selected':'') + '>host（域名，如 git.internal 或 *.dev.internal）</option>' +
    '</select>' +
    '<label>匹配值</label><input id="rf-value" style="width:100%" value="' + esc(v||'') + '" placeholder="10.12.0.0/16 或 git.internal">' +
    '<label style="display:flex;gap:8px;align-items:center;margin-top:10px"><input type="checkbox" id="rf-resolve" ' + (resolve?'checked':'') + '> host 需要客户端写入系统 hosts（仅 host 类型）</label>' +
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

/* ================= Relay 令牌 ================= */
async function renderTokens() {
  $('view').innerHTML = '<div class="page-title">' + ic('key-round', 20) + 'Relay 令牌</div><div class="page-desc">下游节点连入本节点的预共享密钥（psk_ 48 位），服务端只存哈希，全文仅创建时展示一次</div>' +
    '<div class="toolbar"><div class="spacer"></div><button onclick="openCreateToken()">' + ic('plus', 15) + '生成令牌</button></div>' +
    '<div class="card table-wrap"><table><thead><tr><th>前缀</th><th>备注</th><th>最近使用</th><th>创建时间</th><th>操作</th></tr></thead><tbody id="tok-body"></tbody></table></div>';
  await loadTokens();
}
async function loadTokens() {
  const body = $('tok-body'); if (!body) return;
  try {
    const d = await api('GET', '/api/v1/admin/node/relay-tokens');
    body.innerHTML = (d.items||[]).map(t =>
      '<tr><td class="mono">' + esc(t.token_prefix) + '</td>' +
      '<td>' + esc(t.remark || '-') + '</td>' +
      '<td style="color:var(--dim)">' + esc(t.last_used_at || '未使用') + '</td>' +
      '<td style="color:var(--dim)">' + esc(t.created_at) + '</td>' +
      '<td><button class="danger small" onclick="delToken(\'' + esc(t.id) + '\')">吊销</button></td></tr>'
    ).join('') || '<tr><td colspan="5" class="empty">暂无令牌</td></tr>';
  } catch(e) { toast(e.message, 'err'); }
}
function openCreateToken() {
  openModal('生成 Relay 令牌',
    '<label>备注（如：分公司跳板机）</label><input id="nt-remark" style="width:100%">',
    [
      {label:'取消', kind:'ghost', fn: closeModal},
      {label:'生成', fn: async () => {
        try {
          const d = await api('POST', '/api/v1/admin/node/relay-tokens', { remark: $('nt-remark').value.trim() });
          openModal('令牌已生成 — 仅此一次展示',
            '<div class="secret-box"><span class="mono">' + esc(d.token) + '</span></div>' +
            '<div class="actions" style="justify-content:flex-start;margin-top:10px"><button class="ghost small" onclick="copyText(\'' + esc(d.token) + '\')">' + ic('copy', 13) + '复制令牌</button></div>' +
            '<div class="hint" style="color:var(--warn)">' + ic('triangle-alert', 13) + ' 请立即保存，服务端只存哈希，无法找回</div>',
            [{label:'我已保存', fn: () => { closeModal(); loadTokens(); }}]);
        } catch(e) { toast(e.message, 'err'); }
      }},
    ]);
}
async function delToken(id) {
  confirmAction('确定吊销该令牌？使用它的下游节点将在断开后无法重连。', async () => {
    try { await api('DELETE', '/api/v1/admin/node/relay-tokens/' + id); toast('已吊销', 'ok'); loadTokens(); }
    catch(e) { toast(e.message, 'err'); }
  });
}

/* ================= 审计日志 ================= */
async function renderAudit() {
  $('view').innerHTML = '<div class="page-title">' + ic('scroll-text', 20) + '审计日志</div><div class="page-desc">全部敏感操作留痕：登录、增删改、启停、重置、吊销</div>' +
    '<div class="toolbar">' +
      '<select onchange="S.filter.auditAction=this.value;S.page.audit=1;renderAudit()">' +
        '<option value="">全部动作</option>' +
        ['admin.login','admin.init','rule.create','rule.update','rule.delete','rule.batch_import',
         'group.create','group.update','group.delete','group.update_rules',
         'account.create','account.update','account.delete','account.reset_password','account.enable','account.disable',
         'relay_token.create','relay_token.delete','node.update_settings'].map(a =>
          '<option value="' + a + '" ' + (S.filter.auditAction===a?'selected':'') + '>' + a + '</option>').join('') +
      '</select>' +
    '</div>' +
    '<div class="card table-wrap"><table><thead><tr><th>时间</th><th>操作人</th><th>动作</th><th>目标</th><th>详情</th><th>来源 IP</th></tr></thead><tbody id="audit-body"></tbody></table><div id="audit-pager"></div></div>';
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
    $('audit-pager').innerHTML = pager('audit', d.total||0, 'renderAudit');
  } catch(e) { toast(e.message, 'err'); }
}

/* ================= 节点设置 ================= */
async function renderSettings() {
  $('view').innerHTML = '<div class="page-title">' + ic('settings', 20) + '节点设置</div><div class="page-desc">基础信息、公网接入、管理员与系统日志</div>' +
    '<div class="card"><h3>基础信息</h3>' +
      '<label>节点名称</label><div style="display:flex;gap:10px"><input id="set-name" style="flex:1"><button onclick="saveNodeName()">保存</button></div>' +
      '<label>公网接入地址（connect_url 与隧道端点主机名）</label><div style="display:flex;gap:10px"><input id="set-host" style="flex:1" placeholder="cdn.example.com"><button onclick="savePublicHost()">保存</button></div>' +
    '</div>' +
    '<div class="card"><h3>管理员</h3>' +
      '<div class="table-wrap"><table><thead><tr><th>用户名</th><th>创建时间</th><th>操作</th></tr></thead><tbody id="admin-body"></tbody></table></div>' +
      '<div class="toolbar" style="margin-top:12px"><input id="na-user" placeholder="新管理员用户名"><input id="na-pass" type="password" placeholder="密码（≥10位含大小写数字）"><button onclick="createAdmin()">' + ic('plus', 15) + '新建管理员</button></div>' +
    '</div>' +
    '<div class="card"><h3>修改我的密码</h3>' +
      '<label>旧密码</label><input id="pw-old" type="password" style="width:280px">' +
      '<label>新密码（≥10 位，含大小写字母与数字）</label><input id="pw-new" type="password" style="width:280px">' +
      '<div style="margin-top:12px"><button onclick="changePassword()">修改密码（修改后需重新登录）</button></div>' +
    '</div>' +
    '<div class="card"><h3>服务信息</h3><div id="set-info"></div></div>' +
    '<div class="card"><h3>最近系统日志</h3><div id="set-logs" class="mono" style="max-height:300px;overflow-y:auto;color:var(--dim);font-size:12px"></div></div>';
  try {
    const st = await api('GET', '/api/v1/admin/node/status');
    $('set-name').value = st.node_name || '';
    $('set-info').innerHTML =
      kv('版本', 'v' + st.version) + kv('运行时长', fmtUptime(st.uptime)) +
      kv('Relay 监听', st.roles.listener.enabled ? st.roles.listener.addr : '未启用') +
      kv('上游连接', st.roles.connector.enabled ? st.roles.connector.upstream + '（' + st.roles.connector.status + '）' : '未启用') +
      kv('本地代理', st.proxy.enabled ? st.proxy.listen : '未启用') +
      (st.cert_fingerprint
        ? '<div class="kv"><span class="k">证书指纹 (SHA-256)</span><span class="mono" style="font-size:11px;word-break:break-all">' + esc(st.cert_fingerprint) +
          ' <button class="ghost small" onclick="copyText(\'' + esc(st.cert_fingerprint) + '\')">' + ic('copy', 13) + '复制</button></span></div>'
        : '');
  } catch(e) { toast(e.message, 'err'); }
  try {
    const conf = await api('GET', '/api/v1/admin/admins');
    $('admin-body').innerHTML = (conf.items||[]).map(a =>
      '<tr><td><b>' + esc(a.username) + '</b></td><td style="color:var(--dim)">' + esc(a.created_at) + '</td>' +
      '<td><button class="danger small" onclick="delAdmin(\'' + esc(a.id) + '\',\'' + esc(a.username) + '\')">删除</button></td></tr>'
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
}
function toggleTheme() {
  localStorage.setItem('ag_theme', (localStorage.getItem('ag_theme') || 'light') === 'dark' ? 'light' : 'dark');
  applyTheme();
}

/* ================= 启动 ================= */
window.addEventListener('DOMContentLoaded', () => {
  hydrateIcons();
  applyTheme();
  $('login-pass').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
  $('login-user').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
  if (S.access) { enterApp(); }
});
</script>
</body>
</html>
"#;

/// 管理页面（带安全响应头）
pub async fn admin_page_handler() -> impl IntoResponse {
    let mut resp = Html(ADMIN_HTML).into_response();
    let headers = resp.headers_mut();
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self' ws: wss:; img-src 'self' data:; frame-ancestors 'none'",
        ),
    );
    resp
}

pub fn create_ui_router() -> Router {
    Router::new()
        .route("/", get(admin_page_handler))
        .route("/admin", get(admin_page_handler))
}
