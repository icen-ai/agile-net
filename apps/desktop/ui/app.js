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
    'reconnecting-nodes': '正在自动重连 {n} 个已保存的扇入…',
    'connected-toast': '已连接 {name}（下发规则 {n} 条）',
    'proxy-on': '代理已启动', 'proxy-off': '代理已停止',
    'btn-start-proxy': '启动代理', 'btn-stop-proxy': '停止代理',
    'err-need-url': '请粘贴接入链接', 'err-bad-url': '链接格式不正确，应以 agilenet://connect? 开头',
    'clip-ok': '已识别剪贴板中的接入链接', 'clip-none': '剪贴板中没有接入链接', 'clip-fail': '无法读取剪贴板',
    'disconnected': '已断开', 'no-rules': '无生效规则', 'no-creds': '尚未添加扇入',
  },
  en: {
    'st-connected': 'Connected', 'st-connecting': 'Connecting', 'st-reconnecting': 'Reconnecting', 'st-disconnected': 'Disconnected',
    'st-unreachable': 'Unreachable', 'st-degraded': 'Some networks unreachable',
    'banner-degraded': 'Node {name} unreachable, reconnecting…',
    'banner-down': 'Node {name} is offline; its networks are unreachable',
    'proxy-running': 'Proxy running', 'proxy-stopped': 'Proxy stopped',
    'reconnecting-nodes': 'Reconnecting {n} saved fan-ins…',
    'connected-toast': 'Connected {name} ({n} rules)',
    'proxy-on': 'Proxy started', 'proxy-off': 'Proxy stopped',
    'btn-start-proxy': 'Start Proxy', 'btn-stop-proxy': 'Stop Proxy',
    'err-need-url': 'Please paste a connect URL', 'err-bad-url': 'Invalid URL: must start with agilenet://connect?',
    'clip-ok': 'Connect URL detected in clipboard', 'clip-none': 'No connect URL in clipboard', 'clip-fail': 'Cannot read clipboard',
    'disconnected': 'Disconnected', 'no-rules': 'No active rules', 'no-creds': 'No fan-in saved',
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

/* 行内帮助（共享组件 .ahelp，样式在 components.css）：问号图标 + 纯 CSS hover 说明卡 */
function ahelp(text) {
  return '<span class="ahelp">' + AgIcon('badge-question-mark', 13) + '<span class="ahelp-tip">' + esc(text) + '</span></span>';
}

/* 变更检测写入：内容不变不动 DOM（轮询渲染防频闪） */
function setText(id, s) { const el = $(id); if (el && el.textContent !== s) el.textContent = s; }
function setHtml(id, h) { const el = $(id); if (el && el.innerHTML !== h) el.innerHTML = h; }

/* ================= 行内编辑（.agedit，共享样式在 components.css） =================
   通用小模式：显示「值 [修改]」→ 点击变输入框 + [保存]；Enter 保存 / Esc 取消。
   opts: { get(): 显示值, editValue?(): 输入框初值（默认同 get）, validate?(v): 错误文案|null, set(v): Promise }
   validate 报错 → toast 且不写入（保持编辑态）；轮询侧用返回句柄 refresh() 同步显示值（编辑中不打扰）。 */
function bindInlineEdit(el, opts) {
  let editing = false, lastVal = null;
  el.classList.add('agedit');
  function render() {
    if (editing) return;
    const v = opts.get();
    if (v === lastVal && el.firstChild) return; // 变更检测：显示值未变不动 DOM
    lastVal = v;
    el.innerHTML = '<span class="agedit-val">' + esc(v) + '</span>' +
      '<button type="button" class="ghost small agedit-btn">修改</button>';
    el.querySelector('.agedit-btn').onclick = () => {
      editing = true;
      el.innerHTML = '<input type="text" class="agedit-input" autocomplete="off" spellcheck="false">' +
        '<button type="button" class="ghost small agedit-btn">保存</button>';
      const input = el.querySelector('.agedit-input');
      const btn = el.querySelector('.agedit-btn');
      input.value = opts.editValue ? opts.editValue() : v;
      input.focus(); input.select();
      const cancel = () => { editing = false; lastVal = null; render(); };
      const save = async () => {
        const val = input.value.trim();
        const err = opts.validate ? opts.validate(val) : null;
        if (err) { toast(err, 'err'); input.focus(); return; }
        btn.disabled = true;
        try {
          await opts.set(val);
          editing = false; lastVal = null;
          render();
        } catch (e) {
          toast(friendlyError(e), 'err');
          btn.disabled = false;
        }
      };
      btn.onclick = save;
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); save(); }
        if (e.key === 'Escape') cancel();
      });
    };
  }
  render();
  return { refresh: render };
}

/* ================= ag-select 统一自定义下拉（共享组件，样式在 components.css） =================
   渐进增强：原生 select 保留为数据/逻辑载体（视觉隐藏），自定义 UI 与其双向同步——
   选择自定义项 = 写回 sel.value 并 dispatch change（冒泡，既有绑定照常触发）；
   程序化改选项/值后调 agSelectRefresh(sel) 刷新标签；sel.disabled 同步禁用态。
   弹出层 fixed 挂 body（避开 overflow 裁剪），点击外部 / Esc / 滚动 / 缩放关闭。 */
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

/* 扫描 root 内未增强的 select 并增强（幂等）；动态内容渲染后再调一次即可 */
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
    btn.innerHTML = '<span class="agsel-label"></span>' + AgIcon('chevron-down', 14);
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

/* ================= ag-tabs 横向页签条（共享组件，样式在 components.css） =================
   结构：<div class="agtabs"><div class="agtabs-pill"><button class="agtab" data-agtab="k">…
         面板 = 与页签条同容器内的直属 [data-agpanel="k"]；点击置 active 并显示对应面板。
   纯显隐切换不重渲染；onSwitch(key) 供页面同步状态。 */
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

/* ================= 灵动岛（状态 + 通知 + 异常详情） =================
   形变原则：容器显式宽高动画（overflow:hidden 全程包裹内容），
   旧内容即刻退场、新内容延迟淡入——任何中间帧都不会出现内容溢出岛体。 */
const Island = {
  timer: null, canExpand: false, detailNodes: [], current: 'bar', _t1: null, _t2: null,
  init() {
    $('island-bar').onclick = () => { if (this.canExpand) this.toggleDetail(); };
    // 展开详情时点击岛外任意处自动收回
    document.addEventListener('click', (e) => {
      if (this.current === 'detail' && !e.target.closest('#island')) this.morph('bar');
    });
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
    } else {
      // 同态连续调用（如两条通知 200ms 内接连到达）：上一次的 reveal 定时器已被
      // clear，若不补显，内容会永远残留 visibility:hidden —— 空岛（白 pill 无内容）
      parts[showPart].style.visibility = '';
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
  // 无任何活跃连接且未保存扇入 = 空状态：只显示接入引导；有数据后显示仪表盘卡片网格
  const empty = (!nodes || nodes.length === 0) && !(window._credsRaw || []).length;
  $('onboarding').style.display = empty ? 'block' : 'none';
  const dg = $('dash-grid');
  if (dg) dg.style.display = empty ? 'none' : '';
}

/* ================= 列表过滤（搜索） ================= */
const FILTERS = { creds: '', rules: '' };
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
  ['creds', 'rules'].forEach(key => {
    $('search-' + key).querySelector('input').oninput = (e) => setFilter(key, e.target.value);
  });
}
function setFilter(key, v) {
  FILTERS[key] = v.trim().toLowerCase();
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
  trackFaninTraffic(nodes);
  refreshAdminEntry();
  await restorePaused(nodes);
  const sig = JSON.stringify(nodes);
  if (force || sig !== lastNodesSig) {
    lastNodesSig = sig;
    await loadPaused(nodes);
    renderMergedRules(nodes);
    renderCredList(window._credsRaw || [], window._nodeStatus || {});
  }
  updateOnboarding(nodes);
  updateDashFanin();
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

/* ---- 规则统一表格（自定义 放行/映射 + 端点拉取合并；类型过滤 RL_FILTER 与搜索 FILTERS.rules 叠加） ---- */
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
  const tf = RL_FILTER;
  const pausedMap = window._paused || {};
  const custom = window._custom || { bypass: [], hosts: [] };
  const hit = (...xs) => !f || xs.some(x => x && String(x).toLowerCase().includes(f));
  const rows = [];
  // 自定义放行（引擎优先级最高，排在最前）
  if (tf === 'all' || tf === 'bypass') {
    for (const r of custom.bypass) {
      const way = r.via_subscription ? '经过订阅' : '直连';
      if (!hit(r.pattern, '放行', way, '自定义')) continue;
      rows.push('<tr class="' + (r.enabled ? '' : 'rule-paused') + '">' +
        '<td><span class="badge b-ok">放行</span></td>' +
        '<td class="mono">' + esc(r.pattern) + '</td>' +
        '<td>' + way + '</td>' +
        '<td class="dim">自定义</td>' +
        '<td><label class="switch"><input type="checkbox" data-cr="' + esc(r.id) + '"' + (r.enabled ? ' checked' : '') + '><span class="slider"></span></label></td>' +
        '<td><button class="danger small icon-btn" title="删除该放行规则" data-crdel="' + esc(r.id) + '">' + AgIcon('trash-2', 13) + '</button></td></tr>');
    }
  }
  // hosts 映射（用户自建可启停/删除；系统既有只读不显示操作）
  if (tf === 'all' || tf === 'host') {
    for (const r of custom.hosts) {
      const sys = r.source === 'system';
      const src = sys ? '系统 hosts' : '自定义';
      if (!hit(r.hostname, r.ip, '映射', src)) continue;
      rows.push('<tr class="' + (r.enabled ? '' : 'rule-paused') + '">' +
        '<td><span class="badge b-gray">映射</span></td>' +
        '<td class="mono">' + esc(r.hostname) + '</td>' +
        '<td class="mono">→ ' + esc(r.ip) + '</td>' +
        '<td class="dim">' + src + '</td>' +
        (sys
          ? '<td><span class="dim">只读</span></td><td></td>'
          : '<td><label class="switch"><input type="checkbox" data-cr="' + esc(r.id) + '"' + (r.enabled ? ' checked' : '') + '><span class="slider"></span></label></td>' +
            '<td><button class="danger small icon-btn" title="删除该映射" data-crdel="' + esc(r.id) + '">' + AgIcon('trash-2', 13) + '</button></td>') +
        '</tr>');
    }
  }
  // 端点拉取（来源即端点名；启停走既有暂停语义）
  if (tf === 'all' || tf === 'pulled') {
    for (const n of nodes) {
      const dot = n.status === 'Connected' ? 'ok' : (n.status === 'Disconnected' ? 'down' : 'warn');
      const pset = pausedMap[n.node_id] || new Set();
      for (const r of (n.rules || [])) {
        const key = ruleKey(r);
        if (!hit(r.value, r.type, n.node_name)) continue;
        const paused = pset.has(key);
        rows.push('<tr class="' + (paused ? 'rule-paused' : '') + '"><td><span class="rdot ' + dot + '"></span><span class="badge b-ok">' + esc(r.type) + '</span></td>' +
          '<td class="mono">' + esc(r.value) + '</td>' +
          '<td class="dim">—</td>' +
          '<td class="dim">' + esc(n.node_name) + '</td>' +
          '<td><label class="switch"><input type="checkbox" data-node="' + esc(n.node_id) + '" data-rule="' + esc(key) + '"' + (paused ? '' : ' checked') + '><span class="slider"></span></label></td>' +
          '<td></td></tr>');
      }
    }
  }
  $('rules-body').innerHTML = rows.join('') || '<tr><td colspan="6" class="empty">' + ((f || tf !== 'all') ? '无匹配结果' : T('no-rules')) + '</td></tr>';
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

/* ================= 自定义规则（放行 / hosts 映射）与组合 =================
   后端契约（apps/desktop/src/custom_rules.rs + lib.rs 命令层，GUI 本机能力，Web 远程面隐藏）：
   list_custom_rules() -> { bypass:[{id,pattern,via_subscription,enabled}],
                            hosts:[{id,hostname,ip,enabled,source}] }（source=user|system，system 只读）；
   组合 rule_keys：自定义 = 其 id，拉取 = ruleKey(r)（type:value 小写）。
   组合中的拉取 key 引擎忽略，由本模块经既有暂停接口编排（orchestrateCombo）。 */
let RL_FILTER = 'all';    // 类型过滤（与搜索叠加）：all | bypass | host | pulled
let CUSTOM_SIG = null;    // list_custom_rules 轮询变更检测签名
let COMBO_ITEMS = [];
let COMBO_SIG = null;
let COMBO_EDIT_ID = null;
let CE_MEMBERS = new Set(); // 组合编辑弹窗成员工作集（搜索重渲染不丢勾选）

/* ---- 自定义规则数据（10s 轮询 + 变更后调用；签名一致不重绘） ---- */
async function refreshCustomRules(force) {
  if (HTTP_MODE) return;
  let data;
  try { data = await invoke('list_custom_rules'); } catch (e) { return; }
  const sig = JSON.stringify(data);
  if (!force && sig === CUSTOM_SIG) return;
  CUSTOM_SIG = sig;
  window._custom = data;
  renderMergedRules(window._nodes || []);
}

/* ---- 单条启停 / 删除（立即生效；后端落盘并热更引擎） ---- */
async function toggleCustomRule(id, enabled, cb) {
  try {
    await invoke('set_custom_rule_enabled', { id, enabled });
    const c = window._custom;
    if (c) {
      const r = (c.bypass || []).find(x => x.id === id) || (c.hosts || []).find(x => x.id === id);
      if (r) { r.enabled = enabled; CUSTOM_SIG = JSON.stringify(c); }
    }
    const tr = cb.closest('tr');
    if (tr) tr.classList.toggle('rule-paused', !enabled);
    toast(enabled ? '规则已启用（立即生效）' : '规则已停用（立即生效）', 'ok');
  } catch (e) {
    cb.checked = !enabled;
    toast(friendlyError(e), 'err');
  }
}
async function deleteCustomRule(id, btn) {
  if (btn.dataset.confirm === '1') {
    try {
      await invoke('remove_custom_rule', { id });
      toast('规则已删除', 'ok');
      refreshCustomRules(true);
      refreshCombos(true); // 后端级联清理组合成员中的失效 key
    } catch (e) { toast(friendlyError(e), 'err'); }
    return;
  }
  btn.dataset.confirm = '1';
  const old = btn.innerHTML;
  btn.innerHTML = '<span style="font-size:11px">确认</span>';
  setTimeout(() => { if (btn.isConnected) { btn.dataset.confirm = ''; btn.innerHTML = old; } }, 2500);
}

/* ---- 前端预校验（后端仍兜底；错误就地展示在弹窗内） ---- */
function validIPv4(ip) {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  return !!m && m.slice(1).every(o => +o <= 255);
}
function validIP(ip) {
  return validIPv4(ip) || (ip.includes(':') && /^[0-9a-fA-F:]+$/.test(ip));
}

/* ---- 组合数据与列表 ---- */
async function refreshCombos(force) {
  if (HTTP_MODE) return;
  let items;
  try { items = await invoke('list_rule_combos'); } catch (e) { return; }
  const sig = JSON.stringify(items);
  if (!force && sig === COMBO_SIG) return;
  COMBO_SIG = sig;
  COMBO_ITEMS = items;
  renderComboList();
}
function renderComboList() {
  const list = $('combo-list');
  if (!COMBO_ITEMS.length) {
    list.innerHTML = '<div class="empty">尚未创建组合（组合 = 成组启停的命名规则集合）</div>';
    return;
  }
  list.innerHTML = COMBO_ITEMS.map(c =>
    '<div class="node-card"><div class="info">' +
    '<div class="name">' + esc(c.name) + ' ' + (c.enabled ? '<span class="badge b-ok">已启用</span>' : '<span class="badge b-gray">已停用</span>') + '</div>' +
    '<div class="addr">成员 ' + c.rule_keys.length + ' 条</div>' +
    '</div><div class="card-actions">' +
    '<label class="switch"><input type="checkbox" data-combo-toggle="' + esc(c.id) + '"' + (c.enabled ? ' checked' : '') + '><span class="slider"></span></label>' +
    '<button class="ghost small" data-combo-edit="' + esc(c.id) + '">编辑</button>' +
    '<button class="danger small" data-combo-del="' + esc(c.id) + '">删除</button>' +
    '</div></div>').join('');
}

/* 组合启停编排：组合中的拉取成员（type:value key）引擎忽略，由前端经既有暂停接口处理——
   启用 → 拉取成员全部取消暂停；停用 → 拉取成员暂停，
   但成员同时被另一个已启用组合覆盖则不动（交叉组网语义）。
   作用于当前持有该规则的端点；window._paused 缓存同步并本地持久。 */
function comboPulledKeys(ruleKeys) {
  const ids = new Set();
  const c = window._custom;
  if (c) { (c.bypass || []).forEach(r => ids.add(r.id)); (c.hosts || []).forEach(r => ids.add(r.id)); }
  return (ruleKeys || []).filter(k => !ids.has(k));
}
async function orchestrateCombo(combo, enabling) {
  let keys = comboPulledKeys(combo.rule_keys);
  if (!keys.length) return;
  if (!enabling) {
    // 交叉覆盖保护：仍被其他已启用组合引用的成员保持现状
    const covered = new Set();
    for (const o of COMBO_ITEMS) {
      if (o.id !== combo.id && o.enabled) (o.rule_keys || []).forEach(k => covered.add(k));
    }
    keys = keys.filter(k => !covered.has(k));
    if (!keys.length) return;
  }
  const pausedMap = window._paused || (window._paused = {});
  for (const n of (window._nodes || [])) {
    const have = new Set((n.rules || []).map(ruleKey));
    const targets = keys.filter(k => have.has(k));
    if (!targets.length) continue;
    const set = pausedMap[n.node_id] || (pausedMap[n.node_id] = new Set());
    for (const k of targets) {
      try {
        await invoke('set_rule_paused', { nodeId: n.node_id, ruleKey: k, paused: !enabling });
        if (enabling) set.delete(k); else set.add(k);
      } catch (e) { /* 单条失败不阻断其余成员编排 */ }
    }
  }
  persistPaused();
}

async function toggleCombo(id, enabled, cb) {
  const combo = COMBO_ITEMS.find(c => c.id === id);
  if (!combo) { if (cb) cb.checked = !enabled; return; }
  try {
    await invoke('set_combo_enabled', { id, enabled });
    await refreshCombos(true);
    await orchestrateCombo(combo, enabled);
    renderMergedRules(window._nodes || []);
    toast(enabled ? '组合已启用（成员规则生效）' : '组合已停用（拉取成员已暂停）', 'ok');
  } catch (e) {
    if (cb) cb.checked = !enabled;
    toast(friendlyError(e), 'err');
  }
}
async function deleteCombo(id, btn) {
  if (btn.dataset.confirm === '1') {
    const combo = COMBO_ITEMS.find(c => c.id === id);
    try {
      await invoke('remove_combo', { id });
      await refreshCombos(true);
      // 删除已启用组合 ≈ 停用：其拉取成员按交叉覆盖保护暂停
      if (combo && combo.enabled) {
        await orchestrateCombo(combo, false);
        renderMergedRules(window._nodes || []);
      }
      if (COMBO_EDIT_ID === id) { $('combo-edit-modal').style.display = 'none'; COMBO_EDIT_ID = null; }
      toast('组合已删除', 'ok');
    } catch (e) { toast(friendlyError(e), 'err'); }
    return;
  }
  btn.dataset.confirm = '1';
  const old = btn.innerHTML;
  btn.innerHTML = '<span style="font-size:11px">确认</span>';
  setTimeout(() => { if (btn.isConnected) { btn.dataset.confirm = ''; btn.innerHTML = old; } }, 2500);
}

/* ---- 编辑组合弹窗（名称 + 全部规则简洁清单复选） ---- */
function comboEditOpen(c) {
  COMBO_EDIT_ID = c.id;
  CE_MEMBERS = new Set(c.rule_keys);
  $('ce-name').value = c.name;
  $('ce-search').value = '';
  $('ce-err').textContent = '';
  renderComboEditList('');
  $('combo-edit-modal').style.display = 'flex';
  $('ce-name').focus();
}
/* 全部规则简洁清单（自定义 + 拉取；系统 hosts 只读不可选；拉取跨端点同 key 去重） */
function allRuleChoices() {
  const out = [];
  const c = window._custom || { bypass: [], hosts: [] };
  (c.bypass || []).forEach(r => out.push({ key: r.id, badge: '放行', cls: 'b-ok', value: r.pattern, source: '自定义' }));
  (c.hosts || []).forEach(r => {
    if (r.source !== 'system') out.push({ key: r.id, badge: '映射', cls: 'b-gray', value: r.hostname + ' → ' + r.ip, source: '自定义' });
  });
  const seen = new Set(out.map(o => o.key));
  for (const n of (window._nodes || [])) {
    for (const r of (n.rules || [])) {
      const key = ruleKey(r);
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ key, badge: r.type, cls: 'b-ok', value: r.value, source: n.node_name });
    }
  }
  return out;
}
function renderComboEditList(f) {
  const items = allRuleChoices().filter(it => !f ||
    it.value.toLowerCase().includes(f) || it.badge.toLowerCase().includes(f) || it.source.toLowerCase().includes(f));
  $('ce-list').innerHTML = items.length ? items.map(it =>
    '<label class="combo-rule-row"><input type="checkbox" data-ce-key="' + esc(it.key) + '"' + (CE_MEMBERS.has(it.key) ? ' checked' : '') + '>' +
    '<span class="badge ' + it.cls + '">' + esc(it.badge) + '</span>' +
    '<span class="mono combo-rule-val">' + esc(it.value) + '</span>' +
    '<span class="combo-rule-src">' + esc(it.source) + '</span></label>').join('')
    : '<div class="empty">' + (f ? '无匹配结果' : '暂无可选规则（先连接扇入或新建放行/映射）') + '</div>';
}
async function comboEditSave() {
  const name = $('ce-name').value.trim();
  if (!name) { $('ce-err').textContent = '组合名称不能为空'; return; }
  const combo = COMBO_ITEMS.find(c => c.id === COMBO_EDIT_ID);
  const before = new Set(combo ? combo.rule_keys : []);
  const btn = $('ce-ok');
  btn.disabled = true;
  try {
    await invoke('update_combo', { id: COMBO_EDIT_ID, name, ruleKeys: [...CE_MEMBERS] });
    $('combo-edit-modal').style.display = 'none';
    COMBO_EDIT_ID = null;
    await refreshCombos(true);
    // 已启用组合成员变更同步编排：新增拉取成员取消暂停，移除的按交叉覆盖保护暂停
    if (combo && combo.enabled) {
      const added = [...CE_MEMBERS].filter(k => !before.has(k));
      const removed = [...before].filter(k => !CE_MEMBERS.has(k));
      if (added.length) await orchestrateCombo({ id: combo.id, rule_keys: added }, true);
      if (removed.length) await orchestrateCombo({ id: combo.id, rule_keys: removed }, false);
      if (added.length || removed.length) renderMergedRules(window._nodes || []);
    }
    toast('组合已保存', 'ok');
  } catch (e) {
    $('ce-err').textContent = friendlyError(e);
  } finally {
    btn.disabled = false;
  }
}

/* ---- 规则页全部事件绑定（CSP 禁内联事件，统一显式绑定/委托） ---- */
function initRules() {
  agTabsBind($('rl-tabs'), (key) => { if (key === 'combo') refreshCombos(true); });
  // 类型过滤 chips（与搜索叠加）
  $('rl-filter').addEventListener('click', (e) => {
    const b = e.target.closest('[data-rfilter]');
    if (!b || b.classList.contains('active')) return;
    RL_FILTER = b.dataset.rfilter;
    $('rl-filter').querySelectorAll('.agtab').forEach(t => t.classList.toggle('active', t === b));
    renderMergedRules(window._nodes || []);
  });
  // 统一表格事件委托：自定义行启停 / 删除（拉取行启停见启动区既有绑定）
  $('rules-body').addEventListener('change', (e) => {
    const cb = e.target.closest('input[data-cr]');
    if (cb) toggleCustomRule(cb.dataset.cr, cb.checked, cb);
  });
  $('rules-body').addEventListener('click', (e) => {
    const btn = e.target.closest('[data-crdel]');
    if (btn) deleteCustomRule(btn.dataset.crdel, btn);
  });

  /* ---- 新增放行弹窗 ---- */
  $('btn-add-bypass').onclick = () => {
    $('bp-pattern').value = '';
    $('bp-via').value = 'direct';
    agSelectRefresh($('bp-via'));
    $('bp-err').textContent = '';
    $('bypass-modal').style.display = 'flex';
    $('bp-pattern').focus();
  };
  $('bp-cancel').onclick = () => { $('bypass-modal').style.display = 'none'; };
  $('bp-pattern').addEventListener('keydown', e => { if (e.key === 'Enter') $('bp-ok').click(); });
  $('bp-ok').onclick = async () => {
    const pattern = $('bp-pattern').value.trim();
    if (!pattern || /\s/.test(pattern)) { $('bp-err').textContent = '匹配值不能为空且不含空白字符'; return; }
    const btn = $('bp-ok');
    btn.disabled = true;
    try {
      await invoke('add_bypass_rule', { pattern, viaSubscription: $('bp-via').value === 'sub' });
      $('bypass-modal').style.display = 'none';
      toast('放行规则已添加（默认启用，立即生效）', 'ok');
      refreshCustomRules(true);
    } catch (e) {
      $('bp-err').textContent = friendlyError(e);
    } finally {
      btn.disabled = false;
    }
  };

  /* ---- 新增映射弹窗 ---- */
  $('btn-add-host').onclick = () => {
    $('hm-name').value = '';
    $('hm-ip').value = '';
    $('hm-system').checked = true;
    $('hm-err').textContent = '';
    $('host-modal').style.display = 'flex';
    $('hm-name').focus();
  };
  $('hm-cancel').onclick = () => { $('host-modal').style.display = 'none'; };
  $('hm-ip').addEventListener('keydown', e => { if (e.key === 'Enter') $('hm-ok').click(); });
  $('hm-ok').onclick = async () => {
    const hostname = $('hm-name').value.trim().toLowerCase();
    const ip = $('hm-ip').value.trim();
    if (!hostname || /\s/.test(hostname) || hostname.includes('*') || hostname.includes('#')) {
      $('hm-err').textContent = '主机名不合法（不含空白、*、#）'; return;
    }
    if (validIP(hostname)) { $('hm-err').textContent = '主机名不能是 IP'; return; }
    if (!validIP(ip)) { $('hm-err').textContent = 'IP 地址不合法'; return; }
    const btn = $('hm-ok');
    btn.disabled = true;
    try {
      const r = await invoke('add_host_mapping', { hostname, ip, toSystem: $('hm-system').checked });
      $('host-modal').style.display = 'none';
      toast(r.persisted === 'system' ? '映射已添加，已写入系统 hosts' : '映射已添加，仅本软件内生效（无系统 hosts 写权限）', 'ok');
      refreshCustomRules(true);
    } catch (e) {
      $('hm-err').textContent = friendlyError(e);
    } finally {
      btn.disabled = false;
    }
  };

  /* ---- 新建组合弹窗 ---- */
  $('btn-add-combo').onclick = () => {
    $('cb-name').value = '';
    $('cb-err').textContent = '';
    $('combo-modal').style.display = 'flex';
    $('cb-name').focus();
  };
  $('cb-cancel').onclick = () => { $('combo-modal').style.display = 'none'; };
  $('cb-name').addEventListener('keydown', e => { if (e.key === 'Enter') $('cb-ok').click(); });
  $('cb-ok').onclick = async () => {
    const name = $('cb-name').value.trim();
    if (!name) { $('cb-err').textContent = '请填写组合名称'; return; }
    const btn = $('cb-ok');
    btn.disabled = true;
    try {
      await invoke('add_combo', { name });
      $('combo-modal').style.display = 'none';
      toast('组合已创建，点「编辑」勾选成员', 'ok');
      refreshCombos(true);
    } catch (e) {
      $('cb-err').textContent = friendlyError(e);
    } finally {
      btn.disabled = false;
    }
  };

  /* ---- 组合列表（启停 / 编辑 / 删除）与编辑弹窗 ---- */
  $('combo-list').addEventListener('change', (e) => {
    const cb = e.target.closest('input[data-combo-toggle]');
    if (cb) toggleCombo(cb.dataset.comboToggle, cb.checked, cb);
  });
  $('combo-list').addEventListener('click', (e) => {
    const eb = e.target.closest('[data-combo-edit]');
    if (eb) {
      const c = COMBO_ITEMS.find(x => x.id === eb.dataset.comboEdit);
      if (c) comboEditOpen(c);
      return;
    }
    const db = e.target.closest('[data-combo-del]');
    if (db) deleteCombo(db.dataset.comboDel, db);
  });
  $('ce-search').addEventListener('input', () => renderComboEditList($('ce-search').value.trim().toLowerCase()));
  $('ce-list').addEventListener('change', (e) => {
    const cb = e.target.closest('input[data-ce-key]');
    if (!cb) return;
    if (cb.checked) CE_MEMBERS.add(cb.dataset.ceKey); else CE_MEMBERS.delete(cb.dataset.ceKey);
  });
  $('ce-cancel').onclick = () => { $('combo-edit-modal').style.display = 'none'; COMBO_EDIT_ID = null; };
  $('ce-ok').onclick = comboEditSave;
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
          await invoke('start_proxy', { port: proxyPort() });
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

/** 标题栏管理端入口：本机服务端恒第一，可管理端点/扇出按名称排序；无项置灰 */
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
        remotes.push({ kind: 'up', id: n.node_id, up: m.node_name, label: m.node_name, sub: '扇出 · 经 ' + n.node_name });
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
  // 内嵌管理端（SPA）toast 统一接入灵动岛（origin 校验，只收当前管理 iframe）
  window.addEventListener('message', (e) => {
    if (ADMIN && e.origin === ADMIN.origin && e.data && e.data.type === 'ag-toast') {
      toast(String(e.data.msg || ''), typeof e.data.kind === 'string' ? e.data.kind : 'info');
    }
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

/* ================= 控制台通道（管理此端点；内嵌进主窗口） ================= */
async function openNodeConsole(nodeId) {
  const n = (window._nodes || []).find(x => x.node_id === nodeId);
  const label = n ? n.node_name + (n.username ? ' · ' + n.username : '') : nodeId;
  await enterAdmin(nodeId, null, label);
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
/* 本地代理端口：运行中以 proxy_status 为准；未运行取本地保存值（默认 57890）。
   端口修改走代理卡监听行 inline-edit（bindInlineEdit），变更即重启代理生效。 */
let PROXY_ST = { running: false, port: 0 };
let proxyAddrEdit = null;
function proxyPort() {
  if (PROXY_ST.running && PROXY_ST.port) return PROXY_ST.port;
  const p = parseInt(localStorage.getItem('ag_proxy_port') || '57890', 10);
  return p >= 1 && p <= 65535 ? p : 57890;
}
function validPort(v) {
  if (!/^\d+$/.test(v)) return '端口须为 1-65535 的数字';
  const p = parseInt(v, 10);
  return (p >= 1 && p <= 65535) ? null : '端口须为 1-65535';
}
async function refreshProxy() {
  try {
    const st = await invoke('proxy_status');
    PROXY_ST = st;
    // 运行中的实际端口同步为本地基准（外部变更也能对齐）
    if (st.running && st.port) localStorage.setItem('ag_proxy_port', String(st.port));
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
    // 仪表盘代理卡：开关态 / 状态徽标 / 监听地址（inline-edit 自行变更检测）
    if ($('d-proxy').checked !== st.running) $('d-proxy').checked = st.running;
    setHtml('d-proxy-badge', st.running ? '<span class="badge b-ok">运行中</span>' : '<span class="badge b-gray">未启动</span>');
    if (proxyAddrEdit) proxyAddrEdit.refresh();
    const hint = st.running
      ? (CUR_PROXY_MODE === 'system'
        ? '已接管系统代理 127.0.0.1:' + st.port + '，浏览器即开即用'
        : '本地代理运行中，应用手动指向 127.0.0.1:' + st.port + ' 即可')
      : '系统代理：自动接管系统流量（推荐）；本地代理：仅监听端口，需手动配置应用';
    if ($('proxy-hint').textContent !== hint) $('proxy-hint').textContent = hint;
  } catch (e) {}
}
async function toggleProxy(e) {
  const on = e.target.checked;
  try {
    if (on) {
      const actual = await invoke('start_proxy', { port: proxyPort() });
      toast(T('proxy-on') + ' 127.0.0.1:' + actual, 'ok');
    } else {
      await invoke('stop_proxy');
      toast(T('proxy-off'), 'ok');
    }
    refreshProxy();
  } catch (err) {
    e.target.checked = !on;
    toast(friendlyError(err), 'err');
  }
}

/* ================= 仪表盘：扇入卡（已连接 / 已保存概览 + 流量趋势） ================= */
// 扇入流量速率序列（list_nodes 每次轮询累一点；计数为当前会话语义，重连归零按新基准）
let _tfLast = null, _tfSeries = [];
function trackFaninTraffic(nodes) {
  const up = nodes.reduce((s, n) => s + (n.bytes_up || 0), 0);
  const down = nodes.reduce((s, n) => s + (n.bytes_down || 0), 0);
  const total = up + down;
  if (_tfLast !== null) {
    let delta = total - _tfLast;
    if (delta < 0) delta = total; // 会话重连计数归零：负差按新基准
    _tfSeries.push(delta);
    if (_tfSeries.length > 90) _tfSeries.shift();
  }
  _tfLast = total;
  window._tfTotals = { up, down };
}
function updateDashFanin() {
  const nodes = window._nodes || [];
  const saved = (window._credsRaw || []).length;
  const conn = nodes.filter(n => n.status === 'Connected').length;
  const trying = nodes.length - conn;
  setText('d-fanin-val', conn + ' 已连接');
  setText('d-fanin-sub', saved + ' 个已保存' + (trying ? ' · ' + trying + ' 个连接中/重连中' : ''));
  const tf = window._tfTotals || { up: 0, down: 0 };
  const has = tf.up + tf.down > 0;
  const tfEl = $('d-fanin-tf'), sparkEl = $('d-fanin-spark');
  if (tfEl) {
    tfEl.style.display = has ? '' : 'none';
    if (has) setText('d-fanin-tf', '↑ ' + fmtBytes(tf.up) + ' · ↓ ' + fmtBytes(tf.down));
  }
  if (sparkEl) {
    sparkEl.style.display = has ? '' : 'none';
    if (has) AgChart.sparkline(sparkEl, _tfSeries.length > 1 ? _tfSeries : [0, 0]);
  }
}

/* ================= 扇入列表（已保存扇入为主体 + 未保存的活跃连接；连接/断开/导出/删除） ================= */
async function refreshCreds() {
  try {
    const creds = await invoke('list_credentials');
    window._credsRaw = creds;
    window._creds = Object.fromEntries(creds);
    renderCredList(creds, window._nodeStatus || {});
    invoke('list_nodes').then(nodes => updateOnboarding(nodes)).catch(() => {});
    updateDashFanin();
  } catch (e) {}
}
function renderCredList(creds, statusMap) {
  const list = $('creds-list');
  const f = FILTERS.creds;
  const nodeMap = Object.fromEntries((window._nodes || []).map(n => [n.node_id, n]));
  // 未保存的活跃连接（手动连接未勾选保存凭据）：附在已保存扇入之后，仅可断开/管理
  const savedKeys = new Set(creds.map(([k]) => k));
  const unsaved = (window._nodes || []).filter(n => !savedKeys.has(n.node_id));
  const live = (st) => st === 'Connected' || st === 'Connecting' || st === 'Reconnecting';
  const match = (name, username, addr, st) => !f ||
    name.toLowerCase().includes(f) || (username || '').toLowerCase().includes(f) ||
    addr.toLowerCase().includes(f) || (st ? statusText(st) : '未连接').includes(f);
  const shownCreds = creds.filter(([key, c]) =>
    match(key.includes('@') ? key.slice(0, key.indexOf('@')) : key, c.username, c.addr, statusMap[key]));
  const shownUnsaved = unsaved.filter(n => match(n.node_name, n.username, n.addr, n.status));
  if (!shownCreds.length && !shownUnsaved.length) {
    list.innerHTML = '<div class="empty">' + (f ? '无匹配结果' : T('no-creds')) + '</div>';
    return;
  }
  list.innerHTML = shownCreds.map(([key, c]) => {
    const st = statusMap[key];
    const n = nodeMap[key];
    const badge = st ? statusBadgeHtml(st) : '<span class="badge b-gray">未连接</span>';
    const mainBtn = st === 'Connected'
      ? '<button class="ghost small" data-act="disconnect" data-key="' + esc(key) + '">断开</button>'
      : '<button class="small" data-act="reconnect" data-key="' + esc(key) + '">' + (st ? '重连' : '连接') + '</button>';
    const epName = key.includes('@') ? key.slice(0, key.indexOf('@')) : key;
    return '<div class="node-card' + (live(st) ? '' : ' down') + '"><div class="info">' +
      '<div class="name">' + esc(epName) + ' <span class="dim">· ' + esc(c.username) + '</span> ' + badge + '</div>' +
      '<div class="addr mono">' + esc(c.addr) + (c.insecure ? ' · <span class="badge b-warn">insecure</span>' : '') + '</div>' +
      '</div><div class="card-actions">' +
      (n && n.admin_console && st === 'Connected' && !HTTP_MODE
        ? '<button class="ghost small" data-act="console" data-id="' + esc(key) + '">' + AgIcon('monitor', 13) + ' 管理</button>' : '') +
      mainBtn +
      '<button class="ghost small icon-btn" title="导出接入链接（复制到剪贴板）" data-act="export" data-key="' + esc(key) + '">' + AgIcon('share-2', 13) + '</button>' +
      '<button class="danger small icon-btn" title="删除该扇入" data-act="delcred" data-key="' + esc(key) + '">' + AgIcon('trash-2', 13) + '</button>' +
      '</div></div>';
  }).join('') + shownUnsaved.map(n =>
    '<div class="node-card' + (live(n.status) ? '' : ' down') + '"><div class="info">' +
    '<div class="name">' + esc(n.node_name) + (n.username ? ' <span class="dim">· ' + esc(n.username) + '</span>' : '') + ' ' + statusBadgeHtml(n.status) + ' <span class="badge b-gray">未保存</span></div>' +
    '<div class="addr mono">' + esc(n.addr) + '</div>' +
    '</div><div class="card-actions">' +
    (n.admin_console && n.status === 'Connected' && !HTTP_MODE
      ? '<button class="ghost small" data-act="console" data-id="' + esc(n.node_id) + '">' + AgIcon('monitor', 13) + ' 管理</button>' : '') +
    '<button class="danger small" data-act="disconnect" data-key="' + esc(n.node_id) + '">断开</button></div></div>'
  ).join('');
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
      toast('已删除保存的扇入', 'ok');
      refreshCreds();
    } catch (e) { toast(friendlyError(e), 'err'); }
    return;
  }
  btn.dataset.confirm = '1';
  const old = btn.innerHTML;
  btn.innerHTML = '<span style="font-size:11px">确认</span>';
  setTimeout(() => { if (btn.isConnected) { btn.dataset.confirm = ''; btn.innerHTML = old; } }, 2500);
}

/* ================= 扇出连接（内嵌节点 DB 管理，变更热生效） ================= */
let FO_EDIT_ID = null;
let FO_ITEMS = [];

function foBadge(c) {
  if (!c.enabled) return '<span class="badge b-off">已禁用</span>';
  const st = c.state;
  if (st === 'connected') return '<span class="badge b-ok">已连接</span>';
  if (st === 'connecting') return '<span class="badge b-warn"><span class="pulse"></span>连接中</span>';
  if (st === 'reconnecting') return '<span class="badge b-warn"><span class="pulse"></span>重连中</span>';
  if (st === 'disconnected') return '<span class="badge b-off">已断开</span>';
  return '<span class="badge b-gray">未启动</span>';
}

/** 权限组下拉：拉本机内嵌节点组清单（保留当前选择；失败不阻断列表） */
async function foLoadGroups() {
  try {
    const groups = await invoke('list_embedded_groups');
    const cur = $('fo-group').value;
    $('fo-group').innerHTML = '<option value="">不收敛（放行一切）</option>' +
      groups.map(g => '<option value="' + esc(g.id) + '">' + esc(g.name) + '</option>').join('');
    if (groups.some(g => g.id === cur)) $('fo-group').value = cur;
    agSelectRefresh($('fo-group'));
  } catch (e) { /* 组清单加载失败不阻断扇出列表 */ }
}

async function refreshUpstreams() {
  foLoadGroups();
  try {
    FO_ITEMS = await invoke('list_server_connectors');
  } catch (e) { $('fo-list').innerHTML = '<div class="empty">加载失败</div>'; return; }
  if (!FO_ITEMS.length) {
    $('fo-list').innerHTML = '<div class="empty">尚未配置扇出连接（添加后内嵌端点将扇出到目标端点）</div>';
    return;
  }
  $('fo-list').innerHTML = FO_ITEMS.map(c =>
    '<div class="node-card"><div class="info">' +
    '<div class="name">' + esc(c.name || c.upstream_addr) + ' ' + foBadge(c) + '</div>' +
    '<div class="addr mono">' + esc(c.upstream_addr) + ' · ' + esc(c.token_prefix) + ' · SNI ' + esc(c.sni_hostname) +
    (c.insecure ? ' · <span class="badge b-warn">insecure</span>' : '') +
    ' · 组 ' + (c.group_name ? esc(c.group_name) : '不收敛') + '</div>' +
    '</div><div class="card-actions">' +
    '<button class="ghost small" data-fo-edit="' + esc(c.id) + '">编辑</button>' +
    '<button class="danger small" data-fo-del="' + esc(c.id) + '">删除</button>' +
    '</div></div>'
  ).join('');
}

/* ---- 新建/编辑扇出模态（字段对齐管理端「新建扇出」；advertise 每行一条，逗号拼接入库） ---- */
function foOpenModal(c) {
  FO_EDIT_ID = c ? c.id : null;
  $('fo-modal-title').textContent = c ? '编辑扇出' : '新建扇出';
  $('fo-ok').textContent = c ? '保存' : '创建';
  $('fo-token-hint').style.display = c ? '' : 'none';
  $('fo-name').value = c ? c.name : '';
  $('fo-addr').value = c ? c.upstream_addr : '';
  $('fo-token').value = '';
  $('fo-sni').value = c ? c.sni_hostname : 'cdn.cloudflare.com';
  $('fo-insecure').checked = c ? !!c.insecure : false;
  $('fo-advertise').value = c ? (c.advertise || '').split(',').filter(Boolean).join('\n') : '';
  $('fo-group').value = c ? (c.group_id || '') : '';
  agSelectRefresh($('fo-group'));
  $('fo-remark').value = c ? (c.remark || '') : '';
  $('fo-err').textContent = '';
  $('fo-modal').style.display = 'flex';
  $(c ? 'fo-name' : 'fo-addr').focus();
}
function foCloseModal() { $('fo-modal').style.display = 'none'; FO_EDIT_ID = null; }

function initUpstreams() {
  agTabsBind($('fo-tabs'));
  $('btn-fo-refresh').onclick = refreshUpstreams;
  $('btn-fo-add').onclick = () => foOpenModal(null);
  $('fo-cancel').onclick = foCloseModal;
  $('fo-ok').onclick = async () => {
    const name = $('fo-name').value.trim();
    const addr = $('fo-addr').value.trim();
    const token = $('fo-token').value.trim();
    const sni = $('fo-sni').value.trim() || 'cdn.cloudflare.com';
    const insecure = $('fo-insecure').checked;
    const groupId = $('fo-group').value || null;
    const advertise = $('fo-advertise').value.split('\n').map(s => s.trim()).filter(Boolean).join(',');
    const remark = $('fo-remark').value.trim();
    if (!addr) { $('fo-err').textContent = '请填写目标地址'; return; }
    if (!FO_EDIT_ID && !token) { $('fo-err').textContent = '请填写 Relay Token'; return; }
    $('fo-err').textContent = '';
    try {
      if (FO_EDIT_ID) {
        await invoke('update_server_connector', { id: FO_EDIT_ID, name, upstreamAddr: addr, token, sniHostname: sni, insecure, groupId, advertise, remark });
        toast('扇出连接已更新（热生效）', 'ok');
      } else {
        await invoke('add_server_connector', { name, upstreamAddr: addr, token, sniHostname: sni, insecure, groupId, advertise, remark });
        toast('扇出连接已添加（热生效）', 'ok');
      }
      foCloseModal();
      refreshUpstreams();
    } catch (e) { $('fo-err').textContent = friendlyError(e); }
  };
  $('fo-list').addEventListener('click', async (e) => {
    const editBtn = e.target.closest('[data-fo-edit]');
    const delBtn = e.target.closest('[data-fo-del]');
    if (editBtn) {
      const c = FO_ITEMS.find(x => x.id === editBtn.dataset.foEdit);
      if (c) foOpenModal(c);
      return;
    }
    if (delBtn) {
      try {
        await invoke('remove_server_connector', { id: delBtn.dataset.foDel });
        toast('扇出连接已删除（热生效）', 'ok');
        if (FO_EDIT_ID === delBtn.dataset.foDel) foCloseModal();
        refreshUpstreams();
      } catch (err) { toast(friendlyError(err), 'err'); }
    }
  });
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
  const off = $('d-fanin-off');
  if (off) off.style.display = on ? 'none' : '';
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

/* 仪表盘扇出卡：监听状态徽标 + 连通数 + API/Relay 地址简述（10s 轮询 + 变更后调用） */
async function renderDashFanout() {
  if (HTTP_MODE) return;
  let st = null, conns = [];
  try { st = await invoke('server_status'); } catch (e) {}
  try { conns = await invoke('list_server_connectors'); } catch (e) {}
  const running = !!(st && st.running);
  const total = conns.length;
  const ok = conns.filter(c => c.enabled && c.state === 'connected').length;
  setHtml('d-server-badge', running ? '<span class="badge b-ok">监听中</span>' : '<span class="badge b-gray">未开启</span>');
  setText('d-fanout-val', total ? ok + ' / ' + total + ' 连通' : '未扇出');
  setText('d-fanout-sub', running
    ? 'API ' + (st.api_addr || '-') + ' · Relay ' + (st.relay_addr || '-')
    : (total ? '扇出监听未开启 · ' + total + ' 条扇出已配置' : '扇出监听未开启'));
}

/* 扇出监听开关（扇出页 r-server 与仪表盘 d-server 双入口同一逻辑，状态互相同步） */
function syncServerSwitch(v) {
  $('r-server').checked = v;
  const d = $('d-server');
  if (d) d.checked = v;
}
async function serverToggle(on, el) {
  try {
    if (on) {
      // 首开强制设管理密码
      const st = await invoke('server_status');
      if (!st.has_admin) {
        el.checked = false;
        const cred = await askPassword({
          title: '设置服务端管理密码',
          desc: '首开服务端角色须先设置内嵌端点管理员，该密码用于登录控制台。',
          showUser: true,
        });
        if (!cred) return;
        await invoke('init_server_admin', { username: cred.user, password: cred.pass });
        el.checked = true;
        toast('管理员已创建', 'ok');
      }
    }
    await invoke('set_server_role', { enabled: on });
    syncServerSwitch(on);
    await refreshServerPanel();
    refreshAdminEntry();
    renderDashFanout();
    toast(on ? '服务端角色已开启（内嵌端点运行中）' : '服务端角色已关闭', 'ok');
  } catch (err) {
    syncServerSwitch(false);
    toast(friendlyError(err), 'err');
    refreshServerPanel();
    renderDashFanout();
  }
}
function refreshWebPanel() {
  const on = $('r-web').checked;
  $('web-panel').style.display = on ? 'block' : 'none';
  $('web-status').textContent = on ? '监听地址保存后生效；浏览器访问需输入管理密码' : '';
}
/* Web 远程面监听地址（inline-edit 数据源；initRoles 自 get_role_settings 载入） */
let WEB_LISTEN = '127.0.0.1:59291';
function validListenAddr(v) {
  const m = v.match(/^(.+):(\d+)$/);
  if (!m || !m[1].trim()) return '监听地址格式须为 IP:端口';
  const p = parseInt(m[2], 10);
  return (p >= 1 && p <= 65535) ? null : '端口须为 1-65535';
}
/* 代理卡监听行 / 远程卡监听地址：统一 inline-edit（显示 ip:port [修改] → 输入框 + [保存]） */
function initInlineEdits() {
  proxyAddrEdit = bindInlineEdit($('d-proxy-addr'), {
    get: () => '127.0.0.1:' + proxyPort(),
    editValue: () => String(proxyPort()),
    validate: validPort,
    set: async (v) => {
      const port = parseInt(v, 10);
      localStorage.setItem('ag_proxy_port', String(port));
      const st = await invoke('proxy_status');
      if (st.running && st.port !== port) {
        await invoke('stop_proxy');
        const actual = await invoke('start_proxy', { port });
        toast('端口已修改为 ' + actual + '，代理已重启生效', 'ok');
      } else {
        toast(st.running ? '端口未变更' : '端口已保存，下次启动代理生效', 'ok');
      }
      refreshProxy();
      refreshSysproxy();
    },
  });
  bindInlineEdit($('web-listen'), {
    get: () => WEB_LISTEN,
    validate: validListenAddr,
    set: async (v) => {
      await invoke('set_web_role', { enabled: $('r-web').checked, listen: v });
      WEB_LISTEN = v;
      toast('监听地址已保存', 'ok');
    },
  });
}
async function initRoles() {
  let settings = { client: true, server: false, web: false, web_listen: '127.0.0.1:59291' };
  try { settings = await invoke('get_role_settings'); } catch (e) {}
  $('r-client').checked = settings.client;
  $('r-server').checked = settings.server;
  $('d-server').checked = settings.server;
  $('r-web').checked = settings.web;
  // TUN 初值（详细状态由 refreshTun 轮询同步；此处先落开关）
  TUN_UPSTREAM = settings.external_upstream || TUN_UPSTREAM;
  $('tun-mode').checked = !!settings.tun_mode;
  const subMode = settings.sub_mode || 'rule';
  $('sub-mode').value = subMode;
  $('sub-mode').dataset.prev = subMode;
  applySubFeature(!!settings.subscription_feature);
  WEB_LISTEN = settings.web_listen;
  applyClientRole(settings.client);
  refreshServerPanel();
  refreshWebPanel();

  $('r-client').onchange = async (e) => {
    try {
      await invoke('set_client_role', { enabled: e.target.checked });
      applyClientRole(e.target.checked);
      toast(e.target.checked ? '扇入已开启' : '扇入已停用（已断开全部端点）', 'ok');
      if (e.target.checked) { refreshNodes(true); refreshProxy(); refreshCreds(); }
    } catch (err) {
      e.target.checked = !e.target.checked;
      toast(friendlyError(err), 'err');
    }
  };

  $('r-server').onchange = (e) => serverToggle(e.target.checked, e.target);
  $('d-server').onchange = (e) => serverToggle(e.target.checked, e.target);

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
      await invoke('set_web_role', { enabled: on, listen: WEB_LISTEN || null });
      refreshWebPanel();
      toast(on ? 'Web 远程面已开启' : 'Web 远程面已关闭', 'ok');
    } catch (err) {
      e.target.checked = !on;
      toast(friendlyError(err), 'err');
    }
  };

  $('btn-open-console').onclick = () => enterAdmin(null, null, '本机服务端');

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
  // 无论内核是否运行都刷新代理页（未运行时回落缓存快照，方便查看节点情况）
  refreshGroups();
}

/* ---------- 订阅内核流量（后端 /traffic WS 单任务累计，前端 2s 轮询同一数据源） ----------
   订阅页内核卡与首页订阅卡共用本模块序列，不另起轮询；
   速率序列照 trackFaninTraffic 的 delta 保护：累计倒退 = 内核重启清零，按新基准。 */
const SubTraffic = {
  data: null, _last: null, series: [], _sig: '',
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
    this.data = t;
    this.render();
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
    return '<div class="snode-card' + (cur ? ' current' : '') + '" data-group="' + esc(CUR_GROUP) + '" data-node="' + esc(n) + '">' +
      '<div class="node-name">' + (cur ? '<span class="node-check">' + AgIcon('check', 11) + '</span>' : '') +
      '<span class="node-name-text" title="' + esc(n) + '">' + esc(n) + '</span></div>' +
      '<div class="node-foot"><span class="node-proto">' + esc(p.type || '') + '</span>' +
      '<span class="node-delay' + (hist ? ' ok' : '') + '">' + (hist ? hist + ' ms' : '') + '</span>' +
      (PROXY_CACHED ? '' : '<button class="node-test" data-test="' + esc(n) + '" title="测速">' + AgIcon('zap', 13) + '</button>') +
      '</div></div>';
  }).join('');
  updateDashSub();
}

// provider 节点无单节点测速 API，后端仍是整组并发测（耗时相同），但单点只更新本卡片
async function testNode(btn) {
  const card = btn.closest('.snode-card');
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
  const cards = [...$('node-grid').querySelectorAll('.snode-card')];
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
      toast(friendlyError(err), 'err');
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
  $('node-grid').addEventListener('click', async (e) => {
    const testBtn = e.target.closest('.node-test');
    if (testBtn) {
      e.stopPropagation();
      testNode(testBtn);
      return;
    }
    const card = e.target.closest('.snode-card');
    if (!card) return;
    if (PROXY_CACHED) { toast('订阅内核未运行，仅展示缓存节点', 'err'); return; }
    try {
      await invoke('select_proxy', { group: card.dataset.group, name: card.dataset.node });
      document.querySelectorAll('.snode-card').forEach(c => c.classList.toggle('current', c === card));
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
  // TUN 模式下冲突由后端巡检 30s 内自动收回（§2.6），不打扰用户
  if (st.managed && st.conflict && !TUN_ON) {
    banner.style.display = 'flex';
    $('sysproxy-banner-text').textContent = '系统代理已被外部修改（当前 ' + (st.current || '未启用') + '，期望 ' + st.expected + '）';
    if (!_spConflict) { _spConflict = true; toast('系统代理已被外部修改，可在「首页」收回', 'err'); }
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
          await invoke('start_proxy', { port: proxyPort() });
        }
        await invoke('set_system_proxy', { enabled: true });
        toast('已切换到系统代理（自动接管系统流量）', 'ok');
      } else {
        await invoke('set_system_proxy', { enabled: false });
        toast('已切换到本地代理（手动指向 127.0.0.1:' + proxyPort() + '）', 'ok');
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

/* ================= 网络检测（出口 IP / 文字归属地 / 内网 IP） =================
   JS 侧缓存结果：30s 轮询 + 内核状态翻转/手动刷新时重探；签名对比，不变不重绘。
   订阅内核运行时经 mihomo mixed 出口探测（验证订阅代理真实生效），否则直连。 */
const NetProbe = {
  data: null,   // { ip, country, country_code, via } 或 { fail: true, via }
  lan: '',
  _sig: '',
  _busy: false,
  async refresh(force) {
    if (HTTP_MODE || (this._busy && !force)) return;
    this._busy = true;
    const via = !!window._subRunning;
    try {
      const r = await invoke('fetch_exit_ip', { viaProxy: via });
      this.data = { ip: r.ip, country: r.country, country_code: r.country_code, via };
    } catch (e) {
      this.data = { fail: true, via };
    }
    this._busy = false;
    this.render();
  },
  async refreshLan() {
    if (HTTP_MODE) return;
    try {
      const r = await invoke('lan_ip');
      this.lan = r.ip + (r.iface ? '（' + r.iface + '）' : '');
    } catch (e) { this.lan = ''; }
    this.render();
  },
  render() {
    const sig = JSON.stringify(this.data) + '|' + this.lan + '|' + window._subRunning;
    if (sig === this._sig) return;
    this._sig = sig;
    const d = this.data;
    const geo = (x) => [x.country_code, x.country].filter(Boolean).join(' · ');
    // 首页网络检测卡：失败仅显示「探测失败」，不占位报错
    setText('d-net-ip', !d ? '探测中…' : (d.fail ? '探测失败' : d.ip));
    setText('d-net-geo', !d ? '' : (d.fail
      ? (d.via ? '经 mihomo 出口探测失败' : '直连出口探测失败')
      : (geo(d) || '归属地未知') + ' · ' + (d.via ? '经 mihomo 出口' : '直连出口')));
    setText('d-net-lan', this.lan || '-');
    // 订阅页：内核运行时同显出口（验证 mihomo 是否代理成功），只采用经内核出口的探测结果
    if ($('sub-exit-ip')) {
      if (!window._subRunning) {
        setText('sub-exit-ip', '内核未运行');
        setText('sub-exit-geo', '');
      } else if (d && d.via && !d.fail) {
        setText('sub-exit-ip', d.ip);
        setText('sub-exit-geo', (geo(d) || '归属地未知') + ' · 经 mihomo 出口');
      } else if (d && d.via && d.fail) {
        setText('sub-exit-ip', '探测失败');
        setText('sub-exit-geo', '经 mihomo 出口探测失败');
      } else {
        setText('sub-exit-ip', '探测中…');
        setText('sub-exit-geo', '');
      }
    }
  },
};

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
  if (v === 'connect') { refreshNodes(); refreshProxy(); renderDashFanout(); NetProbe.render(); }
  if (v === 'nodes') { refreshNodes(true); refreshCreds(); }
  if (v === 'routes') { refreshNodes(); refreshCustomRules(); refreshCombos(); }
  if (v === 'upstreams') refreshUpstreams();
  if (v === 'subscription') { refreshSubs(); refreshSubStatus(); refreshSubScripts(); SubTraffic.poll(); }
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
  initUpstreams();
  initRules();

  // 浏览器模式（Web 远程面）：本机专属卡片/开关经 .local-only 隐藏，未登录先出登录框
  if (HTTP_MODE) {
    document.body.classList.add('http-mode');
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
  initInlineEdits();
  initSubscription();
  initSubFeature();
  refreshSubFeature();
  initSysproxy();
  initTun();
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

  setInterval(() => { refreshNodes(); refreshProxy(); refreshSubStatus(); refreshSysproxy(); refreshTun(); renderDashFanout(); refreshCustomRules(); refreshCombos(); }, 10000);
  // 订阅内核流量 2s 轮询（sub_traffic 读 Atomic 快照，廉价；内部变更检测不重绘）
  setInterval(() => { SubTraffic.poll(); }, 2000);
  // 出口 IP 探测 30s 轮询（结果带签名对比，不变不重绘）
  setInterval(() => { NetProbe.refresh(); }, 30000);
});
