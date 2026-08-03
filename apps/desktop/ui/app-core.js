'use strict';
/* 从 app.js 拆分：invoke 桥 / 全局状态 / 本端工具与组件（纯搬运，零逻辑变更）。
   $ / esc / ahelp 已沉淀共享层 agutil.js（index.html 先于本文件引入）；图标走共享 icons.js 的 AgIcon。 */

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
/* 性能模式（减少特效）：切 html.no-blur 关毛玻璃与动画（components.css/style.css 托底规则）。
   localStorage 缓存先行避免首帧等待，initRoles 读 get_role_settings().reduce_effects 后校正。 */
function applyReduceEffects(on) {
  document.documentElement.classList.toggle('no-blur', !!on);
}
// 解析即应用，避免首帧浅色闪烁（与 wiki / 控制台行为一致）
applyTheme();
applyReduceEffects(localStorage.getItem('ag_reduce_fx') === '1');

/* odo 数字滚动驱动（结构 .odo > .odo-digit > .odo-strip 见 components.css；滚动动效由 CSS transition 完成）。
   用法：元素带 class="odo"，每帧调 odoSet(el, text)——按字符对齐 diff：数字位复用/新建 digit 并写
   strip.style.transform = translateY(-N em)，非数字位（. / : 单位等）放裸文本节点；值短变长自动补 digit、
   长变短自动裁；内部签名对比，文本未变不动 DOM。仅供 hero 中控台等少量大数字使用，勿全站铺开。 */
function odoSet(el, text) {
  if (!el) return;
  text = String(text);
  if (el._odoSig === text) return;
  el._odoSig = text;
  const olds = [...el.querySelectorAll('.odo-digit')];
  const frag = document.createDocumentFragment();
  const used = [];
  let di = 0;
  for (const ch of text) {
    if (ch >= '0' && ch <= '9') {
      let d = olds[di++];
      if (!d) {
        d = document.createElement('span');
        d.className = 'odo-digit';
        const strip = document.createElement('span');
        strip.className = 'odo-strip';
        for (let n = 0; n <= 9; n++) { const s = document.createElement('span'); s.textContent = n; strip.appendChild(s); }
        d.appendChild(strip);
      }
      d._odoN = ch;
      used.push(d);
      frag.appendChild(d);
    } else {
      frag.appendChild(document.createTextNode(ch));
    }
  }
  el.textContent = '';
  el.appendChild(frag);
  used.forEach(d => { d.firstChild.style.transform = 'translateY(-' + d._odoN + 'em)'; });
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
  let s = String(e);
  // 命令契约前缀（具体页面已按前缀分流；兜底场景剥掉前缀再展示）
  if (s.indexOf('NEED_DOWNLOAD:') === 0) s = s.slice('NEED_DOWNLOAD:'.length);
  if (s.indexOf('NEED_ELEVATION:') === 0) s = s.slice('NEED_ELEVATION:'.length);
  if (/login failed|401|invalid username|invalid_credentials/i.test(s)) return '账号或密码错误，请核对接入信息';
  if (/tunnel_token|not a client/i.test(s)) return '该账号不是客户端账号，请向管理员确认';
  if (/certificate|tls|TLS|certificate verify/i.test(s)) return '证书校验失败：请检查证书固定配置，或仅在受信网络开启 insecure';
  if (/timed out|timeout|deadline/i.test(s)) return '连接超时：端点不可达或网络受限';
  if (/ConnectionRefused|refused|10061/i.test(s)) return '无法连接端点：地址/端口错误或端点未启动';
  if (/dns|resolve|lookup/i.test(s)) return '域名解析失败：请检查端点地址';
  if (/account disabled/i.test(s)) return '账号已被禁用，请联系管理员';
  return s.length > 120 ? s.slice(0, 120) + '…' : s;
}

function fmtBytes(n) {
  if (!n) return '0B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (v >= 100 ? v.toFixed(0) : v.toFixed(1)) + u[i];
}

function fmtAgo(ts) {
  if (!ts) return '未刷新';
  const d = Date.now() / 1000 - ts;
  if (d < 3600) return Math.max(1, Math.floor(d / 60)) + ' 分钟前';
  if (d < 86400) return Math.floor(d / 3600) + ' 小时前';
  if (d < 86400 * 30) return Math.floor(d / 86400) + ' 天前';
  return Math.floor(d / 86400 / 30) + ' 个月前';
}

function fmtDur(s) {
  s = Math.max(0, Math.floor(s || 0));
  if (s < 60) return s + 's';
  if (s < 3600) { const m = Math.floor(s / 60), r = s % 60; return m + 'm' + (r ? r + 's' : ''); }
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  return h + 'h' + (m ? m + 'm' : '');
}

/* ---- 右键上下文菜单（共享组件 .ctx-menu；fixed 浮层，边缘收进视口，点外部/Esc 关闭） ---- */
let ctxOpen = null;
function ctxClose() {
  if (!ctxOpen) return;
  const o = ctxOpen; ctxOpen = null;
  o.el.remove();
  o.cleanup();
}
function ctxShow(x, y, items) {
  ctxClose();
  const el = document.createElement('div');
  el.className = 'ctx-menu';
  items.forEach(it => {
    if (it === '-') {
      const s = document.createElement('div');
      s.className = 'ctx-sep';
      el.appendChild(s);
      return;
    }
    const b = document.createElement('button');
    b.className = 'ctx-item' + (it.danger ? ' danger' : '');
    b.textContent = it.label;
    b.onclick = () => { ctxClose(); it.fn(); };
    el.appendChild(b);
  });
  document.body.appendChild(el);
  const w = el.offsetWidth, h = el.offsetHeight;
  el.style.left = Math.max(8, Math.min(x, window.innerWidth - w - 8)) + 'px';
  el.style.top = Math.max(8, Math.min(y, window.innerHeight - h - 8)) + 'px';
  const onDown = (e) => { if (!el.contains(e.target)) ctxClose(); };
  const onKey = (e) => { if (e.key === 'Escape') ctxClose(); };
  document.addEventListener('pointerdown', onDown, true);
  document.addEventListener('keydown', onKey, true);
  ctxOpen = { el, cleanup() {
    document.removeEventListener('pointerdown', onDown, true);
    document.removeEventListener('keydown', onKey, true);
  } };
}
