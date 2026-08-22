'use strict';
/* Split from app.js: invoke bridge / global state / local utils & components (pure move, zero logic change).
   $ / esc / ahelp live in shared layer agutil.js (index.html loads it before this file); icons use shared icons.js AgIcon. */

/* Dual-transport invoke bridge: IPC inside Tauri window; HTTP REST in browser (Web remote panel).
   REST endpoints map 1:1 to commands (server side see crates/client/src/api.rs), envelope {code,data}/{code,message}. */
const TAURI = window.__TAURI__ || null;
const HTTP_MODE = !TAURI;
let httpToken = localStorage.getItem('ag_web_token') || '';

const CMD_MAP = {
  list_nodes:        ['GET', '/api/v1/nodes'],
  connect_node:      ['POST', '/api/v1/nodes', a => a.input],
  disconnect_node:   ['POST', '/api/v1/nodes/disconnect', a => ({ node_id: a.nodeId })],
  send_pending_note: ['POST', '/api/v1/nodes/pending-note', a => ({ node_id: a.nodeId, body: a.body })],
  list_credentials:  ['GET', '/api/v1/credentials'],
  delete_credential: ['DELETE', a => '/api/v1/credentials?key=' + encodeURIComponent(a.key)],
  export_credential: ['GET', a => '/api/v1/credentials/export?confirm=true&key=' + encodeURIComponent(a.key)],
  rename_credential: ['POST', '/api/v1/credentials/rename', a => ({ key: a.key, name: a.name })],
  set_credential_myname: ['POST', '/api/v1/credentials/myname', a => ({ key: a.key, myname: a.myname })],
  list_notifications: ['GET', '/api/v1/notifications'],
  notification_read: ['POST', '/api/v1/notifications/read', a => ({ id: a.id })],
  notifications_read_all: ['POST', '/api/v1/notifications/read-all'],
  clear_notifications:  ['DELETE', '/api/v1/notifications'],
  get_machine_identity: ['GET', '/api/v1/identity'],
  set_machine_myname:   ['POST', '/api/v1/identity/myname', a => ({ name: a.name })],
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
  if (!spec) throw new Error(AgI18n.t('core.err-no-web'));
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
    throw new Error(AgI18n.t('core.err-auth-expired'));
  }
  const json = await resp.json().catch(() => ({}));
  if (json.code !== 0) throw new Error(json.message || AgI18n.t('core.err-request-failed', { code: json.code }));
  return json.data;
}

const invoke = TAURI ? TAURI.core.invoke : httpInvoke;

/* ================= Native-ize: block WebView browser behaviors (Tauri window only; browser remote panel unaffected) ================= */
if (TAURI) {
  // Context menu / drag
  document.addEventListener('contextmenu', e => e.preventDefault());
  document.addEventListener('dragstart', e => e.preventDefault());
  // Browser shortcuts: F12 / DevTools / view source / refresh / print / zoom
  document.addEventListener('keydown', e => {
    const k = e.key.toLowerCase();
    const devCombo = e.ctrlKey && e.shiftKey && ['i', 'j', 'c'].includes(k);
    const zoomCombo = e.ctrlKey && ['=', '-', '0', '+'].includes(e.key);
    if (e.key === 'F12' || e.key === 'F5' || devCombo || zoomCombo ||
        (e.ctrlKey && ['u', 'r', 'p'].includes(k))) e.preventDefault();
  });
  // Ctrl + wheel zoom
  document.addEventListener('wheel', e => { if (e.ctrlKey) e.preventDefault(); }, { passive: false });
  // Disable browser hints: form autofill / spellcheck etc.
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

/* ================= i18n & theme ================= */
/* Locale entries moved to lang/desktop-core.js (core.*); T(k) keeps the old-key compat bridge for app-views etc.;
   st-connected is synonymous with common.connected, aliased to avoid duplicate keys */
const CORE_ALIAS = { 'st-connected': 'common.connected' };
const T = (k, vars) => AgI18n.t(CORE_ALIAS[k] || ('core.' + k), vars);
function applyLanguage() { AgI18n.setLang(localStorage.getItem('ag_lang') || 'zh'); }
/* Language switch: refresh node/proxy sections (former applyLanguage behavior); re-render in place if Dynamic Island detail is expanded */
AgI18n.onChange(() => {
  refreshNodes(true); refreshProxy();
  if (Island.current === 'detail') Island.renderDetail();
  // Custom ag-select labels only sync on change; refresh them so option text follows the new language
  document.querySelectorAll('select[data-agsel]').forEach(agSelectRefresh);
});
function applyTheme() {
  const theme = localStorage.getItem('ag_theme') || 'light';
  document.documentElement.dataset.theme = theme;
  // update the titlebar toggle icon (moon = "switch to dark", sun = "switch to light")
  const btn = document.getElementById('btn-theme');
  if (btn) {
    const ic = btn.querySelector('i, svg');
    if (ic) {
      const newIcon = document.createElement('i');
      newIcon.setAttribute('data-ic', theme === 'dark' ? 'sun' : 'moon');
      newIcon.setAttribute('data-sz', '16');
      ic.replaceWith(newIcon);
      if (window.AgIconHydrate) AgIconHydrate(btn);
    }
  }
}
/* Performance mode (reduced effects): toggle html.no-blur to disable glass blur & animations (fallback rules in components.css/style.css).
   localStorage cache applied first to avoid first-frame wait; initRoles corrects after reading get_role_settings().reduce_effects. */
function applyReduceEffects(on) {
  document.documentElement.classList.toggle('no-blur', !!on);
}
// Apply at parse time to avoid first-frame light flash (same behavior as wiki / admin console)
applyTheme();
applyReduceEffects(localStorage.getItem('ag_reduce_fx') === '1');

/* odo digit scroll driver (structure .odo > .odo-digit > .odo-strip see components.css; scroll animation done by CSS transition).
   Usage: element with class="odo", call odoSet(el, text) per frame — char-aligned diff: digit chars reuse/create a digit and set
   strip.style.transform = translateY(-N em), non-digit chars (. / : units etc.) become bare text nodes; value growing auto-adds digits,
   shrinking auto-trims; internal signature compare, unchanged text leaves DOM alone. Only for a few big numbers like the hero dashboard; do not roll out site-wide. */
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

/* Change-detection writes: leave DOM untouched when content is unchanged (anti-flicker for polling renders) */
function setText(id, s) { const el = $(id); if (el && el.textContent !== s) el.textContent = s; }
function setHtml(id, h) { const el = $(id); if (el && el.innerHTML !== h) el.innerHTML = h; }

/* ---- Global Esc-to-close for modals: the topmost visible .modal-mask closes through its own
   cancel button, so Promise-based modals (askConfirm/askPassword) resolve correctly; masks
   without a cancel button (login) are exempt. Inline editors / dropdowns / ctx menus handle Esc
   themselves and never open a modal-mask, so no conflicts. ---- */
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  const open = [...document.querySelectorAll('.modal-mask')].filter(m => m.style.display === 'flex');
  const mask = open[open.length - 1];
  if (!mask) return;
  const cancel = mask.querySelector('button[id$="-cancel"], button[id$="-close"]');
  if (cancel) { e.preventDefault(); cancel.click(); }
});

/* ================= Inline edit (.agedit, shared styles in components.css) =================
   Generic mini pattern: shows "value [Edit]" → click turns into input + [Save]; Enter saves / Esc cancels.
   opts: { get(): display value, editValue?(): input initial value (defaults to get), validate?(v): error text|null,
           confirm?(v): Promise<boolean> gate before set (e.g. disruptive-change warning; false = abort edit, no write),
           set(v): Promise }
   validate error → toast without writing (stays in edit mode); polling side syncs the display value via returned handle refresh() (never disturbs while editing). */
function bindInlineEdit(el, opts) {
  let editing = false, lastVal = null;
  el.classList.add('agedit');
  function render() {
    if (editing) return;
    const v = opts.get();
    if (v === lastVal && el.firstChild) return; // change detection: display value unchanged, leave DOM alone
    lastVal = v;
    el.innerHTML = '<span class="agedit-val">' + esc(v) + '</span>' +
      '<button type="button" class="ghost small agedit-btn">' + AgI18n.t('common.edit') + '</button>';
    el.querySelector('.agedit-btn').onclick = () => {
      editing = true;
      el.innerHTML = '<input type="text" class="agedit-input" autocomplete="off" spellcheck="false">' +
        '<button type="button" class="ghost small agedit-btn">' + AgI18n.t('common.save') + '</button>';
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
          if (opts.confirm && !(await opts.confirm(val))) { editing = false; lastVal = null; render(); return; }
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

/* ================= ag-select unified custom dropdown (shared component, styles in components.css) =================
   Progressive enhancement: native select kept as data/logic carrier (visually hidden), custom UI synced both ways —
   picking a custom item = write back sel.value and dispatch change (bubbles, existing bindings fire as usual);
   after programmatically changing options/value call agSelectRefresh(sel) to refresh the label; sel.disabled syncs disabled state.
   Popup is fixed on body (avoids overflow clipping), closes on outside click / Esc / scroll / resize. */
let agselOpen = null; // currently open dropdown {root, btn, pop, cleanup} (only one open at a time globally)

function agSelClose() {
  if (!agselOpen) return;
  const o = agselOpen; agselOpen = null;
  o.root.classList.remove('open');
  o.btn.setAttribute('aria-expanded', 'false');
  o.pop.remove();
  o.cleanup();
}

/* Label & disabled-state sync (called on enhance/open/select/refresh) */
function agSelSyncLabel(sel) {
  const root = sel._agsel; if (!root) return;
  const opt = sel.options[sel.selectedIndex];
  root.querySelector('.agsel-label').textContent = opt ? opt.textContent : '';
  root.querySelector('.agsel-btn').disabled = sel.disabled;
}

/* Rebuild the option list on open (naturally handles dynamic option changes) and position the popup */
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
  // Position: below button by default, flip above when space below is insufficient; shift left if right edge overflows
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

/* Scan for unenhanced selects under root and enhance them (idempotent); call once more after dynamic content renders */
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
    // Sync label when external code sets the value directly and dispatches change
    sel.addEventListener('change', () => agSelSyncLabel(sel));
    agSelSyncLabel(sel);
  });
}

/* Refresh the custom UI after programmatic option/value/disabled changes (safe no-op when not enhanced) */
function agSelectRefresh(sel) { if (sel && sel._agsel) agSelSyncLabel(sel); }

/* ================= ag-tabs horizontal tab bar (shared component, styles in components.css) =================
   Structure: <div class="agtabs"><div class="agtabs-pill"><button class="agtab" data-agtab="k">…
         panel = direct [data-agpanel="k"] child in the same container as the tab bar; click sets active and shows the matching panel.
   Pure show/hide toggle, no re-render; onSwitch(key) lets the page sync state. */
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

/* ================= Dynamic Island (status + notifications + error detail) =================
   Morph principle: explicit width/height animation on the container (overflow:hidden wraps content the whole time),
   old content exits instantly, new content fades in delayed — no intermediate frame ever shows content overflowing the island. */
const Island = {
  timer: null, canExpand: false, detailNodes: [], current: 'bar', _t1: null, _t2: null,
  init() {
    $('island-bar').onclick = () => { if (this.canExpand) this.toggleDetail(); };
    // Collapse automatically when clicking anywhere outside the island while detail is expanded
    document.addEventListener('click', (e) => {
      if (this.current === 'detail' && !e.target.closest('#island')) this.morph('bar');
    });
  },
  _parts() { return { bar: $('island-bar'), msg: $('island-msg'), detail: $('island-detail') }; },
  /** Explicit-size morph: measure before animating, shape before content (Apple-style spring); bar stays visible across detail expand/collapse */
  morph(showPart) {
    const el = $('island');
    const parts = this._parts();
    const prev = this.current;
    const same = showPart === prev;
    // 1. Freeze current rendered size (can interrupt mid-transition and resume from any frame)
    const cw = el.offsetWidth, ch = el.offsetHeight;
    el.style.width = cw + 'px'; el.style.height = ch + 'px';
    // 2. Switch content layout: detail state = bar + detail coexist; newly appearing parts take space but stay invisible
    const barPersist = (showPart === 'detail' && prev === 'bar') || (showPart === 'bar' && prev === 'detail');
    if (!same) {
      for (const [k, p] of Object.entries(parts)) {
        const show = k === showPart || (showPart === 'detail' && k === 'bar');
        p.style.display = show ? (k === 'detail' ? 'block' : 'flex') : 'none';
        p.style.visibility = (show && k === showPart && !(k === 'bar' && barPersist)) ? 'hidden' : '';
      }
    }
    // 3. Measure target size (temporarily auto, done within the same frame without repaint)
    el.style.transition = 'none';
    el.style.width = ''; el.style.height = '';
    const tw = el.offsetWidth, th = el.offsetHeight;
    el.style.width = cw + 'px'; el.style.height = ch + 'px';
    void el.offsetHeight;
    el.style.transition = '';
    // 4. Spring-morph to target size
    requestAnimationFrame(() => { el.style.width = tw + 'px'; el.style.height = th + 'px'; });
    el.classList.toggle('expanded', showPart !== 'bar');
    el.dataset.state = showPart;  // three-state gradient colors: bar persistent / msg light gradient / detail strong gradient
    // 5. Morph past halfway → new content fades in (blur + slight drift dissipates); scenes with the bar persistently visible skip fade-out/in
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
      // Consecutive same-state calls (e.g. two notifications arriving within 200ms): the previous reveal timer was
      // cleared; without forcing visibility here the content would stay visibility:hidden forever — empty island (blank white pill)
      parts[showPart].style.visibility = '';
    }
    // 6. Release the explicit size at the end (back to adaptive)
    this._t2 = setTimeout(() => { el.style.width = ''; el.style.height = ''; }, 520);
    this.current = showPart;
  },
  /** Normal status bar. mode: on | off | warn */
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
    else if (changed && this.current === 'bar') this.morph('bar');  // spring transition even when text just grows/shrinks
  },
  /** Transient notification (spring pop-out, auto-collapse) */
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
    $('island-detail').innerHTML = '<div class="dt-title">' + esc(AgI18n.t('core.island-detail')) + '</div>' +
      this.detailNodes.map(n =>
        '<div class="island-row"><span class="dot off"></span><b>' + esc(n.issuer_node_name || n.node_name) + '</b>' +
        '<span class="mono">' + esc(n.addr) + '</span><span class="st">' + esc(statusText(n.status)) + '</span></div>'
      ).join('');
  },
  hideDetail() { if (this.current === 'detail') this.morph('bar'); },
};
function toast(msg, type) { Island.notify(msg, type); }

/** Map low-level errors to user-friendly messages */
function friendlyError(e) {
  let s = String(e);
  // Command contract prefixes (specific pages already dispatch by prefix; the fallback path strips the prefix before showing)
  if (s.indexOf('NEED_DOWNLOAD:') === 0) s = s.slice('NEED_DOWNLOAD:'.length);
  if (s.indexOf('NEED_ELEVATION:') === 0) s = s.slice('NEED_ELEVATION:'.length);
  if (/authentication failed|rejected.*token|invalid.*token|login failed|401|invalid_credentials/i.test(s)) return AgI18n.t('core.err-login');
  if (/certificate|tls|TLS|certificate verify/i.test(s)) return AgI18n.t('core.err-cert');
  if (/timed out|timeout|deadline/i.test(s)) return AgI18n.t('core.err-timeout');
  if (/ConnectionRefused|refused|10061/i.test(s)) return AgI18n.t('core.err-refused');
  if (/dns|resolve|lookup/i.test(s)) return AgI18n.t('core.err-dns');
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
  if (!ts) return AgI18n.t('core.ago-never');
  const d = Date.now() / 1000 - ts;
  if (d < 3600) return AgI18n.t('core.ago-min', { n: Math.max(1, Math.floor(d / 60)) });
  if (d < 86400) return AgI18n.t('core.ago-hour', { n: Math.floor(d / 3600) });
  if (d < 86400 * 30) return AgI18n.t('core.ago-day', { n: Math.floor(d / 86400) });
  return AgI18n.t('core.ago-month', { n: Math.floor(d / 86400 / 30) });
}

function fmtDur(s) {
  s = Math.max(0, Math.floor(s || 0));
  if (s < 60) return s + 's';
  if (s < 3600) { const m = Math.floor(s / 60), r = s % 60; return m + 'm' + (r ? r + 's' : ''); }
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  return h + 'h' + (m ? m + 'm' : '');
}

/* ---- Right-click context menu (shared component .ctx-menu; fixed overlay, clamped into viewport, closes on outside click/Esc) ---- */
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
