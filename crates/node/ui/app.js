'use strict';
/* ================= Icons =================
   Shared icon table apps/desktop/ui/icons.js served via /ui/icons.js (AgIcon/AgIconHydrate, AGENTS.md §6);
   the ic alias is kept here for existing callers; no local icon table is maintained. */
const ic = AgIcon;
/* AgI18n short alias: runtime /ui/agi18n.js, locale entries /ui/aglang.js (common and term domains) + /ui/lang/admin.js (admin console shard) */
const T = (k, vars) => AgI18n.t(k, vars);

/* ================= ag-select unified custom dropdown (shared component, styles in /ui/components.css) =================
   Progressive enhancement: the native select stays as the data/logic carrier (visually hidden), the custom UI syncs with it both ways —
   picking a custom option writes back sel.value and dispatches change (bubbling, existing bindings fire as usual);
   after programmatic option/value changes call agSelectRefresh(sel) to refresh the label; sel.disabled syncs the disabled state.
   Popup is fixed-position on body (avoids modal overflow clipping, z-index above modals); closes on outside click / Esc / scroll / resize. */
let agselOpen = null; // currently open dropdown {root, btn, pop, cleanup} (only one open globally at a time)

function agSelClose() {
  if (!agselOpen) return;
  const o = agselOpen; agselOpen = null;
  o.root.classList.remove('open');
  o.btn.setAttribute('aria-expanded', 'false');
  o.pop.remove();
  o.cleanup();
}

/* Label and disabled-state sync (called on enhance/open/select/refresh) */
function agSelSyncLabel(sel) {
  const root = sel._agsel; if (!root) return;
  const opt = sel.options[sel.selectedIndex];
  root.querySelector('.agsel-label').textContent = opt ? opt.textContent : '';
  root.querySelector('.agsel-btn').disabled = sel.disabled;
}

/* Rebuild the option list on open (naturally tolerates dynamic option changes) and position the popup */
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
  // Position: below the button by default, flip above when space below is short; shift left if the right edge overflows
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

/* Scan for unenhanced selects under root and enhance them (idempotent); call after any innerHTML render entry point */
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
    btn.innerHTML = '<span class="agsel-label"></span>' + ic('chevron-down', 14);
    wrap.appendChild(btn);
    sel.parentNode.insertBefore(wrap, sel.nextSibling);
    sel._agsel = wrap;
    btn.addEventListener('click', () => {
      if (sel.disabled) return;
      if (agselOpen && agselOpen.root === wrap) { agSelClose(); return; }
      agSelClose();
      agSelOpenPop(sel, wrap, btn);
    });
    // Sync the label when external code sets the value directly and dispatches change
    sel.addEventListener('change', () => agSelSyncLabel(sel));
    agSelSyncLabel(sel);
  });
}

/* Refresh the custom UI after programmatic option/value/disabled changes (safe no-op when not enhanced) */
function agSelectRefresh(sel) { if (sel && sel._agsel) agSelSyncLabel(sel); }

/* ================= ag-tabs horizontal tab bar (shared component, styles in /ui/components.css) =================
   Structure: <div class="agtabs"><div class="agtabs-pill"><button class="agtab" data-agtab="k">…
         Panel = direct [data-agpanel="k"] child in the same container as the tab bar; clicking sets active and shows the matching panel.
   Pure show/hide switching, no re-render (polling signature detection unaffected); onSwitch(key) lets pages sync state. */
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

/* ================= Infrastructure =================
   $ / esc / ahelp come from shared base utils /ui/agutil.js (AGENTS.md §6); no local copies kept here */
const S = {
  access: localStorage.getItem('ag_access') || '',
  refresh: localStorage.getItem('ag_refresh') || '',
  view: 'dashboard',
  page: { accounts: 1, groups: 1, rules: 1, audit: 1 },
  size: { accounts: 10, groups: 10, rules: 10, audit: 15 },
  filter: { accounts: '', accountsEnabled: '', accountsGroup: '', rules: '', rulesType: '', auditAction: '' },
  faninTab: 'listen',   // fan-in page current tab: listen | peers | tokens
  faninQuery: '',       // fan-in page search term: shared by the peers/tokens tabs (kept across tab switches)
  groups: [],
  timers: [],
  ws: null,
};

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
  return (d? d + T('adm.unitDay') + ' ':'') + (h? h + T('adm.unitHour') + ' ':'') + m + T('adm.unitMin');
}
function toast(msg, type) {
  // When embedded in the GUI, notifications all go through the shell Dynamic Island (avoids two coexisting notification components)
  if (window.parent !== window) {
    try {
      window.parent.postMessage({ type: 'ag-toast', msg: String(msg), kind: type || 'info' }, '*');
      return;
    } catch (e) { /* fall back to local toast when postMessage is unavailable */ }
  }
  const el = document.createElement('div');
  el.className = 'toast ' + (type||'');
  el.textContent = msg;
  $('toasts').appendChild(el);
  setTimeout(() => el.remove(), 3600);
}
async function copyText(text) {
  try { await navigator.clipboard.writeText(text); toast(T('adm.copied'), 'ok'); }
  catch(e) { toast(T('adm.copyFailed'), 'err'); }
}

/* ================= API client (auto token refresh) ================= */
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
  if (res.status === 401) { doLogout(); throw new Error(T('adm.sessionExpired')); }
  let j;
  try { j = await res.json(); } catch(e) { throw new Error(T('adm.badResponse', { status: res.status })); }
  if (j.code !== 0) throw new Error(j.message || T('adm.errCode', { code: j.code }));
  return j.data;
}

/* ================= Modal ================= */
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
  (actions || [{label: T('common.close'), kind:'ghost', fn: closeModal}]).forEach(a => {
    const b = document.createElement('button');
    b.textContent = a.label;
    if (a.kind) b.className = a.kind;
    b.onclick = a.fn;
    bar.appendChild(b);
  });
  modal.appendChild(bar);
  mask.appendChild(modal);
  root.appendChild(mask);
  agSelectEnhance(modal);
}
function closeModal() { $('modal-root').innerHTML = ''; }
function confirmAction(text, onYes) {
  openModal(T('adm.confirmTitle'), '<p style="color:var(--dim)">' + esc(text) + '</p>', [
    {label: T('common.cancel'), kind:'ghost', fn: closeModal},
    {label: T('adm.confirmExec'), kind:'danger', fn: async () => { closeModal(); await onYes(); }},
  ]);
}

/* ================= Share card (federation P1) =================
   Issuance dialogs (account / fan-in token): endpoint choice (public identity / LAN direct) +
   tab switch (full link / key only) + copy. The link is rebuilt from the parsed fields via the
   shared AgLink parser on endpoint switch (the secret is shown only this once, no refetch). */
function aglinkErrText(code) {
  return T('aglink.' + (code || 'missing'));
}
function shareCardHtml(endpoints) {
  const eps = endpoints || [];
  const epRow = eps.length > 1
    ? '<label>' + T('share.endpoint') + '</label><select data-share-ep style="width:100%">' +
      eps.map(e => '<option value="' + esc(e.addr) + '">' + T('share.ep.' + e.kind) + ' · ' + esc(e.addr) + '</option>').join('') + '</select>'
    : '';
  return epRow +
    '<div class="agtabs" style="margin:10px 0 6px"><div class="agtabs-pill">' +
      '<button class="agtab active" data-share-tab="link">' + T('share.tabLink') + '</button>' +
      '<button class="agtab" data-share-tab="key">' + T('share.tabKey') + '</button>' +
    '</div></div>' +
    '<div class="secret-box"><span class="mono" data-share-val></span></div>' +
    '<div class="actions" style="justify-content:flex-start;margin-top:10px">' +
      '<button class="ghost small" data-share-copy data-act="copy">' + ic('copy', 13) + T('common.copy') + '</button>' +
      '<button class="ghost small" data-share-anet>' + ic('download', 13) + T('share.downloadAnet') + '</button>' +
    '</div>';
}
function shareCardBind(root, opts) {
  const parsed = AgLink.parse(opts.link);
  if (parsed.error) return;
  const epSel = root.querySelector('[data-share-ep]');
  const valBox = root.querySelector('[data-share-val]');
  const copyBtn = root.querySelector('[data-share-copy]');
  if (!valBox || !copyBtn) return;
  let tab = 'link';
  function currentLink() {
    const addr = epSel ? epSel.value : parsed.addr;
    return opts.role === 'fanout'
      ? AgLink.buildFanout({ addr, token: parsed.token, sni: parsed.sni, fp: parsed.fp, insecure: parsed.insecure })
      : AgLink.buildConnect({
          addr, account: parsed.account, password: parsed.password, fp: parsed.fp,
          insecure: parsed.insecure, admin: parsed.admin,
          // federation P2: keep the disaster set of a delegated credential across rebuilds
          entries: (parsed.entries || []).map((a, i) => ({ addr: a, fp: (parsed.entryFps || [])[i] || '' })),
          // federation P3: keep the E2E routing hint, the entrust word, the consumer tier and the admin hint
          ehint: parsed.ehint || '',
          en: parsed.en || '',
          emode: parsed.emode || '',
          eadmin: !!parsed.eadmin,
        });
  }
  function render() {
    const v = tab === 'link' ? currentLink() : opts.secret;
    valBox.textContent = v;
    copyBtn.dataset.copy = v;
    root.querySelectorAll('[data-share-tab]').forEach(b => b.classList.toggle('active', b.dataset.shareTab === tab));
  }
  root.querySelectorAll('[data-share-tab]').forEach(b => { b.onclick = () => { tab = b.dataset.shareTab; render(); }; });
  if (epSel) epSel.onchange = render;
  const anetBtn = root.querySelector('[data-share-anet]');
  if (anetBtn) anetBtn.onclick = () => openAnetExport(opts.role, parsed, currentLink(), opts.note || '');
  render();
}

/* ================= .anet credential file (federation P1 §2.8) =================
   Export: envelope meta (issuer/note) + optional 4-digit PIN (default recommended) -> native
   save (desktop console bridge) or blob download (browser). Import: meta preview first, then
   PIN if needed, then apply by role (fanout -> prefilled form; connect -> client-side notice). */
async function anetIssuer() {
  if (!S.nodeName) {
    try { S.nodeName = (await api('GET', '/api/v1/admin/node/status')).node_name || 'AgileNet'; } catch(e) { S.nodeName = 'AgileNet'; }
  }
  return S.nodeName;
}
function anetErrText(code) {
  const map = { bad_json: 'badFile', bad_magic: 'badFile', bad_version: 'badFile', bad_role: 'badFile', bad_payload: 'badFile', bad_enc: 'badFile', decrypt: 'badPin', bad_pin: 'badPin', need_pin: 'badPin', no_crypto: 'noCrypto' };
  return T('anet.' + (map[code] || 'badFile'));
}
function isEmbeddedConsole() { return document.documentElement.classList.contains('embed') && window.parent !== window; }
/* Save .anet text: native save dialog via the desktop console bridge when embedded, blob download otherwise */
async function anetSaveFile(name, content) {
  if (isEmbeddedConsole()) {
    return new Promise((resolve) => {
      const onMsg = (e) => {
        const d = e.data || {};
        if (d.type === 'ag-anet-saved') { window.removeEventListener('message', onMsg); resolve(!!d.ok); }
      };
      window.addEventListener('message', onMsg);
      window.parent.postMessage({ type: 'ag-anet-save', name, content }, '*');
      setTimeout(() => { window.removeEventListener('message', onMsg); resolve(false); }, 120000);
    });
  }
  const blob = new Blob([content], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  return true;
}
function anetExportDialogHtml(defaultNote) {
  const cryptoOk = AgAnet.canEncrypt();
  return '<label>' + T('anet.note') + '</label><input id="ax-note" style="width:100%" value="' + esc(defaultNote || '') + '" placeholder="' + T('anet.notePh') + '">' +
    '<label class="chk" style="display:flex;align-items:center;gap:6px;margin-top:10px"><input type="checkbox" id="ax-pin-on" ' + (cryptoOk ? 'checked' : 'disabled') + '> ' + T('anet.pinLabel') + '</label>' +
    '<div id="ax-pin-row"><input id="ax-pin" class="mono" style="width:140px" maxlength="4" inputmode="numeric" placeholder="' + T('anet.pinPh') + '">' +
    '<div class="hint">' + T('anet.pinHint') + '</div></div>' +
    (cryptoOk ? '' : '<div class="hint" style="color:var(--warn)">' + T('anet.noCrypto') + '</div>');
}
async function openAnetExport(role, parsed, link, defaultNote) {
  const issuer = await anetIssuer();
  openModal(T('anet.exportTitle'), anetExportDialogHtml(defaultNote), [
    {label: T('common.cancel'), kind:'ghost', fn: closeModal},
    {label: T('anet.export'), fn: async () => {
      const note = $('ax-note').value.trim();
      const pinOn = $('ax-pin-on').checked;
      const pin = pinOn ? $('ax-pin').value.trim() : '';
      if (pinOn && !/^\d{4}$/.test(pin)) { toast(T('anet.pinNeed4'), 'err'); return; }
      // Payload = the parsed technical fields + the concrete link (endpoint choice already applied)
      const payload = { ...parsed, link };
      try {
        const text = await AgAnet.build({ role, issuer, note }, payload, pin);
        const name = AgAnet.suggestName(issuer, note || (role === 'fanout' ? parsed.sni : parsed.account));
        const saved = await anetSaveFile(name, text);
        if (saved) { closeModal(); toast(T('anet.exported'), 'ok'); }
      } catch(e) { toast(anetErrText(e.code), 'err'); }
    }},
  ]);
  $('ax-pin-on').onchange = (e) => { $('ax-pin-row').style.display = e.target.checked ? 'block' : 'none'; };
}
/* Import: meta preview first, then PIN when encrypted, then apply by role */
function openAnetImport(text, fileName) {
  let parsed;
  try { parsed = AgAnet.parse(text); } catch(e) { toast(anetErrText(e.code), 'err'); return; }
  const env = parsed.envelope;
  const roleText = env.role === 'fanout' ? T('anet.roleFanout') : T('anet.roleConnect');
  openModal(T('anet.importTitle'),
    '<div class="kv"><span class="k">' + T('anet.metaRole') + '</span><span><span class="badge b-info">' + roleText + '</span> ' +
      (parsed.needPin ? '<span class="badge b-warn">' + T('anet.encrypted') + '</span>' : '<span class="badge b-info">' + T('anet.plaintext') + '</span>') + '</span></div>' +
    '<div class="kv"><span class="k">' + T('anet.metaIssuer') + '</span><span>' + esc(env.issuer || '-') + '</span></div>' +
    '<div class="kv"><span class="k">' + T('anet.metaTime') + '</span><span>' + esc((env.created_at || '').replace('T', ' ').replace(/\..*$/, '')) + '</span></div>' +
    '<div class="kv"><span class="k">' + T('anet.metaNote') + '</span><span>' + esc(env.note || '-') + '</span></div>' +
    (fileName ? '<div class="kv"><span class="k">' + T('anet.metaFile') + '</span><span class="mono" style="font-size:12px">' + esc(fileName) + '</span></div>' : '') +
    (parsed.needPin
      ? '<label style="margin-top:10px">' + T('anet.pinNeed') + '</label><input id="ai-pin" class="mono" style="width:140px" maxlength="4" inputmode="numeric">'
      : ''),
    [
      {label: T('common.cancel'), kind:'ghost', fn: closeModal},
      {label: T('anet.apply'), fn: async () => {
        let payload;
        if (parsed.needPin) {
          try { payload = await AgAnet.decrypt(env, $('ai-pin').value.trim()); }
          catch(e) { toast(anetErrText(e.code), 'err'); return; }
        } else {
          payload = env.payload;
        }
        applyAnetPayload(env.role, payload);
      }},
    ]);
}
function applyAnetPayload(role, payload) {
  if (role === 'fanout') {
    closeModal();
    openCreateConnector(payload || {});
    toast(T('anet.appliedFanout'), 'ok');
  } else {
    // A connect credential is for clients, not for this console — explain instead of silently dropping
    toast(T('anet.connectHere'), 'err');
  }
}

/* ================= Universal import wizard (blind-plug; dashboard 「导入」 button) =================
   One dialog for every credential carrier: anet:// link paste, .anet file, QR image.
   Shared component agimport.js; this is the admin-console adapter. Fan-in credentials belong
   to clients — the wizard explains and keeps the confirm icon gray (same rule as applyAnetPayload). */
function pickAnetFileUniversal() {
  // Embedded console: the desktop host owns the native open dialog (same bridge as the connectors tab)
  if (isEmbeddedConsole()) {
    return new Promise((resolve) => {
      const onMsg = (e) => {
        const d = e.data || {};
        if (d.type === 'ag-anet-open-result') {
          window.removeEventListener('message', onMsg);
          resolve(d.content != null ? { name: d.name, content: d.content } : null);
        }
      };
      window.addEventListener('message', onMsg);
      window.parent.postMessage({ type: 'ag-anet-open' }, '*');
      setTimeout(() => { window.removeEventListener('message', onMsg); resolve(null); }, 120000);
    });
  }
  return new Promise((resolve) => {
    const inp = document.createElement('input');
    inp.type = 'file';
    inp.accept = '.anet,application/json';
    inp.onchange = async () => {
      const f = inp.files[0];
      resolve(f ? { name: f.name, content: await f.text() } : null);
    };
    inp.addEventListener('cancel', () => resolve(null));
    inp.click();
  });
}
function pickQrImageUniversal() {
  return new Promise((resolve, reject) => {
    const inp = document.createElement('input');
    inp.type = 'file';
    inp.accept = 'image/png,image/jpeg';
    inp.onchange = async () => {
      const f = inp.files[0];
      if (!f) { resolve(null); return; }
      try {
        const buf = await f.arrayBuffer();
        const post = () => fetch('/api/v1/admin/tool/qr-decode', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer ' + S.access, 'Content-Type': 'application/octet-stream' },
          body: buf,
        });
        let res = await post();
        if (res.status === 401 && await refreshSession()) res = await post();
        const j = await res.json().catch(() => ({}));
        if (j.code !== 0) { reject(new Error(j.message || T('import.badLink'))); return; }
        resolve(j.data.text);
      } catch (e) { reject(e); }
    };
    inp.addEventListener('cancel', () => resolve(null));
    inp.click();
  });
}
function openUniversalImport() {
  AgImport.open({
    context: 'admin',
    connectApplicable: false, // fan-in credentials are for clients; this console imports fan-out only
    pickAnetFile: pickAnetFileUniversal,
    pickQrImage: pickQrImageUniversal,
    applyFanout: async ({ parsed }, details) => {
      try {
        await api('POST', '/api/v1/admin/connectors', {
          name: details.name || parsed.addr,
          upstream_addr: parsed.addr,
          token: parsed.token,
          sni_hostname: parsed.sni || '',
          insecure: !!parsed.insecure,
          pinned_fingerprint: parsed.fp || '',
          advertise: [],
          remark: details.remark,
        });
        return true;
      } catch (e) { return e.message; }
    },
    onDone: () => {
      toast(T('fanout.createdToast'), 'ok');
      if (S.view === 'connectors') loadConnectors();
    },
    toast: (m, k) => toast(m, k),
  });
}

/* ================= Login/logout ================= */
async function doLogin() {
  const u = $('login-user').value.trim(), p = $('login-pass').value;
  $('login-err').textContent = '';
  if (!u || !p) { $('login-err').textContent = T('login.needCred'); return; }
  try {
    const res = await fetch('/api/v1/auth/login', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({username: u, password: p})
    });
    const j = await res.json();
    if (j.code !== 0) { $('login-err').textContent = j.message || T('login.failed'); return; }
    S.access = j.data.access_token; S.refresh = j.data.refresh_token || '';
    localStorage.setItem('ag_access', S.access);
    localStorage.setItem('ag_refresh', S.refresh);
    enterApp();
  } catch(e) { $('login-err').textContent = T('login.netError'); }
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

/* ================= View routing ================= */
function switchView(v) {
  S.view = v;
  S.timers.forEach(clearInterval); S.timers = [];
  document.querySelectorAll('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.view === v));
  const fn = ({dashboard: renderDashboard, accounts: renderAccounts, groups: renderGroups,
    rules: renderRules, fanin: renderFanIn, connectors: renderConnectors, audit: renderAudit, settings: renderSettings})[v] || renderDashboard;
  fn();
}
async function loadGroupsCache() {
  try { const d = await api('GET', '/api/v1/admin/groups?page_size=100'); S.groups = d.items || []; } catch(e) { S.groups = []; }
  // After a group cache refresh, sync the labels of existing custom dropdowns (option lists are rebuilt by each render entry)
  document.querySelectorAll('select[data-agsel]').forEach(agSelectRefresh);
}
function groupName(id) {
  const g = S.groups.find(g => g.id === id);
  return g ? g.name : (id || '-');
}
/* Group-set display: resolve each member of a stored CSV to its cached name (dangling ids verbatim) */
function groupNamesOf(csv) {
  const parts = String(csv || '').split(',').filter(Boolean);
  if (!parts.length) return '-';
  return parts.map(id => groupName(id)).join(', ');
}
/* Proxy mode text (client proxy slot mode: system = system proxy / local = local proxy) */
function proxyModeText(m) { return ({ system: T('adm.modeSystem'), local: T('adm.modeLocal') })[m] || m || ''; }
/* Connection status text (shared by fan-out connectors and the dashboard; function form re-fetches locale entries after a language switch) */
function connStatusText(st) {
  return ({ connected: T('common.connected'), connecting: T('adm.connecting'),
    reconnecting: T('adm.reconnecting'), disconnected: T('adm.disconnected') })[st] || st || T('adm.unknown');
}
function pager(viewKey, total) {
  const page = S.page[viewKey], size = S.size[viewKey];
  const pages = Math.max(1, Math.ceil(total / size));
  return '<div class="pager"><span>' + T('adm.pager', { total, page, pages }) + '</span>' +
    '<button class="ghost small" ' + (page<=1?'disabled':'') + ' data-pager="' + viewKey + '" data-delta="-1">' + T('adm.prevPage') + '</button>' +
    '<button class="ghost small" ' + (page>=pages?'disabled':'') + ' data-pager="' + viewKey + '" data-delta="1">' + T('adm.nextPage') + '</button></div>';
}
function shortId(id) { return esc(String(id||'').substring(0,8)); }

/* ================= Dynamic content event delegation =================
   Dynamic HTML always uses data-* markers with unified dispatch at document level (replaces inline onclick/onchange, aligning with desktop CSP constraints);
   delegation is bound on document, so polling innerHTML rewrites do not break bindings. Click actions use data-act, change actions use data-act-chg. */
const ACT_CLICK = {
  'copy': b => copyText(b.dataset.copy),
  'show-qr': b => showQr(b.dataset.id),
  'acc-reset': b => resetAccountPwd(b.dataset.id, b.dataset.name),
  'acc-toggle': b => toggleAccount(b.dataset.id, b.dataset.enabled === 'true'),
  'acc-del': b => delAccount(b.dataset.id, b.dataset.name),
  'grp-detail': b => openGroupDetail(b.dataset.id),
  'grp-bind': b => openBindRules(b.dataset.id, b.dataset.name),
  'grp-edit': b => openEditGroup(b.dataset.id, b.dataset.name, b.dataset.remark || '', b.dataset.e2e === '1'),
  'grp-del': b => delGroup(b.dataset.id, b.dataset.name, Number(b.dataset.count || 0)),
  'rule-edit': b => openEditRule(b.dataset.id, b.dataset.type, b.dataset.value, b.dataset.resolve === 'true', b.dataset.remark || ''),
  'rule-del': b => delRule(b.dataset.id, b.dataset.value, Number(b.dataset.count || 0)),
  'tok-edit': b => openEditToken(b.dataset.id, b.dataset.group || '', b.dataset.expose === 'true', b.dataset.scope),
  'tok-del': b => delToken(b.dataset.id),
  'conn-edit': b => openEditConnector(b.dataset.id),
  'conn-toggle': b => toggleConnector(b.dataset.id, b.dataset.enabled === 'true'),
  'conn-del': b => delConnector(b.dataset.id, b.dataset.name),
  'deleg-revoke': b => revokeDelegation(b.dataset.id, b.dataset.name),
  'grp-copy': b => copyAdopted(b.dataset.id, b.dataset.name),
  'fed-adopt-now': b => { adoptPushed(b.dataset.node, b.dataset.group).then(() => { closeModal(); }); },
  'pool-toggle': b => {
    const row = document.querySelector('[data-poolrow="' + CSS.escape(b.dataset.node) + '"]');
    if (row) row.hidden = !row.hidden;
  },
  'fed-adopt': b => adoptPushed(b.dataset.node, b.dataset.group),
  'admin-del': b => delAdmin(b.dataset.id, b.dataset.name),
};
const ACT_CHANGE = {
  'tok-expose': el => toggleExpose(el.dataset.id, el.checked),
  'tok-scope': el => setScope(el.dataset.id, el.value),
};
document.addEventListener('click', (e) => {
  const p = e.target.closest('[data-pager]');
  if (p) {
    if (p.disabled) return;
    const key = p.dataset.pager;
    S.page[key] += Number(p.dataset.delta);
    ({ accounts: renderAccounts, groups: renderGroups, rules: renderRules, audit: renderAudit }[key] || (() => {}))();
    return;
  }
  const b = e.target.closest('[data-act]');
  if (!b) return;
  const fn = ACT_CLICK[b.dataset.act];
  if (fn) fn(b);
});
document.addEventListener('change', (e) => {
  const el = e.target.closest('[data-act-chg]');
  if (!el) return;
  const fn = ACT_CHANGE[el.dataset.actChg];
  if (fn) fn(el);
});

/* ================= Dashboard ================= */
async function renderDashboard() {
  $('view').innerHTML = '<div class="page-title">' + ic('layout-dashboard', 20) + '<span id="dash-title">' + T('dashboard.title', { name: T('term.endpoint') }) + '</span>' +
    '<div class="spacer"></div><button class="ghost small" id="dash-import">' + ic('link', 15) + T('import.title') + '</button></div><div class="page-desc">' + T('dashboard.desc') + '</div>' +
    '<div class="stat-grid" id="dash-stats"></div>' +
    '<div class="tf-grid" id="dash-tf">' +
      tfCard('fanin', T('dashboard.tfFanin'), 'fanin') +
      tfCard('fanout', T('dashboard.tfFanout'), 'connectors') +
      tfCard('transit', T('dashboard.tfTransit'), 'fanin') +
    '</div>' +
    '<div class="card"><h3>' + T('dashboard.chartTitle') + '</h3><div class="chart-wrap" id="traffic-chart"></div></div>' +
    '<div class="card"><h3>' + T('dashboard.events') + '</h3><div id="events-list" class="mono" data-loading="1" style="max-height:180px;overflow-y:auto;color:var(--dim)">' + T('dashboard.eventsLoading') + '</div></div>';
  // Card click navigation (event delegation: containers persist, load's innerHTML rewrites do not break bindings; same path in embed mode)
  const gotoView = (e) => {
    const card = e.target.closest('[data-goto]');
    if (card) switchView(card.dataset.goto);
  };
  $('dash-stats').onclick = gotoView;
  $('dash-tf').onclick = gotoView;
  $('dash-import').onclick = openUniversalImport;

  async function load() {
    try {
      const st = await api('GET', '/api/v1/admin/node/status');
      // Title bar follows the endpoint name (Tauri console window)
      const tbt = document.querySelector('.tb-title');
      if (tbt && st.node_name) tbt.textContent = st.node_name;
      const tt = $('dash-title'), tname = T('dashboard.title', { name: st.node_name || T('term.endpoint') });
      if (tt && tt.textContent !== tname) tt.textContent = tname;
      const L = st.roles.listener, CS = st.roles.connectors || [], P = st.proxy, A = st.accounts;
      const fanoutSub = CS.length
        ? CS.map(c => '<div class="mono">' + esc(c.upstream) + ' <span class="badge ' +
            (c.status === 'connected' ? 'b-ok' : (c.status === 'disconnected' ? 'b-off' : 'b-warn')) + '">' +
            esc(connStatusText(c.status)) + '</span></div>').join('')
        : '-';
      // Local proxy sub-line: with mode (client proxy slot) → mode + listen; otherwise the node's legacy proxy_listen wording
      const proxySub = P.mode
        ? esc(proxyModeText(P.mode)) + (P.enabled && P.listen ? ' · ' + esc(P.listen) : '')
        : (P.enabled ? esc(P.listen) + ' · ' + T('dashboard.proxyStats', { active: P.active_connections||0, rules: P.rule_count||0 }) : T('dashboard.proxyRules', { n: P.rule_count||0 }));
      let cards =
        statCard(T('dashboard.cardName'), esc(st.node_name), 'v' + esc(st.version) + ' · ' + T('dashboard.uptime', { up: fmtUptime(st.uptime) }), 'settings') +
        statCard(T('dashboard.cardRelay'), L.enabled ? '<span class="badge b-ok">' + T('adm.stOn') + '</span>' : '<span class="badge b-off">' + T('adm.stNotOn') + '</span>',
          L.enabled ? esc(L.addr) + ' · ' + T('dashboard.relaySub', { peers: L.connected_connectors||0, clients: L.online_clients||0 }) : '-', 'fanin') +
        statCard(T('dashboard.cardFanout'), CS.length ? '<span class="badge b-ok">' + T('dashboard.connCount', { n: CS.length }) + '</span>' : '<span class="badge b-off">' + T('dashboard.noFanout') + '</span>', fanoutSub, 'connectors') +
        statCard(T('dashboard.cardProxy'), P.enabled ? '<span class="badge b-ok">' + T('adm.stOn') + '</span>' : '<span class="badge b-off">' + T('adm.stNotOn') + '</span>', proxySub, 'settings') +
        statCard(T('dashboard.cardAccounts'), T('adm.countN', { n: A.total||0 }), T('dashboard.accSub', { on: A.online||0, off: A.disabled||0 }), 'accounts') +
        statCard(T('dashboard.cardSystem'), (st.system.memory_mb||0) + ' MB', T('dashboard.sysSub', { cpu: (st.system.cpu_usage||0).toFixed(1), mem: st.system.total_memory_mb||0 }));
      if (L.enabled && (L.peers||[]).length) {
        cards += statCard(T('dashboard.cardPeers'), (L.peers||[]).map(p => '<div class="mono"><span class="dot on"></span>' + esc(p) + '</div>').join(''), '');
      }
      $('dash-stats').innerHTML = cards;
      // Three traffic cards: fan-in (today + 24h trend) / fan-out (totals + per-item details) / relay path (totals + pairs)
      updateTfCards(st);
    } catch(e) { toast(e.message, 'err'); }

    try {
      const t = await api('GET', '/api/v1/admin/node/stats?period=24h&group_by=time');
      const pts = t.points || [];
      AgChart.line($('traffic-chart'), {
        x: pts.map(p => p.time),
        series: [
          { name: 'RX', values: pts.map(p => p.bytes_rx) },
          { name: 'TX', values: pts.map(p => p.bytes_tx) },
        ],
        fmtY: fmtBytes,
        fmtX: h => String(h || '').slice(11, 16),
        empty: T('dashboard.chartEmpty'),
      });
    } catch(e) {}
  }
  function statCard(k, v, sub, view) {
    return '<div class="stat' + (view ? ' link' : '') + '"' + (view ? ' data-goto="' + view + '"' : '') +
      '><div class="k">' + k + '</div><div class="v">' + v + '</div><div class="sub">' + sub + '</div></div>';
  }
  await load();
  S.timers.push(setInterval(load, 15000));

  // WebSocket live events
  try {
    if (S.ws) { S.ws.close(); S.ws = null; }
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(proto + '://' + location.host + '/api/v1/admin/node/events');
    S.ws = ws;
    // Auth via the first message after upgrade (token stays out of the URL, avoiding access logs / browser history)
    ws.onopen = () => { try { ws.send(S.access); } catch(e) {} };
    ws.onmessage = (ev) => {
      try {
        const e = JSON.parse(ev.data);
        const list = $('events-list');
        if (!list) return;
        if (list.dataset.loading) { list.innerHTML = ''; delete list.dataset.loading; }
        const line = document.createElement('div');
        line.textContent = '[' + (e.time||'').substring(11,19) + '] ' + e.type + ' ' + JSON.stringify(e.data||{});
        list.prepend(line);
        while (list.children.length > 50) list.lastChild.remove();
      } catch(err) {}
    };
    ws.onclose = () => { const l = $('events-list'); if (l && S.view === 'dashboard') l.innerHTML = '<span style="color:var(--dim2)">' + esc(T('dashboard.eventsClosed')) + '</span>'; };
  } catch(e) {}
}

/* ================= Traffic cards (fan-in / fan-out / relay path; sparkline via shared AgChart component) =================
   Data sources: status contract st.roles.fanout_traffic / st.roles.transit / st.traffic_24h;
   fan-in today's totals are aggregated from traffic_24h.fanin by local date; missing contract fields (old endpoints) degrade gracefully to '-'.
   Change detection: numbers/detail areas each compare their own signature, chart signature lives inside AgChart; nothing rewrites without changes. */
function tfCard(key, title, gotoView) {
  return '<div class="card tf-card link" data-goto="' + gotoView + '"><h3>' + title + '</h3>' +
    '<div class="tf-nums" id="tf-' + key + '-nums"></div>' +
    '<div class="tf-spark" id="tf-' + key + '-spark"></div>' +
    '<div class="tf-detail" id="tf-' + key + '-detail"></div></div>';
}
function tfNums(key, up, down, scope) {
  const el = $('tf-' + key + '-nums'); if (!el) return;
  const html = (up == null)
    ? '<div class="n"><div class="k">' + T('common.empty') + '</div></div>'
    : '<div class="n"><div class="k">' + T('dashboard.down') + esc(scope) + '</div><div class="v">' + fmtBytes(down) + '</div></div>' +
      '<div class="n"><div class="k">' + T('dashboard.up') + esc(scope) + '</div><div class="v">' + fmtBytes(up) + '</div></div>';
  if (el.dataset.sig !== html) { el.dataset.sig = html; el.innerHTML = html; }
}
function tfSpark(key, points) {
  const el = $('tf-' + key + '-spark'); if (!el) return;
  const pts = Array.isArray(points) ? points : [];
  AgChart.sparkline(el, [
    { name: T('dashboard.down'), values: pts.map(p => +p.down || 0) },
    { name: T('dashboard.up'), values: pts.map(p => +p.up || 0) },
  ]);
}
function tfDetail(key, rows) {
  const el = $('tf-' + key + '-detail'); if (!el) return;
  const html = rows.length
    ? rows.slice(0, 5).map(r =>
        '<div class="row"><span class="l">' + esc(r.l) + '</span><span class="v mono">' + esc(r.v) + '</span></div>').join('') +
      (rows.length > 5 ? '<div class="row"><span class="l">' + T('dashboard.moreRows', { n: rows.length }) + '</span><span></span></div>' : '')
    : '<div class="row"><span class="l" style="color:var(--dim2)">' + T('common.empty') + '</span></div>';
  if (el.dataset.sig !== html) { el.dataset.sig = html; el.innerHTML = html; }
}
/* Today's totals: hour is a "YYYY-MM-DD HH:00" local-time string, filtered by local date prefix */
function tfTodaySum(points) {
  const d = new Date();
  const pfx = d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
  let up = 0, down = 0;
  (points || []).forEach(p => {
    if (String(p.hour || '').slice(0, 10) === pfx) { up += +p.up || 0; down += +p.down || 0; }
  });
  return { up, down };
}
function tfUpDown(up, down) { return '↑ ' + fmtBytes(up) + ' · ↓ ' + fmtBytes(down); }
function updateTfCards(st) {
  const R = st.roles || {}, T24 = st.traffic_24h || {};
  // Fan-in: today's up/down + 24h trend; detail = current per-peer fan-in counters (peer_traffic)
  const fi = Array.isArray(T24.fanin) ? tfTodaySum(T24.fanin) : null;
  tfNums('fanin', fi ? fi.up : null, fi ? fi.down : 0, T('dashboard.scopeToday'));
  tfSpark('fanin', T24.fanin);
  tfDetail('fanin', ((R.listener || {}).peer_traffic || []).map(p => ({
    l: p.node_id, v: tfUpDown(p.bytes_up, p.bytes_down),
  })));
  // Fan-out: fanout_traffic totals + per-connector details
  const fo = Array.isArray(R.fanout_traffic) ? R.fanout_traffic : null;
  let foUp = 0, foDown = 0;
  (fo || []).forEach(c => { foUp += +c.bytes_up || 0; foDown += +c.bytes_down || 0; });
  tfNums('fanout', fo ? foUp : null, foDown, T('dashboard.scopeTotal'));
  tfSpark('fanout', T24.fanout);
  tfDetail('fanout', (fo || []).map(c => ({ l: c.name, v: tfUpDown(c.bytes_up, c.bytes_down) })));
  // Relay path: transit totals + pairs (start → end; only the adjacent two hops are visible within a sovereignty domain boundary)
  const tr = R.transit || null;
  tfNums('transit', tr ? +tr.bytes_up || 0 : null, tr ? +tr.bytes_down || 0 : 0, T('dashboard.scopeTotal'));
  tfSpark('transit', T24.transit);
  tfDetail('transit', ((tr && tr.pairs) || []).map(p => ({
    l: (p.from || '?') + ' → ' + (p.to || '?'), v: tfUpDown(p.bytes_up, p.bytes_down),
  })));
}

/* ================= Client accounts ================= */
async function renderAccounts() {
  $('view').innerHTML = '<div class="page-title">' + ic('users', 20) + T('accounts.title') + '</div><div class="page-desc">' + T('accounts.desc') + '</div>' +
    '<div class="toolbar">' +
      '<input id="acc-q" placeholder="' + T('accounts.searchPh') + '" value="' + esc(S.filter.accounts) + '">' +
      '<select id="acc-group">' +
        '<option value="">' + T('accounts.allGroups') + '</option>' +
        S.groups.map(g => '<option value="' + esc(g.id) + '" ' + (S.filter.accountsGroup===g.id?'selected':'') + '>' + esc(g.name) + '</option>').join('') +
      '</select>' +
      '<select id="acc-enabled">' +
        '<option value="">' + T('accounts.allStatus') + '</option>' +
        '<option value="true" ' + (S.filter.accountsEnabled==='true'?'selected':'') + '>' + T('adm.stOn') + '</option>' +
        '<option value="false" ' + (S.filter.accountsEnabled==='false'?'selected':'') + '>' + T('adm.stOff') + '</option>' +
      '</select>' +
      '<div class="spacer"></div>' +
      '<button id="acc-create">' + ic('plus', 15) + T('accounts.create') + '</button>' +
    '</div>' +
    '<div class="card table-wrap"><table><thead><tr><th>' + T('term.account') + '</th><th>' + T('term.group') + '</th><th>' + T('accounts.colOnline') + '</th><th>' + T('common.status') + '</th><th>' + T('accounts.colLastSeen') + '</th><th>' + T('common.remark') + '</th><th>' + T('common.action') + '</th></tr></thead><tbody id="acc-body"></tbody></table><div id="acc-pager"></div></div>';
  agSelectEnhance($('view'));
  $('acc-q').oninput = (e) => { S.filter.accounts = e.target.value; S.page.accounts = 1; renderAccounts(); };
  $('acc-group').onchange = (e) => { S.filter.accountsGroup = e.target.value; S.page.accounts = 1; renderAccounts(); };
  $('acc-enabled').onchange = (e) => { S.filter.accountsEnabled = e.target.value; S.page.accounts = 1; renderAccounts(); };
  $('acc-create').onclick = openCreateAccount;
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
      '<tr><td><b>' + esc(a.username) + '</b>' + (a.admin_console ? ' <span class="badge b-info">' + T('accounts.badgeAdmin') + '</span>' : '') + '<div class="mono" style="color:var(--dim2)">' + shortId(a.id) + '</div></td>' +
      '<td>' + esc(a.group_name || groupName(a.group_id)) + '</td>' +
      '<td><span class="dot ' + (a.online?'on':'off') + '"></span>' + (a.online ? T('adm.online') : T('adm.offline')) + '</td>' +
      '<td>' + (a.enabled ? '<span class="badge b-ok">' + T('adm.stOn') + '</span>' : '<span class="badge b-off">' + T('adm.stOff') + '</span>') + '</td>' +
      '<td style="color:var(--dim)">' + esc(a.last_seen_at || T('common.never')) + '</td>' +
      '<td style="color:var(--dim)">' + esc(a.remark || '-') + '</td>' +
      '<td style="white-space:nowrap">' +
        '<button class="ghost small" data-act="acc-reset" data-id="' + esc(a.id) + '" data-name="' + esc(a.username) + '">' + T('accounts.resetPwd') + '</button> ' +
        '<button class="ghost small" data-act="acc-toggle" data-id="' + esc(a.id) + '" data-enabled="' + !a.enabled + '">' + (a.enabled ? T('common.disable') : T('common.enable')) + '</button> ' +
        '<button class="danger small" data-act="acc-del" data-id="' + esc(a.id) + '" data-name="' + esc(a.username) + '">' + T('common.delete') + '</button>' +
      '</td></tr>'
    ).join('') || '<tr><td colspan="7" class="empty">' + T('accounts.empty') + '</td></tr>';
    $('acc-pager').innerHTML = pager('accounts', d.total||0);
  } catch(e) { toast(e.message, 'err'); }
}
function openCreateAccount() {
  if (!S.groups.length) { toast(T('accounts.needGroup'), 'err'); return; }
  openModal(T('accounts.createTitle'),
    '<label>' + T('accounts.nameLabel') + '</label><input id="na-user" style="width:100%">' +
    '<label>' + T('term.group') + '</label><select id="na-group" style="width:100%">' +
      S.groups.map(g => '<option value="' + esc(g.id) + '">' + esc(g.name) + '</option>').join('') + '</select>' +
    '<label>' + T('common.remark') + '</label><input id="na-remark" style="width:100%">' +
    '<label class="chk" style="display:flex;align-items:center;gap:6px;margin-top:8px"><input type="checkbox" id="na-admin"> ' + T('accounts.adminGrant') + '</label>' +
    '<div class="hint" id="na-admin-warn" style="color:var(--danger-text);display:none">' + ic('triangle-alert', 13) + ' ' + T('accounts.adminWarn') + '</div>',
    [
      {label: T('common.cancel'), kind:'ghost', fn: closeModal},
      {label: T('common.create'), fn: async () => {
        const username = $('na-user').value.trim(), group_id = $('na-group').value, remark = $('na-remark').value.trim();
        const admin_console = $('na-admin').checked;
        try {
          const d = await api('POST', '/api/v1/admin/accounts', {username, group_id, remark, admin_console});
          showAccountSecret(T('accounts.createdTitle'), d.username, d.password, d.connect_url, d.id, admin_console, d.endpoints);
          loadAccounts();
        } catch(e) { toast(e.message, 'err'); }
      }},
    ]);
  $('na-admin').onchange = (e) => { $('na-admin-warn').style.display = e.target.checked ? 'block' : 'none'; };
}
function showAccountSecret(title, username, password, connectUrl, accountId, isAdminLink, endpoints) {
  openModal(title,
    (isAdminLink ? '<div class="hint" style="color:var(--danger-text);margin-bottom:8px">' + ic('triangle-alert', 13) + ' ' + T('accounts.adminLinkHint') + '</div>' : '') +
    '<div class="kv"><span class="k">' + T('term.account') + '</span><span><b>' + esc(username) + '</b></span></div>' +
    shareCardHtml(endpoints) +
    '<div class="actions" style="justify-content:flex-start;margin-top:10px">' +
    '<button class="ghost small" data-act="show-qr" data-id="' + esc(accountId) + '">' + ic('qr-code', 13) + T('accounts.showQr') + '</button></div>' +
    '<div class="qr-box" id="qr-box"></div>' +
    '<div class="hint" style="color:var(--warn)">' + ic('triangle-alert', 13) + ' ' + T('accounts.secretHint') + '</div>',
    [{label: T('accounts.saved'), fn: closeModal}]);
  shareCardBind($('modal-root'), { role: 'connect', secret: password, link: connectUrl, endpoints, note: username });
}
async function showQr(accountId) {
  try {
    const res = await fetch('/api/v1/admin/accounts/' + accountId + '/qrcode', { headers: { 'Authorization': 'Bearer ' + S.access } });
    if (!res.ok) { toast(T('accounts.qrExpired'), 'err'); return; }
    const svg = await res.text();
    $('qr-box').innerHTML = svg;
  } catch(e) { toast(e.message, 'err'); }
}
async function resetAccountPwd(id, username) {
  confirmAction(T('accounts.resetConfirm', { name: username }), async () => {
    try {
      const d = await api('POST', '/api/v1/admin/accounts/' + id + '/reset-password');
      showAccountSecret(T('accounts.resetTitle'), username, d.password, d.connect_url, id, false, d.endpoints);
    } catch(e) { toast(e.message, 'err'); }
  });
}
async function toggleAccount(id, enabled) {
  try {
    await api('PUT', '/api/v1/admin/accounts/' + id, { enabled });
    toast(enabled ? T('common.enabled') : T('accounts.disabledToast'), 'ok');
    loadAccounts();
  } catch(e) { toast(e.message, 'err'); }
}
async function delAccount(id, username) {
  confirmAction(T('accounts.delConfirm', { name: username }), async () => {
    try { await api('DELETE', '/api/v1/admin/accounts/' + id); toast(T('adm.deleted'), 'ok'); loadAccounts(); }
    catch(e) { toast(e.message, 'err'); }
  });
}

/* ================= Groups ================= */
async function renderGroups() {
  $('view').innerHTML = '<div class="page-title">' + ic('shield', 20) + T('term.group') + '</div><div class="page-desc">' + T('groups.desc') + '</div>' +
    '<div class="toolbar"><input id="grp-q" placeholder="' + T('groups.searchPh') + '" value="' + esc(S.filter.groups||'') + '">' +
    '<div class="spacer"></div><button class="ghost" id="grp-adopt">' + ic('download', 15) + T('groups.adopt') + '</button><button id="grp-create">' + ic('plus', 15) + T('groups.create') + '</button></div>' +
    '<div class="card table-wrap"><table><thead><tr><th>' + T('common.name') + '</th><th>' + T('groups.colRules') + '</th><th>' + T('groups.colAccounts') + '</th><th>' + T('common.remark') + '</th><th>' + T('common.action') + '</th></tr></thead><tbody id="grp-body"></tbody></table><div id="grp-pager"></div></div>';
  $('grp-q').oninput = (e) => { S.filter.groups = e.target.value; S.page.groups = 1; renderGroups(); };
  $('grp-adopt').onclick = openAdoptCenter;
  $('grp-create').onclick = openCreateGroup;
  await loadGroups();
}
async function loadGroups() {
  const body = $('grp-body'); if (!body) return;
  let url = '/api/v1/admin/groups?page=' + S.page.groups + '&page_size=' + S.size.groups;
  if (S.filter.groups) url += '&q=' + encodeURIComponent(S.filter.groups);
  try {
    const d = await api('GET', url);
    body.innerHTML = (d.items||[]).map(g => {
      const adopted = !!g.adopted_node;
      const nameCell = '<b>' + esc(g.name) + '</b>' + (g.e2e_required ? ' <span class="badge b-warn" title="' + T('groups.e2e') + '">E2E</span>' : '') +
        (adopted ? ' <span class="badge b-info" title="' + esc(T('groups.adoptedTip', { node: g.adopted_node, src: g.adopted_name })) + '">' + T('groups.adoptedBadge') + '</span>' : '') +
        '<div class="mono" style="color:var(--dim2)">' + shortId(g.id) + '</div>';
      // adopted groups are read-only mirrors: 绑定/编辑 swap for 复制 (detach into an editable group)
      const ops = adopted
        ? '<button class="ghost small" data-act="grp-detail" data-id="' + esc(g.id) + '">' + T('groups.detail') + '</button> ' +
          '<button class="ghost small" data-act="grp-copy" data-id="' + esc(g.id) + '" data-name="' + esc(g.name) + '">' + T('groups.copy') + '</button> ' +
          '<button class="danger small" data-act="grp-del" data-id="' + esc(g.id) + '" data-name="' + esc(g.name) + '" data-count="' + g.account_count + '">' + T('common.delete') + '</button>'
        : '<button class="ghost small" data-act="grp-detail" data-id="' + esc(g.id) + '">' + T('groups.detail') + '</button> ' +
          '<button class="ghost small" data-act="grp-bind" data-id="' + esc(g.id) + '" data-name="' + esc(g.name) + '">' + T('groups.bind') + '</button> ' +
          '<button class="ghost small" data-act="grp-edit" data-id="' + esc(g.id) + '" data-name="' + esc(g.name) + '" data-remark="' + esc(g.remark||'') + '" data-e2e="' + (g.e2e_required ? '1' : '') + '">' + T('common.edit') + '</button> ' +
          '<button class="danger small" data-act="grp-del" data-id="' + esc(g.id) + '" data-name="' + esc(g.name) + '" data-count="' + g.account_count + '">' + T('common.delete') + '</button>';
      return '<tr><td>' + nameCell + '</td>' +
        '<td><span class="badge b-info">' + g.rule_count + '</span></td>' +
        '<td><span class="badge b-info">' + g.account_count + '</span></td>' +
        '<td style="color:var(--dim)">' + esc(g.remark || '-') + '</td>' +
        '<td style="white-space:nowrap">' + ops + '</td></tr>';
    }).join('') || '<tr><td colspan="5" class="empty">' + T('groups.empty') + '</td></tr>';
    $('grp-pager').innerHTML = pager('groups', d.total||0);
    S.groups = d.items || S.groups;
  } catch(e) { toast(e.message, 'err'); }
}
function openCreateGroup() {
  openModal(T('groups.createTitle'),
    '<label>' + T('adm.nameUnique') + '</label><input id="ng-name" style="width:100%">' +
    '<label>' + T('common.remark') + '</label><input id="ng-remark" style="width:100%">' +
    '<label class="chk" style="display:flex;align-items:center;gap:6px;margin-top:8px"><input type="checkbox" id="ng-e2e"> ' + T('groups.e2e') + ' ' + ahelp(T('groups.e2eTip')) + '</label>',
    [
      {label: T('common.cancel'), kind:'ghost', fn: closeModal},
      {label: T('common.create'), fn: async () => {
        try {
          await api('POST', '/api/v1/admin/groups', { name: $('ng-name').value.trim(), remark: $('ng-remark').value.trim(), e2e_required: $('ng-e2e').checked });
          closeModal(); toast(T('adm.created'), 'ok'); loadGroupsCache(); loadGroups();
        } catch(e) { toast(e.message, 'err'); }
      }},
    ]);
}
function openEditGroup(id, name, remark, e2e) {
  openModal(T('groups.editTitle'),
    '<label>' + T('common.name') + '</label><input id="eg-name" style="width:100%" value="' + esc(name) + '">' +
    '<label>' + T('common.remark') + '</label><input id="eg-remark" style="width:100%" value="' + esc(remark) + '">' +
    '<label class="chk" style="display:flex;align-items:center;gap:6px;margin-top:8px"><input type="checkbox" id="eg-e2e"' + (e2e ? ' checked' : '') + '> ' + T('groups.e2e') + ' ' + ahelp(T('groups.e2eTip')) + '</label>',
    [
      {label: T('common.cancel'), kind:'ghost', fn: closeModal},
      {label: T('common.save'), fn: async () => {
        try {
          await api('PUT', '/api/v1/admin/groups/' + id, { name: $('eg-name').value.trim(), remark: $('eg-remark').value.trim(), e2e_required: $('eg-e2e').checked });
          closeModal(); toast(T('adm.saved'), 'ok'); loadGroupsCache(); loadGroups();
        } catch(e) { toast(e.message, 'err'); }
      }},
    ]);
}
async function openGroupDetail(id) {
  try {
    const [g, d] = await Promise.all([
      api('GET', '/api/v1/admin/groups/' + id),
      api('GET', '/api/v1/admin/groups/' + id + '/detail'),
    ]);
    openModal(T('groups.detailTitle', { name: g.name }),
      '<h3 style="margin:10px 0 6px">' + T('groups.relRules', { n: (g.rules||[]).length }) + '</h3>' +
      ((g.rules||[]).map(r => '<div class="kv"><span class="mono">' + esc(r.value) + '</span><span class="badge b-info">' + esc(r.type) + '</span></div>').join('') || '<div class="empty">' + T('common.none') + '</div>') +
      '<h3 style="margin:14px 0 6px">' + T('groups.relAccounts', { n: (d.accounts||[]).length }) + '</h3>' +
      ((d.accounts||[]).map(a => '<div class="kv"><span>' + esc(a.username) + '</span><span>' + (a.enabled?'<span class="badge b-ok">' + T('adm.stOn') + '</span>':'<span class="badge b-off">' + T('adm.stOff') + '</span>') + '</span></div>').join('') || '<div class="empty">' + T('common.none') + '</div>') +
      '<h3 style="margin:14px 0 6px">' + T('groups.relTokens', { n: (d.relay_tokens||[]).length }) + '</h3>' +
      ((d.relay_tokens||[]).map(t => '<div class="kv"><span class="mono">' + esc(t.token_prefix) + '</span><span style="color:var(--dim)">' + esc(t.remark || '-') + '</span></div>').join('') || '<div class="empty">' + T('common.none') + '</div>') +
      '<h3 style="margin:14px 0 6px">' + T('groups.relConns', { n: (d.connectors||[]).length }) + '</h3>' +
      ((d.connectors||[]).map(c => '<div class="kv"><span><b>' + esc(c.name) + '</b> <span class="mono" style="color:var(--dim);font-size:12px">' + esc(c.upstream_addr) + '</span></span><span>' + (c.enabled?'<span class="badge b-ok">' + T('adm.stOn') + '</span>':'<span class="badge b-off">' + T('adm.stOff') + '</span>') + '</span></div>').join('') || '<div class="empty">' + T('common.none') + '</div>'));
  } catch(e) { toast(e.message, 'err'); }
}
async function openBindRules(id, name) {
  try {
    const [detail, all] = await Promise.all([
      api('GET', '/api/v1/admin/groups/' + id),
      api('GET', '/api/v1/admin/rules?page_size=100'),
    ]);
    const bound = new Set((detail.rules||[]).map(r => r.id));
    openModal(T('groups.bindTitle', { name }),
      '<div class="rule-check">' +
      (all.items||[]).map(r =>
        '<label><input type="checkbox" class="bind-rule" value="' + esc(r.id) + '" ' + (bound.has(r.id)?'checked':'') + '>' +
        '<span class="mono">' + esc(r.value) + '</span><span class="badge b-info">' + esc(r.type) + '</span>' +
        (r.remark ? '<span style="color:var(--dim)">' + esc(r.remark) + '</span>' : '') + '</label>'
      ).join('') || '<div class="empty">' + T('groups.bindEmpty') + '</div>' + '</div>',
      [
        {label: T('common.cancel'), kind:'ghost', fn: closeModal},
        {label: T('groups.bindSave'), fn: async () => {
          const ids = [...document.querySelectorAll('.bind-rule:checked')].map(c => c.value);
          try {
            await api('PUT', '/api/v1/admin/groups/' + id + '/rules', { rule_ids: ids });
            closeModal(); toast(T('groups.bindUpdated'), 'ok'); loadGroups();
          } catch(e) { toast(e.message, 'err'); }
        }},
      ]);
  } catch(e) { toast(e.message, 'err'); }
}
async function delGroup(id, name, accountCount) {
  const forceNote = accountCount > 0 ? T('groups.forceNote', { n: accountCount }) : '';
  openModal(T('groups.delTitle'),
    '<p style="color:var(--dim)">' + T('groups.delConfirm', { name: '<b>' + esc(name) + '</b>' }) + esc(forceNote) + '</p>',
    [
      {label: T('common.cancel'), kind:'ghost', fn: closeModal},
      ...(accountCount > 0 ? [{label: T('adm.forceDelete'), kind:'danger', fn: async () => {
        closeModal();
        try { await api('DELETE', '/api/v1/admin/groups/' + id + '?force=true'); toast(T('adm.forceDeleted'), 'ok'); loadGroupsCache(); loadGroups(); }
        catch(e) { toast(e.message, 'err'); }
      }}] : []),
      {label: T('common.delete'), kind:'danger', fn: async () => {
        closeModal();
        try { await api('DELETE', '/api/v1/admin/groups/' + id); toast(T('adm.deleted'), 'ok'); loadGroupsCache(); loadGroups(); }
        catch(e) { toast(e.message, 'err'); }
      }},
    ]);
}

/* ================= Routing rules ================= */
async function renderRules() {
  $('view').innerHTML = '<div class="page-title">' + ic('route', 20) + T('rules.title') + '</div><div class="page-desc">' + T('rules.admDesc') + '</div>' +
    '<div class="toolbar">' +
      '<input id="rule-q" placeholder="' + T('rules.admSearchPh') + '" value="' + esc(S.filter.rules) + '">' +
      '<select id="rule-type">' +
        '<option value="">' + T('rules.allTypes') + '</option>' +
        '<option value="ip-cidr" ' + (S.filter.rulesType==='ip-cidr'?'selected':'') + '>ip-cidr</option>' +
        '<option value="host" ' + (S.filter.rulesType==='host'?'selected':'') + '>host</option>' +
      '</select>' +
      '<div class="spacer"></div>' +
      '<button class="ghost" id="rule-adopt">' + ic('download', 15) + T('groups.adopt') + '</button>' +
      '<button class="ghost" id="rule-batch">' + T('rules.batch') + '</button>' +
      '<button id="rule-create">' + ic('plus', 15) + T('rules.create') + '</button>' +
    '</div>' +
    '<div class="card table-wrap"><table><thead><tr><th>' + T('rules.colType') + '</th><th>' + T('rules.colMatch') + '</th><th>' + T('rules.colResolve') + '</th><th>' + T('rules.colRefGroups') + '</th><th>' + T('common.remark') + '</th><th>' + T('common.action') + '</th></tr></thead><tbody id="rule-body"></tbody></table><div id="rule-pager"></div></div>';
  agSelectEnhance($('view'));
  $('rule-q').oninput = (e) => { S.filter.rules = e.target.value; S.page.rules = 1; renderRules(); };
  $('rule-type').onchange = (e) => { S.filter.rulesType = e.target.value; S.page.rules = 1; renderRules(); };
  $('rule-batch').onclick = openBatchImport;
  $('rule-adopt').onclick = openAdoptCenter;
  $('rule-create').onclick = openCreateRule;
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
      '<td>' + (r.resolve ? '<span class="badge b-warn">' + T('common.yes') + '</span>' : '<span style="color:var(--dim2)">' + T('common.no') + '</span>') + '</td>' +
      '<td>' + (r.group_count || 0) + '</td>' +
      '<td style="color:var(--dim)">' + esc(r.remark || '-') + '</td>' +
      '<td style="white-space:nowrap">' +
        '<button class="ghost small" data-act="rule-edit" data-id="' + esc(r.id) + '" data-type="' + esc(r.type) + '" data-value="' + esc(r.value) + '" data-resolve="' + r.resolve + '" data-remark="' + esc(r.remark||'') + '">' + T('common.edit') + '</button> ' +
        '<button class="danger small" data-act="rule-del" data-id="' + esc(r.id) + '" data-value="' + esc(r.value) + '" data-count="' + (r.group_count||0) + '">' + T('common.delete') + '</button>' +
      '</td></tr>'
    ).join('') || '<tr><td colspan="6" class="empty">' + T('rules.empty') + '</td></tr>';
    $('rule-pager').innerHTML = pager('rules', d.total||0);
  } catch(e) { toast(e.message, 'err'); }
}
function ruleFormHtml(t, v, resolve, remark) {
  // “写入系统 hosts” only makes sense for the host type: hide that switch for non-host types (linked when switching type in the create form)
  return '<label>' + T('rules.colType') + '</label><select id="rf-type" style="width:100%" ' + (t?'disabled':'') + '>' +
      '<option value="ip-cidr" ' + (t==='ip-cidr'?'selected':'') + '>' + T('rules.typeCidr') + '</option>' +
      '<option value="host" ' + (t==='host'?'selected':'') + '>' + T('rules.typeHost') + '</option>' +
    '</select>' +
    '<label>' + T('rules.colMatch') + '</label><input id="rf-value" style="width:100%" value="' + esc(v||'') + '" placeholder="' + T('rules.valuePh') + '">' +
    '<label id="rf-resolve-row" style="display:' + (t === 'host' ? 'flex' : 'none') + ';gap:8px;align-items:center;margin-top:10px"><input type="checkbox" id="rf-resolve" ' + (resolve?'checked':'') + '> ' + T('rules.resolveLabel') + '</label>' +
    '<label>' + T('common.remark') + '</label><input id="rf-remark" style="width:100%" value="' + esc(remark||'') + '">';
}
function openCreateRule() {
  openModal(T('rules.createTitle'), ruleFormHtml('', '', false, ''), [
    {label: T('common.cancel'), kind:'ghost', fn: closeModal},
    {label: T('common.create'), fn: async () => {
      try {
        await api('POST', '/api/v1/admin/rules', {
          type: $('rf-type').value, value: $('rf-value').value.trim(),
          resolve: $('rf-resolve').checked, remark: $('rf-remark').value.trim(),
        });
        closeModal(); toast(T('adm.created'), 'ok'); loadRules();
      } catch(e) { toast(e.message, 'err'); }
    }},
  ]);
  $('rf-type').addEventListener('change', () => {
    $('rf-resolve-row').style.display = $('rf-type').value === 'host' ? 'flex' : 'none';
  });
}
function openEditRule(id, type, value, resolve, remark) {
  openModal(T('rules.editTitle'), ruleFormHtml(type, value, resolve, remark), [
    {label: T('common.cancel'), kind:'ghost', fn: closeModal},
    {label: T('common.save'), fn: async () => {
      try {
        await api('PUT', '/api/v1/admin/rules/' + id, {
          value: $('rf-value').value.trim(), resolve: $('rf-resolve').checked, remark: $('rf-remark').value.trim(),
        });
        closeModal(); toast(T('adm.saved'), 'ok'); loadRules();
      } catch(e) { toast(e.message, 'err'); }
    }},
  ]);
}
async function delRule(id, value, groupCount) {
  if (groupCount > 0) {
    openModal(T('rules.refTitle'),
      '<p style="color:var(--dim)">' + T('rules.refBody', { value: '<span class="mono">' + esc(value) + '</span>', n: groupCount }) + '</p>',
      [
        {label: T('common.cancel'), kind:'ghost', fn: closeModal},
        {label: T('adm.forceDelete'), kind:'danger', fn: async () => {
          closeModal();
          try { await api('DELETE', '/api/v1/admin/rules/' + id + '?force=true'); toast(T('adm.forceDeleted'), 'ok'); loadRules(); }
          catch(e) { toast(e.message, 'err'); }
        }},
      ]);
  } else {
    confirmAction(T('rules.delConfirm', { value }), async () => {
      try { await api('DELETE', '/api/v1/admin/rules/' + id); toast(T('adm.deleted'), 'ok'); loadRules(); }
      catch(e) { toast(e.message, 'err'); }
    });
  }
}
function openBatchImport() {
  openModal(T('rules.batchTitle'),
    '<label>' + T('rules.batchLabel') + '</label>' +
    '<textarea id="bi-text" style="width:100%;height:160px" class="mono" placeholder=\'' + T('rules.batchPh') + '\'></textarea>' +
    '<label>' + T('rules.conflictLabel') + '</label><select id="bi-mode" style="width:100%"><option value="skip">' + T('rules.conflictSkip') + '</option><option value="overwrite">' + T('rules.conflictOverwrite') + '</option><option value="error">' + T('rules.conflictError') + '</option></select>',
    [
      {label: T('common.cancel'), kind:'ghost', fn: closeModal},
      {label: T('common.import'), fn: async () => {
        let rules;
        try {
          const text = $('bi-text').value.trim();
          try { rules = JSON.parse(text); }
          catch(e) {
            rules = text.split('\n').map(l => l.trim()).filter(Boolean).map(l => JSON.parse(l));
          }
          if (!Array.isArray(rules)) throw new Error(T('rules.formatErr'));
        } catch(e) { toast(T('rules.jsonErr', { msg: e.message }), 'err'); return; }
        try {
          const d = await api('POST', '/api/v1/admin/rules/batch', { rules, on_conflict: $('bi-mode').value });
          closeModal();
          toast(T('rules.importResult', { created: d.created, skipped: d.skipped, updated: d.updated }) + (d.errors.length ? T('rules.importErrors', { n: d.errors.length }) : ''), d.errors.length ? 'err' : 'ok');
          loadRules();
        } catch(e) { toast(e.message, 'err'); }
      }},
    ]);
}

/* ================= Fan-in (who is connected to this endpoint: listener / peers / tokens) ================= */
/* Latest list data cache: besides polling signature detection, search filtering and tab switching reuse it directly (no refetch) */
let FANIN_PEERS = [];
let FANIN_TOKENS = [];
/* Authorizable pool cache (federation P1): node_id -> { advertise, groups } (fetched with the fan-in status) */
let FED_OFFERS = {};
async function renderFanIn() {
  const tab = S.faninTab;
  $('view').innerHTML = '<div class="page-title">' + ic('orbit', 20) + T('term.fanin') + '</div><div class="page-desc">' + T('fanin.admDesc') + '</div>' +
    '<div class="agtabs" id="fanin-tabs">' +
      '<div class="agtabs-pill">' +
        '<button class="agtab' + (tab === 'listen' ? ' active' : '') + '" data-agtab="listen">' + T('fanin.tabListen') + '</button>' +
        '<button class="agtab' + (tab === 'peers' ? ' active' : '') + '" data-agtab="peers">' + T('fanin.tabPeers') + '</button>' +
        '<button class="agtab' + (tab === 'tokens' ? ' active' : '') + '" data-agtab="tokens">' + T('fanin.tabTokens') + '</button>' +
      '</div>' +
      '<div class="agtabs-tools"><input id="fanin-q" style="width:230px" placeholder="' + T('fanin.admSearchPh') + '" value="' + esc(S.faninQuery) + '"' + (tab === 'listen' ? ' hidden' : '') + '></div>' +
    '</div>' +
    '<div data-agpanel="listen"><div class="card"><h3>' + T('fanin.listenerTitle') + '</h3><div id="fanin-listener"></div></div></div>' +
    '<div data-agpanel="peers" hidden><div class="card"><h3>' + T('fanin.peersTitle') + '</h3><div class="table-wrap"><table><thead><tr><th>' + T('fanin.colPeer') + '</th><th>' + T('dashboard.up') + '</th><th>' + T('dashboard.down') + '</th><th>' + T('fanin.advRoutes') + '</th><th>' + T('fanin.colPool') + '</th></tr></thead><tbody id="fanin-peers"></tbody></table></div></div></div>' +
    '<div data-agpanel="tokens" hidden><div class="card"><h3>' + T('fanin.tokensTitle') + ahelp(T('fanin.tokenHelp')) + '</h3>' +
      '<div class="toolbar"><div class="spacer"></div><button id="tok-create">' + ic('plus', 15) + T('fanin.createToken') + '</button></div>' +
      '<div class="table-wrap"><table><thead><tr><th>' + T('fanin.colPrefix') + '</th><th>' + T('term.group') + '</th><th>' + T('fanin.colRate') + '</th><th>' + T('common.remark') + '</th><th>' + T('fanin.colExpose') + '</th><th>' + T('fanin.colLastUsed') + '</th><th>' + T('common.createdAt') + '</th><th>' + T('common.action') + '</th></tr></thead><tbody id="tok-body"></tbody></table></div></div></div>';
  agTabsBind($('fanin-tabs'), (k) => {
    S.faninTab = k;
    $('fanin-q').hidden = (k === 'listen');
  });
  $('tok-create').onclick = openCreateToken;
  // Related search shared by the peers/tokens tabs: typing filters both tables; the term survives tab switches and applies to each
  $('fanin-q').oninput = (e) => {
    S.faninQuery = e.target.value;
    renderFaninPeers();
    renderFaninTokens();
  };
  await Promise.all([loadFaninStatus(), loadTokens()]);
  S.timers.push(setInterval(loadFaninStatus, 10000));
}
/* Listener card + peers table share roles.listener: single fetch, single-signature change detection (no DOM rewrite when unchanged) */
async function loadFaninStatus() {
  const box = $('fanin-listener'); if (!box) return;
  let L;
  try { L = (await api('GET', '/api/v1/admin/node/status')).roles.listener; }
  catch(e) { toast(e.message, 'err'); return; }
  L = L || { enabled: false };
  // Authorizable pool (federation P1): refreshed with its own signature, ahead of the listener
  // early-return — pushed groups change without the peer list changing (idle reconnect re-pushes)
  let poolChanged = false;
  try {
    const f = await api('GET', '/api/v1/admin/federation/offered');
    const psig = JSON.stringify(f.items || []);
    if (psig !== box.dataset.psig) {
      box.dataset.psig = psig;
      FED_OFFERS = {};
      (f.items || []).forEach(o => { FED_OFFERS[o.node_id] = o; });
      poolChanged = true;
    }
  } catch(e) { /* pool failure never blocks the peer list */ }
  const sig = JSON.stringify(L);
  if (sig === box.dataset.sig && !poolChanged) return;
  box.dataset.sig = sig;
  if (!L.enabled) {
    box.innerHTML = '<div class="empty">' + T('fanin.listenerOff') + '</div>';
  } else {
    box.innerHTML =
      '<div class="kv"><span class="k">' + T('fanin.addr') + '</span><span class="mono">' + esc(L.addr || '-') + '</span></div>' +
      '<div class="kv"><span class="k">TLS</span><span>' + (L.tls ? '<span class="badge b-ok">' + T('common.enabled') + '</span>' : '<span class="badge b-off">' + T('adm.stNotOn') + '</span>') + '</span></div>' +
      '<div class="kv"><span class="k">' + T('fanin.endpoints') + '</span><span>' + T('fanin.connectedCount', { n: L.connected_connectors || 0 }) + '</span></div>' +
      '<div class="kv"><span class="k">' + T('fanin.onlineClients') + '</span><span>' + T('adm.countN', { n: L.online_clients || 0 }) + '</span></div>';
  }
  const traffic = L.enabled ? (L.peer_traffic || []) : [];
  const peers = L.enabled ? (L.peers || []) : [];
  // Pad peers missing from traffic with 0 (traffic counters are cumulative since startup)
  const rows = traffic.slice();
  const seen = new Set(traffic.map(t => t.node_id));
  peers.filter(p => !seen.has(p)).forEach(p => rows.push({ node_id: p, bytes_up: 0, bytes_down: 0 }));
  FANIN_PEERS = rows;
  renderFaninPeers();
}
/* Pushed-group detail of one peer (source-tagged; one-click adoption into a local group) */
function poolDetailHtml(o) {
  const adv = (o.advertise || []);
  const groups = (o.groups || []);
  return '<div style="padding:2px 0 10px">' +
    (adv.length ? '<div class="hint" style="margin:4px 0">' + T('fanin.advRoutes') + '</div><div>' +
      adv.map(a => '<span class="badge b-info mono" style="margin:0 6px 4px 0">' + esc(a) + '</span>').join('') + '</div>' : '') +
    (groups.length ? '<div class="hint" style="margin:8px 0 4px">' + T('fanin.pushedGroups') + ahelp(T('fanin.poolHelp')) + '</div>' +
      groups.map(g =>
        '<div class="kv"><span><b>' + esc(g.name) + '</b> <span style="color:var(--dim)">' + T('fanin.rulesN', { n: (g.rules || []).length }) + '</span>' +
        (g.remark ? ' <span style="color:var(--dim2)">' + esc(g.remark) + '</span>' : '') + '</span>' +
        '<span><button class="ghost small" data-act="fed-adopt" data-node="' + esc(o.node_id) + '" data-group="' + esc(g.name) + '">' + T('fanin.adopt') + '</button></span></div>'
      ).join('') : '') +
    '</div>';
}
function renderFaninPeers() {
  const body = $('fanin-peers'); if (!body) return;
  const q = S.faninQuery.trim().toLowerCase();
  const rows = q ? FANIN_PEERS.filter(t => (t.node_id || '').toLowerCase().includes(q)) : FANIN_PEERS;
  body.innerHTML = rows.map(t => {
    const o = FED_OFFERS[t.node_id];
    const hasPool = !!(o && ((o.advertise || []).length || (o.groups || []).length));
    // Advertised route column: always rendered (badges, capped) so an empty set reads as
    // "无宣告" instead of a missing pool entry — delegation issuance depends on confirming this
    const adv = (o && o.advertise) || [];
    const advCell = adv.length
      ? adv.slice(0, 3).map(a => '<span class="badge b-info mono" style="margin:0 4px 2px 0">' + esc(a) + '</span>').join('') +
        (adv.length > 3 ? '<span class="hint" title="' + esc(adv.join(', ')) + '">+' + (adv.length - 3) + '</span>' : '')
      : '<span style="color:var(--dim2)">' + T('fanin.noAdv') + '</span>';
    let html = '<tr><td class="mono"><span class="dot on"></span>' + esc(t.node_id) + '</td>' +
      '<td class="mono">' + fmtBytes(t.bytes_up) + '</td>' +
      '<td class="mono">' + fmtBytes(t.bytes_down) + '</td>' +
      '<td>' + advCell + '</td>' +
      '<td>' + (hasPool ? '<button class="ghost small" data-act="pool-toggle" data-node="' + esc(t.node_id) + '">' + T('fanin.poolDetail') + '</button>' : '') + '</td></tr>';
    if (hasPool) html += '<tr data-poolrow="' + esc(t.node_id) + '" hidden><td colspan="5" style="background:var(--bg2)">' + poolDetailHtml(o) + '</td></tr>';
    return html;
  }).join('') || '<tr><td colspan="5" class="empty">' + (q ? T('fanin.noMatchPeers') : T('fanin.emptyPeers')) + '</td></tr>';
}
/* One-click adoption: materialize a pushed group into a local group (federation P1 acceptance) */
async function adoptPushed(nodeId, groupName) {
  try {
    const d = await api('POST', '/api/v1/admin/federation/adopt', { node_id: nodeId, group: groupName });
    toast(T('fanin.adopted', { name: d.name, n: d.rule_count, r: d.reused }), 'ok');
    loadGroupsCache();
  } catch(e) { toast(e.message, 'err'); }
}
/* Adoption center (federation P1 acceptance): every fan-in peer's pushed groups, split into
   待采纳 (adoptable) / 跟随中 (already mirrored, read-only, auto-updating — copy to edit). */
async function openAdoptCenter() {
  let items = [];
  try { items = (await api('GET', '/api/v1/admin/federation/offered')).items || []; }
  catch(e) { toast(e.message, 'err'); return; }
  const peers = items.filter(o => (o.groups || []).length);
  const body = peers.length ? peers.map(o =>
    '<div style="margin:10px 0 4px"><b>' + esc(o.node_id) + '</b></div>' +
    o.groups.map(g => {
      const status = g.adopted
        ? '<span class="badge b-ok">' + T('groups.adoptedBadge') + '</span> <span class="hint">' + esc(g.adopted_name || '') + '</span>'
        : '<span class="badge b-off">' + T('groups.adoptPending') + '</span>';
      const action = g.adopted
        ? '<button class="ghost small" data-act="grp-copy" data-id="' + esc(g.adopted_id) + '" data-name="' + esc(g.adopted_name || g.name) + '">' + T('groups.copy') + '</button>'
        : '<button class="ghost small" data-act="fed-adopt-now" data-node="' + esc(o.node_id) + '" data-group="' + esc(g.name) + '">' + T('fanin.adopt') + '</button>';
      return '<div class="kv"><span><b>' + esc(g.name) + '</b> ' +
        '<span style="color:var(--dim)">' + T('fanin.rulesN', { n: (g.rules || []).length }) + '</span> ' +
        (g.e2e_required ? '<span class="badge b-warn">E2E</span> ' : '') + status + '</span>' +
        '<span>' + action + '</span></div>';
    }).join('')
  ).join('') : '<div class="empty">' + T('groups.adoptEmpty') + '</div>';
  openModal(T('groups.adoptTitle'),
    '<div class="hint" style="margin-bottom:8px">' + T('groups.adoptHint') + '</div>' + body,
    [{label: T('common.close'), kind: 'ghost', fn: closeModal}]);
}
/* Detach an adopted mirror into an editable local group (the mirror keeps following its source). */
async function copyAdopted(id, name) {
  confirmAction(T('groups.copyConfirm', { name }), async () => {
    try {
      const d = await api('POST', '/api/v1/admin/federation/adopted/' + encodeURIComponent(id) + '/copy');
      toast(T('groups.copiedToast', { name: d.name }), 'ok');
      loadGroupsCache(); loadGroups();
    } catch(e) { toast(e.message, 'err'); }
  });
}
async function loadTokens() {
  const body = $('tok-body'); if (!body) return;
  try {
    const d = await api('GET', '/api/v1/admin/node/relay-tokens');
    FANIN_TOKENS = d.items || [];
    renderFaninTokens();
  } catch(e) { toast(e.message, 'err'); }
}
/* Token filter dimensions: prefix / remark / group name (shares the same search term as the peers table) */
function renderFaninTokens() {
  const body = $('tok-body'); if (!body) return;
  const q = S.faninQuery.trim().toLowerCase();
  const items = q ? FANIN_TOKENS.filter(t =>
    (t.token_prefix || '').toLowerCase().includes(q) ||
    (t.remark || '').toLowerCase().includes(q) ||
    (t.group_id && (t.group_name || groupNamesOf(t.group_id)).toLowerCase().includes(q))
  ) : FANIN_TOKENS;
  body.innerHTML = items.map(t =>
    '<tr><td class="mono">' + esc(t.token_prefix) + '</td>' +
    '<td>' + (t.group_id ? esc(t.group_name || groupNamesOf(t.group_id)) : '<span style="color:var(--dim2)">' + T('adm.noRestrict') + '</span>') + '</td>' +
    '<td class="mono">' + (t.rate_limit_kbps ? esc(t.rate_limit_kbps) + ' KB/s' : '<span style="color:var(--dim2)">' + T('adm.unlimited') + '</span>') + '</td>' +
    '<td>' + esc(t.remark || '-') + '</td>' +
    '<td><label class="chk" style="display:flex;align-items:center;gap:5px"><input type="checkbox" data-act-chg="tok-expose" data-id="' + esc(t.id) + '"' + (t.expose_control ? ' checked' : '') +
      '><span style="font-size:12px">' + T('fanin.allowManage') + '</span></label>' +
      (t.expose_control ? '<select class="ghost small" data-act-chg="tok-scope" data-id="' + esc(t.id) + '">' +
        ['ro','rules','full'].map(sc => '<option value="' + sc + '" ' + (t.control_scope === sc ? 'selected' : '') + '>' + ({ro: T('fanin.scopeRo'), rules: T('fanin.scopeRules'), full: T('fanin.scopeFull')})[sc] + '</option>').join('') + '</select>' : '') + '</td>' +
    '<td style="color:var(--dim)">' + esc(t.last_used_at || T('fanin.unused')) + '</td>' +
    '<td style="color:var(--dim)">' + esc(t.created_at) + '</td>' +
    '<td style="white-space:nowrap"><button class="ghost small" data-act="tok-edit" data-id="' + esc(t.id) + '" data-group="' + esc(t.group_id||'') + '" data-expose="' + t.expose_control + '" data-scope="' + esc(t.control_scope) + '">' + T('common.edit') + '</button> ' +
    '<button class="danger small" data-act="tok-del" data-id="' + esc(t.id) + '">' + T('adm.revoke') + '</button></td></tr>'
  ).join('') || '<tr><td colspan="8" class="empty">' + (q ? T('fanin.noMatchTokens') : T('fanin.emptyTokens')) + '</td></tr>';
  agSelectEnhance(body);
}
async function toggleExpose(id, on) {
  try {
    const cur = (await api('GET', '/api/v1/admin/node/relay-tokens')).items.find(t => t.id === id);
    await api('PUT', '/api/v1/admin/node/relay-tokens/' + id, { expose_control: on, control_scope: (cur && cur.control_scope) || 'full' });
    toast(on ? T('fanin.exposeOn') : T('fanin.exposeOff'), 'ok');
    loadTokens();
  } catch(e) { toast(e.message, 'err'); loadTokens(); }
}
async function setScope(id, scope) {
  try {
    await api('PUT', '/api/v1/admin/node/relay-tokens/' + id, { expose_control: true, control_scope: scope });
    toast(T('fanin.scopeUpdated'), 'ok');
  } catch(e) { toast(e.message, 'err'); }
}
function openCreateToken() {
  openModal(T('fanin.createTitle'),
    '<label>' + T('fanin.remarkLabel') + '</label><input id="nt-remark" style="width:100%">' +
    '<label>' + T('adm.groupLabel') + '</label>' +
    '<div class="rule-check" style="max-height:130px">' +
      (S.groups.length ? S.groups.map(g =>
        '<label><input type="checkbox" class="nt-acl" value="' + esc(g.id) + '"' + (g.e2e_required ? ' disabled' : '') + '>' +
        '<span>' + esc(g.name) + '</span>' + (g.e2e_required ? '<span class="badge b-warn">E2E</span>' : '<span class="badge b-info">' + (g.rule_count || 0) + '</span>') + '</label>'
      ).join('') : '<div class="empty">' + T('groups.empty') + '</div>') + '</div>' +
    '<label>' + T('fanin.rateLabel') + '</label><input id="nt-rate" type="number" min="1" placeholder="' + T('fanin.ratePh') + '" style="width:100%">' +
    '<div class="hint">' + T('fanin.rateHint') + '</div>' +
    '<label class="chk" style="display:flex;align-items:center;gap:6px;margin-top:8px"><input type="checkbox" id="nt-expose"> ' + T('fanin.exposeLabel') + '</label>' +
    '<div id="nt-expose-opts" style="display:none;margin:6px 0">' +
      '<label>' + T('fanin.scopeLabel') + '</label><select id="nt-scope" style="width:100%">' +
        '<option value="ro">' + T('fanin.scopeRoFull') + '</option>' +
        '<option value="rules">' + T('fanin.scopeRulesFull') + '</option>' +
        '<option value="full" selected>' + T('fanin.scopeFullFull') + '</option>' +
      '</select>' +
      '<div class="hint" style="color:var(--danger-text)">' + ic('triangle-alert', 13) + ' ' + T('fanin.exposeHint') + '</div>' +
    '</div>',
    [
      {label: T('common.cancel'), kind:'ghost', fn: closeModal},
      {label: T('fanin.generate'), fn: async () => {
        try {
          const rateVal = parseInt($('nt-rate').value, 10);
          const d = await api('POST', '/api/v1/admin/node/relay-tokens', {
            remark: $('nt-remark').value.trim(),
            expose_control: $('nt-expose').checked,
            control_scope: $('nt-scope').value,
            group_id: [...document.querySelectorAll('.nt-acl:checked')].map(c => c.value).join(',') || null,
            rate_limit_kbps: rateVal > 0 ? rateVal : null,
          });
          openModal(T('fanin.createdTitle'),
            '<div class="kv"><span class="k">' + T('common.remark') + '</span><span>' + esc(d.remark || '-') + '</span></div>' +
            shareCardHtml(d.endpoints) +
            '<div class="hint" style="color:var(--warn)">' + ic('triangle-alert', 13) + ' ' + T('fanin.createdHint') + '</div>',
            [{label: T('accounts.saved'), fn: () => { closeModal(); loadTokens(); }}]);
          shareCardBind($('modal-root'), { role: 'fanout', secret: d.token, link: d.share_url, endpoints: d.endpoints, note: d.remark || d.token_prefix });
        } catch(e) { toast(e.message, 'err'); }
      }},
    ]);
  $('nt-expose').onchange = (e) => { $('nt-expose-opts').style.display = e.target.checked ? 'block' : 'none'; };
}
async function delToken(id) {
  confirmAction(T('fanin.revokeConfirm'), async () => {
    try { await api('DELETE', '/api/v1/admin/node/relay-tokens/' + id); toast(T('adm.revoked'), 'ok'); loadTokens(); }
    catch(e) { toast(e.message, 'err'); }
  });
}
/* Edit bound group: PUT tri-state semantics (absent = unchanged / null = unbound / string = bind to group);
   editing is an explicit user choice so it is always sent; control-plane exposure is changed directly in the list (group_id not sent = unchanged) */
function openEditToken(id, groupId, exposeControl, controlScope, rateKbps) {
  openModal(T('fanin.editTitle'),
    '<label>' + T('adm.groupLabel') + '</label>' +
    '<div class="rule-check" style="max-height:130px">' +
      (S.groups.length ? S.groups.map(g =>
        '<label><input type="checkbox" class="et-acl" value="' + esc(g.id) + '" ' + ((groupId||'').split(',').includes(g.id)?'checked':'') + (g.e2e_required ? ' disabled' : '') + '>' +
        '<span>' + esc(g.name) + '</span>' + (g.e2e_required ? '<span class="badge b-warn">E2E</span>' : '<span class="badge b-info">' + (g.rule_count || 0) + '</span>') + '</label>'
      ).join('') : '<div class="empty">' + T('groups.empty') + '</div>') + '</div>' +
    '<label>' + T('fanin.editRateLabel') + '</label><input id="et-rate" type="number" min="1" value="' + (rateKbps > 0 ? rateKbps : '') + '" placeholder="' + T('adm.unlimited') + '" style="width:100%">' +
    '<div class="hint">' + T('fanin.editHint') + '</div>',
    [
      {label: T('common.cancel'), kind:'ghost', fn: closeModal},
      {label: T('common.save'), fn: async () => {
        try {
          const rateVal = parseInt($('et-rate').value, 10);
          await api('PUT', '/api/v1/admin/node/relay-tokens/' + id, {
            expose_control: exposeControl, control_scope: controlScope,
            group_id: [...document.querySelectorAll('.et-acl:checked')].map(c => c.value).join(',') || null,
            rate_limit_kbps: rateVal > 0 ? rateVal : null,
          });
          closeModal(); toast(T('adm.saved'), 'ok'); loadTokens();
        } catch(e) { toast(e.message, 'err'); }
      }},
    ]);
}

/* ================= Fan-out (upstream connectors) + Delegation (federation P2) ================= */
function connStatusBadge(st) {
  return '<span class="badge ' + (st === 'connected' ? 'b-ok' : (st === 'disconnected' ? 'b-off' : 'b-warn')) + '">' +
    esc(connStatusText(st)) + '</span>';
}
async function renderConnectors() {
  $('view').innerHTML = '<div class="page-title">' + ic('git-fork', 20) + T('term.fanout') + '</div><div class="page-desc">' + T('fanout.admDesc') + '</div>' +
    '<div class="agtabs" style="margin:14px 0 12px"><div class="agtabs-pill">' +
      '<button class="agtab active" data-ftab="conns">' + T('deleg.tabConns') + '</button>' +
      '<button class="agtab" data-ftab="deleg">' + T('deleg.tab') + '</button>' +
    '</div></div>' +
    '<div id="ftab-conns">' +
      '<div class="toolbar"><div class="spacer"></div><button class="ghost" id="conn-import">' + ic('upload', 15) + T('anet.importBtn') + '</button><button id="conn-create">' + ic('plus', 15) + T('fanout.create') + '</button></div>' +
      '<input type="file" id="conn-import-file" accept=".anet,application/json" style="display:none">' +
      '<div class="card table-wrap"><table><thead><tr><th>' + T('common.name') + '</th><th>' + T('fanout.colUpstream') + '</th><th>' + T('term.group') + '</th><th>' + T('common.status') + '</th><th>' + T('adm.stOn') + '</th><th>' + T('common.remark') + '</th><th>' + T('common.action') + '</th></tr></thead><tbody id="conn-body"></tbody></table></div>' +
    '</div>' +
    '<div id="ftab-deleg" style="display:none">' +
      '<div class="toolbar"><div class="hint" style="max-width:560px">' + T('deleg.desc') + '</div><div class="spacer"></div><button id="deleg-issue">' + ic('plus', 15) + T('deleg.issue') + '</button></div>' +
      '<div class="card table-wrap"><table><thead><tr><th>' + T('deleg.colLabel') + '</th><th>' + T('deleg.colGroups') + '</th><th>' + T('deleg.colSet') + '</th><th>' + T('common.createdAt') + '</th><th>' + T('common.action') + '</th></tr></thead><tbody id="deleg-body"></tbody></table></div>' +
    '</div>';
  // ag-tabs switching (explicit binding, no inline handlers)
  $('view').querySelectorAll('[data-ftab]').forEach(b => {
    b.onclick = () => {
      $('view').querySelectorAll('[data-ftab]').forEach(x => x.classList.toggle('active', x === b));
      $('ftab-conns').style.display = b.dataset.ftab === 'conns' ? '' : 'none';
      $('ftab-deleg').style.display = b.dataset.ftab === 'deleg' ? '' : 'none';
    };
  });
  $('conn-create').onclick = () => openCreateConnector();
  // .anet import: native open dialog via the desktop bridge when embedded, file picker otherwise
  $('conn-import').onclick = () => {
    if (isEmbeddedConsole()) window.parent.postMessage({ type: 'ag-anet-open' }, '*');
    else $('conn-import-file').click();
  };
  $('conn-import-file').onchange = async (e) => {
    const f = e.target.files[0];
    e.target.value = '';
    if (!f) return;
    openAnetImport(await f.text(), f.name);
  };
  $('deleg-issue').onclick = () => openIssueDelegation();
  await Promise.all([loadConnectors(), loadDelegation()]);
  S.timers.push(setInterval(() => { loadConnectors(); loadDelegation(); }, 5000));
}
async function loadConnectors() {
  const body = $('conn-body'); if (!body) return;
  try {
    const d = await api('GET', '/api/v1/admin/connectors');
    const items = d.items || [];
    // Polling change detection: identical signature → no DOM rewrite (avoids flicker)
    const sig = JSON.stringify(items);
    if (sig === body.dataset.sig) return;
    body.dataset.sig = sig;
    body.innerHTML = items.map(c => {
      const adv = (c.advertise || '').split(',').filter(Boolean).join(' · ');
      return '<tr><td><b>' + esc(c.name) + '</b><div class="mono" style="color:var(--dim2)">' + (c.token_prefix ? esc(c.token_prefix) : shortId(c.id)) + '</div></td>' +
      '<td class="mono">' + esc(c.upstream_addr) + (adv ? '<div style="color:var(--dim2);font-size:12px">' + esc(adv) + '</div>' : '') + '</td>' +
      '<td>' + (c.group_id ? esc(c.group_name || groupNamesOf(c.group_id)) : '<span style="color:var(--dim2)">' + T('adm.noRestrict') + '</span>') + '</td>' +
      '<td>' + connStatusBadge(c.state) + '</td>' +
      '<td>' + (c.enabled ? '<span class="badge b-ok">' + T('adm.stOn') + '</span>' : '<span class="badge b-off">' + T('adm.stOff') + '</span>') + '</td>' +
      '<td style="color:var(--dim)">' + esc(c.remark || '-') + '</td>' +
      '<td style="white-space:nowrap">' +
        '<button class="ghost small" data-act="conn-edit" data-id="' + esc(c.id) + '">' + T('common.edit') + '</button> ' +
        '<button class="ghost small" data-act="conn-toggle" data-id="' + esc(c.id) + '" data-enabled="' + !c.enabled + '">' + (c.enabled ? T('common.disable') : T('common.enable')) + '</button> ' +
        '<button class="danger small" data-act="conn-del" data-id="' + esc(c.id) + '" data-name="' + esc(c.name) + '">' + T('common.delete') + '</button>' +
      '</td></tr>';
    }).join('') || '<tr><td colspan="7" class="empty">' + T('fanout.empty') + '</td></tr>';
  } catch(e) { toast(e.message, 'err'); }
}
/* ---- Delegation (federation P2): issue / list / revoke delegated tokens ---- */
function delegStateBadge(st) {
  if (st && st.startsWith('failed')) {
    return '<span class="badge b-off" title="' + esc(st) + '">' + T('deleg.stFailed') + '</span>';
  }
  const map = {
    registered: ['b-ok', T('deleg.stRegistered')],
    pending: ['b-warn', T('deleg.stPending')],
    unsupported: ['b-off', T('deleg.stUnsupported')],
  };
  const m = map[st] || ['b-off', T('deleg.stOffline')];
  return '<span class="badge ' + m[0] + '">' + m[1] + '</span>';
}
async function loadDelegation() {
  const body = $('deleg-body'); if (!body) return;
  try {
    const d = await api('GET', '/api/v1/admin/delegation/tokens');
    const items = d.items || [];
    // polling change detection: identical signature → no DOM rewrite (avoids flicker)
    const sig = JSON.stringify(items);
    if (sig === body.dataset.sig) return;
    body.dataset.sig = sig;
    body.innerHTML = items.map(t => {
      const groups = (t.groups || []).map(g =>
        '<span class="badge b-info">' + esc(g.name) + '</span>' + (g.e2e_required ? ' <span class="badge b-warn">E2E</span>' : '')
      ).join(' ');
      // tier badge: only meaningful on E2E tokens (split = rule delivery, dedicated = 专线)
      const anyE2e = (t.groups || []).some(g => g.e2e_required);
      const tierBadge = anyE2e
        ? ' <span class="badge ' + (t.mode === 'split' ? 'b-info' : 'b-off') + '">' + (t.mode === 'split' ? T('deleg.modeSplit') : T('deleg.modeDedicated')) + '</span>'
        : '';
      // admin-grant badge (ro/rules/full)
      const adminBadge = t.admin_scope
        ? ' <span class="badge b-warn">' + T('deleg.badgeAdmin') + '·' + esc(t.admin_scope) + '</span>'
        : '';
      const regs = (t.regs || []).map(r =>
        '<div style="display:flex;align-items:center;gap:6px;padding:2px 0">' +
          (r.is_primary ? '<span class="badge b-ok">' + T('deleg.primaryBadge') + '</span>' : '') +
          '<span>' + esc(r.connector_name) + '</span>' + delegStateBadge(r.state) + '</div>'
      ).join('');
      return '<tr><td><b>' + esc(t.label || t.token_prefix) + '</b>' + tierBadge + adminBadge + '<div class="mono" style="color:var(--dim2)">' + esc(t.token_prefix) + '</div></td>' +
        '<td>' + (groups || '-') + '</td>' +
        '<td>' + (regs || '-') + '</td>' +
        '<td style="color:var(--dim);white-space:nowrap">' + esc((t.created_at || '').replace('T', ' ').replace(/\..*$/, '')) + '</td>' +
        '<td><button class="danger small" data-act="deleg-revoke" data-id="' + esc(t.id) + '" data-name="' + esc(t.label || t.token_prefix) + '">' + T('adm.revoke') + '</button></td></tr>';
    }).join('') || '<tr><td colspan="5" class="empty">' + T('deleg.empty') + '</td></tr>';
  } catch(e) { toast(e.message, 'err'); }
}
async function revokeDelegation(id, name) {
  confirmAction(T('deleg.revokeConfirm', { name }), async () => {
    try {
      await api('DELETE', '/api/v1/admin/delegation/tokens/' + encodeURIComponent(id));
      toast(T('deleg.revokedToast'), 'ok');
      loadDelegation();
    } catch(e) { toast(e.message, 'err'); }
  });
}
/* Issue dialog: failover-set multi-select (online v3+ upstreams pre-checked; v2 upstreams
   disabled with a reason) -> primary-entry radio (linked to the checked set) -> local group
   multi-select (E2E groups badged) -> label. The share card shows once with the full link. */
async function openIssueDelegation() {
  let conns = [];
  try { conns = (await api('GET', '/api/v1/admin/connectors')).items || []; } catch(e) { toast(e.message, 'err'); return; }
  const usable = conns.filter(c => c.enabled);
  if (!usable.length) { toast(T('deleg.noUpstreams'), 'err'); return; }
  if (!(S.groups || []).length) { toast(T('groups.empty'), 'err'); return; }

  const targetRows = usable.map(c => {
    const ver = c.upstream_version || 0;
    const old = c.state === 'connected' && ver < 3;
    const pre = c.state === 'connected' && ver >= 3;
    const verNote = old ? ' <span class="hint">' + T('deleg.unsupported', { v: ver }) + '</span>' : '';
    return '<label class="chk" style="display:flex;align-items:center;gap:8px;padding:5px 4px">' +
      '<input type="checkbox" class="di-target" value="' + esc(c.id) + '"' + (pre ? ' checked' : '') + (old ? ' disabled' : '') + '>' +
      '<span><b>' + esc(c.name) + '</b> <span class="mono" style="color:var(--dim2)">' + esc(c.upstream_addr) + '</span></span>' +
      connStatusBadge(c.state) + verNote + '</label>';
  }).join('');
  const groupRows = (S.groups || []).map(g =>
    '<label><input type="checkbox" class="di-group" value="' + esc(g.id) + '">' +
    '<span>' + esc(g.name) + '</span>' + (g.e2e_required ? '<span class="badge b-warn">E2E</span>' : '<span class="badge b-info">' + (g.rule_count || 0) + '</span>') + '</label>'
  ).join('');

  openModal(T('deleg.issue'),
    '<label>' + T('deleg.targets') + ' ' + ahelp(T('deleg.targetsHelp')) + '</label>' +
    '<div class="rule-check" style="max-height:150px">' + targetRows + '</div>' +
    '<label style="margin-top:10px">' + T('deleg.primary') + ' ' + ahelp(T('deleg.primaryHelp')) + '</label>' +
    '<div id="di-primary" style="padding:2px 4px"></div>' +
    '<label style="margin-top:10px">' + T('term.group') + ' ' + ahelp(T('deleg.groupsHelp')) + '</label>' +
    '<div class="rule-check" style="max-height:130px">' + groupRows + '</div>' +
    '<div id="di-mode-wrap" style="display:none">' +
      '<label style="margin-top:10px">' + T('deleg.mode') + ' ' + ahelp(T('deleg.modeHelp')) + '</label>' +
      '<div style="padding:2px 4px">' +
        '<label class="chk" style="display:inline-flex;align-items:center;gap:5px;margin-right:14px"><input type="radio" name="di-mode" value="dedicated" checked> ' + T('deleg.modeDedicated') + '</label>' +
        '<label class="chk" style="display:inline-flex;align-items:center;gap:5px"><input type="radio" name="di-mode" value="split"> ' + T('deleg.modeSplit') + '</label>' +
      '</div></div>' +
    '<div id="di-admin-wrap" style="display:none">' +
      '<label class="chk" style="display:flex;align-items:center;gap:6px;margin-top:10px"><input type="checkbox" id="di-admin"> ' + T('deleg.admin') + ' ' + ahelp(T('deleg.adminHelp')) + '</label>' +
      '<div id="di-admin-scope" style="display:none;padding:2px 4px">' +
        '<label class="chk" style="display:inline-flex;align-items:center;gap:5px;margin-right:14px"><input type="radio" name="di-scope" value="ro"> ' + T('deleg.scopeRo') + '</label>' +
        '<label class="chk" style="display:inline-flex;align-items:center;gap:5px;margin-right:14px"><input type="radio" name="di-scope" value="rules"> ' + T('deleg.scopeRules') + '</label>' +
        '<label class="chk" style="display:inline-flex;align-items:center;gap:5px"><input type="radio" name="di-scope" value="full" checked> ' + T('deleg.scopeFull') + '</label>' +
      '</div></div>' +
    '<label style="margin-top:10px">' + T('common.remark') + '</label><input id="di-label" style="width:100%" placeholder="' + T('deleg.labelPh') + '">',
    [
      {label: T('common.cancel'), kind: 'ghost', fn: closeModal},
      {label: T('deleg.issue'), fn: async () => {
        const targets = [...document.querySelectorAll('.di-target:checked')].map(c => c.value);
        const groupIds = [...document.querySelectorAll('.di-group:checked')].map(c => c.value);
        if (!targets.length) { toast(T('deleg.needTargets'), 'err'); return; }
        if (!groupIds.length) { toast(T('deleg.needGroups'), 'err'); return; }
        const primary = $('di-primary').dataset.value || targets[0];
        const mode = (document.querySelector('input[name="di-mode"]:checked') || {}).value || 'dedicated';
        const adminScope = ($('di-admin').checked && (document.querySelector('input[name="di-scope"]:checked') || {}).value) || '';
        try {
          const d = await api('POST', '/api/v1/admin/delegation/tokens', {
            label: $('di-label').value.trim(),
            group_ids: groupIds,
            regs: targets.map(id => ({ connector_id: id, is_primary: id === primary })),
            mode,
            admin_scope: adminScope,
          });
          closeModal();
          openModal(T('deleg.issuedTitle'), shareCardHtml([]), []);
          shareCardBind($('modal-root'), { role: 'connect', secret: d.token, link: d.share_url, endpoints: [], note: d.label });
          loadDelegation();
        } catch(e) { toast(e.message, 'err'); }
      }},
    ]);

  // primary radio follows the checked set (first checked entry wins by default)
  const primaryBox = $('di-primary');
  function syncPrimary() {
    const checked = [...document.querySelectorAll('.di-target:checked')].map(c => c.value);
    const keep = checked.includes(primaryBox.dataset.value) ? primaryBox.dataset.value : checked[0];
    primaryBox.dataset.value = keep || '';
    primaryBox.innerHTML = checked.map(id => {
      const c = usable.find(x => x.id === id);
      return '<label class="chk" style="display:inline-flex;align-items:center;gap:5px;margin-right:14px">' +
        '<input type="radio" name="di-primary" value="' + esc(id) + '"' + (id === keep ? ' checked' : '') + '> ' +
        esc(c ? c.name : id) + '</label>';
    }).join('') || '<div class="hint">' + T('deleg.needTargets') + '</div>';
  }
  document.querySelectorAll('.di-target').forEach(c => c.addEventListener('change', syncPrimary));
  primaryBox.addEventListener('change', (e) => {
    if (e.target && e.target.value) primaryBox.dataset.value = e.target.value;
  });
  syncPrimary();

  // the access-mode and admin-grant choices only exist when an E2E group is checked (both ride the E2E channel)
  const e2eIds = new Set((S.groups || []).filter(g => g.e2e_required).map(g => g.id));
  function syncMode() {
    const anyE2e = [...document.querySelectorAll('.di-group:checked')].some(c => e2eIds.has(c.value));
    $('di-mode-wrap').style.display = anyE2e ? '' : 'none';
    $('di-admin-wrap').style.display = anyE2e ? '' : 'none';
  }
  document.querySelectorAll('.di-group').forEach(c => c.addEventListener('change', syncMode));
  $('di-admin').addEventListener('change', (e) => {
    $('di-admin-scope').style.display = e.target.checked ? '' : 'none';
  });
  syncMode();
}
function connectorFormHtml(c) {
  c = c || {};
  return '<div class="paste-bar"><input id="cf-paste" class="mono" style="width:100%" placeholder="' + T('fanout.pastePh') + '">' +
    '<div class="hint" id="cf-paste-err" style="display:none;color:var(--danger-text)"></div></div>' +
    '<label>' + T('adm.nameUnique') + '</label><input id="cf-name" style="width:100%" value="' + esc(c.name||'') + '">' +
    '<label>' + T('fanout.upstreamLabel') + '</label><input id="cf-addr" class="mono" style="width:100%" value="' + esc(c.upstream_addr||'') + '" placeholder="peer.example.com:54430">' +
    '<label>' + T('fanout.tokenLabel') + '</label><input id="cf-token" type="password" class="mono" style="width:100%" autocomplete="off" placeholder="' + (c.id ? T('fanout.tokenKeep') : T('fanout.tokenPh')) + '">' +
    '<label>' + T('fanout.sniHostLabel') + '</label><input id="cf-sni" class="mono" style="width:100%" value="' + esc(c.sni_hostname||'') + '">' +
    '<label>' + T('fanout.fpLabel') + ' <span class="hint">' + T('fanout.fpHint') + '</span></label><input id="cf-fp" class="mono" style="width:100%" value="' + esc(c.pinned_fingerprint||'') + '" placeholder="sha256...">' +
    '<label class="chk" style="display:flex;align-items:center;gap:6px;margin-top:8px"><input type="checkbox" id="cf-insecure" ' + (c.insecure?'checked':'') + '> ' + T('fanout.insecure') + '</label>' +
    '<label>' + T('fanout.advertiseLabel') + ' <span class="hint">' + T('fanout.advertiseHint') + '</span></label><textarea id="cf-advertise" class="mono" style="width:100%;height:90px" placeholder="10.12.0.0/16&#10;git.internal">' + esc((c.advertise||'').split(',').filter(Boolean).join('\n')) + '</textarea>' +
    '<label>' + T('adm.groupLabel') + '</label>' +
    '<div class="rule-check" style="max-height:130px">' +
      (S.groups.length ? S.groups.map(g =>
        '<label><input type="checkbox" class="cf-acl" value="' + esc(g.id) + '" ' + ((c.group_id||'').split(',').includes(g.id)?'checked':'') + (g.e2e_required ? ' disabled' : '') + '>' +
        '<span>' + esc(g.name) + '</span>' + (g.e2e_required ? '<span class="badge b-warn">E2E</span>' : '<span class="badge b-info">' + (g.rule_count || 0) + '</span>') + '</label>'
      ).join('') : '<div class="empty">' + T('groups.empty') + '</div>') + '</div>' +
    '<label>' + T('fanout.pushLabel') + ' <span class="hint">' + T('fanout.pushHint') + '</span></label>' +
    '<div class="rule-check" style="max-height:130px">' +
      (S.groups.length ? S.groups.map(g =>
        '<label><input type="checkbox" class="cf-push" value="' + esc(g.id) + '" ' + ((c.push_groups||'').split(',').includes(g.id)?'checked':'') + '>' +
        '<span>' + esc(g.name) + '</span><span class="badge b-info">' + (g.rule_count||0) + '</span></label>'
      ).join('') : '<div class="empty">' + T('groups.empty') + '</div>') + '</div>' +
    '<label>' + T('common.remark') + '</label><input id="cf-remark" style="width:100%" value="' + esc(c.remark||'') + '">';
}
/* Paste-to-import (federation P1): the shared AgLink parser fills all technical fields from an
   anet://fanout link; on failure the form stays manual with an inline error line. */
function fillConnectorFields(p) {
  $('cf-addr').value = p.addr || '';
  if (p.token) $('cf-token').value = p.token;
  $('cf-sni').value = p.sni || '';
  $('cf-fp').value = p.fp || '';
  $('cf-insecure').checked = !!p.insecure;
}
function bindConnectorPaste() {
  const box = $('cf-paste');
  if (!box) return;
  const fill = () => {
    const raw = box.value.trim();
    if (!raw) return;
    const p = AgLink.parse(raw);
    const err = $('cf-paste-err');
    if (p.error || p.role !== 'fanout') {
      err.textContent = aglinkErrText(p.role && p.role !== 'fanout' ? 'bad_role' : p.error);
      err.style.display = 'block';
      return;
    }
    err.style.display = 'none';
    fillConnectorFields(p);
    box.value = '';
    toast(T('fanout.pasted'), 'ok');
  };
  box.addEventListener('paste', () => setTimeout(fill, 0));
  box.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); fill(); } });
}
function connectorFormBody() {
  return {
    name: $('cf-name').value.trim(),
    upstream_addr: $('cf-addr').value.trim(),
    sni_hostname: $('cf-sni').value.trim(),
    insecure: $('cf-insecure').checked,
    pinned_fingerprint: $('cf-fp').value.trim(),
    advertise: $('cf-advertise').value.split('\n').map(s => s.trim()).filter(Boolean),
    group_id: [...document.querySelectorAll('.cf-acl:checked')].map(c => c.value).join(',') || null,
    push_groups: [...document.querySelectorAll('.cf-push:checked')].map(c => c.value),
    remark: $('cf-remark').value.trim(),
  };
}
function openCreateConnector(pref) {
  openModal(T('fanout.create'), connectorFormHtml(), [
    {label: T('common.cancel'), kind:'ghost', fn: closeModal},
    {label: T('common.create'), fn: async () => {
      const body = connectorFormBody();
      const token = $('cf-token').value.trim();
      if (!body.name || !body.upstream_addr || !token) { toast(T('fanout.needAll'), 'err'); return; }
      try {
        await api('POST', '/api/v1/admin/connectors', { ...body, token });
        closeModal(); toast(T('fanout.createdToast'), 'ok'); loadConnectors();
      } catch(e) { toast(e.message, 'err'); }
    }},
  ]);
  bindConnectorPaste();
  // .anet import prefill (technical fields from the envelope payload; business fields stay manual)
  if (pref && typeof pref === 'object') fillConnectorFields(pref);
}
async function openEditConnector(id) {
  let c;
  try { c = ((await api('GET', '/api/v1/admin/connectors')).items||[]).find(x => x.id === id); }
  catch(e) { toast(e.message, 'err'); return; }
  if (!c) { toast(T('fanout.notFound'), 'err'); return; }
  openModal(T('fanout.editTitle'), connectorFormHtml(c), [
    {label: T('common.cancel'), kind:'ghost', fn: closeModal},
    {label: T('common.save'), fn: async () => {
      const body = connectorFormBody();
      const token = $('cf-token').value.trim();
      if (!body.name || !body.upstream_addr) { toast(T('fanout.needNameAddr'), 'err'); return; }
      try {
        // PUT is a full replacement: empty token = keep original; cert paths are not exposed in the form, pass originals through so they are not wiped
        await api('PUT', '/api/v1/admin/connectors/' + id, {
          ...body, token: token || null,
          ca_cert_path: c.ca_cert_path || '', pinned_cert_path: c.pinned_cert_path || '',
        });
        closeModal(); toast(T('fanout.savedToast'), 'ok'); loadConnectors();
      } catch(e) { toast(e.message, 'err'); }
    }},
  ]);
  bindConnectorPaste();
}
async function toggleConnector(id, enabled) {
  try {
    await api('POST', '/api/v1/admin/connectors/' + id + (enabled ? '/enable' : '/disable'));
    toast(enabled ? T('fanout.enabledToast') : T('fanout.disabledToast'), 'ok');
    loadConnectors();
  } catch(e) { toast(e.message, 'err'); }
}
async function delConnector(id, name) {
  confirmAction(T('fanout.delConfirm', { name }), async () => {
    try { await api('DELETE', '/api/v1/admin/connectors/' + id); toast(T('adm.deleted'), 'ok'); loadConnectors(); }
    catch(e) { toast(e.message, 'err'); }
  });
}

/* ================= Audit log ================= */
async function renderAudit() {
  $('view').innerHTML = '<div class="page-title">' + ic('scroll-text', 20) + T('audit.title') + '</div><div class="page-desc">' + T('audit.desc') + '</div>' +
    '<div class="toolbar">' +
      '<select id="audit-action">' +
        '<option value="">' + T('audit.allActions') + '</option>' +
        ['admin.login','admin.init','rule.create','rule.update','rule.delete','rule.batch_import',
         'group.create','group.update','group.delete','group.update_rules',
         'account.create','account.update','account.delete','account.reset_password','account.enable','account.disable',
         'relay_token.create','relay_token.delete','relay_token.expose_control','relay_token.set_group',
         'connector.create','connector.update','connector.delete','connector.enable','connector.disable',
         'federation.adopt',
         'account.issue_admin_link','admin.console_access','admin.session_via_relay','node.update_settings'].map(a =>
          '<option value="' + a + '" ' + (S.filter.auditAction===a?'selected':'') + '>' + a + '</option>').join('') +
      '</select>' +
    '</div>' +
    '<div class="card table-wrap"><table><thead><tr><th>' + T('audit.colTime') + '</th><th>' + T('audit.colOperator') + '</th><th>' + T('audit.colAction') + '</th><th>' + T('audit.colTarget') + '</th><th>' + T('audit.colDetail') + '</th><th>' + T('audit.colIp') + '</th></tr></thead><tbody id="audit-body"></tbody></table><div id="audit-pager"></div></div>';
  agSelectEnhance($('view'));
  $('audit-action').onchange = (e) => { S.filter.auditAction = e.target.value; S.page.audit = 1; renderAudit(); };
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
    ).join('') || '<tr><td colspan="6" class="empty">' + T('audit.empty') + '</td></tr>';
    $('audit-pager').innerHTML = pager('audit', d.total||0);
  } catch(e) { toast(e.message, 'err'); }
}

/* ================= Node settings ================= */
async function renderSettings() {
  // Sections: server info (name / public host / runtime info) → admin surface (admins / my password) → system logs; grouping reordered only, all element ids kept
  $('view').innerHTML = '<div class="page-title">' + ic('settings', 20) + T('set.title') + '</div><div class="page-desc">' + T('set.desc') + '</div>' +
    '<div class="card"><h3>' + T('set.serverInfo') + '</h3>' +
      '<label>' + T('set.nodeName') + '</label><div style="display:flex;gap:10px"><input id="set-name" style="flex:1"><button id="set-name-save">' + T('common.save') + '</button></div>' +
      '<label>' + T('set.publicHost') + ' ' + ahelp(T('set.publicHostTip')) + '</label><div style="display:flex;gap:10px"><input id="set-host" style="flex:1" placeholder="anet.example.com"><button id="set-host-save">' + T('common.save') + '</button></div>' +
      '<label>' + T('set.apiUrl') + ' ' + ahelp(T('set.apiUrlTip')) + '</label><div style="display:flex;gap:10px"><input id="set-apiurl" class="mono" style="flex:1" placeholder="https://anet.example.com"><button id="set-apiurl-save">' + T('common.save') + '</button></div>' +
      '<div id="set-info" style="margin-top:14px"></div>' +
    '</div>' +
    '<div class="card"><h3>' + T('set.admins') + '</h3>' +
      '<div class="table-wrap"><table><thead><tr><th>' + T('set.colUsername') + '</th><th>' + T('common.createdAt') + '</th><th>' + T('common.action') + '</th></tr></thead><tbody id="admin-body"></tbody></table></div>' +
      '<div class="toolbar" style="margin-top:12px"><input id="na-user" placeholder="' + T('set.newAdminPh') + '"><input id="na-pass" type="password" placeholder="' + T('set.newPassPh') + '"><button id="admin-create">' + ic('plus', 15) + T('set.createAdmin') + '</button></div>' +
    '</div>' +
    '<div class="card"><h3>' + T('set.changePwd') + '</h3>' +
      '<label>' + T('set.oldPwd') + '</label><input id="pw-old" type="password" style="width:280px">' +
      '<label>' + T('set.newPwdLabel') + '</label><input id="pw-new" type="password" style="width:280px">' +
      '<div style="margin-top:12px"><button id="pw-change">' + T('set.changePwdBtn') + '</button></div>' +
    '</div>' +
    '<div class="card"><h3>' + T('set.sysLogs') + '</h3><div id="set-logs" class="mono" style="max-height:300px;overflow-y:auto;color:var(--dim);font-size:12px"></div></div>';
  $('set-name-save').onclick = saveNodeName;
  $('set-host-save').onclick = savePublicHost;
  $('set-apiurl-save').onclick = savePublicApiUrl;
  $('admin-create').onclick = createAdmin;
  $('pw-change').onclick = changePassword;
  try {
    const st = await api('GET', '/api/v1/admin/node/status');
    $('set-name').value = st.node_name || '';
    $('set-host').value = st.public_host || '';
    $('set-apiurl').value = st.public_api_url || '';
    $('set-info').innerHTML =
      kv(T('set.version'), 'v' + st.version) + kv(T('set.uptime'), fmtUptime(st.uptime)) +
      kv(T('dashboard.cardRelay'), st.roles.listener.enabled ? st.roles.listener.addr : T('adm.stNotOn')) +
      kv(T('dashboard.cardFanout'), (st.roles.connectors || []).length
        ? st.roles.connectors.map(c => esc(c.upstream) + '（' + esc(connStatusText(c.status)) + '）').join(' · ')
        : T('dashboard.noFanout')) +
      kv(T('dashboard.cardProxy'), (st.proxy.mode ? proxyModeText(st.proxy.mode) + ' · ' : '') + (st.proxy.enabled ? st.proxy.listen : T('adm.stNotOn'))) +
      (st.cert_fingerprint
        ? '<div class="kv"><span class="k">' + T('set.certFp') + '</span><span class="mono" style="font-size:11px;word-break:break-all">' + esc(st.cert_fingerprint) +
          ' <button class="ghost small" data-act="copy" data-copy="' + esc(st.cert_fingerprint) + '">' + ic('copy', 13) + T('common.copy') + '</button></span></div>'
        : '');
  } catch(e) { toast(e.message, 'err'); }
  try {
    const conf = await api('GET', '/api/v1/admin/admins');
    $('admin-body').innerHTML = (conf.items||[]).map(a =>
      '<tr><td><b>' + esc(a.username) + '</b></td><td style="color:var(--dim)">' + esc(a.created_at) + '</td>' +
      '<td><button class="danger small" data-act="admin-del" data-id="' + esc(a.id) + '" data-name="' + esc(a.username) + '">' + T('common.delete') + '</button></td></tr>'
    ).join('') || '<tr><td colspan="3" class="empty">' + T('common.none') + '</td></tr>';
  } catch(e) {}
  try {
    const d = await api('GET', '/api/v1/admin/node/logs?limit=100');
    $('set-logs').innerHTML = (d.items||[]).map(l =>
      '<div>[' + esc((l.time||'').substring(11,23)) + '] <span style="color:' + (l.level==='error'?'var(--danger)':l.level==='warn'?'var(--warn)':'var(--dim)') + '">' + esc(l.level) + '</span> ' + esc(l.message) + '</div>'
    ).join('') || '<div class="empty">' + T('set.noLogs') + '</div>';
  } catch(e) {}
  function kv(k, v) { return '<div class="kv"><span class="k">' + esc(k) + '</span><span>' + esc(v) + '</span></div>'; }
}
async function saveNodeName() {
  try {
    await api('PUT', '/api/v1/admin/node/settings', { node_name: $('set-name').value.trim() });
    toast(T('adm.saved'), 'ok');
  } catch(e) { toast(e.message, 'err'); }
}
async function savePublicHost() {
  try {
    await api('PUT', '/api/v1/admin/node/settings', { public_host: $('set-host').value.trim() });
    toast(T('set.hostSaved'), 'ok');
  } catch(e) { toast(e.message, 'err'); }
}
async function savePublicApiUrl() {
  try {
    await api('PUT', '/api/v1/admin/node/settings', { public_api_url: $('set-apiurl').value.trim() });
    toast(T('set.urlSaved'), 'ok');
  } catch(e) { toast(e.message, 'err'); }
}
async function createAdmin() {
  const username = $('na-user').value.trim(), password = $('na-pass').value;
  if (!username || !password) { toast(T('set.needCred'), 'err'); return; }
  try {
    await api('POST', '/api/v1/admin/admins', { username, password });
    toast(T('set.adminCreated'), 'ok');
    $('na-user').value = ''; $('na-pass').value = '';
    renderSettings();
  } catch(e) { toast(e.message, 'err'); }
}
async function delAdmin(id, username) {
  confirmAction(T('set.delAdminConfirm', { name: username }), async () => {
    try { await api('DELETE', '/api/v1/admin/admins/' + id); toast(T('adm.deleted'), 'ok'); renderSettings(); }
    catch(e) { toast(e.message, 'err'); }
  });
}
async function changePassword() {
  const old_password = $('pw-old').value, new_password = $('pw-new').value;
  if (!old_password || !new_password) { toast(T('set.needPwd'), 'err'); return; }
  try {
    await api('PUT', '/api/v1/auth/password', { old_password, new_password });
    toast(T('set.pwdChanged'), 'ok');
    setTimeout(doLogout, 1200);
  } catch(e) { toast(e.message, 'err'); }
}

/* ================= Theme toggle ================= */
function applyTheme() {
  const t = localStorage.getItem('ag_theme') || 'light';
  document.documentElement.dataset.theme = t;
  const btn = $('theme-btn');
  if (btn) btn.innerHTML = ic(t === 'dark' ? 'sun' : 'moon', 14) + (t === 'dark' ? T('settings.themeLight') : T('settings.themeDark'));
  const lb = $('login-theme-btn');
  if (lb) lb.innerHTML = ic(t === 'dark' ? 'sun' : 'moon', 15);
}
function toggleTheme() {
  localStorage.setItem('ag_theme', (localStorage.getItem('ag_theme') || 'light') === 'dark' ? 'light' : 'dark');
  applyTheme();
}

/* ================= Startup ================= */
window.addEventListener('DOMContentLoaded', async () => {
  AgIconHydrate();
  applyTheme();
  // Language switch: init the selected option and hydrate static markers; re-render the current view on onChange
  // (a view rebuild clears signature caches — dataset.sig lives on the new DOM, polling change detection semantics unchanged)
  const langSel = $('lang-select');
  if (langSel) {
    langSel.value = AgI18n.lang;
    langSel.addEventListener('change', () => AgI18n.setLang(langSel.value));
  }
  AgI18n.hydrate(document);
  AgI18n.onChange(() => {
    applyTheme();
    closeModal();
    if ($('app').style.display !== 'none') switchView(S.view);
  });
  // Static element event binding (HTML never uses inline event attributes, aligning with desktop CSP constraints)
  $('login-btn').onclick = doLogin;
  $('login-theme-btn').onclick = toggleTheme;
  $('theme-btn').onclick = toggleTheme;
  $('logout-btn').onclick = doLogout;
  document.querySelectorAll('.nav-item[data-view]').forEach(n => { n.onclick = () => switchView(n.dataset.view); });
  // Tauri console window: show the custom title bar (frameless window), wire window controls and the theme broadcast
  if (window.__TAURI__) {
    document.body.classList.add('tb-mode');
    $('titlebar').style.display = 'flex';
    const tbt0 = document.querySelector('.tb-title');
    if (tbt0) tbt0.textContent = document.title;
    try {
      const cw = window.__TAURI__.window.getCurrentWindow();
      $('tb-min').onclick = () => cw.minimize();
      $('tb-max').onclick = () => cw.toggleMaximize();
      $('tb-close').onclick = () => cw.close();
      window.__TAURI__.event.listen('ag-theme', e => {
        try { localStorage.setItem('ag_theme', e.payload); applyTheme(); } catch(_) {}
      });
    } catch(_) {}
  }
  // Sidebar collapse (persisted; matches the desktop GUI icon mode)
  if (localStorage.getItem('ag_admin_sidebar') === 'collapsed') document.body.classList.add('collapsed');
  $('btn-collapse').onclick = () => {
    const c = document.body.classList.toggle('collapsed');
    localStorage.setItem('ag_admin_sidebar', c ? 'collapsed' : '');
  };
  // Main-window embed bridge: navigation and theme driven via postMessage (cross-origin safe whitelist)
  window.addEventListener('message', e => {
    const d = e.data || {};
    if (d.type === 'ag-theme' && (d.theme === 'dark' || d.theme === 'light')) {
      try { localStorage.setItem('ag_theme', d.theme); applyTheme(); } catch(_) {}
    }
    if (d.type === 'ag-nav' && {dashboard:1,accounts:1,groups:1,rules:1,fanin:1,connectors:1,audit:1,settings:1}[d.view]) {
      switchView(d.view);
    }
    // Desktop bridge: native open-dialog result (ag-anet-open was requested by an import entry)
    if (d.type === 'ag-anet-open-result' && typeof d.content === 'string' && S.access) {
      openAnetImport(d.content, d.name || '');
    }
  });
  // .anet drag-drop import (global entry; file picker lives on the fan-out page): meta preview first
  document.addEventListener('dragover', (e) => {
    if (S.access && [...(e.dataTransfer ? e.dataTransfer.items : [])].some(i => i.kind === 'file')) e.preventDefault();
  });
  document.addEventListener('drop', async (e) => {
    if (!S.access) return;
    const f = e.dataTransfer && e.dataTransfer.files && [...e.dataTransfer.files].find(f => /\.anet$/i.test(f.name));
    if (!f) return;
    e.preventDefault();
    openAnetImport(await f.text(), f.name);
  });
  $('login-pass').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
  $('login-user').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
  // Console channel ticket bootstrap: #boot=<ticket> → exchange for an admin session (one-time, invalidated on exchange)
  const boot = location.hash.match(/#boot=([A-Za-z0-9_-]+)/);
  if (boot) {
    history.replaceState(null, '', location.pathname);
    try {
      const res = await fetch('/api/v1/auth/admin-bootstrap', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ ticket: boot[1] })
      });
      const j = await res.json();
      if (j.code === 0) {
        S.access = j.data.access_token; S.refresh = j.data.refresh_token || '';
        localStorage.setItem('ag_access', S.access);
        localStorage.setItem('ag_refresh', S.refresh);
        toast(T('adm.bootOk'), 'ok');
      } else {
        toast(j.message || T('adm.bootInvalid'), 'err');
      }
    } catch(e) { toast(T('adm.bootFailed'), 'err'); }
  }
  if (S.access) { enterApp(); }
});
