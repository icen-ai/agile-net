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

/* ================= agseg single-choice segmented group (shared agtabs texture, components.css) =================
   For dialog dimension pickers (entry/trust/route/…): the same pill segment texture as tab bars,
   one active per group. segHtml renders, segVal reads, segSet drives linkage (active + per-option
   disabled), and one delegated document click handles every group (SEG_EVT is reassigned per dialog). */
const SEG_EVT = {};
function segHtml(name, options, current) {
  return '<div class="agtabs" style="margin:2px 0 6px"><div class="agtabs-pill">' + options.map(o =>
    '<button type="button" class="agtab' + (o.v === current ? ' active' : '') + '" data-seg="' + name + '" data-v="' + o.v + '"' +
    (o.disabled ? ' disabled' : '') + '>' + esc(o.label) + '</button>').join('') + '</div></div>';
}
function segVal(name) {
  const b = document.querySelector('[data-seg="' + name + '"].active');
  return b ? b.dataset.v : '';
}
function segSet(name, v, disabledMap) {
  document.querySelectorAll('[data-seg="' + name + '"]').forEach(b => {
    b.classList.toggle('active', b.dataset.v === v);
    if (disabledMap) b.disabled = !!disabledMap[b.dataset.v];
  });
}
document.addEventListener('click', (e) => {
  const b = e.target.closest('[data-seg]');
  if (!b || b.disabled) return;
  const name = b.dataset.seg;
  const pill = b.closest('.agtabs-pill');
  (pill || document).querySelectorAll('[data-seg="' + name + '"]').forEach(x => x.classList.toggle('active', x === b));
  if (SEG_EVT[name]) SEG_EVT[name](b.dataset.v);
});

/* ================= AgTbl bridge (shared table framework, /ui/agtbl.js) =================
   Header state (sort/filter) applies to the item array BEFORE the HTML build; tblSig folds that
   state into a view's signature guard so a sort/filter change forces exactly one re-render. */
function tblSig(key) { return JSON.stringify([AgTbl.sortState(key), AgTbl.filters(key)]); }
function tblApply(key, items, sortGetters, filterGetters) {
  let out = items;
  if (filterGetters) {
    for (const [idx, get] of Object.entries(filterGetters)) {
      const v = AgTbl.filterGet(key, idx);
      if (Array.isArray(v)) { if (v.length) out = out.filter(it => v.includes(get(it))); }
      else if (v) { const q = v.toLowerCase(); out = out.filter(it => String(get(it) ?? '').toLowerCase().includes(q)); }
    }
  }
  const st = AgTbl.sortState(key);
  if (st && sortGetters && sortGetters[st.id]) {
    const get = sortGetters[st.id];
    out = out.slice().sort((a, b) => {
      const va = get(a), vb = get(b);
      const c = (typeof va === 'number' && typeof vb === 'number') ? va - vb
        : String(va ?? '').toLowerCase().localeCompare(String(vb ?? '').toLowerCase());
      return st.dir === 'asc' ? c : -c;
    });
  }
  return out;
}
function tblAttach(tbodyId, opts) {
  const body = $(tbodyId);
  if (!body) return;
  const table = body.closest('table');
  if (table) AgTbl.attach(table, opts);
}

/* ================= Infrastructure =================
   $ / esc / ahelp come from shared base utils /ui/agutil.js (AGENTS.md §6); no local copies kept here */
const S = {
  access: localStorage.getItem('ag_access') || '',
  refresh: localStorage.getItem('ag_refresh') || '',
  view: 'dashboard',
  page: { groups: 1, rules: 1, audit: 1 },
  size: { groups: 10, rules: 10, audit: 15 },
  filter: { rules: '', rulesType: '', auditAction: '' },
  faninTab: 'listen',   // fan-in page current tab: listen | peers | tokens
  faninQuery: '',       // fan-in page search term: shared by the peers/tokens tabs (kept across tab switches)
  fanoutTab: 'conns',   // fan-out page current tab: watch | conns | issue
  devQ: '',             // devices page search term
  devState: '',         // devices page state filter: '' | online | offline | pending | certified | revoked
  devFp: '',            // devices page: fingerprint of the open detail view ('' = list)
  apprState: 'pending', // approvals page filter: pending | all | approved | rejected
  apprTimer: null,      // global pending-approval badge poller (survives view switches)
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
   Issuance dialogs (fan-in token / delegated token): endpoint choice (public identity / LAN direct) +
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
      ? AgLink.buildFanout({ addr, token: parsed.token, sni: parsed.sni, fp: parsed.fp, insecure: parsed.insecure, myname: parsed.myname || '' })
      : AgLink.buildConnect({
          addr, account: parsed.account, password: parsed.password, fp: parsed.fp,
          insecure: parsed.insecure,
          // federation P2: keep the disaster set of a delegated credential across rebuilds
          entries: (parsed.entries || []).map((a, i) => ({ addr: a, fp: (parsed.entryFps || [])[i] || '' })),
          // federation P3: keep the entrust word, the consumer mode and the admin flag
          en: parsed.en || '',
          emode: parsed.emode || '',
          eadmin: !!parsed.eadmin,
          // M3-T6: keep the issuer-suggested "my name" across endpoint switches
          myname: parsed.myname || '',
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
          my_name: parsed.myname || '',
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
  if (S.apprTimer) { clearInterval(S.apprTimer); S.apprTimer = null; }
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
  // Pending-approval badge: global poller (paused while hidden) + hover identity card shell
  refreshApprovalsBadge();
  if (S.apprTimer) clearInterval(S.apprTimer);
  S.apprTimer = setInterval(() => { if (!document.hidden) refreshApprovalsBadge(); }, 20000);
  AgIdCard.attach({ load: devCardHtml });
  switchView(S.view || 'dashboard');
}

/* ================= Topology view (node.md M6-T4): transitive-cert switch + trust list +
   adopted sources + visibility receipts ================= */
async function renderTopo() {
  $('view').innerHTML = '<div class="page-title">' + ic('earth', 20) + T('topo.title') + '</div><div class="page-desc">' + T('topo.desc') + '</div>' +
    '<div class="card"><h3>' + T('topo.certTitle') + ahelp(T('topo.certHelp')) + '</h3>' +
      '<label class="chk" style="display:flex;align-items:center;gap:8px"><input type="checkbox" id="topo-in"> <span>' + T('topo.inSwitch') + '</span></label>' +
      '<div class="kv" style="margin-top:8px"><span class="k">' + T('topo.ownFp') + '</span><span id="topo-ownfp"></span></div>' +
      '<label style="display:block;margin-top:8px">' + T('topo.trustList') + '</label>' +
      '<textarea id="topo-trust" rows="3" style="width:100%" placeholder="' + T('topo.trustPh') + '"></textarea>' +
      '<div style="margin-top:8px"><button id="topo-save">' + T('common.save') + '</button></div></div>' +
    '<div class="card"><h3>' + T('topo.adoptedTitle') + '</h3><div class="table-wrap"><table><thead><tr><th>' + T('dev.colDevice') + '</th><th>' + T('topo.colHolder') + '</th><th>' + T('topo.colOrigin') + '</th><th>' + T('common.status') + '</th></tr></thead><tbody id="topo-adopted"></tbody></table></div></div>' +
    '<div class="card"><h3>' + T('topo.receiptsTitle') + ahelp(T('topo.receiptsHelp')) + '</h3><div class="table-wrap"><table><thead><tr><th>' + T('topo.colArtifact') + '</th><th>' + T('topo.colHolder') + '</th><th>' + T('topo.colVis') + '</th><th>' + T('common.status') + '</th><th>' + T('common.createdAt') + '</th></tr></thead><tbody id="topo-receipts"></tbody></table></div></div>';
  $('topo-save').onclick = saveTopoSettings;
  $('topo-in').onchange = () => {};
  await loadTopo();
}
async function loadTopo() {
  try {
    const d = await api('GET', '/api/v1/admin/federation/cert');
    const inEl = $('topo-in'); if (!inEl) return;
    inEl.checked = !!d.enabled;
    $('topo-ownfp').innerHTML = agcopy(d.own_fp || '', (d.own_fp || '').slice(0, 12) + '…');
    $('topo-trust').value = (d.trust_list || []).join('\n');
    const adopted = tblApply('adm-topo-adopted', d.adopted || [],
      { device: a => a.remark || a.my_name || '', holder: a => a.subject || '' },
      { 3: a => a.state || '' });
    $('topo-adopted').innerHTML = adopted.map(a =>
      '<tr><td><b data-agid="' + esc(a.device_fp) + '" data-act="dev-open" data-fp="' + esc(a.device_fp) + '" style="cursor:pointer">' + esc(a.remark || a.my_name || a.device_fp.slice(0, 12)) + '</b></td>' +
      '<td>' + esc(a.subject || '-') + '</td><td class="mono" style="color:var(--dim2)">' + esc((a.origin_fp || '').slice(0, 12)) + '</td>' +
      '<td>' + devStateBadge(a.state) + '</td></tr>'
    ).join('') || '<tr><td colspan="4" class="empty">' + T('common.empty') + '</td></tr>';
    tblAttach('topo-adopted', {
      key: 'adm-topo-adopted',
      sort: { 0: 'device', 1: 'holder' },
      filter: {
        3: { label: 'common.status', type: 'enum', options: [
          { v: 'certified', label: 'dev.stCertified' },
          { v: 'pending', label: 'dev.stPending' },
          { v: 'revoked', label: 'dev.stRevoked' },
        ] },
      },
      onSort: () => loadTopo(),
      onFilter: () => loadTopo(),
    });
  } catch (e) { toast(e.message, 'err'); }
  try {
    const r = await api('GET', '/api/v1/admin/federation/receipts');
    const body = $('topo-receipts'); if (!body) return;
    const items = tblApply('adm-topo-receipts', r.items || [],
      { created: it => it.created_at || '' },
      { 2: it => it.visibility || '' });
    body.innerHTML = items.map(it =>
      '<tr><td>' + esc(it.artifact) + '</td><td>' + esc(it.holder) + '</td>' +
      '<td><span class="badge ' + (it.visibility === 'approve' ? 'b-warn' : 'b-info') + '">' + esc(it.visibility) + '</span></td>' +
      '<td>' + esc(it.state) + '</td><td style="color:var(--dim2)">' + esc((it.created_at || '').replace('T', ' ').replace('Z', '')) + '</td></tr>'
    ).join('') || '<tr><td colspan="5" class="empty">' + T('common.empty') + '</td></tr>';
    tblAttach('topo-receipts', {
      key: 'adm-topo-receipts',
      sort: { 4: 'created' },
      filter: {
        2: { label: 'topo.colVis', type: 'enum', options: [
          { v: 'disclose', label: 'disclose' }, { v: 'approve', label: 'approve' }] },
      },
      onSort: () => loadTopo(),
      onFilter: () => loadTopo(),
    });
  } catch (e) { toast(e.message, 'err'); }
}
async function saveTopoSettings() {
  const trust = $('topo-trust').value.split('\n').map(s => s.trim()).filter(Boolean);
  try {
    await api('PUT', '/api/v1/admin/federation/cert', { enabled: $('topo-in').checked, trust_list: trust });
    toast(T('common.success'), 'ok');
  } catch (e) { toast(e.message, 'err'); }
}

/* ================= View routing ================= */
function switchView(v) {
  S.view = v;
  S.timers.forEach(clearInterval); S.timers = [];
  document.querySelectorAll('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.view === v));
  const fn = ({dashboard: renderDashboard, groups: renderGroups,
    rules: renderRules, fanin: renderFanIn, connectors: renderConnectors, devices: renderDevices, approvals: renderApprovals, topo: renderTopo, audit: renderAudit, settings: renderSettings})[v] || renderDashboard;
  fn();
}
async function loadGroupsCache() {
  try { const d = await api('GET', '/api/v1/admin/groups?page_size=100'); S.groups = d.items || []; } catch(e) { S.groups = []; }
  // After a group cache refresh, sync the labels of existing custom dropdowns (option lists are rebuilt by each render entry)
  document.querySelectorAll('select[data-agsel]').forEach(agSelectRefresh);
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
  'grp-detail': b => openGroupDetail(b.dataset.id),
  'grp-bind': b => openBindRules(b.dataset.id, b.dataset.name),
  'grp-edit': b => openEditGroup(b.dataset.id, b.dataset.name, b.dataset.remark || '', b.dataset.e2e === '1'),
  'grp-del': b => delGroup(b.dataset.id, b.dataset.name),
  'rule-edit': b => openEditRule(b.dataset.id, b.dataset.type, b.dataset.value, b.dataset.resolve === 'true', b.dataset.remark || ''),
  'rule-del': b => delRule(b.dataset.id, b.dataset.value, Number(b.dataset.count || 0)),
  'tok-edit': b => openEditToken(b.dataset.id, b.dataset.group || '', b.dataset.expose === 'true', b.dataset.scope, b.dataset.expires || '', b.dataset.maxuses || '', b.dataset.rate || '', b.dataset.remark || ''),
  'tok-del': b => delToken(b.dataset.id),
  'conn-edit': b => openEditConnector(b.dataset.id),
  'conn-toggle': b => toggleConnector(b.dataset.id, b.dataset.enabled === 'true'),
  'conn-del': b => delConnector(b.dataset.id, b.dataset.name),
  'deleg-revoke': b => revokeDelegation(b.dataset.id, b.dataset.name),
  'deleg-expand': b => toggleSessWrap('deleg:' + b.dataset.id),
  'grp-copy': b => copyAdopted(b.dataset.id, b.dataset.name),
  'fed-adopt-now': b => { adoptPushed(b.dataset.node, b.dataset.group).then(() => { closeModal(); }); },
  'fed-adopt': b => adoptPushed(b.dataset.node, b.dataset.group),
  'admin-del': b => delAdmin(b.dataset.id, b.dataset.name),
  // session management (M3-T1): expand/collapse + kicks
  'sess-toggle': b => toggleSessWrap(b.dataset.sessrow),
  'tok-sess': b => toggleSessWrap('tok:' + b.dataset.id),
  'watch-sess': b => toggleSessWrap('watch:' + b.dataset.id),
  'sess-kick': b => kickSession(b.dataset.key, b.dataset.name || ''),
  'sess-kickall': b => kickTokenSessions(b.dataset.hash, b.dataset.name || ''),
  'sess-kickall-fanin': b => kickFaninSessions(b.dataset.hash, b.dataset.name || ''),
  // devices (M3-T2) + approvals (M3-T4)
  'dev-open': b => {
    S.devFp = b.dataset.fp || '';
    if (!S.devFp) return;
    // entering the detail view without switchView: clear the list poller explicitly
    S.timers.forEach(clearInterval); S.timers = [];
    if (S.view !== 'devices') switchView('devices'); else renderDeviceDetail();
  },
  'dev-certify': b => openCertify(b.dataset.fp),
  'dev-revoke': b => openRevoke(b.dataset.fp),
  'dev-rebind': b => openRebind(b.dataset.fp),
  'appr-approve': b => openDecide(b.dataset.id, 'approve'),
  'appr-reject': b => openDecide(b.dataset.id, 'reject'),
  'appr-reject-revoke': b => openDecide(b.dataset.id, 'reject_revoke'),
  'appr-reopen': b => reopenApproval(b.dataset.id),
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
    ({ groups: renderGroups, rules: renderRules, audit: renderAudit }[key] || (() => {}))();
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

/* ================= Live session inventory + device registry join (node.md M3-T1/T4) =================
   SESS = /sessions rows (fanin peers + delegated consumers); DEV_MAP = /devices rows keyed by
   device_fp (certification state badges + hover identity cards). Pollers skip while the page is
   hidden; every container re-renders under its own signature so unchanged polls rewrite nothing. */
let SESS = [];
let DEV_MAP = {};
/* Expanded session blocks across polls (keys: res-row id / 'deleg:'+id / 'tok:'+id / 'watch:'+id) */
const SESS_OPEN = new Set();
async function loadSessions() {
  if (document.hidden) return;
  try { const d = await api('GET', '/api/v1/admin/sessions'); SESS = d.items || []; }
  catch (e) { /* listener off or transient failure: keep the last snapshot */ }
}
async function loadDevices() {
  if (document.hidden) return;
  try {
    const d = await api('GET', '/api/v1/admin/devices');
    DEV_MAP = {};
    (d.items || []).forEach(x => { DEV_MAP[x.device_fp] = x; });
  } catch (e) { /* keep the last snapshot */ }
}
async function reloadSessions() {
  await Promise.all([loadSessions(), loadDevices()]);
  rerenderSessBlocks();
}
/* Re-render every session-bearing container of the current view from caches (no refetch) */
function rerenderSessBlocks() {
  if (S.view === 'fanin') { renderFaninPeers(); renderFaninTokens(); }
  else if (S.view === 'connectors') { renderConnsSess(); renderDelegation(); renderWatch(); }
}
/* Generic expand/collapse: the toggle carries data-sessopen="key", the block data-sesswrap="key";
   SESS_OPEN persists the state across signature-driven rebuilds. */
function toggleSessWrap(key) {
  if (!key) return;
  if (SESS_OPEN.has(key)) SESS_OPEN.delete(key); else SESS_OPEN.add(key);
  const open = SESS_OPEN.has(key);
  const w = document.querySelector('[data-sesswrap="' + CSS.escape(key) + '"]');
  if (w) w.hidden = !open;
  document.querySelectorAll('[data-sessopen="' + CSS.escape(key) + '"]').forEach(t => t.classList.toggle('open', open));
}
function sessWrapAttrs(key) { return 'data-sesswrap="' + esc(key) + '"' + (SESS_OPEN.has(key) ? '' : ' hidden'); }

/* Column model ported from the design prototype (target/badge-preview scenario 8) */
const SESS_COL_W = { who: 'minmax(150px,1.5fr)', ip: '108px', entry: '116px', ago: '64px', tr: '128px', key: '76px', token: '126px', chans: '62px', op: '58px' };
function sessGrid(cols) { return cols.map(c => SESS_COL_W[c] || '1fr').join(' '); }
/* Mono copyable field (.agcopy, M3-T7): full value copied, visible text may be truncated */
function agcopy(full, display) {
  return '<span class="agcopy" data-act="copy" data-copy="' + esc(full) + '" title="' + esc(full) + '"><span class="agcopy-v">' + esc(display == null ? full : display) + '</span>' + ic('copy', 11) + '</span>';
}
function devStateBadge(st) {
  const m = ({ certified: ['b-ok', 'dev.stCertified'], pending: ['b-warn', 'dev.stPending'], revoked: ['b-off', 'dev.stRevoked'] })[st];
  return m ? '<span class="badge ' + m[0] + '">' + T(m[1]) + '</span>' : '<span class="badge b-info">' + T('dev.stUnknown') + '</span>';
}
/* Clickable + hoverable device name: click jumps to the device page, hover opens the identity card */
function devNameHtml(fp, name) {
  if (!fp) return '<b>' + esc(name || '-') + '</b>';
  return '<b data-agid="' + esc(fp) + '" data-act="dev-open" data-fp="' + esc(fp) + '" style="cursor:pointer">' + esc(name || T('dev.unnamed')) + '</b>';
}
function fmtAgo(s) { s = Number(s) || 0; return s < 60 ? T('sess.justNow') : fmtUptime(s); }
function sessEntryBadge(entry) {
  if (!entry) return '-';
  return '<span class="badge b-info">' + (entry === 'direct' ? T('deleg.badgeDirect') : T('deleg.badgeRelay')) + '</span>';
}
function sessRowHtml(s, cols) {
  const d = DEV_MAP[s.device_fp] || {};
  const st = d.state || '';
  const fpShort = (s.device_fp || '').slice(0, 12);
  const authMark = st === 'certified'
    ? ' <span class="nb-auth" title="' + T('dev.stCertified') + '">' + ic('badge-check', 10) + '</span>'
    : '';
  const cell = {
    who: '<div class="sess-who"><span class="sess-dot pulse"></span>' + devNameHtml(s.device_fp, s.my_name || d.subject) +
      (s.device_fp ? '<span class="nodebadge">' + esc(fpShort) + authMark + '</span>' : '') +
      (st && st !== 'certified' ? ' ' + devStateBadge(st) : '') + '</div>',
    ip: '<div class="mono" style="color:var(--dim)">' + esc(s.ip || '-') + '</div>',
    entry: '<div>' + sessEntryBadge(s.entry) + '</div>',
    ago: '<div style="color:var(--dim)">' + fmtAgo(s.connected_at) + '</div>',
    tr: '<div class="tr-col"><div class="tr-rate"><span class="live-dot"></span><span class="up">↑ ' + fmtBytes(s.bytes_up) + '</span><span class="dn">↓ ' + fmtBytes(s.bytes_down) + '</span></div></div>',
    key: '<div>' + agcopy(s.session_key || '', String(s.session_key || '').slice(0, 6)) + '</div>',
    token: '<div style="color:var(--dim)">' + esc(s.token_label || '-') + '</div>',
    chans: '<div style="color:var(--dim)">' + (s.channels || 0) + '</div>',
    op: '<div><button class="danger small" data-act="sess-kick" data-key="' + esc(s.session_key) + '" data-name="' + esc(s.my_name || s.session_key || '') + '">' + T('sess.kick') + '</button></div>',
  };
  return '<div class="sess-row" style="grid-template-columns:' + sessGrid(cols) + '">' + cols.map(c => cell[c] || '').join('') + '</div>';
}
/* Inner panel of an expanded block: toolbar (count + optional kick-all) + header row + session rows */
function sessPanelInner(b) {
  return '<div class="sess-toolbar"><span>' + (b.toolbarText || T('sess.toolbar', { n: b.sessions.length })) + '</span>' +
      (b.kickallHash && b.sessions.length ? '<button class="danger small" data-act="sess-kickall" data-hash="' + esc(b.kickallHash) + '" data-name="' + esc(b.name || '') + '">' + T('sess.kickAll') + '</button>' : '') +
      (b.kickallFanin && b.sessions.length ? '<button class="danger small" data-act="sess-kickall-fanin" data-hash="' + esc(b.kickallFanin) + '" data-name="' + esc(b.name || '') + '">' + T('sess.kickAll') + '</button>' : '') + '</div>' +
    '<div class="sess-row sess-head-row" style="grid-template-columns:' + sessGrid(b.cols) + '">' + b.cols.map(c => '<div>' + T('sess.col.' + c) + '</div>').join('') + '</div>' +
    (b.sessions.length ? b.sessions.map(s => sessRowHtml(s, b.cols)).join('') : '<div class="empty">' + T('sess.empty') + '</div>') +
    (b.extra || '');
}
/* Resource row (prototype sessBlockHtml): name/sub + tags + online badge; click expands the session panel */
function sessBlockHtml(b) {
  const cap = b.cap ? (b.online + '/' + b.cap) : String(b.online);
  const open = SESS_OPEN.has(b.id);
  return '<div class="res-row' + (open ? ' open' : '') + '" data-act="sess-toggle" data-sessrow="' + esc(b.id) + '" data-sessopen="' + esc(b.id) + '">' +
      '<div class="res-who"><span class="caret">' + ic('chevron-right', 12) + '</span><div><b>' + esc(b.name) + '</b>' +
      (b.sub ? '<div class="res-sub mono">' + esc(b.sub) + '</div>' : '') + '</div></div>' +
      '<div class="res-meta">' + (b.tags || '') + '<span class="badge ' + (b.online > 0 ? 'b-ok' : 'b-off') + '">' + T('sess.onlineN', { n: cap }) + '</span></div></div>' +
    '<div class="sess-wrap" ' + sessWrapAttrs(b.id) + '>' + sessPanelInner(b) + '</div>';
}
function kickModal(title, text, onYes) {
  openModal(title,
    '<p style="color:var(--dim)">' + esc(text) + '</p>' +
    '<label>' + T('sess.kickMsg') + '</label><input id="kick-msg" style="width:100%" placeholder="' + T('sess.kickMsgPh') + '">',
    [
      { label: T('common.cancel'), kind: 'ghost', fn: closeModal },
      { label: T('sess.kick'), kind: 'danger', fn: async () => { const m = $('kick-msg').value.trim(); closeModal(); await onYes(m); } },
    ]);
}
function kickSession(key, name) {
  kickModal(T('sess.kickTitle'), T('sess.kickConfirm', { name: name || key }), async (msg) => {
    try {
      await api('POST', '/api/v1/admin/sessions/kick', { session_key: key, message: msg });
      toast(T('sess.kicked'), 'ok');
      reloadSessions();
    } catch (e) { toast(e.message, 'err'); }
  });
}
function kickFaninSessions(hash, name) {
  kickModal(T('sess.kickAllTitle'), T('sess.kickAllConfirm', { name: name || hash.slice(0, 12) }), async (msg) => {
    try {
      const d = await api('POST', '/api/v1/admin/sessions/kick_fanin', { token_hash: hash, message: msg });
      toast(T('sess.kickedN', { n: d.kicked || 0 }), 'ok');
      reloadSessions();
    } catch (e) { toast(e.message, 'err'); }
  });
}
function kickTokenSessions(hash, name) {
  kickModal(T('sess.kickAllTitle'), T('sess.kickAllConfirm', { name: name || hash.slice(0, 12) }), async (msg) => {
    try {
      const d = await api('POST', '/api/v1/admin/sessions/kick_token', { token_hash: hash, message: msg });
      toast(T('sess.kickedN', { n: d.kicked || 0 }), 'ok');
      reloadSessions();
    } catch (e) { toast(e.message, 'err'); }
  });
}

/* ================= Hover identity card (node.md M3-T3; shell = AgIdCard in agutil.js) =================
   Any [data-agid="<device_fp>"] element (session rows, device list, approval items) gets the card;
   payloads are cached 30s (device state is slow-moving; the card re-fetches after expiry). */
const DEV_CARD_CACHE = new Map(); // fp -> { html, ts }
async function devCardHtml(fp) {
  const hit = DEV_CARD_CACHE.get(fp);
  if (hit && Date.now() - hit.ts < 30000) return hit.html;
  let d;
  try { d = await api('GET', '/api/v1/admin/devices/' + encodeURIComponent(fp)); }
  catch (e) { return ''; }
  const row = (k, v) => '<div class="agidcard-r"><span class="k">' + esc(k) + '</span><span class="v">' + v + '</span></div>';
  const online = (d.sessions || []).length;
  const html = '<div class="agidcard-h">' + esc(d.my_name || d.subject || T('dev.unnamed')) + ' ' + devStateBadge(d.state) + '</div>' +
    row(T('dev.cardFp'), agcopy(d.device_fp, (d.device_fp || '').slice(0, 16) + '…')) +
    (d.openssh ? row(T('dev.cardKey'), agcopy(d.openssh, d.openssh.slice(0, 30) + '…')) : '') +
    row(T('dev.cardSubject'), esc(d.subject || '-')) +
    row(T('dev.cardOnline'), online ? T('dev.onlineN', { n: online }) : T('dev.offline')) +
    row(T('dev.cardTraffic'), '↑ ' + fmtBytes(d.bytes_up) + ' · ↓ ' + fmtBytes(d.bytes_down));
  DEV_CARD_CACHE.set(fp, { html, ts: Date.now() });
  return html;
}

/* ================= Devices (node.md M3-T2) + pending policy gate (M3-T5) ================= */
async function renderDevices() {
  if (S.devFp) return renderDeviceDetail();
  $('view').innerHTML = '<div class="page-title">' + ic('monitor-smartphone', 20) + T('dev.title') + '</div><div class="page-desc">' + T('dev.desc') + '</div>' +
    '<div class="card"><h3>' + T('dev.policyTitle') + ahelp(T('dev.policyTip')) + '</h3>' +
      '<label class="chk" style="display:flex;align-items:center;gap:8px"><input type="checkbox" id="dev-policy"> <span>' + T('dev.policyAllow') + '</span></label></div>' +
    '<div class="toolbar"><input id="dev-q" placeholder="' + T('dev.searchPh') + '" value="' + esc(S.devQ) + '">' +
      '<select id="dev-state">' +
        ['', 'online', 'offline', 'pending', 'certified', 'revoked'].map(v =>
          '<option value="' + v + '"' + (S.devState === v ? ' selected' : '') + '>' + T('dev.fs' + (v ? v.charAt(0).toUpperCase() + v.slice(1) : 'All')) + '</option>').join('') +
      '</select></div>' +
    '<div class="card table-wrap"><table><thead><tr><th>' + T('dev.colDevice') + '</th><th>' + T('common.status') + '</th><th>' + T('dev.colSess') + '</th><th>' + T('dev.colTraffic') + '</th><th>' + T('dev.colLastSeen') + '</th><th>' + T('common.action') + '</th></tr></thead><tbody id="dev-body"></tbody></table></div>';
  agSelectEnhance($('view'));
  $('dev-q').oninput = (e) => { S.devQ = e.target.value; renderDeviceRows(); };
  $('dev-state').onchange = (e) => { S.devState = e.target.value; renderDeviceRows(); };
  $('dev-policy').onchange = async (e) => {
    const allow = e.target.checked;
    try {
      await api('PUT', '/api/v1/admin/devices/policy', { policy: allow ? 'allow' : 'block' });
      toast(allow ? T('dev.policyOn') : T('dev.policyOff'), 'ok');
    } catch (err) { toast(err.message, 'err'); e.target.checked = !allow; }
  };
  try { const p = await api('GET', '/api/v1/admin/devices/policy'); $('dev-policy').checked = p.policy === 'allow'; } catch (e) {}
  await Promise.all([loadDevices(), loadSessions()]);
  renderDeviceRows();
  S.timers.push(setInterval(async () => { await Promise.all([loadDevices(), loadSessions()]); renderDeviceRows(); }, 10000));
}
function renderDeviceRows() {
  const body = $('dev-body'); if (!body) return;
  const q = S.devQ.trim().toLowerCase();
  let items = Object.values(DEV_MAP);
  if (S.devState === 'online') items = items.filter(d => d.online);
  else if (S.devState === 'offline') items = items.filter(d => !d.online);
  else if (S.devState) items = items.filter(d => d.state === S.devState);
  if (q) items = items.filter(d => ((d.my_name || '') + (d.subject || '') + (d.remark || '') + (d.device_fp || '')).toLowerCase().includes(q));
  // header sort (AgTbl): default stays online-first + last-seen; 状态/搜索走工具栏（不重复进表头）
  const sorted = tblApply('adm-dev', items, {
    name: d => d.my_name || d.subject || '',
    sess: d => d.sessions || 0,
    bytes: d => (d.bytes_up || 0) + (d.bytes_down || 0),
    last: d => d.last_seen || '',
  });
  if (!AgTbl.sortState('adm-dev')) {
    sorted.sort((a, b) => (b.online - a.online) || String(b.last_seen || '').localeCompare(String(a.last_seen || '')));
  }
  items = sorted;
  const sig = JSON.stringify([items, q, S.devState, tblSig('adm-dev')]);
  if (sig === body.dataset.sig) return;
  body.dataset.sig = sig;
  body.innerHTML = items.map(d =>
    '<tr><td><span class="dot ' + (d.online ? 'on' : 'off') + '"></span>' + devNameHtml(d.device_fp, d.my_name || d.subject) +
      '<div style="margin-top:2px">' + agcopy(d.device_fp, d.short_fp || (d.device_fp || '').slice(0, 12)) + '</div>' +
      (d.subject ? '<div style="color:var(--dim2);font-size:12px">' + esc(d.subject) + (d.remark ? ' · ' + esc(d.remark) : '') + '</div>' : (d.remark ? '<div style="color:var(--dim2);font-size:12px">' + esc(d.remark) + '</div>' : '')) + '</td>' +
    '<td>' + devStateBadge(d.state) + '</td>' +
    '<td>' + T('adm.countN', { n: d.sessions || 0 }) + '</td>' +
    '<td class="mono" style="color:var(--dim)">↑ ' + fmtBytes(d.bytes_up) + ' ↓ ' + fmtBytes(d.bytes_down) + '</td>' +
    '<td style="color:var(--dim)">' + esc((d.last_seen || '').replace('T', ' ').replace('Z', '') || T('common.never')) + '</td>' +
    '<td style="white-space:nowrap">' +
      (d.state === 'pending' ? '<button class="ghost small" data-act="dev-certify" data-fp="' + esc(d.device_fp) + '">' + T('dev.certify') + '</button> ' : '') +
      '<button class="ghost small" data-act="dev-open" data-fp="' + esc(d.device_fp) + '">' + T('groups.detail') + '</button></td></tr>'
  ).join('') || '<tr><td colspan="6" class="empty">' + T('dev.empty') + '</td></tr>';
  tblAttach('dev-body', {
    key: 'adm-dev',
    sort: { 0: 'name', 2: 'sess', 3: 'bytes', 4: 'last' },
    onSort: () => { body.dataset.sig = ''; renderDeviceRows(); },
  });
}
async function renderDeviceDetail() {
  const fp = S.devFp;
  $('view').innerHTML = '<div class="page-title">' + ic('monitor-smartphone', 20) + T('dev.detailTitle') + '<div class="spacer"></div><button class="ghost small" id="dev-back">' + ic('chevron-right', 13) + ' ' + T('common.back') + '</button></div>' +
    '<div class="card" id="dev-hero"></div>' +
    '<div class="stat-grid" id="dev-kpis"></div>' +
    '<div class="card"><h3>' + T('dev.sessTitle') + '</h3><div class="table-wrap"><table><thead><tr><th>IP</th><th>' + T('sess.col.ago') + '</th><th>' + T('sess.col.tr') + '</th><th>' + T('sess.col.chans') + '</th><th>' + T('sess.col.key') + '</th><th>' + T('common.action') + '</th></tr></thead><tbody id="dev-sess"></tbody></table></div></div>' +
    '<div class="card"><h3>' + T('dev.trafficTitle') + '</h3>' +
      '<div class="sess-toolbar" style="border:none;padding:0 0 8px"><div class="op" id="dev-tr-range">' +
        '<button class="ghost small" data-range="24h">24h</button><button class="ghost small" data-range="7d">7d</button><button class="ghost small" data-range="30d">30d</button></div></div>' +
      '<div id="dev-traffic"></div></div>' +
    '<div class="card"><h3>' + T('dev.heatTitle') + ahelp(T('dev.heatHelp')) + '</h3><div id="dev-heat"></div></div>' +
    '<div class="card"><h3>' + T('dev.histTitle') + '</h3><div class="table-wrap"><table><thead><tr><th>' + T('sess.col.entry') + '</th><th>IP</th><th>' + T('sess.col.start') + '</th><th>' + T('sess.col.tr') + '</th><th>' + T('sess.col.close') + '</th></tr></thead><tbody id="dev-hist"></tbody></table></div></div>' +
    '<div class="card"><h3>' + T('dev.eventsTitle') + '</h3><div class="agtimeline" id="dev-events"></div></div>';
  $('dev-back').onclick = () => { S.devFp = ''; S.timers.forEach(clearInterval); S.timers = []; renderDevices(); };
  $('dev-tr-range').querySelectorAll('button').forEach(b => b.onclick = () => {
    S.devRange = b.dataset.range;
    $('dev-tr-range').querySelectorAll('button').forEach(x => x.classList.toggle('on', x === b));
    loadDeviceTraffic();
  });
  await loadDeviceDetail();
  loadDeviceCharts();
  S.timers.push(setInterval(loadDeviceDetail, 8000));
}
async function loadDeviceDetail() {
  const hero = $('dev-hero'); if (!hero || !S.devFp) return;
  if (document.hidden) return;
  let d;
  try { d = await api('GET', '/api/v1/admin/devices/' + encodeURIComponent(S.devFp)); }
  catch (e) { toast(e.message, 'err'); S.devFp = ''; renderDevices(); return; }
  if (!hero.isConnected) return; // view switched while the fetch was in flight
  const sig = JSON.stringify([d, tblSig('adm-devsess')]);
  if (sig === hero.dataset.sig) return;
  hero.dataset.sig = sig;
  const online = (d.sessions || []).length;
  const acts =
    (d.state === 'pending' ? '<button data-act="dev-certify" data-fp="' + esc(d.device_fp) + '">' + ic('stamp', 14) + T('dev.certify') + '</button> ' : '') +
    (d.state === 'certified' ? '<button class="ghost" data-act="dev-rebind" data-fp="' + esc(d.device_fp) + '">' + ic('refresh-cw', 14) + T('dev.rebind') + '</button> ' : '') +
    (d.state !== 'revoked' ? '<button class="danger" data-act="dev-revoke" data-fp="' + esc(d.device_fp) + '">' + ic('ban', 14) + T('adm.revoke') + '</button>' : '');
  hero.innerHTML =
    '<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px">' +
      '<b style="font-size:16px">' + esc(d.my_name || d.subject || T('dev.unnamed')) + '</b>' + devStateBadge(d.state) +
      (online ? '<span class="badge b-ok">' + T('dev.onlineN', { n: online }) + '</span>' : '<span class="badge b-info">' + T('dev.offline') + '</span>') +
      '<div class="spacer" style="flex:1"></div>' + acts + '</div>' +
    '<div class="kv"><span class="k">' + T('dev.heroSubject') + '</span><span>' + esc(d.subject || '-') + (d.remark ? ' <span style="color:var(--dim2)">' + esc(d.remark) + '</span>' : '') + '</span></div>' +
    '<div class="kv"><span class="k">' + T('dev.cardFp') + '</span><span>' + agcopy(d.device_fp, d.device_fp) + '</span></div>' +
    (d.openssh ? '<div class="kv"><span class="k">' + T('dev.cardKey') + '</span><span>' + agcopy(d.openssh, d.openssh.slice(0, 42) + '…') + '</span></div>' : '') +
    '<div class="kv"><span class="k">' + T('dev.heroCert') + '</span><span style="color:var(--dim)">' +
      (d.state === 'certified' ? esc((d.certified_by || '-') + ' · ' + (d.certified_at || '')) : '-') + '</span></div>' +
    '<div class="kv"><span class="k">' + T('dev.heroFirst') + '</span><span style="color:var(--dim)">' + esc((d.first_seen || '').replace('T', ' ').replace('Z', '')) + '</span></div>';
  $('dev-kpis').innerHTML =
    agkpi(fmtBytes(d.bytes_up), T('dev.kpiUp')) + agkpi(fmtBytes(d.bytes_down), T('dev.kpiDown')) +
    agkpi(String(online), T('dev.kpiSessions')) +
    agkpi(online ? T('dev.online') : T('dev.offline'), T('dev.kpiOnline')) +
    agkpi(esc((d.last_seen || '-').replace('T', ' ').replace('Z', '')), T('dev.kpiLastSeen'));
  const devSess = tblApply('adm-devsess', d.sessions || [],
    { ago: s => s.online_secs || 0, bytes: s => (s.bytes_up || 0) + (s.bytes_down || 0), chans: s => s.channels || 0 },
    { 0: s => s.ip || '' });
  $('dev-sess').innerHTML = devSess.map(s =>
    '<tr><td class="mono">' + esc(s.ip || '-') + '</td><td style="color:var(--dim)">' + fmtAgo(s.online_secs) + '</td>' +
    '<td class="mono" style="color:var(--dim)">↑ ' + fmtBytes(s.bytes_up) + ' ↓ ' + fmtBytes(s.bytes_down) + '</td>' +
    '<td style="color:var(--dim)">' + (s.channels || 0) + '</td>' +
    '<td>' + agcopy(s.session_key || '', String(s.session_key || '').slice(0, 6)) + '</td>' +
    '<td><button class="danger small" data-act="sess-kick" data-key="' + esc(s.session_key) + '" data-name="' + esc(d.my_name || '') + '">' + T('sess.kick') + '</button></td></tr>'
  ).join('') || '<tr><td colspan="6" class="empty">' + T('sess.empty') + '</td></tr>';
  tblAttach('dev-sess', {
    key: 'adm-devsess',
    sort: { 1: 'ago', 2: 'bytes', 3: 'chans' },
    filter: { 0: { label: 'IP' } },
    onSort: () => loadDeviceDetail(),
    onFilter: () => loadDeviceDetail(),
  });
}
/* KPI card helper (.agkpi, M3-T7): value + label + optional delta slot ({dir: up|down|flat, text}) */
function agkpi(value, label, delta) {
  return '<div class="agkpi"><div class="agkpi-v">' + value +
    (delta ? ' <span class="agkpi-d ' + esc(delta.dir || 'flat') + '">' + ic('trending-up', 11) + esc(delta.text) + '</span>' : '') +
    '</div><div class="agkpi-k">' + esc(label) + '</div></div>';
}
/* ---- device profile extras (M5-T4): traffic series / 7x24 heat / session history / events ---- */
function loadDeviceCharts() {
  S.devRange = S.devRange || '24h';
  loadDeviceTraffic();
  loadDeviceActivity();
  loadDeviceHistory();
  loadDeviceEvents();
}
async function loadDeviceTraffic() {
  const el = $('dev-traffic'); if (!el || !S.devFp) return;
  try {
    const d = await api('GET', '/api/v1/admin/devices/' + encodeURIComponent(S.devFp) + '/traffic?range=' + (S.devRange || '24h'));
    const rows = d.series || [];
    AgChart.line(el, {
      x: rows.map(r => r.ts),
      series: [
        { name: T('dev.kpiUp'), values: rows.map(r => r.up) },
        { name: T('dev.kpiDown'), values: rows.map(r => r.down) },
      ],
      fmtX: ts => {
        const dt = new Date(ts * 1000);
        return (S.devRange === '24h')
          ? String(dt.getHours()).padStart(2, '0') + ':' + String(dt.getMinutes()).padStart(2, '0')
          : (dt.getMonth() + 1) + '/' + dt.getDate();
      },
      fmtY: v => fmtBytes(v),
      empty: T('common.empty'),
    });
  } catch (e) { /* chart area stays empty on fetch failure */ }
}
async function loadDeviceActivity() {
  const el = $('dev-heat'); if (!el || !S.devFp) return;
  try {
    const d = await api('GET', '/api/v1/admin/devices/' + encodeURIComponent(S.devFp) + '/activity');
    // cells: [{weekday, hours:[{sessions, bytes}×24]}] → flat 7×24 byte totals
    const vals = [];
    (d.cells || []).forEach(day => (day.hours || []).forEach(h => vals.push(h.bytes || 0)));
    AgChart.heat(el, { values: vals, fmtV: v => fmtBytes(v) });
  } catch (e) { /* keep empty */ }
}
async function loadDeviceHistory() {
  const body = $('dev-hist'); if (!body || !S.devFp) return;
  try {
    const d = await api('GET', '/api/v1/admin/devices/' + encodeURIComponent(S.devFp) + '/sessions');
    const items = tblApply('adm-devhist', d.items || [],
      { start: r => r.started_at || '', bytes: r => (r.bytes_up || 0) + (r.bytes_down || 0) },
      { 0: r => r.entry || '', 1: r => r.ip || '' });
    body.innerHTML = items.map(r =>
      '<tr><td><span class="badge b-info">' + esc(r.entry || '-') + '</span></td>' +
      '<td class="mono" style="color:var(--dim)">' + esc(r.ip || '-') + '</td>' +
      '<td style="color:var(--dim)">' + esc((r.started_at || '').replace('T', ' ')) + '</td>' +
      '<td class="mono" style="color:var(--dim)">↑ ' + fmtBytes(r.bytes_up) + ' ↓ ' + fmtBytes(r.bytes_down) + '</td>' +
      '<td style="color:var(--dim)">' + (r.close_reason ? esc(reasonText(r.close_reason)) : '-') + '</td></tr>'
    ).join('') || '<tr><td colspan="5" class="empty">' + T('common.empty') + '</td></tr>';
    tblAttach('dev-hist', {
      key: 'adm-devhist',
      sort: { 2: 'start', 3: 'bytes' },
      filter: {
        0: { label: 'sess.col.entry', type: 'enum', options: [
          { v: 'direct', label: 'deleg.badgeDirect' }, { v: 'relay', label: 'deleg.badgeRelay' }] },
        1: { label: 'IP' },
      },
      onSort: () => loadDeviceHistory(),
      onFilter: () => loadDeviceHistory(),
    });
  } catch (e) { /* keep empty */ }
}
async function loadDeviceEvents() {
  const el = $('dev-events'); if (!el || !S.devFp) return;
  try {
    const d = await api('GET', '/api/v1/admin/devices/' + encodeURIComponent(S.devFp) + '/events');
    el.innerHTML = (d.items || []).map(ev => {
      const cls = ev.kind === 'approval' ? 'warn' : '';
      return '<div class="agtl-item ' + cls + '"><div class="agtl-time">' + esc((ev.ts || '').replace('T', ' ').replace('Z', '')) + '</div>' +
        '<div class="agtl-body"><b>' + esc(ev.title) + '</b>' +
        (ev.detail ? ' <span style="color:var(--dim2)">' + esc(String(ev.detail).slice(0, 120)) + '</span>' : '') + '</div></div>';
    }).join('') || '<div class="empty">' + T('common.empty') + '</div>';
  } catch (e) { /* keep empty */ }
}
async function openCertify(fp) {
  const d = DEV_MAP[fp] || {};
  openModal(T('dev.certifyTitle'),
    '<label>' + T('dev.certifySubject') + '</label><input id="cfy-subject" style="width:100%" value="' + esc(d.subject || '') + '" placeholder="' + T('dev.certifySubjectPh') + '">' +
    '<label>' + T('dev.certifyRemark') + '</label><input id="cfy-remark" style="width:100%" value="' + esc(d.remark || '') + '">',
    [
      { label: T('common.cancel'), kind: 'ghost', fn: closeModal },
      { label: T('dev.certify'), fn: async () => {
        const subject = $('cfy-subject').value.trim();
        if (!subject) { toast(T('dev.certifyNeedSubject'), 'err'); return; }
        try {
          await api('POST', '/api/v1/admin/devices/' + encodeURIComponent(fp) + '/certify', { subject, remark: $('cfy-remark').value.trim() });
          closeModal(); toast(T('dev.certifyDone'), 'ok');
          DEV_CARD_CACHE.delete(fp);
          await loadDevices(); renderDeviceRows(); if (S.devFp) loadDeviceDetail();
          refreshApprovalsBadge();
        } catch (e) { toast(e.message, 'err'); }
      } },
    ]);
}
function openRevoke(fp) {
  const d = DEV_MAP[fp] || {};
  openModal(T('dev.revokeTitle'),
    '<p style="color:var(--danger-text)">' + ic('triangle-alert', 13) + ' ' + T('dev.revokeWarn') + '</p>' +
    '<label>' + T('sess.kickMsg') + '</label><input id="revoke-msg" style="width:100%" placeholder="' + T('sess.kickMsgPh') + '">',
    [
      { label: T('common.cancel'), kind: 'ghost', fn: closeModal },
      { label: T('adm.revoke'), kind: 'danger', fn: async () => {
        const msg = $('revoke-msg').value.trim(); closeModal();
        try {
          const r = await api('POST', '/api/v1/admin/devices/' + encodeURIComponent(fp) + '/revoke', { message: msg });
          toast(T('dev.revokeDone', { n: r.kicked || 0 }), 'ok');
          DEV_CARD_CACHE.delete(fp);
          await loadDevices(); renderDeviceRows(); if (S.devFp) loadDeviceDetail();
        } catch (e) { toast(e.message, 'err'); }
      } },
    ]);
}
async function openRebind(oldFp) {
  let pend = [];
  try { pend = (await api('GET', '/api/v1/admin/devices?state=pending')).items || []; }
  catch (e) { toast(e.message, 'err'); return; }
  if (!pend.length) { toast(T('dev.rebindEmpty'), 'err'); return; }
  const old = DEV_MAP[oldFp] || {};
  openModal(T('dev.rebindTitle'),
    '<p style="color:var(--dim)">' + T('dev.rebindHint', { name: old.my_name || old.subject || (oldFp || '').slice(0, 12) }) + '</p>' +
    '<div class="rule-check" style="max-height:180px">' + pend.map((p, i) =>
      '<label><input type="radio" name="rebind-new" value="' + esc(p.device_fp) + '"' + (i === 0 ? ' checked' : '') + '>' +
      '<span><b>' + esc(p.my_name || p.subject || T('dev.unnamed')) + '</b> <span class="mono" style="color:var(--dim2)">' + esc(p.short_fp || '') + '</span></span>' +
      '<span style="color:var(--dim)">' + esc((p.first_seen || '').replace('T', ' ').replace('Z', '')) + '</span></label>').join('') + '</div>' +
    '<label>' + T('sess.kickMsg') + '</label><input id="rebind-msg" style="width:100%" placeholder="' + T('sess.kickMsgPh') + '">',
    [
      { label: T('common.cancel'), kind: 'ghost', fn: closeModal },
      { label: T('dev.rebind'), kind: 'danger', fn: async () => {
        const sel = document.querySelector('input[name="rebind-new"]:checked');
        if (!sel) return;
        const msg = $('rebind-msg').value.trim(); closeModal();
        try {
          const r = await api('POST', '/api/v1/admin/devices/rebind', { old_fp: oldFp, new_fp: sel.value, message: msg });
          toast(T('dev.rebindDone', { n: r.kicked || 0 }), 'ok');
          DEV_CARD_CACHE.delete(oldFp); DEV_CARD_CACHE.delete(sel.value);
          S.devFp = '';
          await loadDevices(); renderDevices();
        } catch (e) { toast(e.message, 'err'); }
      } },
    ]);
}

/* ================= Approval center (node.md M3-T4) ================= */
let APPR_ITEMS = []; // latest loaded list (approve dialog prefills subject/remark from the request detail)
async function renderApprovals() {
  $('view').innerHTML = '<div class="page-title">' + ic('stamp', 20) + T('appr.title') + '</div><div class="page-desc">' + T('appr.desc') + '</div>' +
    '<div class="toolbar"><select id="appr-state">' +
      ['pending', 'all', 'approved', 'rejected'].map(v =>
        '<option value="' + v + '"' + (S.apprState === v ? ' selected' : '') + '>' + T('appr.f' + v.charAt(0).toUpperCase() + v.slice(1)) + '</option>').join('') +
    '</select><input id="appr-search" style="flex:1;min-width:200px" placeholder="' + esc(T('appr.searchPh')) + '" value="' + esc(S.apprSearch || '') + '"></div><div id="appr-list"></div>';
  agSelectEnhance($('view'));
  $('appr-state').onchange = (e) => { S.apprState = e.target.value; loadApprovals(); };
  $('appr-search').oninput = (e) => { S.apprSearch = e.target.value; renderApprList(); };
  await loadApprovals();
  S.timers.push(setInterval(loadApprovals, 12000));
}
function apprTypeBadge(t) {
  const m = ({ device_certify: 'appr.typeCertify', device_rebind: 'appr.typeRebind' })[t];
  return '<span class="badge b-info">' + (m ? T(m) : esc(t)) + '</span>';
}
function apprStateBadge(st) {
  const m = ({ pending: ['b-warn', 'appr.stPending'], approved: ['b-ok', 'appr.stApproved'], rejected: ['b-off', 'appr.stRejected'] })[st] || ['b-info', ''];
  return '<span class="badge ' + m[0] + '">' + (m[1] ? T(m[1]) : esc(st)) + '</span>';
}
async function loadApprovals() {
  const box = $('appr-list'); if (!box) return;
  if (document.hidden) return;
  const qs = S.apprState === 'all' ? '' : '?state=' + S.apprState;
  let items;
  try { items = (await api('GET', '/api/v1/admin/approvals' + qs)).items || []; }
  catch (e) { toast(e.message, 'err'); return; }
  APPR_ITEMS = items;
  renderApprList();
}
/* Keyword filter (holder / fingerprint / subject / appeal+notice bodies) over the fetched page;
   the sig folds the keyword so typing re-renders exactly once per change. */
function apprMatches(a, kw) {
  const dt = a.detail || {};
  const hay = [a.requester, a.object_ref, a.type, dt.subject, dt.my_name, dt.new_fp, dt.ip]
    .concat((a.messages || []).map(m => m.body))
    .filter(Boolean).join(' ').toLowerCase();
  return hay.includes(kw);
}
function renderApprList() {
  const box = $('appr-list'); if (!box) return;
  const kw = (S.apprSearch || '').trim().toLowerCase();
  const items = kw ? APPR_ITEMS.filter(a => apprMatches(a, kw)) : APPR_ITEMS;
  const sig = JSON.stringify([items, kw]);
  if (sig === box.dataset.sig) return;
  box.dataset.sig = sig;
  box.innerHTML = items.map(a => {
    const dt = a.detail || {};
    const fp = a.object_ref || '';
    const detailBits = [];
    if (dt.my_name) detailBits.push(T('appr.detailName') + ' ' + esc(dt.my_name));
    if (dt.ip) detailBits.push('IP ' + esc(dt.ip));
    if (dt.subject) detailBits.push(T('appr.detailSubject') + ' ' + esc(dt.subject));
    if (dt.new_fp) detailBits.push(T('appr.detailNew') + ' ' + esc(String(dt.new_fp).slice(0, 12)));
    const msgs = (a.messages || []).map(m =>
      '<div class="kv"><span class="k">' + (m.direction === 'appeal' ? T('appr.msgAppeal') : T('appr.msgNotice')) + '</span>' +
      '<span style="text-align:right">' + esc(m.body || '') + ' <span style="color:var(--dim2)">' + esc((m.created_at || '').replace('T', ' ').replace(/\..*$/, '')) + '</span></span></div>').join('');
    const acts = a.state === 'pending'
      ? '<div class="actions" style="display:flex;gap:8px;justify-content:flex-end;margin-top:10px">' +
        '<button data-act="appr-approve" data-id="' + esc(a.id) + '">' + ic('check', 13) + T('appr.approve') + '</button> ' +
        '<button class="ghost" data-act="appr-reject" data-id="' + esc(a.id) + '">' + T('appr.reject') + '</button> ' +
        '<button class="danger" data-act="appr-reject-revoke" data-id="' + esc(a.id) + '">' + ic('ban', 13) + T('appr.rejectRevoke') + '</button></div>'
      : '<div class="hint" style="margin-top:8px">' + T('appr.decidedBy', { by: a.decided_by || '-', at: (a.decided_at || '').replace('T', ' ').replace(/\..*$/, '') }) + '</div>' +
        // accidental-reject recovery: a rejected (non-revoked) item can return to pending
        (a.state === 'rejected'
          ? '<div class="actions" style="display:flex;gap:8px;justify-content:flex-end;margin-top:6px">' +
            '<button class="ghost" data-act="appr-reopen" data-id="' + esc(a.id) + '">' + ic('rotate-ccw', 13) + T('appr.reopen') + '</button></div>'
          : '');
    return '<div class="card">' +
      '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' + apprTypeBadge(a.type) + apprStateBadge(a.state) +
        '<b>' + esc(a.requester || '-') + '</b>' +
        (fp ? devNameHtml(fp, (fp || '').slice(0, 12)) : '') +
        '<div class="spacer" style="flex:1"></div><span style="color:var(--dim2);font-size:12px">' + esc((a.created_at || '').replace('T', ' ').replace(/\..*$/, '')) + '</span></div>' +
      (detailBits.length ? '<div class="hint" style="margin-top:6px">' + detailBits.join(' · ') + '</div>' : '') +
      msgs + acts + '</div>';
  }).join('') || '<div class="card"><div class="empty">' + T('appr.empty') + '</div></div>';
}
async function reopenApproval(id) {
  try {
    await api('POST', '/api/v1/admin/approvals/' + encodeURIComponent(id) + '/decide', { action: 'reopen' });
    toast(T('appr.reopened'), 'ok');
    loadApprovals(); refreshApprovalsBadge();
  } catch (e) { toast(e.message, 'err'); }
}
function openDecide(id, action) {
  const close = { label: T('common.cancel'), kind: 'ghost', fn: closeModal };
  const post = async (body) => {
    try {
      await api('POST', '/api/v1/admin/approvals/' + encodeURIComponent(id) + '/decide', body);
      toast(T('appr.done'), 'ok');
      closeModal();
      loadApprovals(); refreshApprovalsBadge(); loadDevices();
    } catch (e) { toast(e.message, 'err'); }
  };
  if (action === 'approve') {
    const it = APPR_ITEMS.find(a => a.id === id) || {};
    const dt = it.detail || {};
    openModal(T('appr.approveTitle'),
      '<label>' + T('dev.certifySubject') + '</label><input id="dc-subject" style="width:100%" value="' + esc(dt.subject || '') + '">' +
      '<label>' + T('dev.certifyRemark') + '</label><input id="dc-remark" style="width:100%" value="' + esc(dt.remark || '') + '">',
      [close, { label: T('appr.approve'), fn: () => {
        const subject = $('dc-subject').value.trim();
        if (!subject) { toast(T('dev.certifyNeedSubject'), 'err'); return; }
        post({ action, subject, remark: $('dc-remark').value.trim() });
      } }]);
    return;
  }
  const revoke = action === 'reject_revoke';
  openModal(revoke ? T('appr.rejectRevokeTitle') : T('appr.rejectTitle'),
    (revoke ? '<p style="color:var(--danger-text)">' + ic('triangle-alert', 13) + ' ' + T('appr.rejectRevokeWarn') + '</p>' : '') +
    '<label>' + T('appr.notice') + ' ' + ahelp(T('appr.noticeTip')) + '</label><input id="dc-notice" style="width:100%">',
    [close, { label: revoke ? T('appr.rejectRevoke') : T('appr.reject'), kind: 'danger', fn: () => post({ action, notice: $('dc-notice').value.trim() }) }]);
}
/* Sidebar pending-count badge: global poller (survives view switches), boosted by WS approval.new */
async function refreshApprovalsBadge() {
  const b = $('nav-approvals-badge'); if (!b) return;
  try {
    const d = await api('GET', '/api/v1/admin/approvals?state=pending');
    const n = (d.items || []).length;
    b.hidden = n === 0;
    b.textContent = n > 99 ? '99+' : String(n);
  } catch (e) { /* badge failure is silent */ }
}

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
      const L = st.roles.listener, CS = st.roles.connectors || [], P = st.proxy;
      const fanoutSub = CS.length
        ? CS.map(c => '<div class="mono">' + esc(c.upstream) + ' <span class="badge ' +
            (c.status === 'connected' ? 'b-ok' : (c.status === 'disconnected' ? 'b-off' : 'b-warn')) + '">' +
            esc(connStatusText(c.status)) + '</span></div>').join('')
        : '-';
      // Local proxy sub-line: with mode (client proxy slot) → mode + listen; otherwise the node's proxy_listen wording
      const proxySub = P.mode
        ? esc(proxyModeText(P.mode)) + (P.enabled && P.listen ? ' · ' + esc(P.listen) : '')
        : (P.enabled ? esc(P.listen) + ' · ' + T('dashboard.proxyStats', { active: P.active_connections||0, rules: P.rule_count||0 }) : T('dashboard.proxyRules', { n: P.rule_count||0 }));
      let cards =
        statCard(T('dashboard.cardName'), esc(st.node_name), 'v' + esc(st.version) + ' · ' + T('dashboard.uptime', { up: fmtUptime(st.uptime) }), 'settings') +
        statCard(T('dashboard.cardRelay'), L.enabled ? '<span class="badge b-ok">' + T('adm.stOn') + '</span>' : '<span class="badge b-off">' + T('adm.stNotOn') + '</span>',
          L.enabled ? esc(L.addr) + ' · ' + T('dashboard.relaySub', { peers: L.connected_connectors||0, clients: L.online_clients||0 }) : '-', 'fanin') +
        statCard(T('dashboard.cardFanout'), CS.length ? '<span class="badge b-ok">' + T('dashboard.connCount', { n: CS.length }) + '</span>' : '<span class="badge b-off">' + T('dashboard.noFanout') + '</span>', fanoutSub, 'connectors') +
        statCard(T('dashboard.cardProxy'), P.enabled ? '<span class="badge b-ok">' + T('adm.stOn') + '</span>' : '<span class="badge b-off">' + T('adm.stNotOn') + '</span>', proxySub, 'settings') +
        statCard(T('dashboard.cardSystem'), (st.system.memory_mb||0) + ' MB', T('dashboard.sysSub', { cpu: (st.system.cpu_usage||0).toFixed(1), mem: st.system.total_memory_mb||0 }));
      if (L.enabled && (L.peers||[]).length) {
        const names = L.peer_names || {};
        cards += statCard(T('dashboard.cardPeers'), (L.peers||[]).map(p => '<div class="mono"><span class="dot on"></span>' + esc(names[p] || p) + '</div>').join(''), '');
      }
      $('dash-stats').innerHTML = cards;
      // Three traffic cards: fan-in (today + 24h trend) / fan-out (totals + per-item details) / relay path (totals + pairs)
      updateTfCards(st);
      // Trend chart: merged up/down of the three traffic_24h dimensions (fan-in + fan-out + transit), no separate stats endpoint
      const t24 = st.traffic_24h || {};
      const hours = new Set();
      ['fanin', 'fanout', 'transit'].forEach(k => (Array.isArray(t24[k]) ? t24[k] : []).forEach(p => hours.add(String(p.hour || ''))));
      const xs = [...hours].filter(Boolean).sort();
      const dimSum = (f) => xs.map(h => ['fanin', 'fanout', 'transit']
        .reduce((acc, k) => acc + (+(((Array.isArray(t24[k]) ? t24[k] : []).find(p => String(p.hour || '') === h) || {})[f]) || 0), 0));
      AgChart.line($('traffic-chart'), {
        x: xs,
        series: [
          { name: 'RX', values: dimSum('down') },
          { name: 'TX', values: dimSum('up') },
        ],
        fmtY: fmtBytes,
        fmtX: h => String(h || '').slice(11, 16),
        empty: T('dashboard.chartEmpty'),
      });
    } catch(e) { toast(e.message, 'err'); }
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
        // Approval center: instant badge + list refresh (M3-T4); the event feed below still prints it
        if (e.type === 'approval.new') {
          refreshApprovalsBadge();
          if (S.view === 'approvals') loadApprovals();
          if (S.view === 'devices') { loadDevices().then(renderDeviceRows); }
        }
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
    l: (R.listener.peer_names || {})[p.node_id] || p.node_id, v: tfUpDown(p.bytes_up, p.bytes_down),
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


/* ================= Groups ================= */
async function renderGroups() {
  $('view').innerHTML = '<div class="page-title">' + ic('shield', 20) + T('term.group') + '</div><div class="page-desc">' + T('groups.desc') + '</div>' +
    '<div class="toolbar"><input id="grp-q" placeholder="' + T('groups.searchPh') + '" value="' + esc(S.filter.groups||'') + '">' +
    '<div class="spacer"></div><button class="ghost" id="grp-adopt">' + ic('download', 15) + T('groups.adopt') + '</button><button id="grp-create">' + ic('plus', 15) + T('groups.create') + '</button></div>' +
    '<div class="card table-wrap"><table><thead><tr><th>' + T('common.name') + '</th><th>' + T('groups.colRules') + '</th><th>' + T('common.remark') + '</th><th>' + T('common.action') + '</th></tr></thead><tbody id="grp-body"></tbody></table><div id="grp-pager"></div></div>';
  $('grp-q').oninput = (e) => { S.filter.groups = e.target.value; S.page.groups = 1; renderGroups(); };
  $('grp-adopt').onclick = openAdoptCenter;
  $('grp-create').onclick = openCreateGroup;
  await loadGroups();
}
async function loadGroups() {
  const body = $('grp-body'); if (!body) return;
  let url = '/api/v1/admin/groups?page=' + S.page.groups + '&page_size=' + S.size.groups;
  if (S.filter.groups) url += '&q=' + encodeURIComponent(S.filter.groups);
  const st = AgTbl.sortState('adm-groups');
  if (st) url += '&sort=' + encodeURIComponent(st.id + ':' + st.dir);
  try {
    const d = await api('GET', url);
    body.innerHTML = (d.items||[]).map(g => {
      const adopted = !!g.adopted_node;
      const nameCell = '<b>' + esc(g.name) + '</b>' + (g.e2e_required ? ' <span class="badge b-warn" title="' + T('groups.e2e') + '">E2E</span>' : '') +
        (adopted ? ' ' + srcBadge(g.adopted_node, T('groups.adoptedTip', { node: g.adopted_node, src: g.adopted_name })) : '') +
        '<div class="mono" style="color:var(--dim2)">' + shortId(g.id) + '</div>';
      // adopted groups are read-only mirrors: 绑定/编辑 swap for 复制 (detach into an editable group)
      const ops = adopted
        ? '<button class="ghost small" data-act="grp-detail" data-id="' + esc(g.id) + '">' + T('groups.detail') + '</button> ' +
          '<button class="ghost small" data-act="grp-copy" data-id="' + esc(g.id) + '" data-name="' + esc(g.name) + '">' + T('groups.copy') + '</button> ' +
          '<button class="danger small" data-act="grp-del" data-id="' + esc(g.id) + '" data-name="' + esc(g.name) + '">' + T('common.delete') + '</button>'
        : '<button class="ghost small" data-act="grp-detail" data-id="' + esc(g.id) + '">' + T('groups.detail') + '</button> ' +
          '<button class="ghost small" data-act="grp-bind" data-id="' + esc(g.id) + '" data-name="' + esc(g.name) + '">' + T('groups.bind') + '</button> ' +
          '<button class="ghost small" data-act="grp-edit" data-id="' + esc(g.id) + '" data-name="' + esc(g.name) + '" data-remark="' + esc(g.remark||'') + '" data-e2e="' + (g.e2e_required ? '1' : '') + '">' + T('common.edit') + '</button> ' +
          '<button class="danger small" data-act="grp-del" data-id="' + esc(g.id) + '" data-name="' + esc(g.name) + '">' + T('common.delete') + '</button>';
      return '<tr><td>' + nameCell + '</td>' +
        '<td><span class="badge b-info">' + g.rule_count + '</span></td>' +
        '<td style="color:var(--dim)">' + esc(g.remark || '-') + '</td>' +
        '<td style="white-space:nowrap">' + ops + '</td></tr>';
    }).join('') || '<tr><td colspan="4" class="empty">' + T('groups.empty') + '</td></tr>';
    $('grp-pager').innerHTML = pager('groups', d.total||0);
    tblAttach('grp-body', {
      key: 'adm-groups',
      sort: { 0: 'name', 1: 'rules' }, // server-side (paged); 备注/操作不按业务排序
      onSort: () => { S.page.groups = 1; loadGroups(); },
    });
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
async function delGroup(id, name) {
  confirmAction(T('groups.delConfirm', { name }), async () => {
    try { await api('DELETE', '/api/v1/admin/groups/' + id); toast(T('adm.deleted'), 'ok'); loadGroupsCache(); loadGroups(); }
    catch(e) { toast(e.message, 'err'); }
  });
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
  const st = AgTbl.sortState('adm-rules');
  if (st) url += '&sort=' + encodeURIComponent(st.id + ':' + st.dir);
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
    tblAttach('rule-body', {
      key: 'adm-rules',
      sort: { 0: 'type', 1: 'value', 3: 'groups' }, // server-side (paged); 解析/备注/操作不按业务排序
      onSort: () => { S.page.rules = 1; loadRules(); },
    });
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
let FANIN_NAMES = {}; // node_id → issuer-assigned display name (token remark; falls back to node_id)
let FANIN_TOKENS = [];
/* Authorizable pool cache (federation P1): node_id -> { advertise, groups } (fetched with the fan-in status) */
let FED_OFFERS = {};
async function renderFanIn() {
  const tab = S.faninTab;
  $('view').innerHTML = '<div class="page-title">' + ic('orbit', 20) + T('term.fanin') + '</div><div class="page-desc">' + T('fanin.admDesc') + '</div>' +
    '<div class="agtabs" id="fanin-tabs">' +
      '<div class="agtabs-pill">' +
        '<button class="agtab' + (tab === 'listen' ? ' active' : '') + '" data-agtab="listen">' + T('adm.tabListen') + '</button>' +
        '<button class="agtab' + (tab === 'peers' ? ' active' : '') + '" data-agtab="peers">' + T('adm.tabConns') + '</button>' +
        '<button class="agtab' + (tab === 'tokens' ? ' active' : '') + '" data-agtab="tokens">' + T('adm.tabIssue') + '</button>' +
      '</div>' +
      '<div class="agtabs-tools"><input id="fanin-q" style="width:230px" placeholder="' + T('fanin.admSearchPh') + '" value="' + esc(S.faninQuery) + '"' + (tab === 'listen' ? ' hidden' : '') + '></div>' +
    '</div>' +
    '<div data-agpanel="listen"><div class="card"><h3>' + T('fanin.listenerTitle') + '</h3><div id="fanin-listener"></div></div></div>' +
    '<div data-agpanel="peers" hidden><div class="card card-flush"><h3>' + T('fanin.peersTitle') + ahelp(T('sess.peersHelp')) + '</h3><div id="fanin-peers"></div></div></div>' +
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
  await Promise.all([loadFaninStatus(), loadTokens(), reloadSessions()]);
  S.timers.push(setInterval(() => { loadFaninStatus(); reloadSessions(); }, 10000));
}
/* Listener card + peers table share roles.listener: single fetch, single-signature change detection (no DOM rewrite when unchanged) */
async function loadFaninStatus() {
  const box = $('fanin-listener'); if (!box) return;
  let st;
  try { st = await api('GET', '/api/v1/admin/node/status'); }
  catch(e) { toast(e.message, 'err'); return; }
  const fp = st.cert_fingerprint || '';
  let L = st.roles.listener;
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
  const sig = JSON.stringify({ L, fp });
  if (sig === box.dataset.sig && !poolChanged) return;
  box.dataset.sig = sig;
  if (!L.enabled) {
    box.innerHTML = '<div class="empty">' + T('fanin.listenerOff') + '</div>';
  } else {
    box.innerHTML =
      '<div class="kv"><span class="k">' + T('fanin.addr') + '</span><span class="mono">' + esc(L.addr || '-') + '</span></div>' +
      '<div class="kv"><span class="k">TLS</span><span>' + (L.tls ? '<span class="badge b-ok">' + T('common.enabled') + '</span>' : '<span class="badge b-off">' + T('adm.stNotOn') + '</span>') + '</span></div>' +
      '<div class="kv"><span class="k">' + T('fanin.endpoints') + '</span><span>' + T('fanin.connectedCount', { n: L.connected_connectors || 0 }) + '</span></div>' +
      '<div class="kv"><span class="k">' + T('fanin.onlineClients') + '</span><span>' + T('adm.countN', { n: L.online_clients || 0 }) + '</span></div>' +
      (fp ? '<div class="kv"><span class="k">' + T('set.certFp') + '</span><span class="mono" style="font-size:11px;word-break:break-all">' + esc(fp) +
        ' <button class="ghost small" data-act="copy" data-copy="' + esc(fp) + '">' + ic('copy', 13) + T('common.copy') + '</button></span></div>' : '');
  }
  const traffic = L.enabled ? (L.peer_traffic || []) : [];
  const peers = L.enabled ? (L.peers || []) : [];
  FANIN_NAMES = (L.enabled && L.peer_names) || {};
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
  const box = $('fanin-peers'); if (!box) return;
  const q = S.faninQuery.trim().toLowerCase();
  const disp = (id) => FANIN_NAMES[id] || id;
  const rows = q ? FANIN_PEERS.filter(t => ((t.node_id || '') + disp(t.node_id)).toLowerCase().includes(q)) : FANIN_PEERS;
  // Signature covers the row data + live sessions + expansion state: unchanged polls rewrite nothing
  const sig = JSON.stringify({ rows, s: SESS, open: [...SESS_OPEN], off: FED_OFFERS, names: FANIN_NAMES });
  if (sig === box.dataset.sig) return;
  box.dataset.sig = sig;
  // M3-T1 resource rows: one row per fan-in peer (grouped by node_id), expanding to its sessions;
  // the pushed-group pool detail moves into the expansion (always visible while expanded)
  box.innerHTML = rows.map(t => {
    const sessions = SESS.filter(s => s.kind === 'fanin' && s.node_id === t.node_id);
    const o = FED_OFFERS[t.node_id];
    const hasPool = !!(o && ((o.advertise || []).length || (o.groups || []).length));
    const name = disp(t.node_id);
    return sessBlockHtml({
      id: 'peer:' + t.node_id,
      name,
      sub: name !== t.node_id ? t.node_id : '',
      tags: '<span class="mono" style="color:var(--dim2);font-size:11.5px">↑ ' + fmtBytes(t.bytes_up) + ' ↓ ' + fmtBytes(t.bytes_down) + '</span>',
      online: sessions.length,
      cap: 0,
      sessions,
      cols: ['who', 'ip', 'chans', 'ago', 'tr', 'key', 'op'],
      extra: hasPool ? '<div style="padding:4px 14px 10px">' + poolDetailHtml(o) + '</div>' : '',
    });
  }).join('') || '<div class="empty">' + (q ? T('fanin.noMatchPeers') : T('fanin.emptyPeers')) + '</div>';
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
        ? srcBadge(o.node_id, T('groups.adoptedTip', { node: o.node_id, src: g.name })) + ' <span class="hint">' + esc(g.adopted_name || '') + '</span>'
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
  let items = q ? FANIN_TOKENS.filter(t =>
    (t.token_prefix || '').toLowerCase().includes(q) ||
    (t.remark || '').toLowerCase().includes(q) ||
    (t.groups || []).some(g => (g.name || '').toLowerCase().includes(q))
  ) : FANIN_TOKENS;
  // header sort (AgTbl); 前缀/备注/组的搜索走工具栏搜索框（不重复进表头）
  items = tblApply('adm-tok', items, {
    rate: t => t.rate_limit_kbps || 0,
    used: t => t.last_used_at || '',
    created: t => t.created_at || '',
  });
  // Signature guard: polling re-renders only on real change (keeps expanded session rows + dropdowns alive)
  const sig = JSON.stringify([items, q, SESS, [...SESS_OPEN], DEV_MAP, tblSig('adm-tok')]);
  if (sig === body.dataset.sig) return;
  body.dataset.sig = sig;
  body.innerHTML = items.map(t => {
    const key = 'tok:' + t.id;
    // M3-T1: fan-in sessions authenticated with this token (per-session kick + kick-all)
    const sessions = SESS.filter(s => s.kind === 'fanin' && s.token_hash === t.token_hash);
    const sessTr = '<tr ' + sessWrapAttrs(key) + '><td colspan="8" style="background:var(--bg2);padding:0">' +
      sessPanelInner({ name: t.remark || t.token_prefix, sessions, cols: ['who', 'ip', 'chans', 'ago', 'tr', 'key', 'op'], kickallFanin: t.token_hash }) + '</td></tr>';
    return '<tr><td class="mono">' + esc(t.token_prefix) + lifecycleBadge(t) + '</td>' +
    '<td>' + ((t.groups || []).length ? t.groups.map(g => grpChip({ name: g.name, adopted: g.adopted_node })).join(' ') : '<span style="color:var(--dim2)">' + T('adm.noRestrict') + '</span>') + '</td>' +
    '<td class="mono">' + (t.rate_limit_kbps ? esc(t.rate_limit_kbps) + ' KB/s' : '<span style="color:var(--dim2)">' + T('adm.unlimited') + '</span>') + '</td>' +
    '<td>' + esc(t.remark || '-') + '</td>' +
    '<td><label class="chk" style="display:flex;align-items:center;gap:5px"><input type="checkbox" data-act-chg="tok-expose" data-id="' + esc(t.id) + '"' + (t.expose_control ? ' checked' : '') +
      '><span style="font-size:12px">' + T('fanin.allowManage') + '</span></label>' +
      (t.expose_control ? '<select class="ghost small" data-act-chg="tok-scope" data-id="' + esc(t.id) + '">' +
        ['ro','rules','full'].map(sc => '<option value="' + sc + '" ' + (t.control_scope === sc ? 'selected' : '') + '>' + ({ro: T('fanin.scopeRo'), rules: T('fanin.scopeRules'), full: T('fanin.scopeFull')})[sc] + '</option>').join('') + '</select>' : '') + '</td>' +
    '<td style="color:var(--dim)">' + esc(t.last_used_at || T('fanin.unused')) + '</td>' +
    '<td style="color:var(--dim)">' + esc(t.created_at) + '</td>' +
    '<td style="white-space:nowrap"><button class="ghost small" data-act="tok-sess" data-id="' + esc(t.id) + '" data-sessopen="' + esc(key) + '" title="' + T('sess.title') + '">' + ic('chevron-right', 13) + '</button> ' +
    '<button class="ghost small" data-act="tok-edit" data-id="' + esc(t.id) + '" data-group="' + esc(t.group_id||'') + '" data-expose="' + t.expose_control + '" data-scope="' + esc(t.control_scope) + '" data-expires="' + esc(t.expires_at||'') + '" data-maxuses="' + esc(t.max_uses||'') + '" data-rate="' + esc(t.rate_limit_kbps||'') + '" data-remark="' + esc(t.remark||'') + '">' + T('common.edit') + '</button> ' +
    '<button class="danger small" data-act="tok-del" data-id="' + esc(t.id) + '">' + T('adm.revoke') + '</button></td></tr>' + sessTr;
  }).join('') || '<tr><td colspan="8" class="empty">' + (q ? T('fanin.noMatchTokens') : T('fanin.emptyTokens')) + '</td></tr>';
  agSelectEnhance(body);
  tblAttach('tok-body', {
    key: 'adm-tok',
    sort: { 2: 'rate', 5: 'used', 6: 'created' },
    onSort: () => { body.dataset.sig = ''; renderFaninTokens(); },
  });
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
    // M3-T6 naming triplet: target name (local display of the peer) + my name (prefilled into the link's myname word)
    nameTriplet('nt', {}, { remark: false }) +
    '<label>' + T('adm.groupLabel') + '</label>' +
    '<div class="rule-check" style="max-height:130px">' +
      (S.groups.length ? S.groups.map(g =>
        '<label><input type="checkbox" class="nt-acl" value="' + esc(g.id) + '"' + (g.e2e_required ? ' disabled' : '') + '>' +
        '<span>' + esc(g.name) + '</span>' + (g.adopted_node ? ' ' + srcBadge(g.adopted_node) : '') + (g.e2e_required ? '<span class="badge b-warn">E2E</span>' : '<span class="badge b-info">' + (g.rule_count || 0) + '</span>') + '</label>'
      ).join('') : '<div class="empty">' + T('groups.empty') + '</div>') + '</div>' +
    '<label>' + T('fanin.rateLabel') + '</label><input id="nt-rate" type="number" min="1" placeholder="' + T('fanin.ratePh') + '" style="width:100%">' +
    '<div class="hint">' + T('fanin.rateHint') + '</div>' +
    lifecycleFieldsHtml('nt', '', '') +
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
          const life = lifecycleFieldsVal('nt');
          const names = nameTripletVal('nt');
          const d = await api('POST', '/api/v1/admin/node/relay-tokens', {
            remark: names.target,
            my_name: names.myname,
            expose_control: $('nt-expose').checked,
            control_scope: $('nt-scope').value,
            group_id: [...document.querySelectorAll('.nt-acl:checked')].map(c => c.value).join(',') || null,
            rate_limit_kbps: rateVal > 0 ? rateVal : null,
            expires_at: life.expires_at,
            max_uses: life.max_uses,
          });
          openModal(T('fanin.createdTitle'),
            '<div class="kv"><span class="k">' + T('common.remark') + '</span><span>' + esc(d.remark || '-') + '</span></div>' +
            shareCardHtml(d.endpoints) +
            '<div class="hint" style="color:var(--warn)">' + ic('triangle-alert', 13) + ' ' + T('fanin.createdHint') + '</div>',
            [{label: T('share.saved'), fn: () => { closeModal(); loadTokens(); }}]);
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
function openEditToken(id, groupId, exposeControl, controlScope, expiresAt, maxUses, rateKbps, remark) {
  openModal(T('fanin.editTitle'),
    // M3-T6: the target name is the issuer-assigned peer display name (relay_token.remark column)
    nameTriplet('et', { target: remark || '' }, { myname: false, remark: false }) +
    '<label>' + T('adm.groupLabel') + '</label>' +
    '<div class="rule-check" style="max-height:130px">' +
      (S.groups.length ? S.groups.map(g =>
        '<label><input type="checkbox" class="et-acl" value="' + esc(g.id) + '" ' + ((groupId||'').split(',').includes(g.id)?'checked':'') + (g.e2e_required ? ' disabled' : '') + '>' +
        '<span>' + esc(g.name) + '</span>' + (g.adopted_node ? ' ' + srcBadge(g.adopted_node) : '') + (g.e2e_required ? '<span class="badge b-warn">E2E</span>' : '<span class="badge b-info">' + (g.rule_count || 0) + '</span>') + '</label>'
      ).join('') : '<div class="empty">' + T('groups.empty') + '</div>') + '</div>' +
    '<label>' + T('fanin.editRateLabel') + '</label><input id="et-rate" type="number" min="1" value="' + (rateKbps > 0 ? rateKbps : '') + '" placeholder="' + T('adm.unlimited') + '" style="width:100%">' +
    lifecycleFieldsHtml('et', expiresAt, maxUses) +
    '<div class="hint">' + T('fanin.editHint') + '</div>',
    [
      {label: T('common.cancel'), kind:'ghost', fn: closeModal},
      {label: T('common.save'), fn: async () => {
        try {
          const rateVal = parseInt($('et-rate').value, 10);
          const life = lifecycleFieldsVal('et');
          await api('PUT', '/api/v1/admin/node/relay-tokens/' + id, {
            expose_control: exposeControl, control_scope: controlScope,
            remark: nameTripletVal('et').target,
            group_id: [...document.querySelectorAll('.et-acl:checked')].map(c => c.value).join(',') || null,
            rate_limit_kbps: rateVal > 0 ? rateVal : null,
            expires_at: life.expires_at || null,
            max_uses: life.max_uses,
          });
          closeModal(); toast(T('adm.saved'), 'ok'); loadTokens();
        } catch(e) { toast(e.message, 'err'); }
      }},
    ]);
}

/* ================= Fan-out (upstream connectors) + unified issuance (delegated tokens) ================= */
function connStatusBadge(st) {
  return '<span class="badge ' + (st === 'connected' ? 'b-ok' : (st === 'disconnected' ? 'b-off' : 'b-warn')) + '">' +
    esc(connStatusText(st)) + '</span>';
}
async function renderConnectors() {
  const tab = S.fanoutTab;
  $('view').innerHTML = '<div class="page-title">' + ic('git-fork', 20) + T('term.fanout') + '</div><div class="page-desc">' + T('fanout.admDesc') + '</div>' +
    '<div class="agtabs" id="fanout-tabs">' +
      '<div class="agtabs-pill">' +
        '<button class="agtab' + (tab === 'watch' ? ' active' : '') + '" data-agtab="watch">' + T('adm.tabListen') + '</button>' +
        '<button class="agtab' + (tab === 'conns' ? ' active' : '') + '" data-agtab="conns">' + T('adm.tabConns') + '</button>' +
        '<button class="agtab' + (tab === 'issue' ? ' active' : '') + '" data-agtab="issue">' + T('adm.tabIssue') + '</button>' +
      '</div>' +
    '</div>' +
    // watch: consumer activity overview — per issued token, every disaster-set entry with its live state
    '<div data-agpanel="watch" hidden><div class="card"><h3>' + T('deleg.watchTitle') + ahelp(T('deleg.watchHelp')) + '</h3>' +
      '<div class="table-wrap"><table><thead><tr><th>' + T('deleg.colLabel') + '</th><th>' + T('deleg.colEntry') + '</th><th>' + T('deleg.colSet') + '</th><th>' + T('deleg.colConcurrency') + '</th><th>' + T('deleg.colActivity') + '</th><th>' + T('common.createdAt') + '</th><th></th></tr></thead><tbody id="watch-body"></tbody></table></div></div></div>' +
    '<div data-agpanel="conns" hidden>' +
      '<div class="toolbar"><div class="spacer"></div><button class="ghost" id="conn-adopt">' + ic('download', 15) + T('groups.adopt') + '</button><button class="ghost" id="conn-import">' + ic('upload', 15) + T('anet.importBtn') + '</button><button id="conn-create">' + ic('plus', 15) + T('fanout.create') + '</button></div>' +
      '<input type="file" id="conn-import-file" accept=".anet,application/json" style="display:none">' +
      // M3-T1: relay transit block — consumer sessions relayed by THIS machine as a rendezvous
      // (entry=relay; a per-connector mapping does not exist by design, one shared block instead)
      '<div class="card card-flush"><h3>' + T('sess.transitTitle') + ahelp(T('sess.transitHelp')) + '</h3><div id="conns-transit"></div></div>' +
      '<div class="card table-wrap"><table><thead><tr><th>' + T('common.name') + '</th><th>' + T('fanout.colUpstream') + '</th><th>' + T('term.group') + '</th><th>' + T('common.status') + '</th><th>' + T('adm.stOn') + '</th><th>' + T('common.remark') + '</th><th>' + T('common.action') + '</th></tr></thead><tbody id="conn-body"></tbody></table></div>' +
    '</div>' +
    '<div data-agpanel="issue" hidden>' +
      '<div class="toolbar"><div class="hint" style="max-width:560px">' + T('deleg.desc') + '</div><div class="spacer"></div><button id="deleg-issue">' + ic('plus', 15) + T('deleg.issue') + '</button></div>' +
      '<div class="card table-wrap"><table><thead><tr><th>' + T('deleg.colLabel') + '</th><th>' + T('deleg.colGroups') + '</th><th>' + T('common.createdAt') + '</th><th>' + T('common.action') + '</th></tr></thead><tbody id="deleg-body"></tbody></table></div>' +
    '</div>';
  agTabsBind($('fanout-tabs'), (k) => { S.fanoutTab = k; });
  $('conn-adopt').onclick = openAdoptCenter;
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
  await Promise.all([loadConnectors(), loadDelegation(), reloadSessions()]);
  S.timers.push(setInterval(() => { loadConnectors(); loadDelegation(); reloadSessions(); }, 5000));
}
/* M3-T1 relay transit block (fan-out 连接 tab): consumer sessions where this machine was the
   rendezvous (entry=relay). Signature-guarded; expansion state lives in SESS_OPEN. */
function renderConnsSess() {
  const box = $('conns-transit'); if (!box) return;
  const sessions = SESS.filter(s => s.kind === 'consumer' && s.entry === 'relay');
  const sig = JSON.stringify([sessions, [...SESS_OPEN], DEV_MAP]);
  if (sig === box.dataset.sig) return;
  box.dataset.sig = sig;
  box.innerHTML = sessBlockHtml({
    id: 'transit',
    name: T('sess.transitRow'),
    sub: T('sess.transitSub'),
    online: sessions.length,
    cap: 0,
    sessions,
    cols: ['who', 'token', 'ip', 'ago', 'tr', 'key', 'op'],
  });
}
/* Latest fan-out list caches: the watch tab joins both sources (delegation tokens × live connectors)
   without its own fetch; every poll updates the caches and re-renders under signature detection. */
let FANOUT_CONNS = [];
let FANOUT_DELEG = [];
async function loadConnectors() {
  try {
    const d = await api('GET', '/api/v1/admin/connectors');
    FANOUT_CONNS = d.items || [];
  } catch(e) { toast(e.message, 'err'); return; }
  const body = $('conn-body');
  if (body) {
    // header sort + 状态漏斗 (AgTbl); polling change detection covers the header state too
    const items = tblApply('adm-conn', FANOUT_CONNS,
      { name: c => c.name || '', addr: c => c.upstream_addr || '' },
      { 3: c => c.state || '' });
    const sig = JSON.stringify([items, tblSig('adm-conn')]);
    if (sig !== body.dataset.sig) {
      body.dataset.sig = sig;
      body.innerHTML = items.map(c => {
        const adv = (c.advertise || '').split(',').filter(Boolean).join(' · ');
        return '<tr><td><b>' + esc(c.name) + '</b><div class="mono" style="color:var(--dim2)">' + (c.token_prefix ? esc(c.token_prefix) : shortId(c.id)) + '</div>' +
        (c.my_name ? '<div style="color:var(--dim2);font-size:11px" title="' + T('triplet.myname') + '">' + ic('upload', 10) + ' ' + esc(c.my_name) + '</div>' : '') +
        (c.peer_node ? nodeBadge(c.peer_node, connAuthTier(c)) : '') + '</td>' +
        '<td class="mono">' + esc(c.upstream_addr) + (adv ? '<div style="color:var(--dim2);font-size:12px">' + esc(adv) + '</div>' : '') + '</td>' +
        '<td>' + ((c.groups || []).length ? c.groups.map(g => grpChip({ name: g.name, adopted: g.adopted_node })).join(' ') : '<span style="color:var(--dim2)">' + T('adm.noRestrict') + '</span>') + '</td>' +
        '<td>' + connStatusBadge(c.state) + '</td>' +
        '<td>' + (c.enabled ? '<span class="badge b-ok">' + T('adm.stOn') + '</span>' : '<span class="badge b-off">' + T('adm.stOff') + '</span>') + '</td>' +
        '<td style="color:var(--dim)">' + esc(c.remark || '-') + '</td>' +
        '<td style="white-space:nowrap">' +
          '<button class="ghost small" data-act="conn-edit" data-id="' + esc(c.id) + '">' + T('common.edit') + '</button> ' +
          '<button class="ghost small" data-act="conn-toggle" data-id="' + esc(c.id) + '" data-enabled="' + !c.enabled + '">' + (c.enabled ? T('common.disable') : T('common.enable')) + '</button> ' +
          '<button class="danger small" data-act="conn-del" data-id="' + esc(c.id) + '" data-name="' + esc(c.name) + '">' + T('common.delete') + '</button>' +
        '</td></tr>';
      }).join('') || '<tr><td colspan="7" class="empty">' + T('fanout.empty') + '</td></tr>';
    }
    tblAttach('conn-body', {
      key: 'adm-conn',
      sort: { 0: 'name', 1: 'addr' },
      filter: {
        3: { label: 'common.status', type: 'enum', options: [
          { v: 'connected', label: 'common.connected' },
          { v: 'connecting', label: 'adm.connecting' },
          { v: 'reconnecting', label: 'adm.reconnecting' },
          { v: 'disconnected', label: 'adm.disconnected' },
        ] },
      },
      onSort: () => { body.dataset.sig = ''; loadConnectors(); },
      onFilter: () => { body.dataset.sig = ''; loadConnectors(); },
    });
  }
  renderConnsSess();
  renderWatch();
}
/* ---- Unified issuance: issue / list / revoke delegated tokens (the token is the only identity) ---- */
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
/* Token lifecycle badge (docs/todo/e2e.md §8): only rendered when the token carries a window
   or a cap; the status string (active/expiring/expired/exhausted) comes computed from the API. */
function lifecycleBadge(t) {
  if (!t || (!t.expires_at && !t.max_uses)) return '';
  const map = {
    active: ['b-ok', 'adm.lifeActive'],
    expiring: ['b-warn', 'adm.lifeExpiring'],
    expired: ['b-off', 'adm.lifeExpired'],
    exhausted: ['b-off', 'adm.lifeExhausted'],
  };
  const m = map[t.lifecycle] || map.active;
  const title = (t.expires_at || '') + (t.max_uses ? (t.expires_at ? ' · ' : '') + T('adm.usedCount') + ' ' + (t.used_count || 0) + '/' + t.max_uses : '');
  return ' <span class="badge ' + m[0] + '" title="' + esc(title.trim()) + '">' + T(m[1]) + '</span>';
}
/* Optional expiry + max-uses field pair for token dialogs (fan-in / delegation issue). */
function lifecycleFieldsHtml(idp, expVal, usesVal) {
  return '<label style="margin-top:10px">' + T('adm.expiryLabel') + ' ' + ahelp(T('adm.expiryHelp')) + '</label>' +
    '<input id="' + idp + '-expiry" type="datetime-local" style="width:100%"' + (expVal ? ' value="' + esc(String(expVal).replace('Z', '').replace(/\+00:00$/, '')) + '"' : '') + '>' +
    '<label style="margin-top:10px">' + T('adm.maxUsesLabel') + ' ' + ahelp(T('adm.maxUsesHelp')) + '</label>' +
    '<input id="' + idp + '-maxuses" type="number" min="1" placeholder="' + T('adm.unlimited') + '" style="width:100%"' + (usesVal ? ' value="' + esc(usesVal) + '"' : '') + '>';
}
function lifecycleFieldsVal(idp) {
  const exp = ($(idp + '-expiry') || {}).value || '';
  const uses = parseInt(($(idp + '-maxuses') || {}).value, 10);
  return { expires_at: exp.trim(), max_uses: uses > 0 ? uses : null };
}
/* Delegated-token badge helpers (shared by the issued list and the fan-out watch tab):
   entry (direct/relay) · concurrency (single/multi≤N) · mode (dedicated/split) · E2E · admin tier */
function delegEntryBadge(t) {
  return '<span class="badge b-info">' + (t.entry_mode === 'direct' ? T('deleg.badgeDirect') : T('deleg.badgeRelay')) + '</span>';
}
function delegConcBadge(t) {
  return t.concurrency === 'multi'
    ? '<span class="badge b-info">' + T('deleg.badgeMulti', { n: t.max_sessions || 0 }) + '</span>'
    : '<span class="badge b-off">' + T('deleg.badgeSingle') + '</span>';
}
function delegTierBadges(t) {
  const anyE2e = (t.groups || []).some(g => g.e2e_required);
  return '<span class="badge ' + (t.mode === 'split' ? 'b-warn' : 'b-info') + '">' + (t.mode === 'split' ? T('deleg.modeSplit') : T('deleg.modeDedicated')) + '</span>' +
    (anyE2e ? ' <span class="badge b-warn">E2E</span>' : '') +
    (t.admin_scope ? ' <span class="badge b-warn">' + T('deleg.badgeAdmin') + '·' + esc(t.admin_scope) + '</span>' : '');
}
/* Disaster-set entry lines: one row per registered connector (primary badge + live registration state).
   Relay tokens additionally join the connector's own connection state when `withConn` (watch tab). */
function delegEntriesHtml(t, withConn) {
  if (t.entry_mode === 'direct') return '<div style="padding:2px 0;color:var(--dim)">' + T('deleg.entryLocal') + '</div>';
  return (t.regs || []).map(r => {
    const c = withConn ? FANOUT_CONNS.find(x => x.id === r.connector_id) : null;
    return '<div style="display:flex;align-items:center;gap:6px;padding:2px 0;flex-wrap:wrap">' +
      (c ? connStatusBadge(c.state) : '') +
      (r.is_primary ? '<span class="badge b-ok">' + T('deleg.primaryBadge') + '</span>' : '') +
      '<span>' + esc(r.connector_name) + '</span>' +
      '<span class="mono" style="color:var(--dim2);font-size:12px">' + esc(r.upstream_addr || '') + '</span>' +
      delegStateBadge(r.state) + '</div>';
  }).join('');
}
async function loadDelegation() {
  try {
    const d = await api('GET', '/api/v1/admin/delegation/tokens');
    FANOUT_DELEG = d.items || [];
  } catch(e) { toast(e.message, 'err'); return; }
  renderDelegation();
  renderWatch();
}
function renderDelegation() {
  const body = $('deleg-body'); if (!body) return;
  // header sort + 标签漏斗 (AgTbl); the signature covers header state so a change re-renders exactly once
  const sig = JSON.stringify({ d: FANOUT_DELEG, s: SESS, open: [...SESS_OPEN], dev: DEV_MAP, tbl: tblSig('adm-deleg') });
  if (sig === body.dataset.sig) return;
  body.dataset.sig = sig;
  const items = tblApply('adm-deleg', FANOUT_DELEG,
    { label: t => t.label || t.token_prefix || '', created: t => t.created_at || '' },
    { 0: t => (t.label || '') + ' ' + (t.token_prefix || '') });
  body.innerHTML = items.map(t => {
    const groups = (t.groups || []).map(g => grpChip({ name: g.name, adopted: g.adopted_node, e2e: g.e2e_required })).join(' ');
    const key = 'deleg:' + t.id;
    // M3-T1: live consumer sessions of this token (grouped by token_hash) + online/cap badge
    const sessions = SESS.filter(s => s.kind === 'consumer' && s.token_hash === t.token_hash);
    const cap = t.concurrency === 'multi' ? (t.max_sessions || 0) : 1;
    const onlineBadge = '<span class="badge ' + (sessions.length ? 'b-ok' : 'b-off') + '">' + T('sess.onlineN', { n: sessions.length + '/' + cap }) + '</span>';
    return '<tr><td><b>' + esc(t.label || t.token_prefix) + '</b> ' + delegEntryBadge(t) + ' ' + delegConcBadge(t) + ' ' + delegTierBadges(t) + lifecycleBadge(t) + ' ' + onlineBadge +
      '<div class="mono" style="color:var(--dim2)">' + esc(t.token_prefix) + '</div></td>' +
      '<td>' + (groups || '-') + '</td>' +
      '<td style="color:var(--dim);white-space:nowrap">' + esc((t.created_at || '').replace('T', ' ').replace(/\..*$/, '')) + '</td>' +
      '<td style="white-space:nowrap"><button class="ghost small" data-act="deleg-expand" data-id="' + esc(t.id) + '" data-sessopen="' + esc(key) + '">' + T('groups.detail') + '</button> ' +
      '<button class="danger small" data-act="deleg-revoke" data-id="' + esc(t.id) + '" data-name="' + esc(t.label || t.token_prefix) + '">' + T('adm.revoke') + '</button></td></tr>' +
      '<tr ' + sessWrapAttrs(key) + '><td colspan="4" style="background:var(--bg2)">' +
        '<div class="hint" style="margin:4px 0">' + T('deleg.colSet') + '</div>' + (delegEntriesHtml(t, false) || '-') +
        sessPanelInner({ name: t.label || t.token_prefix, sessions, cols: ['who', 'ip', 'entry', 'ago', 'tr', 'key', 'op'], kickallHash: t.token_hash }) + '</td></tr>';
  }).join('') || '<tr><td colspan="4" class="empty">' + T('deleg.empty') + '</td></tr>';
  tblAttach('deleg-body', {
    key: 'adm-deleg',
    sort: { 0: 'label', 2: 'created' },
    filter: { 0: { label: 'deleg.colLabel' } },
    onSort: () => { body.dataset.sig = ''; renderDelegation(); },
    onFilter: () => { body.dataset.sig = ''; renderDelegation(); },
  });
}
/* Fan-out watch tab (consumer activity overview): every issued token with each disaster-set entry's
   live state (connector connection × registration) and its recent activity (data-plane opens + lifecycle). */
function renderWatch() {
  const body = $('watch-body'); if (!body) return;
  const sig = JSON.stringify({ d: FANOUT_DELEG, c: FANOUT_CONNS.map(c => [c.id, c.state]), s: SESS, open: [...SESS_OPEN], dev: DEV_MAP, tbl: tblSig('adm-watch') });
  if (sig === body.dataset.sig) return;
  body.dataset.sig = sig;
  // header sort + 入口/并发漏斗 (AgTbl)
  const items = tblApply('adm-watch', FANOUT_DELEG,
    { label: t => t.label || t.token_prefix || '', opens: t => t.used_count || 0, created: t => t.created_at || '' },
    { 1: t => t.entry_mode || 'direct', 3: t => t.concurrency || 'single' });
  body.innerHTML = items.map(t => {
    const key = 'watch:' + t.id;
    const sessions = SESS.filter(s => s.kind === 'consumer' && s.token_hash === t.token_hash);
    return '<tr><td><b>' + esc(t.label || t.token_prefix) + '</b> ' + delegTierBadges(t) + '<div class="mono" style="color:var(--dim2)">' + esc(t.token_prefix) + '</div></td>' +
    '<td>' + delegEntryBadge(t) + '</td>' +
    '<td>' + (delegEntriesHtml(t, true) || '-') + '</td>' +
    '<td>' + delegConcBadge(t) + '</td>' +
    '<td style="white-space:nowrap">' + T('deleg.opensN', { n: t.used_count || 0 }) + lifecycleBadge(t) + '</td>' +
    '<td style="color:var(--dim);white-space:nowrap">' + esc((t.created_at || '').replace('T', ' ').replace(/\..*$/, '')) + '</td>' +
    '<td><button class="ghost small" data-act="watch-sess" data-id="' + esc(t.id) + '" data-sessopen="' + esc(key) + '" title="' + T('sess.title') + '">' + ic('chevron-right', 13) + '</button></td></tr>' +
    '<tr ' + sessWrapAttrs(key) + '><td colspan="7" style="background:var(--bg2);padding:0">' +
      sessPanelInner({ name: t.label || t.token_prefix, sessions, cols: ['who', 'ip', 'entry', 'ago', 'tr', 'key', 'op'], kickallHash: t.token_hash }) + '</td></tr>';
  }).join('') || '<tr><td colspan="7" class="empty">' + T('deleg.empty') + '</td></tr>';
  tblAttach('watch-body', {
    key: 'adm-watch',
    sort: { 0: 'label', 4: 'opens', 5: 'created' },
    filter: {
      1: { label: 'deleg.colEntry', type: 'enum', options: [
        { v: 'direct', label: 'deleg.badgeDirect' }, { v: 'relay', label: 'deleg.badgeRelay' }] },
      3: { label: 'deleg.colConcurrency', type: 'enum', options: [
        { v: 'single', label: 'deleg.concSingle' }, { v: 'multi', label: 'deleg.concMulti' }] },
    },
    onSort: () => { body.dataset.sig = ''; renderWatch(); },
    onFilter: () => { body.dataset.sig = ''; renderWatch(); },
  });
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
/* Unified issuance dialog — four linked dimensions:
   入口 entry: direct (consumer dials this issuer's own listener; TLS is already end-to-end, so the trust
     tier locks to plaintext and the disaster set hides) | relay (via the disaster set: connector
     multi-select with exactly one primary entry).
   信任 trust: plaintext | E2E (only e2e_required groups stay selectable) | E2E + admin tier (ro/rules/full).
   路由 mode: dedicated (全量 — every eligible group is submitted; the picker folds into an advanced
     disclosure) | split (词表 — picker expanded, at least one E2E group required).
   并发 concurrency: single (a new session kicks the old) | multi (cap = node_config
     delegation_max_sessions snapshot, default 8 — the server snapshots it, the dialog only displays).
   The share card shows once with the full link after issuance. */
async function openIssueDelegation() {
  let conns = [];
  try { conns = (await api('GET', '/api/v1/admin/connectors')).items || []; } catch(e) { toast(e.message, 'err'); return; }
  const usable = conns.filter(c => c.enabled);
  if (!(S.groups || []).length) { toast(T('groups.empty'), 'err'); return; }
  // Multi-tier cap display: the live value when the status payload carries it, the default 8 otherwise
  let maxSessions = 8;
  try {
    const st = await api('GET', '/api/v1/admin/node/status');
    if (st.delegation_max_sessions > 0) maxSessions = st.delegation_max_sessions;
  } catch(e) { /* status failure never blocks issuance */ }

  const e2eIds = new Set((S.groups || []).filter(g => g.e2e_required).map(g => g.id));
  const hasRelay = usable.length > 0;
  const targetRows = usable.map(c =>
    '<label class="chk" style="display:flex;align-items:center;gap:8px;padding:5px 4px">' +
      '<input type="checkbox" class="di-target" value="' + esc(c.id) + '"' + (c.state === 'connected' ? ' checked' : '') + '>' +
      '<span><b>' + esc(c.name) + '</b> <span class="mono" style="color:var(--dim2)">' + esc(c.upstream_addr) + '</span></span>' +
      connStatusBadge(c.state) + '</label>'
  ).join('');
  // dedicated mode defaults to 全量: every group starts checked (the picker folds away under 专线)
  const groupRows = (S.groups || []).map(g =>
    '<label><input type="checkbox" class="di-group" value="' + esc(g.id) + '" checked>' +
    '<span>' + esc(g.name) + '</span>' + (g.adopted_node ? ' ' + srcBadge(g.adopted_node) : '') + (g.e2e_required ? '<span class="badge b-warn">E2E</span>' : '<span class="badge b-info">' + (g.rule_count || 0) + '</span>') + '</label>'
  ).join('');

  openModal(T('deleg.issue'),
    // 入口 entry (segmented pills, same texture as the desktop dialog — agseg shared component)
    '<label>' + T('deleg.entry') + ' ' + ahelp(T('deleg.entryHelp')) + '</label>' +
    segHtml('di-entry', [
      { v: 'direct', label: T('deleg.entryDirect') },
      { v: 'relay', label: T('deleg.entryRelay'), disabled: !hasRelay },
    ], hasRelay ? 'relay' : 'direct') +
    '<div id="di-relay-wrap"' + (hasRelay ? '' : ' hidden') + '>' +
      '<label style="margin-top:10px">' + T('deleg.targets') + ' ' + ahelp(T('deleg.targetsHelp')) + '</label>' +
      '<div class="rule-check" style="max-height:150px">' + (targetRows || '<div class="empty">' + T('deleg.noUpstreams') + '</div>') + '</div>' +
      '<label style="margin-top:10px">' + T('deleg.primary') + ' ' + ahelp(T('deleg.primaryHelp')) + '</label>' +
      '<div id="di-primary" style="padding:2px 4px"></div>' +
    '</div>' +
    // 信任 trust
    '<label style="margin-top:10px">' + T('deleg.trust') + ' ' + ahelp(T('deleg.trustHelp')) + '</label>' +
    segHtml('di-trust', [
      { v: 'plain', label: T('deleg.trustPlain') },
      { v: 'e2e', label: T('deleg.trustE2e') },
      { v: 'admin', label: T('deleg.trustAdmin') },
    ], 'plain') +
    '<div class="hint" id="di-trust-lock" style="display:none;color:var(--warn)">' + ic('info', 13) + ' ' + T('deleg.directPlainHint') + '</div>' +
    '<div id="di-scope-wrap" style="display:none">' +
      segHtml('di-scope', [
        { v: 'ro', label: T('deleg.scopeRo') },
        { v: 'rules', label: T('deleg.scopeRules') },
        { v: 'full', label: T('deleg.scopeFull') },
      ], 'full') +
    '</div>' +
    // 路由 mode
    '<label style="margin-top:10px">' + T('deleg.mode') + ' ' + ahelp(T('deleg.modeHelp')) + '</label>' +
    segHtml('di-mode', [
      { v: 'dedicated', label: T('deleg.modeDedicated') },
      { v: 'split', label: T('deleg.modeSplit') },
    ], 'dedicated') +
    // 权限组 groups (dedicated folds the picker into an advanced disclosure; split expands it)
    '<details id="di-groups-wrap" style="margin-top:10px"><summary style="cursor:pointer;color:var(--dim);font-size:12px">' + T('deleg.groupsAdv') + '</summary>' +
      '<label style="margin-top:6px">' + T('term.group') + ' ' + ahelp(T('deleg.groupsHelp')) + '</label>' +
      '<div class="rule-check" style="max-height:150px">' + groupRows + '</div>' +
    '</details>' +
    // 并发 concurrency
    '<label style="margin-top:10px">' + T('deleg.concurrency') + '</label>' +
    segHtml('di-conc', [
      { v: 'single', label: T('deleg.concSingle') },
      { v: 'multi', label: T('deleg.concMulti') + ' ≤' + maxSessions },
    ], 'single') +
    // M3-T6 naming triplet: target name = the token's local label; my name prefills the link's myname word
    nameTriplet('di', {}, { remark: false }) +
    lifecycleFieldsHtml('di', '', ''),
    [
      {label: T('common.cancel'), kind: 'ghost', fn: closeModal},
      {label: T('deleg.issue'), fn: async () => {
        const entry = segVal('di-entry') || 'direct';
        const trust = entry === 'direct' ? 'plain' : (segVal('di-trust') || 'plain');
        const mode = segVal('di-mode') || 'dedicated';
        const concurrency = segVal('di-conc') || 'single';
        const groupIds = [...document.querySelectorAll('.di-group:checked')].map(c => c.value);
        if (!groupIds.length) { toast(T('deleg.needGroups'), 'err'); return; }
        const e2eCount = groupIds.filter(id => e2eIds.has(id)).length;
        if (trust !== 'plain' && e2eCount !== groupIds.length) { toast(T('deleg.e2eOnly'), 'err'); return; }
        if (mode === 'split' && !e2eCount) { toast(T('deleg.splitNeedE2e'), 'err'); return; }
        if (trust === 'admin' && !e2eCount) { toast(T('deleg.adminNeedE2e'), 'err'); return; }
        let regs = [];
        if (entry === 'relay') {
          const targets = [...document.querySelectorAll('.di-target:checked')].map(c => c.value);
          if (!targets.length) { toast(T('deleg.needTargets'), 'err'); return; }
          const primary = $('di-primary').dataset.value || targets[0];
          regs = targets.map(id => ({ connector_id: id, is_primary: id === primary }));
        }
        const adminScope = trust === 'admin' ? (segVal('di-scope') || 'full') : '';
        const life = lifecycleFieldsVal('di');
        const names = nameTripletVal('di');
        try {
          const d = await api('POST', '/api/v1/admin/delegation/tokens', {
            label: names.target,
            my_name: names.myname,
            group_ids: groupIds,
            regs,
            mode,
            admin_scope: adminScope,
            entry_mode: entry,
            concurrency,
            expires_at: life.expires_at,
            max_uses: life.max_uses,
          });
          closeModal();
          openModal(T('deleg.issuedTitle'), shareCardHtml([]),
            [{label: T('share.saved'), fn: () => { closeModal(); loadDelegation(); }}]);
          shareCardBind($('modal-root'), { role: 'connect', secret: d.token, link: d.share_url, endpoints: [], note: d.label });
          loadDelegation();
        } catch(e) { toast(e.message, 'err'); }
      }},
    ]);

  // primary radio follows the checked disaster set (first checked entry wins by default)
  const primaryBox = $('di-primary');
  if ($('di-target')) $('di-target').placeholder = T('deleg.labelPh');
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

  // trust linkage: the E2E tiers keep only e2e_required groups selectable (ineligible boxes uncheck+disable)
  function syncGroupEligibility() {
    const trust = segVal('di-trust') || 'plain';
    document.querySelectorAll('.di-group').forEach(c => {
      const e2e = e2eIds.has(c.value);
      c.disabled = trust !== 'plain' && !e2e;
      if (c.disabled) c.checked = false;
    });
    $('di-scope-wrap').style.display = trust === 'admin' ? '' : 'none';
  }
  SEG_EVT['di-trust'] = syncGroupEligibility;

  // entry linkage: relay shows the disaster set; direct hides it and locks the trust tier to plaintext
  // (direct TLS is already end-to-end — stacking E2E or an admin channel adds nothing)
  function syncEntry() {
    const entry = segVal('di-entry') || 'direct';
    const lock = entry === 'direct';
    $('di-relay-wrap').hidden = lock;
    if (lock) segSet('di-trust', 'plain', { e2e: true, admin: true });
    else segSet('di-trust', segVal('di-trust') || 'plain', { e2e: false, admin: false });
    $('di-trust-lock').style.display = lock ? '' : 'none';
    syncGroupEligibility();
  }
  SEG_EVT['di-entry'] = syncEntry;
  syncEntry();

  // mode linkage: dedicated re-checks every eligible group and folds the picker; split expands it
  SEG_EVT['di-mode'] = () => {
    const mode = segVal('di-mode') || 'dedicated';
    if (mode === 'dedicated') {
      document.querySelectorAll('.di-group:not(:disabled)').forEach(c => { c.checked = true; });
      $('di-groups-wrap').open = false;
    } else {
      $('di-groups-wrap').open = true;
    }
  };
}
function connectorFormHtml(c) {
  c = c || {};
  return '<div class="paste-bar"><input id="cf-paste" class="mono" style="width:100%" placeholder="' + T('fanout.pastePh') + '">' +
    '<div class="hint" id="cf-paste-err" style="display:none;color:var(--danger-text)"></div></div>' +
    // M3-T6 naming triplet: target name (local) / my name (uploaded to the peer) / remark (local private)
    nameTriplet('cf', { target: c.name || '', myname: c.my_name || '', remark: c.remark || '' }) +
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
        '<span>' + esc(g.name) + '</span>' + (g.adopted_node ? ' ' + srcBadge(g.adopted_node) : '') + (g.e2e_required ? '<span class="badge b-warn">E2E</span>' : '<span class="badge b-info">' + (g.rule_count || 0) + '</span>') + '</label>'
      ).join('') : '<div class="empty">' + T('groups.empty') + '</div>') + '</div>' +
    '<label>' + T('fanout.pushLabel') + ' <span class="hint">' + T('fanout.pushHint') + '</span></label>' +
    '<div class="rule-check" style="max-height:130px">' +
      (S.groups.length ? S.groups.map(g =>
        '<label><input type="checkbox" class="cf-push" value="' + esc(g.id) + '" ' + ((c.push_groups||'').split(',').includes(g.id)?'checked':'') + '>' +
        '<span>' + esc(g.name) + '</span>' + (g.adopted_node ? ' ' + srcBadge(g.adopted_node) : '') + '<span class="badge b-info">' + (g.rule_count||0) + '</span></label>'
      ).join('') : '<div class="empty">' + T('groups.empty') + '</div>') + '</div>';
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
  const names = nameTripletVal('cf');
  return {
    name: names.target,
    my_name: names.myname,
    upstream_addr: $('cf-addr').value.trim(),
    sni_hostname: $('cf-sni').value.trim(),
    insecure: $('cf-insecure').checked,
    pinned_fingerprint: $('cf-fp').value.trim(),
    advertise: $('cf-advertise').value.split('\n').map(s => s.trim()).filter(Boolean),
    group_id: [...document.querySelectorAll('.cf-acl:checked')].map(c => c.value).join(',') || null,
    push_groups: [...document.querySelectorAll('.cf-push:checked')].map(c => c.value),
    remark: names.remark,
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
         'relay_token.create','relay_token.delete','relay_token.expose_control','relay_token.set_group','relay_token.set_remark',
         'connector.create','connector.update','connector.delete','connector.enable','connector.disable',
         'federation.adopt','delegation.issue','delegation.revoke',
         'session.kick','session.kick_token',
         'device.certify','device.revoke','device.rebind','device.policy',
         'approval.approve','approval.reject','approval.reject_revoke',
         'admin.console_access','admin.session_via_relay','node.update_settings'].map(a =>
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
  const st = AgTbl.sortState('adm-audit');
  if (st) url += '&sort=' + encodeURIComponent(st.id + ':' + st.dir);
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
    tblAttach('audit-body', {
      key: 'adm-audit',
      sort: { 0: 'time' }, // server-side (paged); 其余列按业务无排序价值
      onSort: () => { S.page.audit = 1; loadAudit(); },
    });
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
    const admins = tblApply('adm-admins', conf.items || [], { name: a => a.username || '', created: a => a.created_at || '' });
    $('admin-body').innerHTML = admins.map(a =>
      '<tr><td><b>' + esc(a.username) + '</b></td><td style="color:var(--dim)">' + esc(a.created_at) + '</td>' +
      '<td><button class="danger small" data-act="admin-del" data-id="' + esc(a.id) + '" data-name="' + esc(a.username) + '">' + T('common.delete') + '</button></td></tr>'
    ).join('') || '<tr><td colspan="3" class="empty">' + T('common.none') + '</td></tr>';
    tblAttach('admin-body', {
      key: 'adm-admins',
      sort: { 0: 'name', 1: 'created' },
      onSort: () => renderSettings(),
    });
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
    if (d.type === 'ag-nav' && {dashboard:1,groups:1,rules:1,fanin:1,connectors:1,devices:1,approvals:1,audit:1,settings:1}[d.view]) {
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
  // Console channel ticket bootstrap: #boot=<ticket> → exchange for an admin session.
  // The credential login form cannot help a ticket console, so it never flashes: the boot state
  // shows while the exchange runs. 429 (shared redemption rate limit over the tunnel) and network
  // wobble retry with backoff; 401 (invalid/expired) is terminal — reopening the console from the
  // client re-pulls the config channel and mints a fresh ticket.
  const boot = location.hash.match(/#boot=([A-Za-z0-9_-]+)/);
  if (boot) {
    history.replaceState(null, '', location.pathname);
    const ticket = boot[1];
    const hadSession = !!S.access; // same forwarder origin keeps the previous session — no splash then
    const showBoot = (msgKey, hintKey, canRetry) => {
      $('login-view').style.display = 'none';
      $('boot-view').style.display = 'flex';
      $('boot-spin').style.display = canRetry ? 'none' : '';
      $('boot-msg').textContent = T(msgKey);
      $('boot-hint').style.display = hintKey ? '' : 'none';
      if (hintKey) $('boot-hint').textContent = T(hintKey);
      $('boot-retry').style.display = canRetry ? '' : 'none';
    };
    if (!hadSession) showBoot('adm.booting', null, false);
    async function attempt(n) {
      try {
        const res = await fetch('/api/v1/auth/admin-bootstrap', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ticket }),
        });
        const j = await res.json().catch(() => ({}));
        if (res.ok && j.code === 0 && j.data) {
          S.access = j.data.access_token; S.refresh = j.data.refresh_token || '';
          localStorage.setItem('ag_access', S.access);
          localStorage.setItem('ag_refresh', S.refresh);
          $('boot-view').style.display = 'none';
          enterApp();
          return;
        }
        if (res.status !== 401 && n < 3) { setTimeout(() => attempt(n + 1), 2000 * (n + 1)); return; }
        if (hadSession) { enterApp(); toast(T('adm.bootFailed'), 'err'); return; }
        showBoot(res.status === 401 ? 'adm.bootInvalid' : 'adm.bootFailed',
          res.status === 401 ? 'adm.bootInvalidHint' : 'adm.bootFailedHint', true);
      } catch (e) {
        if (n < 3) { setTimeout(() => attempt(n + 1), 2000 * (n + 1)); return; }
        if (hadSession) { enterApp(); toast(T('adm.bootFailed'), 'err'); return; }
        showBoot('adm.bootFailed', 'adm.bootFailedHint', true);
      }
    }
    $('boot-retry').onclick = () => { showBoot('adm.booting', null, false); attempt(0); };
    attempt(0);
  } else if (S.access) { enterApp(); }
});
