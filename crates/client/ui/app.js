'use strict';
/* AgileNet client console (svc single-port plane, served at /client).
   Shares the admin login: the Bearer token is read from localStorage ag_access (same origin);
   any 401 redirects to the admin SPA at /. Every fetch stays on absolute /api/v1/client/*.
   Conventions: no inline event attributes, data-ic icon hydration, esc() on remote data,
   signature-guarded polling paused while the page is hidden. */
(function () {

const T = function (k, v) { return AgI18n.t(k, v); };
const API = '/api/v1/client';
const $id = function (id) { return document.getElementById(id); };

const S = { nodesSig: '', credsSig: '', proxySig: '', notifySig: '', certSig: '', timer: null, machineId: null, noteCount: null };

/* ---------------- REST ---------------- */
async function api(path, opts) {
  opts = opts || {};
  const headers = { 'Authorization': 'Bearer ' + (localStorage.getItem('ag_access') || '') };
  if (opts.json !== undefined) {
    headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(opts.json);
    delete opts.json;
  }
  const r = await fetch(API + path, Object.assign({}, opts, { headers: headers }));
  if (r.status === 401) { location.href = '/'; throw new Error('unauthorized'); }
  const j = await r.json().catch(function () { return { code: -1, message: 'bad response' }; });
  if (j.code !== 0) throw new Error(j.message || ('code ' + j.code));
  return j.data;
}

/* ---------------- toast / modal (DOM only) ---------------- */
function toast(msg, kind) {
  const el = document.createElement('div');
  el.className = 'toast ' + (kind || 'info');
  el.textContent = msg;
  $id('toasts').appendChild(el);
  setTimeout(function () {
    el.classList.add('out');
    setTimeout(function () { el.remove(); }, 240);
  }, 2800);
}

function modal(build) {
  const root = $id('modal-root');
  root.innerHTML = '';
  const mask = document.createElement('div');
  mask.className = 'modal-mask';
  const card = document.createElement('div');
  card.className = 'modal-card';
  mask.appendChild(card);
  root.appendChild(mask);
  function close() { root.innerHTML = ''; }
  mask.addEventListener('mousedown', function (e) { if (e.target === mask) close(); });
  build(card, close);
}

function askConfirm(text) {
  return new Promise(function (resolve) {
    modal(function (card, close) {
      card.innerHTML =
        '<div class="modal-body">' + esc(text) + '</div>' +
        '<div class="modal-foot">' +
          '<button class="btn ghost small" data-x>' + esc(T('common.cancel')) + '</button>' +
          '<button class="btn primary small" data-ok>' + esc(T('common.confirm')) + '</button>' +
        '</div>';
      card.querySelector('[data-x]').addEventListener('click', function () { close(); resolve(false); });
      card.querySelector('[data-ok]').addEventListener('click', function () { close(); resolve(true); });
    });
  });
}

function showExport(url) {
  modal(function (card, close) {
    card.innerHTML =
      '<div class="modal-head"><span>' + esc(T('cl.exportTitle')) + '</span>' +
        '<button class="btn ghost small" data-x>' + AgIcon('x', 13) + '</button></div>' +
      '<div class="modal-body">' +
        '<div class="dim warn-line">' + esc(T('cl.exportWarn')) + '</div>' +
        '<textarea class="export-box" readonly></textarea>' +
      '</div>' +
      '<div class="modal-foot">' +
        '<button class="btn primary small" data-copy>' + AgIcon('copy', 13) + '<span>' + esc(T('common.copy')) + '</span></button>' +
      '</div>';
    const ta = card.querySelector('.export-box');
    ta.value = url;
    card.querySelector('[data-x]').addEventListener('click', close);
    card.querySelector('[data-copy]').addEventListener('click', function () {
      const done = function () { toast(T('cl.copied'), 'ok'); };
      ta.select();
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(url).then(done, done);
      } else {
        try { document.execCommand('copy'); } catch (e) { /* noop */ }
        done();
      }
    });
  });
}

/* ---------------- format ---------------- */
function fmtBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + ' B';
  const u = ['KB', 'MB', 'GB', 'TB'];
  let v = n, i = -1;
  do { v /= 1024; i++; } while (v >= 1024 && i < u.length - 1);
  return v.toFixed(v >= 100 ? 0 : 1) + ' ' + u[i];
}

function statusMeta(s) {
  switch (s) {
    case 'Connected': return { pill: 'pill-ok', label: T('common.connected') };
    case 'Connecting': return { pill: 'pill-warn', label: T('cl.connecting') };
    case 'Reconnecting': return { pill: 'pill-warn', label: T('cl.reconnecting') };
    // M4: gated pending certification (amber) / terminal block (red, reason in the row)
    case 'PendingApproval': return { pill: 'pill-warn', label: T('cl.pending') };
    case 'Blocked': return { pill: 'pill-danger', label: T('cl.blocked') };
    default: return { pill: 'pill-dim', label: T('common.disconnected') };
  }
}

/* ---------------- nodes ---------------- */
async function refreshNodes() {
  let nodes;
  try { nodes = await api('/nodes'); } catch (e) { return; }
  const sig = JSON.stringify(nodes);
  if (sig === S.nodesSig) return;
  S.nodesSig = sig;
  renderNodes(nodes);
}

function renderNodes(nodes) {
  const box = $id('node-list');
  if (!nodes.length) {
    box.innerHTML = '<div class="empty dim">' + esc(T('cl.nodesEmpty')) + '</div>';
    return;
  }
  let html = '';
  nodes.forEach(function (n, i) {
    const st = statusMeta(n.status);
    html +=
      '<div class="row">' +
        '<div class="row-main">' +
          '<div class="row-title">' +
            '<span class="name">' + esc(n.label || n.node_name || n.node_id) + '</span>' +
            '<span class="pill ' + st.pill + '">' + esc(st.label) + '</span>' +
            (n.admin_console
              ? '<span class="tag"><i data-ic="shield" data-sz="11"></i>' + esc(T('cl.manage')) + '</span>'
              : '') +
          '</div>' +
          '<div class="row-sub dim">' + esc(n.current_entry || n.addr) +
            ' · ↑ ' + fmtBytes(n.bytes_up) + ' ↓ ' + fmtBytes(n.bytes_down) +
          '</div>' +
          // M4-T2: terminal block — mapped reason + the issuer's one-time notice (their words)
          (n.status === 'Blocked'
            ? '<div class="row-sub">' +
              '<span class="pill pill-danger">' + esc(reasonText(n.block_reason)) + '</span>' +
              (n.block_message ? ' <span class="dim">' + esc(n.block_message) + '</span>' : '') +
              '</div>'
            : '') +
          // M4-T3: pending certification — tip + appeal composer (≤3 notes per session, local count)
          (n.status === 'PendingApproval'
            ? '<div class="row-sub dim">' + esc(T('cl.pendingTip')) + '</div>' +
              '<div class="note-row">' +
                '<input class="note-input" data-note-input="' + i + '" maxlength="512" placeholder="' + esc(T('cl.notePh')) + '">' +
                '<button class="btn ghost small" data-note-send="' + i + '">' + esc(T('cl.noteSend')) + '</button>' +
              '</div>'
            : '') +
        '</div>' +
        '<button class="btn ghost small" data-disc="' + i + '">' + esc(T('cl.disconnect')) + '</button>' +
      '</div>';
  });
  box.innerHTML = html;
  AgIconHydrate(box);
  box.querySelectorAll('[data-disc]').forEach(function (btn) {
    btn.addEventListener('click', async function () {
      const n = nodes[Number(btn.getAttribute('data-disc'))];
      if (!n) return;
      btn.disabled = true;
      try {
        await api('/nodes/disconnect', { method: 'POST', json: { node_id: n.node_id } });
      } catch (e) { toast(String(e.message || e), 'err'); }
      S.nodesSig = '';
      refreshNodes();
    });
  });
  // Appeal-note composer: send on click / Enter; 3-per-session local counter (issuer enforces too)
  box.querySelectorAll('[data-note-send]').forEach(function (btn) {
    btn.addEventListener('click', async function () {
      const n = nodes[Number(btn.getAttribute('data-note-send'))];
      if (!n) return;
      S.noteCount = S.noteCount || {};
      const cnt = S.noteCount[n.node_id] || 0;
      if (cnt >= 3) { toast(T('cl.noteLimit'), 'err'); return; }
      const input = box.querySelector('input[data-note-input="' + btn.getAttribute('data-note-send') + '"]');
      const bodyText = input ? input.value.trim() : '';
      if (!bodyText) return;
      btn.disabled = true;
      try {
        await api('/nodes/pending-note', { method: 'POST', json: { node_id: n.node_id, body: bodyText } });
        S.noteCount[n.node_id] = cnt + 1;
        if (input) input.value = '';
        toast(T('cl.noteSent'), 'ok');
      } catch (e) { toast(String(e.message || e), 'err'); }
      btn.disabled = false;
    });
  });
  box.querySelectorAll('[data-note-input]').forEach(function (input) {
    input.addEventListener('keydown', function (e) {
      if (e.key !== 'Enter') return;
      e.preventDefault();
      const btn = box.querySelector('[data-note-send="' + input.getAttribute('data-note-input') + '"]');
      if (btn && !btn.disabled) btn.click();
    });
  });
  // Identity card: per-endpoint certification state follows the nodes poll
  renderCertList(nodes);
}

/* Identity card cert list (device_state per endpoint; pending = amber, otherwise certified) */
function renderCertList(nodes) {
  const box = $id('machine-cert-list');
  if (!box) return;
  const html = nodes.length
    ? nodes.map(function (n) {
        return '<div class="id-row"><span class="dim">' + esc(n.label || n.node_name || n.node_id) + '</span>' +
          (n.device_state === 'pending'
            ? '<span class="pill pill-warn">' + esc(T('identity.pending')) + '</span>'
            : '<span class="pill pill-ok">' + esc(T('identity.certified')) + '</span>') +
          '</div>';
      }).join('')
    : '<div class="dim" style="padding:6px 0">' + esc(T('identity.noNodes')) + '</div>';
  if (S.certSig === html) return;
  S.certSig = html;
  box.innerHTML = html;
}

/* ---------------- import (shared blind-plug wizard) ---------------- */
function pickAnetFile() {
  return new Promise(function (resolve) {
    const inp = document.createElement('input');
    inp.type = 'file';
    inp.accept = '.anet,.json,text/plain';
    inp.addEventListener('change', function () {
      const f = inp.files && inp.files[0];
      if (!f) { resolve(null); return; }
      const rd = new FileReader();
      rd.onload = function () { resolve({ name: f.name, content: String(rd.result || '') }); };
      rd.onerror = function () { resolve(null); };
      rd.readAsText(f);
    });
    inp.click();
  });
}

function openImport() {
  AgImport.open({
    context: 'admin',
    fanoutApplicable: false,
    toast: toast,
    pickAnetFile: pickAnetFile,
    applyConnect: async function (arg) {
      try {
        // The Rust parser is the source of truth for the REST connect shape
        const parsed = await api('/parse-connect-url', { method: 'POST', json: { url: arg.link } });
        await api('/nodes', { method: 'POST', json: parsed });
        return true;
      } catch (e) { return String(e && e.message || e); }
    },
    onDone: function () {
      S.nodesSig = '';
      S.credsSig = '';
      refreshNodes();
      refreshCreds();
    },
  });
}

/* ---------------- local proxy ---------------- */
async function refreshProxy() {
  let st;
  try { st = await api('/proxy/status'); } catch (e) { return; }
  const sig = JSON.stringify(st);
  if (sig === S.proxySig) return;
  S.proxySig = sig;
  renderProxy(st);
}

function renderProxy(st) {
  const pill = $id('proxy-pill');
  const addr = $id('proxy-addr');
  const portInp = $id('proxy-port');
  if (st.running) {
    pill.className = 'pill pill-ok';
    pill.textContent = T('common.running');
    addr.textContent = '127.0.0.1:' + st.port + ' · SOCKS5/HTTP';
    portInp.hidden = true;
    $id('btn-proxy-start').hidden = true;
    $id('btn-proxy-stop').hidden = false;
  } else {
    pill.className = 'pill pill-dim';
    pill.textContent = T('common.stopped');
    addr.textContent = '';
    portInp.hidden = false;
    $id('btn-proxy-start').hidden = false;
    $id('btn-proxy-stop').hidden = true;
  }
}

/* ---------------- credentials ---------------- */
async function refreshCreds() {
  let list;
  try { list = await api('/credentials'); } catch (e) { return; }
  const sig = JSON.stringify(list);
  if (sig === S.credsSig) return;
  S.credsSig = sig;
  renderCreds(list);
}

function renderCreds(list) {
  const box = $id('cred-list');
  if (!list.length) {
    box.innerHTML = '<div class="empty dim">' + esc(T('common.empty')) + '</div>';
    return;
  }
  let html = '';
  list.forEach(function (pair, i) {
    const c = pair[1] || {};
    html +=
      '<div class="row">' +
        '<div class="row-main">' +
          '<div class="row-title">' +
            '<span class="name">' + esc(c.name || c.label || pair[0]) + '</span>' +
            (c.en ? '<span class="tag">E2E</span>' : '') +
            (c.emode === 'split' ? '<span class="tag">' + esc(T('cl.split')) + '</span>' : '') +
            (c.eadmin ? '<span class="tag">' + esc(T('cl.manage')) + '</span>' : '') +
          '</div>' +
          '<div class="row-sub dim">' + esc(c.addr || '') + '</div>' +
        '</div>' +
        '<button class="btn ghost small" data-exp="' + i + '" title="' + esc(T('common.export')) + '"><i data-ic="download" data-sz="13"></i></button>' +
        '<button class="btn ghost small" data-del="' + i + '" title="' + esc(T('common.delete')) + '"><i data-ic="trash-2" data-sz="13"></i></button>' +
      '</div>';
  });
  box.innerHTML = html;
  AgIconHydrate(box);
  box.querySelectorAll('[data-exp]').forEach(function (btn) {
    btn.addEventListener('click', async function () {
      const pair = list[Number(btn.getAttribute('data-exp'))];
      if (!pair) return;
      if (!(await askConfirm(T('cl.exportConfirm')))) return;
      try {
        const url = await api('/credentials/export?confirm=true&key=' + encodeURIComponent(pair[0]));
        showExport(String(url));
      } catch (e) { toast(String(e.message || e), 'err'); }
    });
  });
  box.querySelectorAll('[data-del]').forEach(function (btn) {
    btn.addEventListener('click', async function () {
      const pair = list[Number(btn.getAttribute('data-del'))];
      if (!pair) return;
      if (!(await askConfirm(T('cl.delCred')))) return;
      try {
        await api('/credentials?key=' + encodeURIComponent(pair[0]), { method: 'DELETE' });
      } catch (e) { toast(String(e.message || e), 'err'); }
      S.credsSig = '';
      refreshCreds();
    });
  });
}

/* ---------------- notifications (M4-T1: bell badge + inbox card) ---------------- */
function fmtTs(ts) {
  return String(ts || '').replace('T', ' ').replace(/(\.\d+)?(Z|\+00:00)$/, '');
}

async function refreshNotify() {
  let data;
  try { data = await api('/notifications'); } catch (e) { return; }
  const unread = data.unread || 0;
  const badge = $id('notify-badge');
  const txt = unread > 99 ? '99+' : String(unread);
  badge.hidden = unread === 0;
  if (badge.textContent !== txt) badge.textContent = txt;
  const sig = JSON.stringify([data.items || [], unread]);
  if (sig === S.notifySig) return;
  S.notifySig = sig;
  renderNotify(data.items || []);
}

function renderNotify(items) {
  const box = $id('notify-list');
  if (!items.length) {
    box.innerHTML = '<div class="empty dim">' + esc(T('notify.empty')) + '</div>';
    return;
  }
  box.innerHTML = items.map(function (n) {
    const ic = n.kind === 'approval' ? 'badge-check' : n.kind === 'session' ? 'triangle-alert' : 'info';
    const kindLabel = T(n.kind === 'approval' ? 'notify.kindApproval' : n.kind === 'session' ? 'notify.kindSession' : 'notify.kindSystem');
    const rc = n.reason_code
      ? '<span class="pill ' + (n.kind === 'session' ? 'pill-danger' : 'pill-warn') + '">' + esc(reasonText(n.reason_code)) + '</span>'
      : '';
    return '<div class="ntf' + (n.read ? '' : ' unread') + '">' +
      '<span class="ntf-ic"><i data-ic="' + ic + '" data-sz="15"></i></span>' +
      '<div class="ntf-main">' +
        '<div class="ntf-title">' + esc(n.title) + ' ' + rc + '</div>' +
        (n.body && n.body !== n.title && n.body !== n.reason_code
          ? '<div class="ntf-body dim">' + esc(n.body) + '</div>' : '') +
        '<div class="ntf-meta dim">' + esc(kindLabel) + ' · ' + esc(fmtTs(n.ts)) + '</div>' +
      '</div></div>';
  }).join('');
  AgIconHydrate(box);
}

/* ---------------- machine identity (M4-T4) ---------------- */
async function loadIdentity() {
  let id;
  try { id = await api('/identity'); } catch (e) { return; }
  S.machineId = id;
  const fp = id.device_fp || '-';
  const pub = id.openssh_pubkey || '-';
  const fpEl = $id('machine-fp'), pubEl = $id('machine-pub');
  if (fpEl.textContent !== fp) { fpEl.textContent = fp; fpEl.title = fp; }
  if (pubEl.textContent !== pub) { pubEl.textContent = pub; pubEl.title = pub; }
  const inp = $id('machine-myname');
  if (document.activeElement !== inp) inp.value = id.myname || '';
}


/* ---------------- admin consoles dropdown ---------------- */
async function toggleAdminMenu() {
  const drop = $id('adm-drop');
  if (!drop.hidden) { drop.hidden = true; return; }
  let list = [];
  try { list = await api('/consoles'); } catch (e) { /* keep local entry only */ }
  let html =
    '<button class="adm-item" data-local><i data-ic="home" data-sz="14"></i><span>' +
    esc(T('cl.adminLocal')) + '</span></button>';
  html += '<div class="adm-div"></div>';
  if (list.length) {
    list.forEach(function (c, i) {
      const issuer = c.kind === 'issuer';
      const kind = issuer ? T('cl.adminIssuer') : T('cl.adminUpstream');
      html +=
        '<button class="adm-item" data-c="' + i + '">' +
          '<i data-ic="' + (issuer ? 'shield' : 'monitor') + '" data-sz="14"></i>' +
          '<span class="adm-name">' + esc(c.name) + '</span>' +
          '<span class="tag">' + esc(kind) + (c.scope ? ' · ' + esc(c.scope) : '') + '</span>' +
        '</button>';
    });
  } else {
    html += '<div class="adm-item disabled dim">' + esc(T('cl.adminEmpty')) + '</div>';
  }
  drop.innerHTML = html;
  AgIconHydrate(drop);
  drop.hidden = false;
  drop.querySelector('[data-local]').addEventListener('click', function () { location.href = '/'; });
  drop.querySelectorAll('[data-c]').forEach(function (btn) {
    btn.addEventListener('click', async function () {
      const c = list[Number(btn.getAttribute('data-c'))];
      if (!c) return;
      btn.disabled = true;
      try {
        const r = await api('/consoles/open', {
          method: 'POST',
          json: { node_id: c.node_id, upstream: c.kind === 'upstream' ? c.name : undefined },
        });
        window.open(r.url, '_blank');
      } catch (e) { toast(String(e.message || e), 'err'); }
      btn.disabled = false;
      drop.hidden = true;
    });
  });
}

/* ---------------- polling (signature-guarded, hidden-paused) ---------------- */
function tick() {
  refreshNodes();
  refreshProxy();
  refreshCreds();
  refreshNotify();
}

function startLoops() {
  if (S.timer) return;
  S.timer = setInterval(tick, 2000);
}

function stopLoops() {
  clearInterval(S.timer);
  S.timer = null;
}

/* ---------------- boot ---------------- */
function syncThemeIcon() {
  const dark = (document.documentElement.dataset.theme || 'light') === 'dark';
  $id('theme-btn').innerHTML = AgIcon(dark ? 'sun' : 'moon', 14);
}

function boot() {
  // Shared admin login: no token -> the admin SPA login page
  if (!localStorage.getItem('ag_access')) { location.replace('/'); return; }

  AgI18n.hydrate(document);
  AgIconHydrate(document);
  syncThemeIcon();

  $id('theme-btn').addEventListener('click', function () {
    const cur = (document.documentElement.dataset.theme || 'light') === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = cur;
    try { localStorage.setItem('ag_theme', cur); } catch (e) { /* noop */ }
    syncThemeIcon();
  });

  $id('btn-import').addEventListener('click', openImport);
  $id('btn-refresh').addEventListener('click', function () {
    S.nodesSig = '';
    S.credsSig = '';
    S.proxySig = '';
    tick();
  });
  $id('btn-proxy-start').addEventListener('click', async function () {
    const port = parseInt($id('proxy-port').value, 10) || 57890;
    try {
      await api('/proxy/start', { method: 'POST', json: { port: port } });
    } catch (e) { toast(String(e.message || e), 'err'); }
    S.proxySig = '';
    refreshProxy();
  });
  $id('btn-proxy-stop').addEventListener('click', async function () {
    try {
      await api('/proxy/stop', { method: 'POST' });
    } catch (e) { toast(String(e.message || e), 'err'); }
    S.proxySig = '';
    refreshProxy();
  });
  $id('adm-menu-btn').addEventListener('click', function (e) {
    e.stopPropagation();
    toggleAdminMenu();
  });
  // Notification inbox: bell toggles the card; read-all / clear actions
  $id('notify-btn').addEventListener('click', function () {
    const card = $id('notify-card');
    card.hidden = !card.hidden;
    if (!card.hidden) refreshNotify();
  });
  $id('btn-notify-read-all').addEventListener('click', async function () {
    try { await api('/notifications/read-all', { method: 'POST' }); } catch (e) { toast(String(e.message || e), 'err'); }
    S.notifySig = '';
    refreshNotify();
  });
  $id('btn-notify-clear').addEventListener('click', async function () {
    if (!(await askConfirm(T('notify.clearConfirm')))) return;
    try { await api('/notifications', { method: 'DELETE' }); } catch (e) { toast(String(e.message || e), 'err'); }
    S.notifySig = '';
    refreshNotify();
  });
  // Machine identity card: copy buttons + 我的名称 save
  $id('btn-machine-fp-copy').addEventListener('click', function () {
    const fp = (S.machineId && S.machineId.device_fp) || '';
    if (fp && navigator.clipboard) navigator.clipboard.writeText(fp).then(function () { toast(T('cl.copied'), 'ok'); }, function () {});
  });
  $id('btn-machine-pub-copy').addEventListener('click', function () {
    const pub = (S.machineId && S.machineId.openssh_pubkey) || '';
    if (pub && navigator.clipboard) navigator.clipboard.writeText(pub).then(function () { toast(T('cl.copied'), 'ok'); }, function () {});
  });
  $id('btn-machine-myname-save').addEventListener('click', async function () {
    try {
      await api('/identity/myname', { method: 'POST', json: { name: $id('machine-myname').value.trim() } });
      toast(T('cl.saved'), 'ok');
      loadIdentity();
    } catch (e) { toast(String(e.message || e), 'err'); }
  });
  $id('machine-myname').addEventListener('keydown', function (e) {
    if (e.key === 'Enter') { e.preventDefault(); $id('btn-machine-myname-save').click(); }
  });
  loadIdentity();
  document.addEventListener('mousedown', function (e) {
    const menu = $id('adm-menu');
    if (menu && !menu.contains(e.target)) $id('adm-drop').hidden = true;
  });
  document.addEventListener('visibilitychange', function () {
    if (document.hidden) stopLoops();
    else { tick(); startLoops(); }
  });

  tick();
  startLoops();
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
else boot();

})();
