'use strict';
/* Split from app.js: three-way role switches / system proxy management / settings view / doctor / sync & backup (pure move, zero logic change) */

/* ================= Three-way role switches ================= */
let pwdResolver = null;

/** Forced admin-password modal (Promisified; cancel resolves null) */
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
  const fp = st.cert_fingerprint || '';
  $('sv-fp').textContent = fp ? fp.slice(0, 16) + '…' : '-';
  $('sv-fp').title = fp;
  $('sv-pubhost').value = st.public_host || '';
}

/* Fan-out listen switch (fan-out view r-server and dashboard d-server are two entries to the same logic, states stay in sync) */
function syncServerSwitch(v) {
  $('r-server').checked = v;
  const d = $('d-server');
  if (d) d.checked = v;
}
async function serverToggle(on, el) {
  try {
    if (on) {
      // First enable forces setting an admin password
      const st = await invoke('server_status');
      if (!st.has_admin) {
        el.checked = false;
        const cred = await askPassword({
          title: AgI18n.t('settings.pwd-server-title'),
          desc: AgI18n.t('settings.pwd-server-desc'),
          showUser: true,
        });
        if (!cred) return;
        await invoke('init_server_admin', { username: cred.user, password: cred.pass });
        el.checked = true;
        toast(AgI18n.t('settings.admin-created'), 'ok');
      }
    }
    await invoke('set_server_role', { enabled: on });
    syncServerSwitch(on);
    await refreshServerPanel();
    refreshAdminEntry();
    renderDashFanout();
    toast(on ? AgI18n.t('settings.server-on') : AgI18n.t('settings.server-off'), 'ok');
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
  $('web-status').textContent = on ? AgI18n.t('settings.web-hint') : '';
}
/* Web remote panel listen address (inline-edit data source; initRoles loads it from get_role_settings) */
let WEB_LISTEN = '127.0.0.1:59291';
function validListenAddr(v) {
  const m = v.match(/^(.+):(\d+)$/);
  if (!m || !m[1].trim()) return AgI18n.t('settings.listen-invalid');
  const p = parseInt(m[2], 10);
  return (p >= 1 && p <= 65535) ? null : AgI18n.t('views.port-invalid-range');
}
/* Proxy card listen row / remote card listen address: unified inline-edit (shows ip:port [修改] → input + [保存]) */
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
        toast(AgI18n.t('settings.port-changed', { port: actual }), 'ok');
      } else {
        toast(st.running ? AgI18n.t('settings.port-unchanged') : AgI18n.t('settings.port-saved'), 'ok');
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
      toast(AgI18n.t('settings.listen-saved'), 'ok');
    },
  });
}
/* Float-ball bubble-notification row: greyed out and disabled while the float ball is off (follows s-float-ball checked state) */
function syncNotifyFloatRow() {
  const fb = $('s-float-ball'), row = $('row-notify-float'), sw = $('s-notify-float');
  if (!fb || !row || !sw) return;
  row.style.opacity = fb.checked ? '' : '.5';
  sw.disabled = !fb.checked;
}
async function initRoles() {
  let settings = { client: true, server: false, web: false, web_listen: '127.0.0.1:59291' };
  try { settings = await invoke('get_role_settings'); } catch (e) {}
  window._rolesCache = settings; // Data source for the Hero current-mode summary (system_proxy/tun_mode/sub_mode; updated at each change point, never re-fetched)
  $('r-client').checked = settings.client;
  $('r-server').checked = settings.server;
  $('d-server').checked = settings.server;
  $('r-web').checked = settings.web;
  // TUN initial value (detailed status synced by refreshTun polling; just set the switch here)
  TUN_UPSTREAM = settings.external_upstream || TUN_UPSTREAM;
  $('tun-mode').checked = !!settings.tun_mode;
  const subMode = settings.sub_mode || 'rule';
  $('sub-mode').value = subMode;
  $('sub-mode').dataset.prev = subMode;
  applySubFeature(!!settings.subscription_feature);
  // Initial values of the settings-view local toggles (system proxy lock / desktop float ball / float-ball bubble notifications / performance mode)
  $('s-sysproxy-lock').checked = !!settings.sysproxy_lock;
  $('s-float-ball').checked = !!settings.float_ball;
  $('s-notify-float').checked = !!settings.notify_float_ball;
  syncNotifyFloatRow();
  // Performance mode: get_role_settings().reduce_effects corrects the value pre-applied from localStorage at startup
  const reduceFx = !!settings.reduce_effects;
  $('s-reduce-effects').checked = reduceFx;
  localStorage.setItem('ag_reduce_fx', reduceFx ? '1' : '0');
  applyReduceEffects(reduceFx);
  WEB_LISTEN = settings.web_listen;
  applyClientRole(settings.client);
  refreshServerPanel();
  refreshWebPanel();

  $('r-client').onchange = async (e) => {
    try {
      await invoke('set_client_role', { enabled: e.target.checked });
      applyClientRole(e.target.checked);
      toast(e.target.checked ? AgI18n.t('settings.client-on') : AgI18n.t('settings.client-off'), 'ok');
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
          title: AgI18n.t('settings.pwd-web-title'),
          desc: AgI18n.t('settings.pwd-web-desc'),
          showUser: false,
        });
        if (!cred) return;
        await invoke('set_web_password', { password: cred.pass });
        e.target.checked = true;
        toast(AgI18n.t('settings.web-pwd-set'), 'ok');
      }
      await invoke('set_web_role', { enabled: on, listen: WEB_LISTEN || null });
      refreshWebPanel();
      toast(on ? AgI18n.t('settings.web-on') : AgI18n.t('settings.web-off'), 'ok');
    } catch (err) {
      e.target.checked = !on;
      toast(friendlyError(err), 'err');
    }
  };

  $('btn-open-console').onclick = () => enterAdmin(null, null, AgI18n.t('views.admin-local'));

  // Relay cert fingerprint: fan-out peers pin this value to verify the self-signed mimicry cert (no insecure needed)
  $('btn-fp-copy').onclick = async () => {
    const fp = (window._serverStatus && window._serverStatus.cert_fingerprint) || '';
    if (!fp) { toast(AgI18n.t('views.fp-unavailable'), 'err'); return; }
    try {
      await navigator.clipboard.writeText(fp);
      toast(AgI18n.t('views.fp-copied'), 'ok');
    } catch (e) { /* clipboard unavailable: stay silent */ }
  };

  // Public endpoint host: hot-applied to node_config.public_host (next connect_url uses it immediately)
  $('btn-pubhost-save').onclick = async () => {
    try {
      await invoke('set_server_public_host', { host: $('sv-pubhost').value.trim() });
      toast(AgI18n.t('views.pubhost-saved'), 'ok');
      refreshServerPanel();
    } catch (e) { toast(friendlyError(e), 'err'); }
  };

  /* Settings-view local toggles: lock system proxy / desktop float ball (roll back the checkbox on failure) */
  $('s-sysproxy-lock').onchange = async (e) => {
    const on = e.target.checked;
    try {
      await invoke('set_sysproxy_lock', { on });
      if (window._rolesCache) window._rolesCache.sysproxy_lock = on;
      toast(on ? AgI18n.t('settings.lock-on') : AgI18n.t('settings.lock-off'), 'ok');
    } catch (err) {
      e.target.checked = !on;
      toast(friendlyError(err), 'err');
    }
  };
  $('s-float-ball').onchange = async (e) => {
    const on = e.target.checked;
    try {
      await invoke('set_float_ball', { on });
      toast(on ? AgI18n.t('settings.float-on') : AgI18n.t('settings.float-off'), 'ok');
    } catch (err) {
      e.target.checked = !on;
      toast(friendlyError(err), 'err');
    }
    syncNotifyFloatRow(); // Grey out and disable the bubble-notification row when the float ball is off
  };
  $('s-notify-float').onchange = async (e) => {
    const on = e.target.checked;
    try {
      await invoke('set_notify_float_ball', { on });
      toast(on ? AgI18n.t('settings.notify-on') : AgI18n.t('settings.notify-off'), 'ok');
    } catch (err) {
      e.target.checked = !on;
      toast(friendlyError(err), 'err');
    }
  };
  $('s-reduce-effects').onchange = async (e) => {
    const on = e.target.checked;
    try {
      await invoke('set_reduce_effects', { on });
      applyReduceEffects(on);
      localStorage.setItem('ag_reduce_fx', on ? '1' : '0');
      toast(on ? AgI18n.t('settings.perf-on') : AgI18n.t('settings.perf-off'), 'ok');
    } catch (err) {
      e.target.checked = !on;
      toast(friendlyError(err), 'err');
    }
  };

  $('pwd-cancel').onclick = () => closePwdModal(null);
  $('pwd-ok').onclick = () => {
    const user = $('pwd-user').value.trim();
    const p1 = $('pwd-pass').value, p2 = $('pwd-pass2').value;
    if ($('pwd-user-row').style.display !== 'none' && !user) { toast(AgI18n.t('settings.pwd-user-required'), 'err'); return; }
    if (p1.length < 10) { toast(AgI18n.t('settings.pwd-too-short'), 'err'); return; }
    if (p1 !== p2) { toast(AgI18n.t('settings.pwd-mismatch'), 'err'); return; }
    closePwdModal({ user, pass: p1 });
  };
}

/* ================= System proxy management ================= */
let _spConflict = false;
let CUR_PROXY_MODE = 'system'; // system=take over the system proxy (default) / local=listen on the port only
async function refreshSysproxy() {
  let st;
  try { st = await invoke('sysproxy_status'); } catch (e) { return; }
  CUR_PROXY_MODE = st.managed ? 'system' : 'local';
  document.querySelectorAll('#proxy-mode .group-tab').forEach(b =>
    b.classList.toggle('active', b.dataset.proxyMode === CUR_PROXY_MODE));
  const banner = $('sysproxy-banner');
  // In TUN mode the backend patrol auto-reclaims conflicts within 30s (§2.6); don't nag the user
  if (st.managed && st.conflict && !TUN_ON) {
    banner.style.display = 'flex';
    $('sysproxy-banner-text').textContent = AgI18n.t('settings.sp-conflict', { cur: st.current || AgI18n.t('settings.sp-none'), want: st.expected });
    if (!_spConflict) { _spConflict = true; toast(AgI18n.t('settings.sp-conflict-toast'), 'err'); }
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
        // If the proxy is not running, start it on the current port first (backend set_system_proxy also brings it up as fallback)
        const st = await invoke('proxy_status');
        if (!st.running) {
          await invoke('start_proxy', { port: proxyPort() });
        }
        await invoke('set_system_proxy', { enabled: true });
        toast(AgI18n.t('settings.sp-system-toast'), 'ok');
      } else {
        await invoke('set_system_proxy', { enabled: false });
        toast(AgI18n.t('settings.sp-local-toast', { addr: '127.0.0.1:' + proxyPort() }), 'ok');
      }
      if (window._rolesCache) window._rolesCache.system_proxy = btn.dataset.proxyMode === 'system';
      refreshSysproxy();
      refreshProxy();
    } catch (err) { toast(friendlyError(err), 'err'); }
  });
  $('btn-sysproxy-reclaim').onclick = async () => {
    try { await invoke('reclaim_sysproxy'); toast(AgI18n.t('settings.sp-reclaimed'), 'ok'); refreshSysproxy(); }
    catch (err) { toast(friendlyError(err), 'err'); }
  };
}

/* ================= Doctor (run_doctor scans item by item; items fade in one by one, fixed items marked 「已自动修复」) ================= */
const DOCTOR_PILL = {
  ok: ['pill-ok', 'settings.doc-ok'], info: ['pill-dim', 'settings.doc-info'], warn: ['pill-warn', 'settings.doc-warn'],
  err: ['pill-danger', 'settings.doc-err'], fixed: ['pill-ok', 'settings.doc-fixed'],
};
function doctorPill(status) {
  const p = DOCTOR_PILL[status] || DOCTOR_PILL.info;
  return '<span class="pill ' + p[0] + '">' + AgI18n.t(p[1]) + '</span>';
}
function doctorSectionHtml(sec) {
  return '<div style="margin-bottom:4px"><b>' + esc(sec.title) + '</b></div>' +
    '<div class="role-list">' +
    (sec.items || []).map(it =>
      '<div class="role-row" style="align-items:flex-start;padding:6px 0">' +
      '<div class="role-info"><b>' + doctorPill(it.status) + ' ' + esc(it.label) + '</b>' +
      (it.detail ? '<span class="hint">' + esc(it.detail) + '</span>' : '') +
      (it.suggestion ? '<span class="hint" style="opacity:.65">' + esc(it.suggestion) + '</span>' : '') +
      '</div></div>').join('') +
    '</div>';
}
function doctorSummaryHtml(res) {
  const sum = res.summary || {};
  const pills = [];
  if (sum.ok) pills.push('<span class="pill pill-ok">' + AgI18n.t('settings.doc-pass', { n: sum.ok }) + '</span>');
  if (sum.warn) pills.push('<span class="pill pill-warn">' + AgI18n.t('settings.doc-warns', { n: sum.warn }) + '</span>');
  if (sum.err) pills.push('<span class="pill pill-danger">' + AgI18n.t('settings.doc-errs', { n: sum.err }) + '</span>');
  if (sum.fixed) pills.push('<span class="pill pill-ok">' + AgI18n.t('settings.doc-fixed-n', { n: sum.fixed }) + '</span>');
  const dur = typeof res.duration_ms === 'number'
    ? (res.duration_ms >= 1000 ? (res.duration_ms / 1000).toFixed(1) + 's' : res.duration_ms + 'ms') : '';
  return (pills.join('') || '<span class="pill pill-dim">' + AgI18n.t('settings.doc-none') + '</span>') +
    (dur ? '<span class="hint" style="margin-top:0">' + AgI18n.t('settings.doc-duration', { dur: esc(dur) }) + '</span>' : '');
}
/* Block-level fade-in helper (shared by streaming and full render) */
function doctorFadeIn(el, delay) {
  el.style.opacity = '0';
  el.style.transform = 'translateY(4px)';
  el.style.transition = 'opacity .3s ease, transform .3s ease';
  setTimeout(() => {
    if (!el.isConnected) return;
    el.style.opacity = '1';
    el.style.transform = 'translateY(0)';
  }, delay || 0);
}
async function runDoctor() {
  const btn = $('btn-doctor-run');
  const panel = $('doctor-panel');
  btn.disabled = true;
  panel.style.display = '';
  panel.innerHTML = '<div class="hint" style="margin-top:10px"><span class="spinner"></span>' + AgI18n.t('settings.doc-preparing') + '</div>';
  let unlisten = [], streamed = false;
  const cleanup = () => { unlisten.forEach(u => { try { u && u(); } catch (e) {} }); unlisten = []; };
  try {
    if (TAURI && TAURI.event) {
      // Streaming: begin carries the section plan and renders skeletons (「诊断中…」 per section); section events replace them in place on arrival
      unlisten.push(await TAURI.event.listen('ag-doctor-begin', (ev) => {
        const plan = ev.payload || [];
        panel.innerHTML = '<div class="doctor-block" id="doctor-summary" style="display:flex;gap:6px;align-items:center;flex-wrap:wrap"></div>' +
          plan.map(p =>
            '<div class="doctor-block" data-sec="' + esc(p[0]) + '" style="margin-top:14px">' +
            '<div style="margin-bottom:4px"><b>' + esc(p[1]) + '</b></div>' +
            '<div class="hint" style="margin-top:0"><span class="spinner"></span>' + AgI18n.t('settings.doc-running') + '</div></div>').join('');
        [...panel.querySelectorAll('.doctor-block')].forEach((b, i) => doctorFadeIn(b, i * 100));
      }));
      unlisten.push(await TAURI.event.listen('ag-doctor-section', (ev) => {
        const sec = ev.payload;
        if (!sec || !sec.id) return;
        const slot = panel.querySelector('.doctor-block[data-sec="' + sec.id + '"]');
        if (!slot) return; // Ignore if begin hasn't arrived yet; the final full render is the fallback
        streamed = true;
        slot.innerHTML = doctorSectionHtml(sec);
        doctorFadeIn(slot, 0);
      }));
    }
    const res = await invoke('run_doctor');
    const sumEl = $('doctor-summary');
    if (streamed && sumEl) {
      // Streaming done: settle the summary at the top (skeletons already replaced section by section with real results)
      sumEl.innerHTML = doctorSummaryHtml(res);
      doctorFadeIn(sumEl, 0);
    } else {
      renderDoctor(res); // No event channel (or events lost): fall back to full render
    }
  } catch (e) {
    panel.innerHTML = '<div class="hint" style="margin-top:10px">' + AgI18n.t('settings.doc-not-ready', { err: esc(friendlyError(e)) }) + '</div>';
  } finally {
    cleanup();
    btn.disabled = false;
  }
}
function renderDoctor(res) {
  const panel = $('doctor-panel');
  const secs = res.sections || [];
  let html = '<div class="doctor-block" style="margin-top:12px;display:flex;gap:6px;align-items:center;flex-wrap:wrap">' +
    doctorSummaryHtml(res) + '</div>';
  html += secs.map(sec =>
    '<div class="doctor-block" style="margin-top:14px">' + doctorSectionHtml(sec) + '</div>').join('');
  panel.innerHTML = html;
  [...panel.querySelectorAll('.doctor-block')].forEach((b, i) => doctorFadeIn(b, i * 150));
}

/* ================= Settings ================= */
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
      toast(e.target.checked ? AgI18n.t('settings.autostart-on') : AgI18n.t('settings.autostart-off'), 'ok');
    } catch (err) {
      e.target.checked = !e.target.checked;
      toast(friendlyError(err), 'err');
    }
  };

  // Doctor (click again to re-run)
  $('btn-doctor-run').onclick = runDoctor;

  // Sync & backup: channel switch toggles config areas; PIN input digit filter; button bindings (all re-entry-guarded inside)
  $('sync-target').onchange = () => syncShowTarget($('sync-target').value);
  $('sync-pin').addEventListener('input', e => { e.target.value = e.target.value.replace(/\D/g, ''); });
  $('btn-sync-save').onclick = syncSave;
  $('btn-sync-check').onclick = syncCheck;
  $('btn-sync-upload').onclick = syncUpload;
  $('btn-sync-restore').onclick = syncRestoreAsk;
  $('btn-sync-export').onclick = syncExportFile;
  $('btn-sync-import').onclick = syncImportAsk;
  $('sync-restore-cancel').onclick = () => { $('sync-restore-modal').style.display = 'none'; };
  $('sync-restore-ok').onclick = syncRestoreDo;
}

/* ================= Sync & backup (WebDAV/S3/manual file; PIN never persisted, read from the card input on every op) =================
   Backend apps/desktop/src/sync.rs: compares versions (upload = max(remote, local)+1); app auto-restarts 500ms after a successful restore/import.
   set_sync_config takes a nested struct {target, webdav:{url,user,pass}, s3:{endpoint,bucket,ak,sk,region,prefix}, pin_set};
   empty pass/sk = keep the original (echoed masked like **ab; leave blank when re-editing). */
let SYNC_CFG = null;     // get_sync_config cache (masked echo / pin_set retention / status line)
let SYNC_RESTORE = null; // Restore-confirm modal context {kind:'remote', st} | {kind:'file', path}

function syncPin() { return $('sync-pin').value.trim(); }
/* PIN validation: empty or exactly 4 digits; toast and return null if invalid (empty string is valid — never use a falsy check) */
function syncPinValid() {
  const p = syncPin();
  if (p && !/^\d{4}$/.test(p)) { toast(AgI18n.t('settings.pin-invalid'), 'err'); return null; }
  return p;
}
/* Backend target is only none/webdav/s3; 「手动导入导出」 is a pure frontend file channel, persisted as none (UI choice stored separately in localStorage) */
function syncTargetBackend() {
  const v = $('sync-target').value;
  return v === 'file' ? 'none' : v;
}
function syncShowTarget(v) {
  $('sync-cfg-webdav').style.display = v === 'webdav' ? 'block' : 'none';
  $('sync-cfg-s3').style.display = v === 's3' ? 'block' : 'none';
  $('sync-cfg-file').style.display = v === 'file' ? 'block' : 'none';
  // Check/upload/restore only make sense for network channels; the file channel uses the export/import buttons in its config area
  const ops = v === 'webdav' || v === 's3';
  ['btn-sync-check', 'btn-sync-upload', 'btn-sync-restore'].forEach(id => { $(id).style.display = ops ? '' : 'none'; });
}
/* Button re-entry guard: disabled + spinner while busy, restore the original innerHTML (incl. icon) when done */
function syncBusy(btn, on, text) {
  if (!btn) return;
  btn.disabled = on;
  if (on) { btn._html = btn.innerHTML; btn.innerHTML = '<span class="spinner"></span>' + text; }
  else if (btn._html) { btn.innerHTML = btn._html; btn._html = null; }
}

/* Render on entering the settings view: target selection, field backfill (mask into placeholder), status line */
async function loadSyncConfig() {
  if (HTTP_MODE) return; // Whole card hidden, and the Web remote panel lacks this command
  let cfg;
  try { cfg = await invoke('get_sync_config'); } catch (e) { return; }
  SYNC_CFG = cfg;
  let ui = ['none', 'webdav', 's3'].includes(cfg.target) ? cfg.target : 'none';
  if (ui === 'none' && localStorage.getItem('ag_sync_target_ui') === 'file') ui = 'file';
  const sel = $('sync-target');
  if (sel.value !== ui) { sel.value = ui; agSelectRefresh(sel); }
  syncShowTarget(ui);
  $('sync-wd-url').value = cfg.webdav_url || '';
  $('sync-wd-user').value = cfg.webdav_user || '';
  $('sync-wd-pass').value = '';
  $('sync-wd-pass').placeholder = cfg.webdav_pass_mask ? AgI18n.t('settings.pw-masked', { mask: cfg.webdav_pass_mask }) : AgI18n.t('settings.pw-keep');
  $('sync-s3-endpoint').value = cfg.s3_endpoint || '';
  $('sync-s3-bucket').value = cfg.s3_bucket || '';
  $('sync-s3-ak').value = cfg.s3_ak || '';
  $('sync-s3-sk').value = '';
  $('sync-s3-sk').placeholder = cfg.s3_sk_mask ? AgI18n.t('settings.pw-masked', { mask: cfg.s3_sk_mask }) : AgI18n.t('settings.pw-keep');
  $('sync-s3-region').value = cfg.s3_region || '';
  $('sync-s3-prefix').value = cfg.s3_prefix || '';
  renderSyncState(cfg);
  $('sync-check-result').style.display = 'none';
}

/* Status line: version number scrolls via odo (odoSet signature-compares internally, no DOM touch when unchanged); other text written with change detection */
function renderSyncState(cfg) {
  odoSet($('sync-ver'), 'v' + (cfg.version || 0));
  let rest = cfg.last_upload_at
    ? AgI18n.t('settings.sync-uploaded', { time: fmtAgo(cfg.last_upload_at) }) + (cfg.last_device ? AgI18n.t('settings.sync-device', { name: cfg.last_device }) : '')
    : AgI18n.t('settings.sync-never');
  if (cfg.last_restore_at) rest += AgI18n.t('settings.sync-restored', { time: fmtAgo(cfg.last_restore_at) });
  setText('sync-state-rest', rest);
}

async function syncSave() {
  const pin = syncPin();
  if (pin && !/^\d{4}$/.test(pin)) { toast(AgI18n.t('settings.pin-invalid'), 'err'); return; }
  const cfg = {
    target: syncTargetBackend(),
    webdav: { url: $('sync-wd-url').value.trim(), user: $('sync-wd-user').value.trim(), pass: $('sync-wd-pass').value },
    s3: {
      endpoint: $('sync-s3-endpoint').value.trim(), bucket: $('sync-s3-bucket').value.trim(),
      ak: $('sync-s3-ak').value.trim(), sk: $('sync-s3-sk').value,
      region: $('sync-s3-region').value.trim(), prefix: $('sync-s3-prefix').value.trim(),
    },
    // pin_set is a UI hint flag only: true once 4 digits entered on this card; blank keeps the old value (PIN itself never persisted; backend also sets true after a PIN'd upload)
    pin_set: pin.length === 4 ? true : !!(SYNC_CFG && SYNC_CFG.pin_set),
  };
  if (cfg.target === 'webdav' && !cfg.webdav.url) { toast(AgI18n.t('settings.wd-url-required'), 'err'); return; }
  if (cfg.target === 's3' && (!cfg.s3.endpoint || !cfg.s3.bucket)) { toast(AgI18n.t('settings.s3-required'), 'err'); return; }
  const btn = $('btn-sync-save');
  syncBusy(btn, true, AgI18n.t('settings.saving'));
  try {
    await invoke('set_sync_config', { cfg });
    localStorage.setItem('ag_sync_target_ui', $('sync-target').value);
    toast(AgI18n.t('settings.sync-saved'), 'ok');
    await loadSyncConfig(); // Re-fetch to refresh the mask and status line
  } catch (e) { toast(friendlyError(e), 'err'); }
  syncBusy(btn, false);
}

/* relation → small text under the status line (rendered after remote check / successful upload) */
function renderSyncCheck(st) {
  const el = $('sync-check-result');
  let s;
  switch (st.relation) {
    case 'newer': s = AgI18n.t('settings.chk-newer', { v: st.remote_version, dev: st.remote_device || AgI18n.t('settings.unknown-device'), time: fmtAgo(st.remote_at) }); break;
    case 'same': s = AgI18n.t('settings.chk-same', { v: st.local_version }); break;
    case 'older': s = AgI18n.t('settings.chk-older', { a: st.local_version, b: st.remote_version }); break;
    case 'empty': s = AgI18n.t('settings.chk-empty'); break;
    case 'unconfigured': s = AgI18n.t('settings.chk-unconfigured'); break;
    case 'need-pin': s = AgI18n.t('settings.chk-need-pin'); break;
    default: s = st.relation;
  }
  el.textContent = s;
  el.style.display = '';
}

async function syncCheck() {
  const pin = syncPinValid(); if (pin === null) return;
  const btn = $('btn-sync-check');
  syncBusy(btn, true, AgI18n.t('settings.checking'));
  try { renderSyncCheck(await invoke('sync_check', { pin })); }
  catch (e) { $('sync-check-result').style.display = 'none'; toast(friendlyError(e), 'err'); }
  syncBusy(btn, false);
}

async function syncUpload() {
  const pin = syncPinValid(); if (pin === null) return;
  const btn = $('btn-sync-upload');
  syncBusy(btn, true, AgI18n.t('settings.uploading'));
  try {
    const st = await invoke('sync_upload', { pin });
    toast(AgI18n.t('settings.uploaded', { v: st.local_version }), 'ok');
    await loadSyncConfig(); // version already +1; status line updates with odo scroll
    renderSyncCheck(st);
  } catch (e) { toast(friendlyError(e), 'err'); }
  syncBusy(btn, false);
}

/* Pull & restore: sync_check first, then the confirm modal; unrestorable relations (unconfigured/no archive/missing PIN) blocked with a toast */
async function syncRestoreAsk() {
  const pin = syncPinValid(); if (pin === null) return;
  const btn = $('btn-sync-restore');
  syncBusy(btn, true, AgI18n.t('settings.checking'));
  try {
    const st = await invoke('sync_check', { pin });
    if (st.relation === 'unconfigured') { toast(AgI18n.t('settings.chk-unconfigured'), 'err'); return; }
    if (st.relation === 'empty') { toast(AgI18n.t('settings.chk-empty'), 'err'); return; }
    if (st.relation === 'need-pin') { toast(AgI18n.t('settings.need-pin-err'), 'err'); return; }
    openSyncRestoreModal({ kind: 'remote', st });
  } catch (e) { toast(friendlyError(e), 'err'); }
  finally { syncBusy(btn, false); }
}

/* Restore-confirm modal: shared by remote (version compare + yellow warning when older) and file import (source text becomes the file path) */
function openSyncRestoreModal(req) {
  SYNC_RESTORE = req;
  const isRemote = req.kind === 'remote';
  setText('sync-restore-src', isRemote
    ? AgI18n.t('settings.restore-src-remote', { ch: $('sync-target').value === 's3' ? 'S3' : 'WebDAV' })
    : AgI18n.t('settings.restore-src-file'));
  setText('sync-restore-remote-k', isRemote ? AgI18n.t('settings.restore-remote-k') : AgI18n.t('settings.restore-file-k'));
  setText('sync-restore-remote', isRemote
    ? AgI18n.t('settings.restore-remote-fmt', { v: req.st.remote_version, dev: req.st.remote_device || AgI18n.t('settings.unknown-device'), time: fmtAgo(req.st.remote_at) })
    : req.path);
  setText('sync-restore-local', 'v' + (isRemote ? req.st.local_version : (SYNC_CFG ? SYNC_CFG.version : 0)));
  $('sync-restore-warn').style.display = isRemote && req.st.relation === 'older' ? '' : 'none';
  $('sync-restore-err').textContent = '';
  syncBusy($('sync-restore-ok'), false); // Reset on reopen (busy state left over from a previous failure)
  $('sync-restore-modal').style.display = 'flex';
}

/* Confirm restore: on success the backend auto-restarts the app in 500ms; no frontend follow-up needed */
async function syncRestoreDo() {
  if (!SYNC_RESTORE) return;
  const pin = syncPinValid(); if (pin === null) return;
  const btn = $('sync-restore-ok');
  syncBusy(btn, true, AgI18n.t('settings.restoring'));
  try {
    if (SYNC_RESTORE.kind === 'remote') await invoke('sync_restore', { pin });
    else await invoke('sync_import', { path: SYNC_RESTORE.path, pin });
  } catch (e) {
    syncBusy(btn, false);
    $('sync-restore-err').textContent = friendlyError(e);
  }
}

/* File-channel export: toast shows the full path; export also bumps version +1, refresh the status line */
async function syncExportFile() {
  const path = $('sync-file-export').value.trim();
  if (!path) { toast(AgI18n.t('settings.export-path-required'), 'err'); return; }
  const pin = syncPinValid(); if (pin === null) return;
  const btn = $('btn-sync-export');
  syncBusy(btn, true, AgI18n.t('settings.exporting'));
  try {
    await invoke('sync_export', { path, pin });
    toast(AgI18n.t('settings.exported', { path }), 'ok');
    await loadSyncConfig();
  } catch (e) { toast(friendlyError(e), 'err'); }
  syncBusy(btn, false);
}

/* File-channel import: same restore-confirm flow (source text is the file path) */
function syncImportAsk() {
  const path = $('sync-file-import').value.trim();
  if (!path) { toast(AgI18n.t('settings.import-path-required'), 'err'); return; }
  if (syncPinValid() === null) return;
  openSyncRestoreModal({ kind: 'file', path });
}


/* Language switch: re-render role panels/conflict banner/sync status line in the new language (doctor result text comes from the backend; only a re-run updates it) */
if (window.AgI18n) AgI18n.onChange(() => {
  refreshServerPanel();
  refreshWebPanel();
  refreshSysproxy();
  if (SYNC_CFG) renderSyncState(SYNC_CFG);
});
