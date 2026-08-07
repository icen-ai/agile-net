'use strict';
/* Startup assembly (kept after the split): Web remote panel login / applySubFeature / titlebar / view navigation & window control / startup sequence.
   Domain code lives in app-core.js / app-views.js / app-subscription.js / app-hero.js / app-logs.js / app-settings.js (pure move, zero logic change) */

/* ---- Web remote panel login ---- */
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
    if (json.code !== 0) { toast(json.message || AgI18n.t('app.loginFailed'), 'err'); return; }
    httpToken = json.data.access_token;
    localStorage.setItem('ag_web_token', httpToken);
    location.reload();
  } catch (e) {
    toast(AgI18n.t('app.loginUnreachable'), 'err');
  }
}

/** Feature-entry visibility (after install/activation the sidebar shows 「订阅/代理」; the dashboard subscription card switches to guide state) */
function applySubFeature(on) {
  document.querySelectorAll('.nav-item.sub-feature').forEach(n => { n.style.display = on ? '' : 'none'; });
  $('btn-activate-sub').style.display = on ? 'none' : '';
  $('btn-deactivate-sub').style.display = on ? '' : 'none';
  const body = $('d-sub-body'), guide = $('d-sub-guide'), sw = $('d-sub-switch');
  if (body) body.style.display = on ? '' : 'none';
  if (guide) guide.style.display = on ? 'none' : '';
  if (sw) sw.style.display = on ? '' : 'none';
}

/* ================= Titlebar (collapse / more menu / about) ================= */
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
  // Sidebar collapse (remembered)
  if (localStorage.getItem('ag_sidebar') === 'collapsed') document.body.classList.add('collapsed');
  $('btn-collapse').onclick = () => {
    const collapsed = document.body.classList.toggle('collapsed');
    localStorage.setItem('ag_sidebar', collapsed ? 'collapsed' : '');
  };
  // More menu (click outside to close)
  const menu = $('more-menu');
  $('btn-more').onclick = (e) => {
    e.stopPropagation();
    menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
  };
  document.addEventListener('click', (e) => {
    if (!e.target.closest('#more-menu') && !e.target.closest('#btn-more')) menu.style.display = 'none';
  });
  // Menu and about-modal actions
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

/* ================= View navigation & window control ================= */
let CUR_VIEW = 'connect';
function switchView(v) {
  if (CUR_VIEW === 'logs' && v !== 'logs') LogsView.stop(); // Leaving the logs view stops polling immediately
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
  if (v === 'notify') refreshNotify(true);
  if (v === 'settings') { refreshSysproxy(); refreshSubFeature(); loadSyncConfig(); loadMachineIdentity(); }
}
function initTitlebar() {
  if (!TAURI || !TAURI.window) return;
  const win = TAURI.window.getCurrentWindow();
  $('tb-min').onclick = () => win.minimize();
  $('tb-max').onclick = () => win.toggleMaximize();
  $('tb-close').onclick = () => win.close();
}

/* ================= Startup ================= */
window.addEventListener('DOMContentLoaded', async () => {
  Island.init();
  bindSearch();
  document.querySelectorAll('#nav-client .nav-item').forEach(n => n.onclick = () => switchView(n.dataset.view));
  document.querySelectorAll('#bnav .bnav-item').forEach(n => n.onclick = () => switchView(n.dataset.view));
  initAdminMode();
  initUpstreams();
  initRules();
  initLogs();
  initAgent();
  initNotify();

  // Browser mode (Web remote panel): local-only cards/toggles hidden via .local-only; show the login modal first when unauthenticated
  if (HTTP_MODE) {
    document.body.classList.add('http-mode');
    const as = $('s-autostart'); if (as) { const l = as.closest('label'); if (l) l.style.display = 'none'; }
    const sp = $('proxy-mode'); if (sp) sp.style.display = 'none';
    const subNav = document.querySelector('.nav-item[data-view="subscription"]');
    if (subNav) subNav.style.display = 'none';
    // Logs view (subscription kernel observability) and local-only settings are desktop capabilities; hidden on the Web remote panel
    const logsNav = document.querySelector('.nav-item[data-view="logs"]');
    if (logsNav) logsNav.style.display = 'none';
    // Narrow-screen bottom nav holds desktop entries like logs; hide it entirely on the Web remote panel (inline none overrides the ≤720px breakpoint's flex)
    $('bnav').style.display = 'none';
    ['row-sysproxy-lock', 'row-doctor', 'row-float-ball', 'row-notify-float', 'row-reduce-effects', 'sync-card', 'agent-card'].forEach(id => {
      const r = $(id); if (r) r.style.display = 'none';
    });
    // Admin console is a local-only capability (ticket/forwarder loopback only); hide its entry on the Web remote panel
    $('btn-admin').style.display = 'none';
    // AI assistant is desktop-only (tauri commands + keyring + local tools)
    $('btn-agent').style.display = 'none';
    $('login-ok').onclick = webLogin;
    $('login-pass').addEventListener('keydown', e => { if (e.key === 'Enter') webLogin(); });
    if (!httpToken) { showLogin(); return; }
  }

  // Uninstall: shown only on desktop (Windows installed build); hidden on the browser remote panel and Android
  const unCard = $('btn-uninstall') && $('btn-uninstall').closest('.card');
  if (HTTP_MODE || /Android/i.test(navigator.userAgent)) {
    if (unCard) unCard.style.display = 'none';
    // Desktop float ball is a desktop window capability; hide on Android too (the bubble-notification row hides along with it)
    const fb = $('row-float-ball'); if (fb) fb.style.display = 'none';
    const nf = $('row-notify-float'); if (nf) nf.style.display = 'none';
  } else {
    $('btn-uninstall').onclick = () => { $('uninstall-modal').style.display = 'flex'; };
    $('un-cancel').onclick = () => { $('uninstall-modal').style.display = 'none'; };
    $('un-ok').onclick = async () => {
      const prefs = $('un-prefs').checked;
      $('un-ok').disabled = true;
      $('un-ok').textContent = AgI18n.t('app.uninstalling');
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
        // The backend then exits the process and launches the system uninstaller; nothing more to do here
      } catch (err) {
        $('un-ok').disabled = false;
        $('un-ok').textContent = AgI18n.t('app.uninstall');
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
  // Universal import wizard (titlebar link button): anet:// link / .anet file / QR image — one dialog for all
  $('btn-agimport').onclick = openUniversalImport;
  $('btn-paste').onclick = pasteFromClipboard;
  // .anet import (file picker entry; drag-drop and file association funnel into the same dialog)
  $('btn-anet').onclick = async () => {
    if (HTTP_MODE) { $('anet-file-input').click(); return; }
    try {
      const r = await invoke('anet_open_file');
      if (r) anetImportDialog(r.content, r.name);
    } catch (e) { toast(friendlyError(e), 'err'); }
  };
  $('anet-file-input').onchange = async (e) => {
    const f = e.target.files[0];
    e.target.value = '';
    if (f) anetImportDialog(await f.text(), f.name);
  };
  // .anet drag-drop import (only .anet files claimed; the subscription card owns its YAML drop)
  document.addEventListener('dragover', (e) => {
    if ([...(e.dataTransfer ? e.dataTransfer.items : [])].some(i => i.kind === 'file')) e.preventDefault();
  });
  document.addEventListener('drop', async (e) => {
    const f = e.dataTransfer && e.dataTransfer.files && [...e.dataTransfer.files].find(f => /\.anet$/i.test(f.name));
    if (!f) return;
    e.preventDefault();
    anetImportDialog(await f.text(), f.name);
  });
  // Deep link / file association payloads (anet:// links routed by role; .anet files into the import dialog)
  if (TAURI && TAURI.event) {
    TAURI.event.listen('ag-open-payload', async (e) => {
      const p = e.payload || {};
      if (p.kind === 'link') {
        const url = String(p.value || '');
        const parsed = AgLink.parse(url);
        if (parsed.error) { toast(AgI18n.t('core.err-bad-url'), 'err'); return; }
        if (parsed.role === 'connect') { switchView('connect'); importUrl(url, null); }
        else { switchView('upstreams'); foOpenModal(null); foFillFields(parsed); toast(AgI18n.t('fanout.pasted'), 'ok'); }
      } else if (p.kind === 'file') {
        try {
          const content = await invoke('read_text_file', { path: String(p.value || '') });
          anetImportDialog(content, String(p.value).split(/[\\/]/).pop());
        } catch (err) { toast(friendlyError(err), 'err'); }
      }
    });
    // Role settings broadcast (float ball / tray mode switches): converge _rolesCache at once
    // instead of waiting for the 10s poll (web.md §1.3; emit ag-roles from the Rust setters)
    TAURI.event.listen('ag-roles', (e) => {
      if (!e.payload) return;
      window._rolesCache = e.payload;
      window._rolesSig = JSON.stringify(e.payload);
      if (window.Hero && Hero.renderMode) Hero.renderMode();
    });
    // Notification center push (M4-T1): a fresh inbox entry refreshes the badge/list at once
    // (the float-ball bubble is raised Rust-side by notify_watch; here: toast + node refresh —
    // a session notice usually flips a node into Blocked/PendingApproval)
    TAURI.event.listen('ag-notify', (e) => {
      const n = e.payload || {};
      refreshNotify(true);
      refreshNodes(true);
      if (n.title) toast(String(n.title), n.kind === 'session' ? 'err' : 'info');
    });
  }
  $('link-paste').onclick = pasteFromClipboard;
  $('link-manual').onclick = () => { switchView('nodes'); $('manual-modal').style.display = 'flex'; };
  // Manual connect modal (next to 导入链接): open / cancel / mask-close; connect closes the modal on submit
  $('btn-manual').onclick = () => { $('manual-modal').style.display = 'flex'; };
  $('btn-manual-cancel').onclick = () => { $('manual-modal').style.display = 'none'; };
  $('manual-modal').onclick = (e) => { if (e.target === $('manual-modal')) $('manual-modal').style.display = 'none'; };
  $('connect-url').addEventListener('keydown', e => { if (e.key === 'Enter') $('btn-import').click(); });
  $('connect-url-hero').addEventListener('keydown', e => { if (e.key === 'Enter') $('btn-import-hero').click(); });
  $('connect-url-hero').focus();
  $('btn-connect').onclick = () => {
    const addr = $('m-addr').value.trim(), token = $('m-token').value.trim();
    const name = $('m-name').value.trim(), fp = $('m-fp').value.trim().toLowerCase();
    if (!addr || !token) { toast(AgI18n.t('app.err.fillAll'), 'err'); return; }
    if (fp && !/^[0-9a-f]{64}$/.test(fp)) { toast(AgI18n.t('fanin.fpInvalid'), 'err'); return; }
    $('manual-modal').style.display = 'none';
    // Delegated credential: the remark doubles as the token label (display identity; the issuer
    // authenticates by token hash only). Fallback label = entry host.
    connectWith({
      addr, label: name || addr.split(':')[0], token,
      insecure: false,
      pinned_fingerprint: fp || null,
      manage_hosts: $('m-hosts').checked,
      save_credential: $('m-save').checked,
      myname: $('m-myname').value.trim() || null,
    }, $('btn-connect'));
  };
  $('d-proxy').onchange = toggleProxy;
  $('btn-net-refresh').onclick = () => { NetProbe.refresh(true); NetProbe.refreshLan(); };
  // Dashboard cards: clicking a non-switch/button area jumps to the matching view (switches handle themselves via change events)
  $('dash-grid').addEventListener('click', (e) => {
    if (e.target.closest('.switch, button, input, select, a, .group-tabs')) return;
    const card = e.target.closest('[data-goto]');
    if (card) switchView(card.dataset.goto);
  });

  // Event delegation for list actions (CSP forbids inline onclick)
  $('creds-list').addEventListener('click', (e) => {
    // Fan-in rename: click the name text itself (inline input)
    const nameEl = e.target.closest('.cred-name');
    if (nameEl) { startCredRename(nameEl); return; }
    const btn = e.target.closest('button[data-act]');
    if (!btn) return;
    const key = btn.dataset.key;
    if (btn.dataset.act === 'reconnect') reconnectSaved(key, btn);
    if (btn.dataset.act === 'disconnect') disconnectNode(key);
    if (btn.dataset.act === 'export') exportCred(key);
    if (btn.dataset.act === 'anet') exportCredAnet(key);
    if (btn.dataset.act === 'delcred') deleteCred(key, btn);
    if (btn.dataset.act === 'console') openNodeConsole(btn.dataset.id);
    if (btn.dataset.act === 'edit') openCredEdit(key);
    if (btn.dataset.act === 'reimport') reimportCred(key);
    if (btn.dataset.act === 'send-note') sendPendingNote(key, btn);
  });
  // Appeal note: Enter inside the composer sends (delegation covers the button)
  $('creds-list').addEventListener('keydown', (e) => {
    if (e.key !== 'Enter') return;
    const input = e.target.closest('input[data-note-input]');
    if (!input) return;
    e.preventDefault();
    const btn = $('creds-list').querySelector('button[data-act="send-note"][data-key="' + CSS.escape(input.dataset.noteInput) + '"]');
    if (btn && !btn.disabled) btn.click();
  });
  // Fan-in credential edit modal (M4-T6 triplet form)
  $('cedit-cancel').onclick = () => { $('cred-edit-modal').style.display = 'none'; CRED_EDIT_KEY = null; };
  $('cred-edit-modal').onclick = (e) => { if (e.target === $('cred-edit-modal')) { $('cred-edit-modal').style.display = 'none'; CRED_EDIT_KEY = null; } };
  $('cedit-ok').onclick = credEditSave;
  $('rules-body').addEventListener('change', (e) => {
    const cb = e.target.closest('input[data-rule]');
    if (cb) toggleRule(cb.dataset.node, cb.dataset.rule, !cb.checked);
  });

  await loadSettings();
  await initRoles();
  initHero();        // Dashboard hero card (master switch/curve/summary; must run after initRoles sets the r-client initial value)
  Onboarding.init(); // Onboarding checklist (whole card skipped when dismissed/done flags exist)
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
  const savedLang = localStorage.getItem('ag_lang');
  if (savedLang && savedLang !== AgI18n.lang) AgI18n.setLang(savedLang);
  $('s-lang').value = AgI18n.lang;
  $('s-theme').value = localStorage.getItem('ag_theme') || 'light';
  agSelectEnhance(document);
  $('s-lang').onchange = (e) => { localStorage.setItem('ag_lang', e.target.value); applyLanguage(); };
  $('s-theme').onchange = (e) => {
    localStorage.setItem('ag_theme', e.target.value);
    applyTheme();
    invoke('broadcast_theme', { theme: e.target.value }).catch(() => {});
    // Admin console iframe sync (cross-origin postMessage)
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
  refreshNotify(true); // M4: inbox badge baseline at startup (10s tick keeps it fresh)

  // Auto-reconnect saved fan-ins on startup
  if (PREFS.autoreconnect && window._creds) {
    const keys = Object.keys(window._creds);
    if (keys.length) {
      toast(T('reconnecting-nodes', { n: keys.length }), 'ok');
      for (const key of keys) {
        await reconnectSaved(key, null);
      }
    }
  }

  /* ---- Main-window poll scheduling: pause the three timers while the window is hidden, resume and refresh immediately when visible (same visibilitychange pattern as tray/float ball) ---- */
  let mainT10 = 0, mainT2 = 0, mainT30 = 0;
  // refreshNodes rides its own AgPulse (扇入列表 header: updated-time + interval select), not this bundle
  function mainTick10s() { refreshProxy(); refreshSubStatus(); refreshSysproxy(); refreshTun(); renderDashFanout(); refreshCustomRules(); refreshCombos(); Hero.tick10s(); refreshRolesCache(); refreshNotify(); }
  // 2s poll of subscription kernel traffic + artifact download state (sub_traffic reads an Atomic snapshot, dl_state reads in-memory state — cheap; internal change detection avoids repaints)
  function mainTick2s() { SubTraffic.poll(); pollDl(); }
  // 30s poll of the egress IP probe (results signature-compared, no repaint when unchanged)
  function mainTick30s() { NetProbe.refresh(); }
  function startMainLoops(immediate) {
    if (mainT10) return;
    if (immediate) { mainTick10s(); mainTick2s(); mainTick30s(); }
    mainT10 = setInterval(mainTick10s, 10000);
    mainT2 = setInterval(mainTick2s, 2000);
    mainT30 = setInterval(mainTick30s, 30000);
  }
  function stopMainLoops() {
    clearInterval(mainT10); clearInterval(mainT2); clearInterval(mainT30);
    mainT10 = mainT2 = mainT30 = 0;
  }
  document.addEventListener('visibilitychange', () => { document.hidden ? stopMainLoops() : startMainLoops(true); });
  startMainLoops(false); // Startup already refreshed everything one round above; just arm the timers here

  /* Per-list auto-refresh pulses (updated-time hint + interval select; no manual refresh buttons —
     the selectable intervals are the rate floor/ceiling, so refresh abuse cannot hammer the engine/DB).
     These run with the same cadence policy as the main loops (ticks skip while hidden). */
  AgPulse.mount($('pulse-nodes'), { key: 'nodes', defMs: 10000, options: [5000, 10000, 30000], onTick: () => refreshNodes() });
  AgPulse.mount($('pulse-fanout'), { key: 'fanout', defMs: 10000, options: [5000, 10000, 30000], onTick: () => refreshUpstreams() });
  AgPulse.mount($('pulse-deleg'), { key: 'deleg', defMs: 10000, options: [5000, 10000, 30000], onTick: () => refreshDelegation() });
  AgPulse.setActive('nodes', true);
  AgPulse.setActive('fanout', true);
  AgPulse.setActive('deleg', true);
  // Rules table: implicit column resize + header click-sort (类型/匹配值/方式/来源; the default order
  // encodes engine priority: bypass → hosts → pulled)
  AgTbl.attach($('rules-table'), {
    key: 'rules',
    sort: { 0: 'type', 1: 'val', 2: 'via', 3: 'src' },
    onSort: () => renderMergedRules(window._nodes || []),
  });
});
