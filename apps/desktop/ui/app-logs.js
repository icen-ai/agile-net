'use strict';
/* Split from app.js: logs view / connection records / event center */

/* ================= Logs view =================
   连接记录 tab: anet local-proxy inbound full ingestion, PER-TARGET aggregated (host:port one row;
   live rates from 1s cumulative deltas; session totals + persisted historical baseline in the row detail).
   Recording default off; 50-row pages; kernel-independent (docs/todo/conn-log.md).
   实时日志: mihomo kernel logs when the kernel runs, anet's own app log ring (app_logs) when it's off —
   mihomo only owns the subscription mechanism. 命中追踪 stays kernel-sourced; 事件中心 is the local audit log.
   Poll only while this page is open (records/logs 1s, hits 2s, events 10s); all renders signature-compared. */

/* ---- Log line rendering (level normalization + keyword mark.logv-hl highlight; esc first then highlight, the replacement string is escaped text too) ---- */
function canonLevel(level) {
  if (level === 'warning' || level === 'warn') return 'warning';
  if (level === 'error' || level === 'err' || level === 'fatal') return 'error';
  if (level === 'debug') return 'debug';
  return 'info';
}
const LV_CLS = { debug: 'lv-debug', info: 'lv-info', warning: 'lv-warn', error: 'lv-error' };
function escapeRegExp(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function logLineHtml(e, kw) {
  const d = new Date(e.time * 1000);
  const pad = (n) => String(n).padStart(2, '0');
  let payload = esc(e.payload);
  if (kw) payload = payload.replace(new RegExp(escapeRegExp(esc(kw)), 'gi'), m => '<mark class="logv-hl">' + m + '</mark>');
  return '<div class="logv-line ' + LV_CLS[canonLevel(e.level)] + '"><span class="dim">' +
    pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()) + '</span> ' + payload + '</div>';
}

const PAGE = 50;

const LogsView = {
  tab: 'conn',
  timer: null, tick: 0,
  kernelOff: false, // kernel-sourced tabs idle when the kernel is down (one final pull lands the empty state)
  cl: { statSig: '', sig: '', page: 0, prev: {}, expanded: null, items: [] }, // prev: key → {up,down,t} for 1s rate deltas
  hitsSig: '', hitsAll: [], hitsPage: 0,
  evSig: '', evAll: [], evPage: 0,
  entries: [],      // live log cache (data source for full re-render on filter change)
  logCursor: null,  // last rendered {time,level,payload} (incremental cursor; losing it = buffer rotation → full redraw)
  follow: true,     // auto scroll to bottom (pauses when the user scrolls up, resumes at bottom)
  enter() {
    this.stop();
    this.tick = 0;
    this.pollNow();
    this.timer = setInterval(() => this.onTick(), 1000);
  },
  stop() { if (this.timer) { clearInterval(this.timer); this.timer = null; } },
  onTick() {
    this.tick++;
    // Window hidden: skip this IPC round (timer keeps idling lightly, resumes on its own when visible again)
    if (document.hidden) return;
    // Connection records are anet-side: kernel-independent, poll every second
    if (this.tab === 'conn') { this.pollConns(); return; }
    if (this.tab === 'ev') { if (this.tick % 10 === 0) this.pollEvents(); return; } // events are low frequency: 10s (local event log, no kernel dependency)
    // Live logs: kernel source while it runs, anet app log ring otherwise — always poll
    if (this.tab === 'log') { this.pollLogs(); return; }
    // Hits are kernel-only: idle when the kernel is down (one settling pull lands the empty state)
    let settling = false;
    if (!window._subRunning) {
      if (this.kernelOff) return;
      this.kernelOff = true; settling = true;
    } else this.kernelOff = false;
    if (this.tab === 'hits') { if (settling || this.tick % 2 === 0) this.pollHits(); }
  },
  pollNow() {
    if (this.tab === 'log') this.pollLogs();
    else if (this.tab === 'hits') this.pollHits();
    else if (this.tab === 'ev') this.pollEvents();
    else this.pollConns();
  },

  /* ---- Connection records (per-target aggregated; conlog_status toolbar + conlog_hosts page, 1s) ---- */
  clFilter() {
    const time = $('cl-time').value;
    let fromMs = null, toMs = null;
    if (time === '1h') fromMs = Date.now() - 3600e3;
    else if (time === '24h') fromMs = Date.now() - 86400e3;
    else if (time === 'custom') {
      fromMs = $('cl-from').value ? new Date($('cl-from').value).getTime() : null;
      toMs = $('cl-to').value ? new Date($('cl-to').value).getTime() : null;
    }
    return {
      keyword: ($('cl-kw').value || '').trim() || null,
      outbound: $('cl-outbound').value || null,
      rowState: $('cl-state').value || null,
      source: $('cl-tun').checked ? 'all' : null,
      fromMs, toMs,
      offset: this.cl.page * PAGE, limit: PAGE,
    };
  },
  async pollConns() {
    if (HTTP_MODE) return;
    // TUN hint follows the role cache (UDP / kernel-direct traffic bypasses the anet inbound under TUN)
    const tunOn = !!(window._rolesCache && window._rolesCache.tun_mode);
    const tunHint = $('cl-tun-hint');
    if (tunHint) tunHint.style.display = tunOn ? '' : 'none';
    try {
      const st = await invoke('conlog_status');
      const ssig = JSON.stringify(st);
      if (ssig !== this.cl.statSig) {
        this.cl.statSig = ssig;
        if ($('cl-enable').checked !== st.enabled) $('cl-enable').checked = st.enabled;
        setText('cl-stats', AgI18n.t('logs.cl.stats', { down: fmtBytes(st.down), up: fmtBytes(st.up), n: st.hosts, a: st.active }));
      }
    } catch (e) { return; }
    let v;
    try { v = await invoke('conlog_hosts', this.clFilter()); } catch (e) { return; }
    // live per-target rates: session-cumulative deltas over the 1s poll cadence
    const now = Date.now();
    for (const r of v.items) {
      const p = this.cl.prev[r.key];
      const dt = p ? Math.max(0.2, (now - p.t) / 1000) : 0;
      r.down_rate = p ? Math.max(0, (r.sess_down - p.down) / dt) : 0;
      r.up_rate = p ? Math.max(0, (r.sess_up - p.up) / dt) : 0;
      this.cl.prev[r.key] = { up: r.sess_up, down: r.sess_down, t: now };
    }
    this.cl.items = v.items;
    const sig = JSON.stringify(v);
    if (sig === this.cl.sig) { this.restoreClDetail(); return; }
    this.cl.sig = sig;
    const body = $('lg-conn-body');
    if (!v.items.length) {
      body.innerHTML = '<tr><td colspan="8" class="empty">' + AgI18n.t('logs.cl.empty') + '</td></tr>';
    } else {
      body.innerHTML = v.items.map(clRowHtml).join('');
    }
    const pages = Math.max(1, Math.ceil(v.total / PAGE));
    setText('cl-page-info', AgI18n.t('logs.cl.pageInfo', { p: Math.min(this.cl.page + 1, pages), pages, n: v.total }));
    $('cl-prev').disabled = this.cl.page <= 0;
    $('cl-next').disabled = this.cl.page + 1 >= pages;
    this.restoreClDetail();
  },

  /* Row detail expand (click; only one open at a time, re-inserted on every redraw = live refresh).
     Covers what the table hides: historical / this-session cumulative bytes, first/last seen, conn/fail
     counts, source — plus the last few per-connection rows from the ring layer. */
  async toggleClDetail(key) {
    const body = $('lg-conn-body');
    const old = body.querySelector('.conn-detail-row');
    if (old) old.remove();
    if (this.cl.expanded === key) { this.cl.expanded = null; return; }
    this.cl.expanded = key;
    await this.restoreClDetail();
  },
  async restoreClDetail() {
    const key = this.cl.expanded;
    if (!key) return;
    const body = $('lg-conn-body');
    const old = body.querySelector('.conn-detail-row');
    if (old) old.remove();
    const rec = this.cl.items.find((r) => r.key === key);
    if (!rec) { this.cl.expanded = null; return; }
    let anchor = null;
    body.querySelectorAll('tr[data-key]').forEach((tr) => { if (tr.dataset.key === key) anchor = tr; });
    if (!anchor) { this.cl.expanded = null; return; }
    let recent = [];
    try {
      const q = await invoke('conlog_query', { keyword: rec.host, source: 'all', limit: 5 });
      recent = q.items || [];
    } catch (e) { /* keep the summary even if the ring query fails */ }
    anchor.insertAdjacentHTML('afterend', clDetailRowHtml(rec, recent));
  },

  /* ---- Live logs (1s; kernel source while running, anet app ring otherwise; incremental append) ---- */
  async pollLogs() {
    if (HTTP_MODE) return;
    let logs;
    if (window._subRunning) {
      try { logs = await invoke('sub_logs'); } catch (e) { return; }
    } else {
      try { logs = await invoke('app_logs', { limit: 500 }); } catch (e) { return; }
    }
    this.entries = logs || [];
    this.renderLogs(false);
  },
  renderLogs(forceFull) {
    const view = $('lg-log-view');
    const kw = ($('lg-log-filter').value || '').trim();
    const lv = $('lg-log-level').value;
    const kwl = kw.toLowerCase();
    const match = (e) => {
      if (lv && canonLevel(e.level) !== lv) return false;
      return !kwl || (e.payload || '').toLowerCase().includes(kwl);
    };
    const entries = this.entries;
    if (!entries.length) { // cleared or nothing yet
      if (view.children.length) view.innerHTML = '';
      this.logCursor = null;
      return;
    }
    let full = forceFull || !this.logCursor;
    let startIdx = entries.length;
    if (!full) {
      let found = false;
      for (let i = entries.length - 1; i >= 0; i--) {
        const e = entries[i];
        if (e.time === this.logCursor.time && e.level === this.logCursor.level && e.payload === this.logCursor.payload) {
          startIdx = i + 1; found = true; break;
        }
      }
      if (!found) full = true;
    }
    if (full) {
      view.innerHTML = entries.filter(match).slice(-500).map(e => logLineHtml(e, kw)).join('');
    } else if (startIdx < entries.length) {
      const tmp = document.createElement('div');
      tmp.innerHTML = entries.slice(startIdx).filter(match).map(e => logLineHtml(e, kw)).join('');
      while (tmp.firstChild) view.appendChild(tmp.firstChild);
      while (view.children.length > 500) view.removeChild(view.firstChild);
    }
    this.logCursor = entries[entries.length - 1];
    if (this.follow) view.scrollTop = view.scrollHeight;
  },

  /* ---- Hit tracking (2s; 50-row client-side pages, wholesale redraw on signature compare) ---- */
  async pollHits() {
    if (HTTP_MODE) return;
    let hits;
    try { hits = await invoke('sub_rule_hits'); } catch (e) { return; }
    const sig = JSON.stringify(hits);
    if (sig === this.hitsSig) return;
    this.hitsSig = sig;
    this.hitsAll = hits || [];
    this.renderHits();
  },
  renderHits() {
    const all = this.hitsAll;
    const body = $('lg-hits-body');
    if (!all.length) {
      body.innerHTML = '<tr><td colspan="5" class="empty">' + AgI18n.t('logs.empty.hits') + '</td></tr>';
      setText('hits-page-info', '');
      $('btn-hits-prev').disabled = true;
      $('btn-hits-next').disabled = true;
      return;
    }
    const pages = Math.max(1, Math.ceil(all.length / PAGE));
    this.hitsPage = Math.min(this.hitsPage, pages - 1);
    body.innerHTML = all.slice(this.hitsPage * PAGE, this.hitsPage * PAGE + PAGE).map(h =>
      '<tr><td class="mono">' + esc(h.rule || '—') + '</td>' +
      '<td class="mono">' + esc(h.payload || '—') + '</td>' +
      '<td class="mono">' + h.count + '</td>' +
      '<td class="mono">' + esc(h.last_host || '—') + '</td>' +
      '<td class="dim">' + esc(fmtAgo(h.last_seen)) + '</td></tr>').join('');
    setText('hits-page-info', AgI18n.t('logs.cl.pageInfo', { p: this.hitsPage + 1, pages, n: all.length }));
    $('btn-hits-prev').disabled = this.hitsPage <= 0;
    $('btn-hits-next').disabled = this.hitsPage + 1 >= pages;
  },

  /* ---- Event center (one pull on tab entry + onTick 10s + manual refresh; 50-row client-side pages over the latest 200) ---- */
  async pollEvents() {
    if (HTTP_MODE) return;
    let evs;
    try { evs = await invoke('recent_events', { limit: 200 }); } catch (e) { return; }
    const sig = JSON.stringify(evs);
    if (sig === this.evSig) return;
    this.evSig = sig;
    this.evAll = evs || [];
    this.renderEvents();
  },
  renderEvents() {
    const all = this.evAll;
    const list = $('lg-ev-list');
    if (!all.length) {
      list.innerHTML = '<div class="empty-state">' + AgIcon('bell', 36) +
        '<div class="empty-t">' + AgI18n.t('logs.empty.ev') + '</div>' +
        '<div class="empty-d">' + AgI18n.t('logs.empty.evDesc') + '</div></div>';
      setText('ev-page-info', '');
      $('btn-ev-prev').disabled = true;
      $('btn-ev-next').disabled = true;
      return;
    }
    const pages = Math.max(1, Math.ceil(all.length / PAGE));
    this.evPage = Math.min(this.evPage, pages - 1);
    list.innerHTML = all.slice(this.evPage * PAGE, this.evPage * PAGE + PAGE).map(evRowHtml).join('');
    setText('ev-page-info', AgI18n.t('logs.cl.pageInfo', { p: this.evPage + 1, pages, n: all.length }));
    $('btn-ev-prev').disabled = this.evPage <= 0;
    $('btn-ev-next').disabled = this.evPage + 1 >= pages;
  },
};

/* Event kind → pill mapping (unrecognized kinds fall back to pill-dim + raw kind name) */
const EV_KIND = {
  role_toggle: ['pill-dim', 'logs.ev.role'],
  kernel: ['pill-ok', 'term.kernel'],
  sysproxy: ['pill-warn', 'logs.ev.sysproxy'],
  custom_rule: ['pill-dim', 'term.rule'],
  sub_script: ['pill-warn', 'logs.ev.script'],
  doctor: ['pill-ok', 'logs.ev.doctor'],
  install: ['pill-dim', 'app.install'],
  uninstall: ['pill-danger', 'app.uninstall'],
  connector: ['pill-dim', 'term.fanout'],
};
/* Event time: today HH:MM:SS; otherwise MM-DD HH:MM */
function evTimeFmt(ts) {
  const d = new Date((ts || 0) * 1000);
  const pad = (n) => String(n).padStart(2, '0');
  const now = new Date();
  const today = d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth() && d.getDate() === now.getDate();
  return today
    ? pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds())
    : pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
}
function evRowHtml(e) {
  const k = EV_KIND[e.kind];
  const cls = k ? k[0] : 'pill-dim';
  const label = k ? AgI18n.t(k[1]) : (e.kind || AgI18n.t('term.events'));
  return '<div class="ev-row"><span class="ev-time">' + evTimeFmt(e.ts) + '</span>' +
    '<span class="pill ' + cls + '">' + esc(label) + '</span>' +
    '<span class="ev-detail" title="' + esc(e.detail) + '">' + esc(e.detail) + '</span></div>';
}

/* ---- Aggregated target row (per host:port) ----
   Live rows get the 3px accent bar and live rates; inactive rows dimmed. */
function clRowHtml(r) {
  const live = r.active > 0;
  const d = new Date(r.last_ms);
  const pad = (n) => String(n).padStart(2, '0');
  const last = pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  const tun = r.source === 'tun_relay' ? ' <span class="pill pill-dim">TUN</span>' : '';
  const kind = r.outbound.kind;
  const outHtml = kind === 'direct'
    ? '<span class="pill pill-dim">' + AgI18n.t('logs.out.direct') + '</span>'
    : kind === 'forward'
      ? '<span class="pill pill-warn">' + AgI18n.t('logs.out.forward') + '</span>'
      : '<span class="pill pill-ok">' + esc(AgI18n.t('logs.out.tunnel', { node: r.outbound.node })) + '</span>';
  const statePill = live
    ? '<span class="pill pill-ok">' + AgI18n.t('logs.conn.live') + '</span>'
    : r.fails > 0
      ? '<span class="pill pill-danger">' + AgI18n.t('logs.cl.failed') + '·' + r.fails + '</span>'
      : '<span class="pill pill-dim">' + AgI18n.t('logs.conn.closed') + '</span>';
  return '<tr data-key="' + esc(r.key) + '" data-host="' + esc(r.host) + '" data-port="' + r.port + '" data-live="' + (live ? '1' : '') + '" style="cursor:pointer"' + (live ? '' : ' class="dim"') + '>' +
    '<td class="mono" title="' + esc(r.key) + '"' + (live ? ' style="box-shadow:inset 3px 0 0 var(--accent)"' : '') + '>' + esc(r.host) + '<span class="dim">:' + r.port + '</span>' + tun + '</td>' +
    '<td>' + outHtml + '</td>' +
    '<td class="dim">' + esc(AgI18n.t('logs.hit.' + r.hit)) + '</td>' +
    '<td class="mono">' + (live ? fmtBytes(Math.round(r.down_rate)) + '/s' : '—') + '</td>' +
    '<td class="mono">' + (live ? fmtBytes(Math.round(r.up_rate)) + '/s' : '—') + '</td>' +
    '<td class="mono">' + r.conns + '</td>' +
    '<td class="mono dim">' + last + '</td>' +
    '<td>' + statePill + '</td></tr>';
}

/* Row detail (click expand): cumulative bytes (history / this session), first/last seen, conn & fail counts,
   source — then the last few per-connection rows from the ring layer. */
function clDetailRowHtml(r, recent) {
  const day = (ms) => {
    const d = new Date(ms);
    const pad = (n) => String(n).padStart(2, '0');
    return pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  };
  const kv = (k, v) => '<span><span class="dim">' + k + ' </span>' + v + '</span>';
  let recentHtml = '';
  if (recent.length) {
    recentHtml = '<div style="margin-top:6px;border-top:1px dashed var(--row-border);padding-top:5px">' +
      '<div class="dim" style="font-size:11px;margin-bottom:3px">' + AgI18n.t('logs.cl.detailRecent') + '</div>' +
      recent.map((c) => {
        const st = typeof c.state === 'string' ? c.state : c.state.state;
        const d = new Date(c.start_ms);
        const pad = (n) => String(n).padStart(2, '0');
        const t = pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
        const stTxt = st === 'active' ? AgI18n.t('logs.conn.live') : st === 'closed' ? AgI18n.t('logs.conn.closed') : AgI18n.t('logs.cl.failed') + (c.state.reason ? '（' + c.state.reason + '）' : '');
        return '<div class="mono" style="font-size:11px;line-height:1.7"><span class="dim">' + t + '</span>　↓' + fmtBytes(c.down) + ' ↑' + fmtBytes(c.up) + '　<span class="dim">' + esc(stTxt) + '</span></div>';
      }).join('') + '</div>';
  }
  return '<tr class="conn-detail-row">' +
    '<td colspan="8" style="padding:8px 14px 10px;border-top:none">' +
    '<div style="font-size:12px;display:flex;gap:16px;flex-wrap:wrap;align-items:center">' +
    kv(AgI18n.t('logs.cl.detailSess'), '<span class="mono">↓' + fmtBytes(r.sess_down) + ' ↑' + fmtBytes(r.sess_up) + '</span>') +
    kv(AgI18n.t('logs.cl.detailHist'), '<span class="mono">↓' + fmtBytes(r.hist_down) + ' ↑' + fmtBytes(r.hist_up) + '</span>') +
    kv(AgI18n.t('logs.cl.detailConns'), '<span class="mono">' + r.conns + (r.fails ? '（' + AgI18n.t('logs.cl.failed') + ' ' + r.fails + '）' : '') + '</span>') +
    kv(AgI18n.t('logs.cl.detailFirst'), '<span class="mono">' + day(r.first_ms) + '</span>') +
    kv(AgI18n.t('logs.cl.detailLast'), '<span class="mono">' + day(r.last_ms) + '</span>') +
    '</div>' + recentHtml + '</td></tr>';
}

/* One-click add rule: direct-allow for the host / route via subscription egress (backend strips scheme/port and is idempotent) */
async function addRuleForHost(host, target) {
  try {
    await invoke('sub_add_rule_for_host', { host, target });
    toast(AgI18n.t(target === 'direct' ? 'logs.rule.direct' : 'logs.rule.sub', { host }), 'ok');
    refreshCustomRules(true);
  } catch (err) { toast(friendlyError(err), 'err'); }
}

function initLogs() {
  agTabsBind($('lg-tabs'), (key) => { LogsView.tab = key; LogsView.tick = 0; LogsView.pollNow(); });
  // Log stream follow: scrolling up pauses auto scroll-to-bottom, back at bottom resumes
  const view = $('lg-log-view');
  view.addEventListener('scroll', () => {
    LogsView.follow = view.scrollTop + view.clientHeight >= view.scrollHeight - 30;
  });
  // Filter change: full re-render from cached entries
  $('lg-log-filter').addEventListener('input', () => LogsView.renderLogs(true));
  $('lg-log-level').addEventListener('change', () => LogsView.renderLogs(true));
  $('btn-lg-clear').onclick = async () => {
    try {
      // source-routed: kernel buffers when the kernel runs, the anet app ring otherwise
      if (window._subRunning) await invoke('sub_clear_logs');
      else await invoke('app_logs_clear');
      LogsView.entries = [];
      LogsView.logCursor = null;
      view.innerHTML = '';
      toast(AgI18n.t('logs.cleared'), 'ok');
    } catch (err) { toast(friendlyError(err), 'err'); }
  };
  $('btn-hits-clear').onclick = async () => {
    try {
      await invoke('sub_clear_logs');
      LogsView.hitsSig = '';
      LogsView.pollHits();
      toast(AgI18n.t('logs.hitsCleared'), 'ok');
    } catch (err) { toast(friendlyError(err), 'err'); }
  };
  $('btn-hits-prev').onclick = () => { if (LogsView.hitsPage > 0) { LogsView.hitsPage--; LogsView.renderHits(); } };
  $('btn-hits-next').onclick = () => { if ((LogsView.hitsPage + 1) * PAGE < LogsView.hitsAll.length) { LogsView.hitsPage++; LogsView.renderHits(); } };
  // Event center: manual refresh (clear signature to force re-pull) + 50-row pages
  $('btn-ev-refresh').onclick = () => { LogsView.evSig = ''; LogsView.pollEvents(); };
  $('btn-ev-prev').onclick = () => { if (LogsView.evPage > 0) { LogsView.evPage--; LogsView.renderEvents(); } };
  $('btn-ev-next').onclick = () => { if ((LogsView.evPage + 1) * PAGE < LogsView.evAll.length) { LogsView.evPage++; LogsView.renderEvents(); } };

  /* ---- Connection records toolbar ---- */
  // Recording toggle (default off; persisted as roles.conn_log_enabled)
  $('cl-enable').onchange = async (e) => {
    const on = e.target.checked;
    e.target.disabled = true;
    try {
      await invoke('conlog_set_enabled', { enabled: on });
      toast(AgI18n.t(on ? 'logs.cl.on' : 'logs.cl.off'), 'ok');
    } catch (err) {
      e.target.checked = !on;
      toast(friendlyError(err), 'err');
    }
    e.target.disabled = false;
    LogsView.cl.statSig = ''; LogsView.cl.sig = '';
    LogsView.pollConns();
  };
  // One-click clear (DOM modal; deletes the on-disk snapshot too)
  $('btn-cl-clear').onclick = async () => {
    if (!(await askConfirm({ title: AgI18n.t('logs.cl.clearTitle'), desc: AgI18n.t('logs.cl.clearConfirm'), icon: 'trash-2', danger: true }))) return;
    try {
      await invoke('conlog_clear');
      LogsView.cl.sig = ''; LogsView.cl.statSig = ''; LogsView.cl.page = 0; LogsView.cl.prev = {};
      LogsView.pollConns();
      toast(AgI18n.t('logs.cl.cleared'), 'ok');
    } catch (err) { toast(friendlyError(err), 'err'); }
  };
  // Filters: any change returns to page 1 and refetches
  const clRefetch = () => { LogsView.cl.page = 0; LogsView.pollConns(); };
  $('cl-kw').addEventListener('input', clRefetch);
  $('cl-outbound').onchange = clRefetch;
  $('cl-state').onchange = clRefetch;
  $('cl-time').onchange = () => {
    const custom = $('cl-time').value === 'custom';
    $('cl-from').hidden = $('cl-to').hidden = !custom;
    clRefetch();
  };
  $('cl-from').onchange = clRefetch;
  $('cl-to').onchange = clRefetch;
  $('cl-tun').onchange = clRefetch;
  $('cl-prev').onclick = () => { if (LogsView.cl.page > 0) { LogsView.cl.page--; LogsView.pollConns(); } };
  $('cl-next').onclick = () => { LogsView.cl.page++; LogsView.pollConns(); };
  // Click a target row to expand/collapse the detail (cumulative bytes, first/last seen, recent connections)
  $('lg-conn-body').addEventListener('click', (e) => {
    if (e.target.closest('.conn-detail-row')) { e.stopPropagation(); return; }
    const tr = e.target.closest('tr[data-key]');
    if (tr) LogsView.toggleClDetail(tr.dataset.key);
  });
  // Row context menu: force-close every connection to this target (active only) / direct / subscription for this domain
  $('lg-conn-body').addEventListener('contextmenu', (e) => {
    if (e.target.closest('.conn-detail-row')) { e.preventDefault(); e.stopPropagation(); return; }
    const tr = e.target.closest('tr[data-key]');
    if (!tr) return;
    e.preventDefault();
    e.stopPropagation();
    const host = tr.dataset.host, port = Number(tr.dataset.port);
    const items = [];
    if (tr.dataset.live === '1') {
      items.push({ label: AgI18n.t('logs.cl.killTarget'), danger: true, fn: async () => {
        try {
          const n = await invoke('conlog_kill_target', { host, port });
          toast(AgI18n.t('logs.cl.killedN', { n }), 'ok');
          LogsView.pollConns();
        } catch (err) { toast(friendlyError(err), 'err'); }
      } });
    }
    if (host) {
      if (items.length) items.push('-');
      items.push({ label: AgI18n.t('logs.ctx.direct'), fn: () => addRuleForHost(host, 'direct') });
      items.push({ label: AgI18n.t('logs.ctx.sub'), fn: () => addRuleForHost(host, 'subscription') });
    }
    if (items.length) ctxShow(e.clientX, e.clientY, items);
  });
}

/* Language switch: clear signatures to force re-pull and redraw (all renders are signature-compared; locale entry changes must break the signature) */
AgI18n.onChange(() => {
  LogsView.cl.sig = LogsView.cl.statSig = LogsView.hitsSig = LogsView.evSig = '';
  if (LogsView.timer) LogsView.pollNow();
});
