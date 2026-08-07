'use strict';
/* Split from app.js: logs view / connection records / event center */

/* ================= Logs view =================
   连接记录 tab: anet local-proxy inbound full ingestion, PER-TARGET aggregated (host:port one row;
   live rates from per-poll cumulative deltas; session totals + persisted historical baseline in the row detail).
   Recording default off; 50-row pages; kernel-independent (docs/todo/conn-log.md).
   实时日志: mihomo kernel logs when the kernel runs, anet's own app log ring (app_logs) when it's off.
   命中追踪 stays kernel-sourced; 事件中心 is the local audit log.
   Polling is AgPulse-driven per tab (updated-time hint + interval select, NO manual refresh button;
   timers run only while this page is open, ticks skip while the window is hidden).
   Tables render through AgTbl.sync: row nodes persist across polls (no wholesale innerHTML rebuild →
   no flicker; hover/expansion survive), changed rows patch in place. Header chrome (AgTbl.attach):
   implicit column resize / sort / filter — near-invisible until interaction. */

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
  kernelOff: false, // kernel-sourced tabs idle when the kernel is down (one final pull lands the empty state)
  cl: { statSig: '', page: 0, prev: {}, expanded: null, items: [] }, // prev: key → {up,down,t} for per-poll rate deltas
  hitsAll: [], hitsPage: 0,
  evAll: [], evPage: 0,
  entries: [],      // live log cache (data source for full re-render on filter change)
  logCursor: null,  // last rendered {time,level,payload} (incremental cursor; losing it = buffer rotation → full redraw)
  follow: true,     // auto scroll to bottom (pauses when the user scrolls up, resumes at bottom)
  pulseKey(tab) { return { conn: 'logconn', log: 'logview', hits: 'loghits', ev: 'logev' }[tab || this.tab]; },
  enter() { AgPulse.setActive(this.pulseKey(), true); },   // setActive ticks immediately (covers the entry pull)
  stop() { ['logconn', 'logview', 'loghits', 'logev'].forEach(k => AgPulse.setActive(k, false)); },
  switchTab(key) {
    AgPulse.setActive(this.pulseKey(), false);
    this.tab = key;
    AgPulse.setActive(this.pulseKey(), true);
  },
  pollNow() { AgPulse.tick(this.pulseKey()); },

  /* ---- Connection records (per-target aggregated; conlog_status toolbar + conlog_hosts page) ----
     All per-column affordances live in the header (AgTbl): 目标 text search, 出口/命中/状态 enum
     funnels, 目标/连接/最近 click-sort (server-side; live targets always pin first). The rate columns
     are deliberately NOT sortable — they are client-side deltas and would misorder a server-paged set. */
  clFilter() {
    const time = $('cl-time').value;
    let fromMs = null, toMs = null;
    if (time === '1h') fromMs = Date.now() - 3600e3;
    else if (time === '24h') fromMs = Date.now() - 86400e3;
    else if (time === 'custom') {
      fromMs = $('cl-from').value ? new Date($('cl-from').value).getTime() : null;
      toMs = $('cl-to').value ? new Date($('cl-to').value).getTime() : null;
    }
    const st = AgTbl.sortState('conn');
    const csv = (i) => {
      const v = AgTbl.filterGet('conn', i);
      return (Array.isArray(v) && v.length) ? v.join(',') : null;
    };
    return {
      keyword: (AgTbl.filterGet('conn', 0) || '').trim() || null,
      outbound: csv(1),
      hit: csv(2),
      rowState: csv(7),
      source: $('cl-tun').checked ? 'all' : null,
      sort: st ? st.id + ':' + st.dir : null, // live targets pin first regardless (backend)
      fromMs, toMs,
      offset: this.cl.page * PAGE, limit: PAGE,
    };
  },
  async pollConns() {
    if (HTTP_MODE) return false;
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
    } catch (e) { return false; }
    let v;
    try { v = await invoke('conlog_hosts', this.clFilter()); } catch (e) { return false; }
    // live per-target rates: session-cumulative deltas over the poll cadence
    const now = Date.now();
    for (const r of v.items) {
      const p = this.cl.prev[r.key];
      const dt = p ? Math.max(0.2, (now - p.t) / 1000) : 0;
      r.down_rate = p ? Math.max(0, (r.sess_down - p.down) / dt) : 0;
      r.up_rate = p ? Math.max(0, (r.sess_up - p.up) / dt) : 0;
      this.cl.prev[r.key] = { up: r.sess_up, down: r.sess_down, t: now };
    }
    this.cl.items = v.items;
    const body = $('lg-conn-body');
    if (!v.items.length) {
      body.innerHTML = '<tr><td colspan="8" class="empty">' + AgI18n.t('logs.cl.empty') + '</td></tr>';
    } else {
      // keyed reconcile: rows persist, changed cells patch in place — no flicker
      AgTbl.sync(body, v.items, { key: r => r.key, html: clRowHtml, patch: patchClRow });
    }
    const pages = Math.max(1, Math.ceil(v.total / PAGE));
    setText('cl-page-info', AgI18n.t('logs.cl.pageInfo', { p: Math.min(this.cl.page + 1, pages), pages, n: v.total }));
    $('cl-prev').disabled = this.cl.page <= 0;
    $('cl-next').disabled = this.cl.page + 1 >= pages;
    await this.restoreClDetail();
    return true;
  },

  /* Row detail expand (click; only one open at a time). Content-signature guarded: the detail node is
     re-written only when its HTML actually changes, and it travels with its anchor row through syncs. */
  async toggleClDetail(key) {
    const body = $('lg-conn-body');
    const old = body.querySelector('.conn-detail-row');
    if (this.cl.expanded === key) {
      this.cl.expanded = null;
      if (old) old.remove();
      return;
    }
    this.cl.expanded = key;
    await this.restoreClDetail();
  },
  async restoreClDetail() {
    const body = $('lg-conn-body');
    const old = body.querySelector('.conn-detail-row');
    const key = this.cl.expanded;
    if (!key) { if (old) old.remove(); return; }
    const rec = this.cl.items.find((r) => r.key === key);
    let anchor = null;
    body.querySelectorAll('tr[data-key]').forEach((tr) => { if (tr.dataset.key === key) anchor = tr; });
    if (!rec || !anchor) { this.cl.expanded = null; if (old) old.remove(); return; }
    let recent = [];
    try {
      const q = await invoke('conlog_query', { keyword: rec.host, source: 'all', limit: 5 });
      recent = q.items || [];
    } catch (e) { /* keep the summary even if the ring query fails */ }
    const html = clDetailRowHtml(rec, recent);
    if (old && old._agsig === html && old.previousElementSibling === anchor) return; // nothing changed
    if (old) old.remove();
    const t = document.createElement('template');
    t.innerHTML = html.trim();
    const row = t.content.firstElementChild;
    row._agsig = html;
    row._agAfter = anchor; // AgTbl.sync moves the detail together with its anchor row
    anchor.insertAdjacentElement('afterend', row);
  },

  /* ---- Live logs (kernel source while running, anet app ring otherwise; incremental append) ---- */
  async pollLogs() {
    if (HTTP_MODE) return false;
    let logs;
    if (window._subRunning) {
      try { logs = await invoke('sub_logs'); } catch (e) { return false; }
    } else {
      try { logs = await invoke('app_logs', { limit: 500 }); } catch (e) { return false; }
    }
    this.entries = logs || [];
    this.renderLogs(false);
    return true;
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

  /* ---- Hit tracking (kernel-only; idle when the kernel is down, one settling pull lands the empty state) ---- */
  async tickHits() {
    if (!window._subRunning) {
      if (this.kernelOff) return false;
      this.kernelOff = true;
      this.hitsAll = [];
      this.renderHits();
      return true;
    }
    this.kernelOff = false;
    return this.pollHits();
  },
  async pollHits() {
    if (HTTP_MODE) return false;
    let hits;
    try { hits = await invoke('sub_rule_hits'); } catch (e) { return false; }
    this.hitsAll = hits || [];
    this.renderHits();
    return true;
  },
  renderHits() {
    let all = this.hitsAll;
    // implicit per-column text filters (header funnels: rule / payload / last target)
    const fq = [0, 1, 3].map(i => AgTbl.filterGet('hits', i).toLowerCase());
    if (fq.some(Boolean)) {
      all = all.filter(h =>
        (!fq[0] || (h.rule || '').toLowerCase().includes(fq[0])) &&
        (!fq[1] || (h.payload || '').toLowerCase().includes(fq[1])) &&
        (!fq[3] || (h.last_host || '').toLowerCase().includes(fq[3])));
    }
    // implicit header sort (default stays backend order: count desc)
    const st = AgTbl.sortState('hits');
    if (st) {
      const get = {
        rule: h => h.rule || '', payload: h => h.payload || '', count: h => h.count || 0,
        host: h => h.last_host || '', seen: h => h.last_seen || 0,
      }[st.id];
      if (get) {
        all = all.slice().sort((a, b) => {
          const va = get(a), vb = get(b);
          const c = typeof va === 'number' ? va - vb : String(va).localeCompare(String(vb));
          return st.dir === 'asc' ? c : -c;
        });
      }
    }
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
    AgTbl.sync(body, all.slice(this.hitsPage * PAGE, this.hitsPage * PAGE + PAGE), {
      key: h => (h.rule || '') + '|' + (h.payload || ''),
      html: hitRowHtml,
    });
    setText('hits-page-info', AgI18n.t('logs.cl.pageInfo', { p: this.hitsPage + 1, pages, n: all.length }));
    $('btn-hits-prev').disabled = this.hitsPage <= 0;
    $('btn-hits-next').disabled = this.hitsPage + 1 >= pages;
  },

  /* ---- Event center (local audit log, 50-row client-side pages over the latest 200) ---- */
  async pollEvents() {
    if (HTTP_MODE) return false;
    let evs;
    try { evs = await invoke('recent_events', { limit: 200 }); } catch (e) { return false; }
    this.evAll = evs || [];
    this.renderEvents();
    return true;
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
    AgTbl.sync(list, all.slice(this.evPage * PAGE, this.evPage * PAGE + PAGE), {
      key: e => e.ts + '|' + e.kind + '|' + e.detail,
      html: evRowHtml,
    });
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
   Cell fragments are shared between clRowHtml (row creation) and patchClRow (in-place update),
   so a live row never gets re-created just because its rates moved. */
function clCells(r) {
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
  const stateHtml = live
    ? '<span class="pill pill-ok">' + AgI18n.t('logs.conn.live') + '</span>'
    : r.fails > 0
      ? '<span class="pill pill-danger">' + AgI18n.t('logs.cl.failed') + '·' + r.fails + '</span>'
      : '<span class="pill pill-dim">' + AgI18n.t('logs.conn.closed') + '</span>';
  return {
    live,
    cells: [
      { html: esc(r.host) + '<span class="dim">:' + r.port + '</span>' + tun, title: r.key },
      { html: outHtml },
      { html: esc(AgI18n.t('logs.hit.' + r.hit)) },
      { html: live ? fmtBytes(Math.round(r.down_rate)) + '/s' : '—' },
      { html: live ? fmtBytes(Math.round(r.up_rate)) + '/s' : '—' },
      { html: String(r.conns) },
      { html: last },
      { html: stateHtml },
    ],
  };
}
function clRowHtml(r) {
  const c = clCells(r);
  return '<tr data-key="' + esc(r.key) + '" data-host="' + esc(r.host) + '" data-port="' + r.port + '" data-live="' + (c.live ? '1' : '') + '" style="cursor:pointer"' + (c.live ? '' : ' class="dim"') + '>' +
    '<td class="mono" title="' + esc(r.key) + '"' + (c.live ? ' style="box-shadow:inset 3px 0 0 var(--accent)"' : '') + '>' + c.cells[0].html + '</td>' +
    '<td>' + c.cells[1].html + '</td>' +
    '<td class="dim">' + c.cells[2].html + '</td>' +
    '<td class="mono">' + c.cells[3].html + '</td>' +
    '<td class="mono">' + c.cells[4].html + '</td>' +
    '<td class="mono">' + c.cells[5].html + '</td>' +
    '<td class="mono dim">' + c.cells[6].html + '</td>' +
    '<td>' + c.cells[7].html + '</td></tr>';
}
/* In-place cell update (AgTbl.sync patch): only differing cells are written — the row node, its hover
   state and the accent bar survive; nothing visibly flickers at the 1s cadence. */
function patchClRow(tr, r) {
  const c = clCells(r);
  const cells = tr.cells;
  if (cells.length !== 8) return false;
  for (let i = 0; i < 8; i++) {
    if (cells[i].innerHTML !== c.cells[i].html) cells[i].innerHTML = c.cells[i].html;
  }
  const title = c.cells[0].title;
  if (cells[0].title !== title) cells[0].title = title;
  const bar = c.live ? 'inset 3px 0 0 var(--accent)' : '';
  if (cells[0].style.boxShadow !== bar) cells[0].style.boxShadow = bar;
  tr.classList.toggle('dim', !c.live);
  const lv = c.live ? '1' : '';
  if (tr.dataset.live !== lv) tr.dataset.live = lv;
  return true;
}

/* Hit row (rule / payload / count / last target / last time) */
function hitRowHtml(h) {
  return '<tr><td class="mono">' + esc(h.rule || '—') + '</td>' +
    '<td class="mono">' + esc(h.payload || '—') + '</td>' +
    '<td class="mono">' + h.count + '</td>' +
    '<td class="mono">' + esc(h.last_host || '—') + '</td>' +
    '<td class="dim">' + esc(fmtAgo(h.last_seen)) + '</td></tr>';
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
  /* Per-tab auto-refresh pulses (updated-time hint + interval select; no manual refresh buttons).
     Timers are activated only while the logs page is open and the tab is current (LogsView.enter/stop/switchTab). */
  AgPulse.mount($('pulse-logconn'), { key: 'logconn', defMs: 1000, options: [1000, 2000, 5000, 10000], onTick: () => LogsView.pollConns() });
  AgPulse.mount($('pulse-logview'), { key: 'logview', defMs: 1000, options: [1000, 2000, 5000], onTick: () => LogsView.pollLogs() });
  AgPulse.mount($('pulse-loghits'), { key: 'loghits', defMs: 2000, options: [2000, 5000, 10000], onTick: () => LogsView.tickHits() });
  AgPulse.mount($('pulse-logev'), { key: 'logev', defMs: 10000, options: [5000, 10000, 30000], onTick: () => LogsView.pollEvents() });

  /* Implicit header chrome: resize on both tables. conn: server-side sort (目标/连接/最近) + funnels
     (目标 text / 出口·命中·状态 enum multi-select) — the toolbar below keeps only the non-column-bound
     controls (time range, TUN inclusion). hits: client-side sort on all columns + text funnels
     (规则/载荷/最近目标). */
  AgTbl.attach($('lg-conn-table'), {
    key: 'conn',
    sort: { 0: 'target', 5: 'conns', 6: 'last' },
    filter: {
      0: { label: 'logs.colTarget' },
      1: { label: 'logs.colExit', type: 'enum', options: [
        { v: 'direct', label: 'logs.out.direct' },
        { v: 'tunnel', label: 'logs.cl.tunnelOpt' },
        { v: 'forward', label: 'term.subscription' },
      ] },
      2: { label: 'logs.cl.colHit', type: 'enum', options: [
        { v: 'user_bypass', label: 'logs.hit.user_bypass' },
        { v: 'explicit_route', label: 'logs.hit.explicit_route' },
        { v: 'preset_bypass', label: 'logs.hit.preset_bypass' },
        { v: 'default', label: 'logs.hit.default' },
      ] },
      7: { label: 'logs.cl.colState', type: 'enum', options: [
        { v: 'active', label: 'logs.conn.live' },
        { v: 'closed', label: 'logs.conn.closed' },
        { v: 'failed', label: 'logs.cl.failed' },
      ] },
    },
    onSort: () => { LogsView.cl.page = 0; LogsView.pollNow(); },
    onFilter: () => { LogsView.cl.page = 0; LogsView.pollNow(); },
  });
  AgTbl.attach($('lg-hits-table'), {
    key: 'hits',
    sort: { 0: 'rule', 1: 'payload', 2: 'count', 3: 'host', 4: 'seen' },
    filter: { 0: { label: 'term.rule' }, 1: { label: 'logs.colPayload' }, 3: { label: 'logs.colLastTarget' } },
    onSort: () => LogsView.renderHits(),
    onFilter: () => { LogsView.hitsPage = 0; LogsView.renderHits(); },
  });

  agTabsBind($('lg-tabs'), (key) => LogsView.switchTab(key));
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
      LogsView.pollNow();
      toast(AgI18n.t('logs.hitsCleared'), 'ok');
    } catch (err) { toast(friendlyError(err), 'err'); }
  };
  $('btn-hits-prev').onclick = () => { if (LogsView.hitsPage > 0) { LogsView.hitsPage--; LogsView.renderHits(); } };
  $('btn-hits-next').onclick = () => { if ((LogsView.hitsPage + 1) * PAGE < LogsView.hitsAll.length) { LogsView.hitsPage++; LogsView.renderHits(); } };
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
    LogsView.cl.statSig = '';
    LogsView.pollNow();
  };
  // One-click clear (DOM modal; deletes the on-disk snapshot too)
  $('btn-cl-clear').onclick = async () => {
    if (!(await askConfirm({ title: AgI18n.t('logs.cl.clearTitle'), desc: AgI18n.t('logs.cl.clearConfirm'), icon: 'trash-2', danger: true }))) return;
    try {
      await invoke('conlog_clear');
      LogsView.cl.statSig = ''; LogsView.cl.page = 0; LogsView.cl.prev = {};
      LogsView.pollNow();
      toast(AgI18n.t('logs.cl.cleared'), 'ok');
    } catch (err) { toast(friendlyError(err), 'err'); }
  };
  // Filters: any change returns to page 1 and refetches (time range + TUN inclusion; the per-column
  // filters live in the table header funnels now)
  const clRefetch = () => { LogsView.cl.page = 0; LogsView.pollNow(); };
  $('cl-time').onchange = () => {
    const custom = $('cl-time').value === 'custom';
    $('cl-from').hidden = $('cl-to').hidden = !custom;
    clRefetch();
  };
  $('cl-from').onchange = clRefetch;
  $('cl-to').onchange = clRefetch;
  $('cl-tun').onchange = clRefetch;
  $('cl-prev').onclick = () => { if (LogsView.cl.page > 0) { LogsView.cl.page--; LogsView.pollNow(); } };
  $('cl-next').onclick = () => { LogsView.cl.page++; LogsView.pollNow(); };
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
          LogsView.pollNow();
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

/* Language switch: row HTML embeds translated pills while AgTbl.sync signatures are data-only —
   drop the rendered rows so the next pull re-renders in the new language (pulse tick does the pull) */
AgI18n.onChange(() => {
  LogsView.cl.statSig = '';
  $('lg-conn-body').innerHTML = '';
  $('lg-hits-body').innerHTML = '';
  $('lg-ev-list').innerHTML = '';
  LogsView.renderLogs(true);
  LogsView.pollNow();
});
