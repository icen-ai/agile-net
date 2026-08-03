'use strict';
/* Split from app.js: logs view / connection detail / event center (pure move, zero logic change) */

/* ================= Logs view (subscription kernel observability: live connections / live logs / hit tracking) =================
   Poll only while this page is open (connections/logs 1s, hits 2s; single timer dispatched by tab), stops on leave;
   when the window is hidden or the kernel is not running, the timer idles lightly and skips kernel IPC (on kernel stop, one final pull is allowed through to land the empty state);
   connection table redrawn wholesale on signature compare, log stream appended incrementally (500-line DOM cap), anti-flicker rendering. */

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

const LogsView = {
  tab: 'conn',
  timer: null, tick: 0,
  kernelOff: false, // kernel not running and empty state already shown (onTick uses this to idle and skip kernel IPC; auto-resets when running again)
  connSig: '', hitsSig: '', evSig: '',
  connMap: {},        // latest connection data id → {c, live} (data source for detail expand/redraw restore)
  connDetailId: null, // id of the expanded connection detail row (only one open at a time; collapses when the row disappears)
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
    if (this.tab === 'ev') { if (this.tick % 10 === 0) this.pollEvents(); return; } // events are low frequency: 10s (local event log, no kernel dependency)
    // Kernel not running: idle and skip kernel IPC; right after a kernel stop, allow one final pull so the page falls back to the 「内核未运行」 empty state
    let settling = false;
    if (!window._subRunning) {
      if (this.kernelOff) return;
      this.kernelOff = true; settling = true;
    } else this.kernelOff = false;
    if (this.tab === 'hits') { if (settling || this.tick % 2 === 0) this.pollHits(); return; }
    if (this.tab === 'log') this.pollLogs();
    else this.pollConns();
  },
  pollNow() {
    if (this.tab === 'log') this.pollLogs();
    else if (this.tab === 'hits') this.pollHits();
    else if (this.tab === 'ev') this.pollEvents();
    else this.pollConns();
  },

  /* ---- Live connections (1s; signature compare, active pinned on top + closed dimmed below, max 100 closed rows) ---- */
  async pollConns() {
    if (HTTP_MODE) return;
    let v;
    try { v = await invoke('sub_connections'); } catch (e) { return; }
    const sig = JSON.stringify(v);
    if (sig === this.connSig) return;
    this.connSig = sig;
    const body = $('lg-conn-body');
    const act = v.active || [];
    const closed = (v.closed || []).slice(0, 100);
    this.connMap = {};
    act.forEach(c => { this.connMap[c.id] = { c, live: true }; });
    closed.forEach(c => { this.connMap[c.id] = { c, live: false }; });
    if (!act.length && !closed.length) {
      this.connDetailId = null;
      body.innerHTML = '<tr><td colspan="7" class="empty">' + AgI18n.t('logs.empty.conn') + '</td></tr>';
      return;
    }
    body.innerHTML = act.map(c => connRowHtml(c, true)).join('') +
      closed.map(c => connRowHtml(c, false)).join('');
    this.restoreConnDetail(); // restore the expanded row after wholesale redraw (latest data = live detail refresh; collapse if the row is gone)
  },

  /* Expand/collapse connection detail (clicking the same row again or another row collapses; only one open at a time) */
  toggleConnDetail(id) {
    const old = $('lg-conn-body').querySelector('.conn-detail-row');
    if (old) old.remove();
    this.connDetailId = this.connDetailId === id ? null : id;
    this.restoreConnDetail();
  },
  restoreConnDetail() {
    const id = this.connDetailId;
    if (!id) return;
    const rec = this.connMap[id];
    if (!rec) { this.connDetailId = null; return; } // row gone: collapse
    let anchor = null;
    $('lg-conn-body').querySelectorAll('tr[data-cid]').forEach(r => { if (r.dataset.cid === id) anchor = r; });
    if (!anchor) { this.connDetailId = null; return; }
    anchor.insertAdjacentHTML('afterend', connDetailRowHtml(rec.c, rec.live));
  },

  /* ---- Live logs (1s; incremental append, full redraw on buffer rotation / filter change) ---- */
  async pollLogs() {
    if (HTTP_MODE) return;
    let logs;
    try { logs = await invoke('sub_logs'); } catch (e) { return; }
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
    if (!entries.length) { // cleared or kernel not running
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

  /* ---- Hit tracking (2s; wholesale redraw on signature compare) ---- */
  async pollHits() {
    if (HTTP_MODE) return;
    let hits;
    try { hits = await invoke('sub_rule_hits'); } catch (e) { return; }
    const sig = JSON.stringify(hits);
    if (sig === this.hitsSig) return;
    this.hitsSig = sig;
    const body = $('lg-hits-body');
    if (!hits || !hits.length) {
      body.innerHTML = '<tr><td colspan="5" class="empty">' + AgI18n.t('logs.empty.hits') + '</td></tr>';
      return;
    }
    body.innerHTML = hits.map(h =>
      '<tr><td class="mono">' + esc(h.rule || '—') + '</td>' +
      '<td class="mono">' + esc(h.payload || '—') + '</td>' +
      '<td class="mono">' + h.count + '</td>' +
      '<td class="mono">' + esc(h.last_host || '—') + '</td>' +
      '<td class="dim">' + esc(fmtAgo(h.last_seen)) + '</td></tr>').join('');
  },

  /* ---- Event center (low frequency: one pull on tab entry + onTick 10s + manual refresh; signature compare, max 50 entries) ---- */
  async pollEvents() {
    if (HTTP_MODE) return;
    let evs;
    try { evs = await invoke('recent_events', { limit: 50 }); } catch (e) { return; }
    const sig = JSON.stringify(evs);
    if (sig === this.evSig) return;
    this.evSig = sig;
    const list = $('lg-ev-list');
    if (!evs || !evs.length) {
      list.innerHTML = '<div class="empty-state">' + AgIcon('bell', 36) +
        '<div class="empty-t">' + AgI18n.t('logs.empty.ev') + '</div>' +
        '<div class="empty-d">' + AgI18n.t('logs.empty.evDesc') + '</div></div>';
      return;
    }
    list.innerHTML = evs.map(evRowHtml).join('');
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

/* Connection row HTML: active rows get a left 3px accent bar (var token, no hardcoded colors), closed rows fully dimmed */
function connRowHtml(c, live) {
  const dim = live ? '' : ' class="dim"';
  const exit = (c.chains && c.chains.length) ? c.chains[0] : '—';
  const chainTitle = (c.chains && c.chains.length) ? ' title="' + esc(c.chains.join(' → ')) + '"' : '';
  const rule = c.rule
    ? esc(c.rule) + (c.rule_payload ? ' <span class="dim">' + esc(c.rule_payload) + '</span>' : '')
    : '<span class="dim">—</span>';
  return '<tr data-cid="' + esc(c.id) + '" data-host="' + esc(c.host || '') + '" data-live="' + (live ? '1' : '') + '" style="cursor:pointer">' +
    '<td class="mono" title="' + esc(c.host || '') + '"' + (live ? ' style="box-shadow:inset 3px 0 0 var(--accent)"' : '') + '>' + esc(c.host || '—') + '</td>' +
    '<td' + dim + '>' + esc(c.process || '—') + '</td>' +
    '<td class="mono">' + rule + '</td>' +
    '<td class="mono"' + chainTitle + '>' + esc(exit) + '</td>' +
    '<td class="mono">' + (live ? fmtBytes(c.down_rate) + '/s' : '—') + '</td>' +
    '<td class="mono">' + (live ? fmtBytes(c.up_rate) + '/s' : '—') + '</td>' +
    '<td class="mono">' + fmtDur(c.elapsed) + '</td></tr>';
}

/* Chain mini topology (pure HTML flex, zero deps, no SVG): local machine → relays in reversed chains order → target host
   (chains[0] is the egress; chain order = local + chains.slice().reverse() + host; empty chains = just local→host two points).
   Dot semantic colors all via var tokens (local accent / relay dim2 / target ok-text), links and right arrows use --border2;
   node names 10px centered, truncated with ellipsis beyond 8 chars, full name in title. */
function connTopoHtml(c) {
  const cut = (s) => s.length > 8 ? s.slice(0, 8) + '…' : s;
  const node = (name, color) =>
    '<div style="flex-shrink:0;display:flex;flex-direction:column;align-items:center;max-width:90px" title="' + esc(name) + '">' +
    '<span style="width:9px;height:9px;border-radius:50%;background:' + color + '"></span>' +
    '<span class="dim" style="margin-top:3px;font-size:10px;line-height:1.3;max-width:90px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(cut(name)) + '</span></div>';
  const link = '<div style="flex:1;min-width:24px;height:9px;display:flex;align-items:center">' +
    '<span style="flex:1;height:1px;background:var(--border2)"></span>' +
    '<span style="width:0;height:0;border-top:3.5px solid transparent;border-bottom:3.5px solid transparent;border-left:5px solid var(--border2)"></span></div>';
  const nodes = [[AgI18n.t('logs.topo.local'), 'var(--accent)']];
  (c.chains || []).slice().reverse().forEach(n => nodes.push([String(n), 'var(--dim2)']));
  nodes.push([c.host || '—', 'var(--ok-text)']);
  return '<div style="display:flex;align-items:flex-start;margin-bottom:7px">' +
    nodes.map((n, i) => (i ? link : '') + node(n[0], n[1])).join('') + '</div>';
}

/* Connection detail expanded row (benchmark Surge: chain topology + two-line inner layout; styles all inline, no CSS class for this).
   Topology row = local → relay chain → target (connTopoHtml); first line = full outbound chain + matched rule;
   second line = process / start time / cumulative traffic / status pill.
   Data re-inserted in place on pollConns wholesale redraw = live refresh. */
function connDetailRowHtml(c, live) {
  const chains = (c.chains && c.chains.length) ? c.chains.join(' → ') : '—';
  const rule = c.rule
    ? esc(c.rule) + (c.rule_payload ? ' <span class="dim">' + esc(c.rule_payload) + '</span>' : '')
    : '<span class="dim">' + AgI18n.t('logs.conn.final') + '</span>';
  const d = c.start ? new Date(c.start * 1000) : null;
  const pad = (n) => String(n).padStart(2, '0');
  const startTxt = d ? pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()) : '—';
  return '<tr class="conn-detail-row">' +
    '<td colspan="7" style="padding:8px 14px 10px;border-top:none">' +
    connTopoHtml(c) +
    '<div style="font-size:12px;line-height:1.7;word-break:break-all">' +
    '<span class="mono" style="font-size:11.5px">' + esc(chains) + '</span>' +
    '<span class="dim">　' + AgI18n.t('term.rule') + '　</span>' + rule + '</div>' +
    '<div class="dim" style="margin-top:3px;font-size:12px;display:flex;gap:14px;flex-wrap:wrap;align-items:center">' +
    '<span>' + AgI18n.t('logs.conn.process') + ' ' + esc(c.process || '—') + '</span>' +
    '<span>' + AgI18n.t('logs.conn.started') + ' ' + startTxt + '</span>' +
    '<span>' + AgI18n.t('logs.conn.down') + ' ' + fmtBytes(c.download) + '</span>' +
    '<span>' + AgI18n.t('logs.conn.up') + ' ' + fmtBytes(c.upload) + '</span>' +
    '<span class="pill ' + (live ? 'pill-ok' : 'pill-dim') + '">' + AgI18n.t(live ? 'logs.conn.live' : 'logs.conn.closed') + '</span>' +
    '</div></td></tr>';
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
      await invoke('sub_clear_logs');
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
  // Event center manual refresh (clear signature to force re-pull and redraw)
  $('btn-ev-refresh').onclick = () => { LogsView.evSig = ''; LogsView.pollEvents(); };
  // Click a connection row to expand/collapse detail (clicking the same row again or another row collapses; only one open at a time);
  // clicks/right-clicks inside the detail row do not leak out (no expand toggle, no row context menu)
  $('lg-conn-body').addEventListener('click', (e) => {
    if (e.target.closest('.conn-detail-row')) { e.stopPropagation(); return; }
    const tr = e.target.closest('tr[data-cid]');
    if (tr) LogsView.toggleConnDetail(tr.dataset.cid);
  });
  // Connection row context menu: force kill (active only) / direct for this domain / subscription for this domain
  $('lg-conn-body').addEventListener('contextmenu', (e) => {
    if (e.target.closest('.conn-detail-row')) { e.preventDefault(); e.stopPropagation(); return; }
    const tr = e.target.closest('tr[data-cid]');
    if (!tr) return;
    e.preventDefault();
    e.stopPropagation();
    const id = tr.dataset.cid, host = tr.dataset.host;
    const items = [];
    if (tr.dataset.live === '1') {
      items.push({ label: AgI18n.t('logs.ctx.kill'), danger: true, fn: async () => {
        try {
          await invoke('sub_close_connection', { id });
          toast(AgI18n.t('logs.killed'), 'ok');
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

/* Language switch: clear signatures to force re-pull and redraw (connections/hits/events all render by signature compare; locale entry changes must break the signature) */
AgI18n.onChange(() => {
  LogsView.connSig = LogsView.hitsSig = LogsView.evSig = '';
  if (LogsView.timer) LogsView.pollNow();
});
