'use strict';
/* AgileNet shared base utilities (agutil, AGENTS.md §6 shared component layer):
   desktop loads via <script src="agutil.js">; admin UI serves it embedded via crates/node/src/ui/mod.rs at /ui/agutil.js
   (same mechanism as agchart.js / icons.js). Only utilities with identical semantics on both ends —
   divergent ones (e.g. fmtBytes output format, toast channel) keep local per-end implementations; never change behavior to force a merge.
   Dependency: icons.js must load first (AgIcon); badge helpers call AgI18n.t at render time. */
(function () {

const $ = (id) => document.getElementById(id);

/* HTML escape: dynamic content must pass through esc before entering innerHTML/attributes */
function esc(s) {
  return String(s ?? '').replace(/[&<>"'`]/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','`':'&#96;'
  }[c]));
}

/* Inline help (shared component .ahelp, styles in components.css): question-mark icon + pure CSS hover tip card */
function ahelp(text) {
  return '<span class="ahelp">' + AgIcon('badge-question-mark', 13) + '<span class="ahelp-tip">' + esc(text) + '</span></span>';
}

/* ---- Source/auth badges (naming sovereignty, node.md M1; styles in components.css) ----
   Group names stay clean; source/auth state rides badges. All strings via AgI18n (badge.* keys
   in aglang.js base layer). */

/* Federation source badge: adopted-group lineage. title optional — defaults to the standard
   "pushed by X · read-only mirror" tip. */
function srcBadge(node, title) {
  const tip = title || AgI18n.t('badge.srcTip', { name: node });
  return '<span class="src src-verify" title="' + esc(tip) + '">' + AgIcon('badge-check', 12) + esc(node) + '</span>';
}

/* Node auth mark: badge-check in ok green for cryptographically verified peers. auth = 'pin'
   (fingerprint pinning) | 'tls' (CA/cert verification); anything else (insecure) shows NO mark. */
function nodeBadge(node, auth, strong) {
  const tip = auth === 'pin' ? AgI18n.t('badge.authPin') : auth === 'tls' ? AgI18n.t('badge.authTls') : '';
  const mark = tip ? '<span class="nb-auth" title="' + esc(tip) + '">' + AgIcon('badge-check', 10) + '</span>' : '';
  return '<span class="nodebadge">' + (strong ? '<b>' : '') + esc(node) + (strong ? '</b>' : '') + mark + '</span>';
}

/* Issuance-table group capsule: one chip carries name + source. g = {name, adopted, e2e}. */
function grpChip(g) {
  const e2e = g.e2e ? ' <span class="badge b-warn">E2E</span>' : '';
  if (g.adopted) {
    const tip = AgI18n.t('badge.srcTip', { name: g.adopted });
    return '<span class="grp-chip" title="' + esc(tip) + '">' + AgIcon('badge-check', 11) + esc(g.name) +
      ' <span class="grp-sep">·</span> ' + esc(g.adopted) + '</span>' + e2e;
  }
  return '<span class="grp-chip local">' + esc(g.name) + '</span>' + e2e;
}

/* Weak "this machine" tag (home icon). */
function localTag() {
  return '<span class="local">' + AgIcon('home', 11) + esc(AgI18n.t('badge.local')) + '</span>';
}

/* Fan-out TLS verification tier (drives nodeBadge's auth mark): fingerprint pinning > pinned
   cert / custom CA > system CA; insecure carries NO mark. c = connector list item. */
function connAuthTier(c) {
  if (c.pinned_fingerprint) return 'pin';
  if (c.insecure) return '';
  return 'tls';
}

/* Session-notice reason code → bilingual fallback text (node.md M4: reason.* keys in aglang.js).
   Unknown/absent codes degrade to the raw code (or the generic unknown label). */
function reasonText(rc) {
  const key = 'reason.' + String(rc || '');
  const t = AgI18n.t(key);
  if (t !== key) return t;
  return rc ? String(rc) : AgI18n.t('reason.unknown');
}

/* ---- Naming triplet (node.md M3-T6; i18n keys triplet.* in aglang.js) ----
   Uniform three-field group for server/client forms: target name (local) / my name (shown to
   the peer) / remark (local private). nameTriplet(prefix, values, opts) renders the inputs
   (opts.target/myname/remark = false hides that field); nameTripletVal(prefix) reads them back
   (hidden fields read as ''). */
function nameTriplet(prefix, values, opts) {
  values = values || {};
  opts = opts || {};
  let h = '';
  if (opts.target !== false) {
    h += '<label>' + AgI18n.t('triplet.target') + '</label>' +
      '<input id="' + prefix + '-target" style="width:100%" value="' + esc(values.target || '') + '">';
  }
  if (opts.myname !== false) {
    h += '<label>' + AgI18n.t('triplet.myname') + ' ' + ahelp(AgI18n.t('triplet.mynameTip')) + '</label>' +
      '<input id="' + prefix + '-myname" style="width:100%" value="' + esc(values.myname || '') + '">';
  }
  if (opts.remark !== false) {
    h += '<label>' + AgI18n.t('triplet.remark') + '</label>' +
      '<input id="' + prefix + '-remark" style="width:100%" value="' + esc(values.remark || '') + '">';
  }
  return h;
}
function nameTripletVal(prefix) {
  const v = (k) => { const el = $(prefix + '-' + k); return el ? el.value.trim() : ''; };
  return { target: v('target'), myname: v('myname'), remark: v('remark') };
}

/* ---- AgIdCard hover identity card shell (.agidcard styles in components.css) ----
   Document-level delegation over [data-agid] anchors: hover intent (240ms) → opts.load(fp,
   anchor) resolves the card HTML (esc applied by the caller) → fixed-position card below the
   anchor (flips above at the viewport edge). The card itself is hoverable (copy buttons inside
   stay clickable); closes on leaving both anchor+card (140ms grace), on scroll, or on outside
   click. attach() once per app; content/click behavior is the caller's (data-act delegation). */
const AgIdCard = (() => {
  let loader = null;
  let card = null, anchor = null;
  let showTimer = 0, hideTimer = 0;
  let overAnchor = false, overCard = false;

  function ensureCard() {
    if (card) return card;
    card = document.createElement('div');
    card.className = 'agidcard';
    card.hidden = true;
    document.body.appendChild(card);
    card.addEventListener('pointerenter', () => { overCard = true; });
    card.addEventListener('pointerleave', () => { overCard = false; scheduleHide(); });
    return card;
  }
  function place(a) {
    const c = ensureCard();
    const r = a.getBoundingClientRect();
    const cw = c.offsetWidth, ch = c.offsetHeight;
    c.style.left = Math.max(8, Math.min(r.left, window.innerWidth - cw - 8)) + 'px';
    let top = r.bottom + 6;
    if (top + ch > window.innerHeight - 8) top = Math.max(8, r.top - ch - 6);
    c.style.top = top + 'px';
  }
  async function show(a) {
    const fp = a.dataset.agid;
    if (!fp || !loader || !a.isConnected) return;
    const html = await loader(fp, a);
    if (anchor !== a || !html || !a.isConnected) return; // stale hover or empty payload
    const c = ensureCard();
    c.innerHTML = html;
    c.hidden = false;
    place(a);
  }
  function hide() {
    clearTimeout(showTimer); clearTimeout(hideTimer);
    if (card) card.hidden = true;
    anchor = null;
  }
  function scheduleHide() {
    clearTimeout(hideTimer);
    hideTimer = setTimeout(() => { if (!overAnchor && !overCard) hide(); }, 140);
  }
  function attach(opts) {
    loader = (opts && opts.load) || null;
    document.addEventListener('pointerover', (e) => {
      const a = e.target && e.target.closest ? e.target.closest('[data-agid]') : null;
      if (!a) {
        if (!card || !card.contains(e.target)) { overAnchor = false; if (anchor) scheduleHide(); }
        return;
      }
      overAnchor = true;
      clearTimeout(hideTimer);
      if (anchor === a && card && !card.hidden) return;
      anchor = a;
      clearTimeout(showTimer);
      showTimer = setTimeout(() => { if (anchor === a) show(a); }, 240);
    });
    document.addEventListener('pointerout', (e) => {
      const a = e.target && e.target.closest ? e.target.closest('[data-agid]') : null;
      if (!a) return;
      overAnchor = false;
      scheduleHide();
    });
    document.addEventListener('scroll', hide, true);
    document.addEventListener('click', (e) => { if (card && !card.contains(e.target)) hide(); }, true);
  }
  return { attach, hide };
})();

/* ---- AgPulse: auto-refresh status widget (last-updated time + interval select; NO manual refresh
   button anywhere). Intervals persist per key (localStorage); the offered options are the rate floor
   and ceiling — abuse-proof by construction. Ticks skip while the document is hidden (same policy as
   the main loops). The poll fn may return false on failure: the timestamp then keeps the last good pull. */
const AgPulse = (() => {
  const reg = new Map(); // key → { key, fn, ms, timer, active, timeEl }
  const pad = (n) => String(n).padStart(2, '0');
  function now() { const d = new Date(); return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()); }
  function mount(el, opts) {
    const key = opts.key;
    const saved = parseInt(localStorage.getItem('agpulse-ms-' + key) || '', 10);
    const ms = opts.options.includes(saved) ? saved : opts.defMs;
    const wrap = document.createElement('span');
    wrap.className = 'agpulse';
    wrap.innerHTML = '<span class="ap-t" title="' + AgI18n.t('pulse.updatedTip') + '">' + AgI18n.t('pulse.updated') + ' --:--:--</span>';
    const sel = document.createElement('select');
    sel.className = 'agp-iv';
    sel.title = AgI18n.t('pulse.intervalTip');
    sel.innerHTML = opts.options.map(m =>
      '<option value="' + m + '"' + (m === ms ? ' selected' : '') + '>' + (m / 1000) + 's</option>').join('');
    wrap.appendChild(sel);
    el.appendChild(wrap);
    const rec = { key, fn: opts.onTick, ms, timer: null, active: false, timeEl: wrap.firstChild };
    reg.set(key, rec);
    sel.addEventListener('change', () => {
      rec.ms = parseInt(sel.value, 10);
      localStorage.setItem('agpulse-ms-' + key, String(rec.ms));
      if (rec.active) { stop(rec); start(rec); tick(key); } // a new cadence applies immediately
    });
    return key;
  }
  function start(rec) { rec.timer = setInterval(() => tick(rec.key), rec.ms); }
  function stop(rec) { if (rec.timer) { clearInterval(rec.timer); rec.timer = null; } }
  async function tick(key) {
    const rec = reg.get(key);
    if (!rec || !rec.active || document.hidden) return;
    let ok;
    try { ok = await rec.fn(); } catch (e) { ok = false; }
    if (ok !== false) beat(key);
  }
  function setActive(key, on) {
    const rec = reg.get(key);
    if (!rec) return;
    if (on && !rec.active) { rec.active = true; stop(rec); start(rec); tick(key); }
    else if (!on && rec.active) { rec.active = false; stop(rec); }
  }
  /* Stamp the updated time without polling (user-action-driven refreshes call their fn directly) */
  function beat(key) {
    const rec = reg.get(key);
    if (rec) rec.timeEl.textContent = AgI18n.t('pulse.updated') + ' ' + now();
  }
  return { mount, tick, setActive, beat };
})();

window.$ = $;
window.esc = esc;
window.ahelp = ahelp;
window.srcBadge = srcBadge;
window.nodeBadge = nodeBadge;
window.grpChip = grpChip;
window.localTag = localTag;
window.connAuthTier = connAuthTier;
window.reasonText = reasonText;
window.nameTriplet = nameTriplet;
window.nameTripletVal = nameTripletVal;
window.AgIdCard = AgIdCard;
window.AgPulse = AgPulse;
})();
