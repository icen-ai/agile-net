'use strict';
/* Split from app.js: fan-in/fan-out/rules/custom rules/combos/admin console/proxy control/dashboard cards (pure move, zero logic change) */

/* ================= Empty state guide ================= */
/* server_status coalescing (web.md §3.3): the 10s tick fans one invoke out to every consumer
   (refreshAdminEntry / renderDashFanout / refreshServerPanel) — in-flight dedup + 1.5s TTL.
   User-action paths (toggles, universal import) call invoke('server_status') directly. */
let _ssCache = { t: 0, p: null };
function serverStatusFresh() {
  const now = Date.now();
  if (_ssCache.p && now - _ssCache.t < 1500) return _ssCache.p;
  _ssCache = { t: now, p: invoke('server_status') };
  return _ssCache.p;
}
function updateOnboarding(nodes) {
  // no active connections and no saved fan-in = empty state: show only the connect guide; show dashboard card grid once data exists
  const empty = (!nodes || nodes.length === 0) && !(window._credsRaw || []).length;
  $('onboarding').style.display = empty ? 'block' : 'none';
  const dg = $('dash-grid');
  if (dg) dg.style.display = empty ? 'none' : '';
}

/* ================= List filter (search) ================= */
const FILTERS = { creds: '', rules: '' };
function bindSearch() {
  document.querySelectorAll('.search-toggle').forEach(btn => {
    btn.onclick = () => {
      const key = btn.dataset.search;
      const row = $('search-' + key);
      const input = row.querySelector('input');
      if (row.hidden) { row.hidden = false; input.focus(); }
      else { row.hidden = true; input.value = ''; setFilter(key, ''); }
    };
  });
  ['creds', 'rules'].forEach(key => {
    $('search-' + key).querySelector('input').oninput = (e) => setFilter(key, e.target.value);
  });
}
function setFilter(key, v) {
  FILTERS[key] = v.trim().toLowerCase();
  if (key === 'rules') renderMergedRules(window._nodes || []);
  if (key === 'creds') renderCredList(window._credsRaw || [], window._nodeStatus || {});
}

/* ================= Node management ================= */
let lastNodesSig = null;
const restoredPaused = new Set();

async function refreshNodes(force) {
  let nodes = [];
  try {
    nodes = await invoke('list_nodes');
  } catch (e) { toast(friendlyError(e), 'err'); updateOnboarding([]); return false; }
  window._nodes = nodes;
  window._nodeStatus = Object.fromEntries(nodes.map(n => [n.node_id, n.status]));
  trackFaninTraffic(nodes);
  refreshAdminEntry();
  await restorePaused(nodes);
  const sig = JSON.stringify(nodes);
  if (force || sig !== lastNodesSig) {
    lastNodesSig = sig;
    await loadPaused(nodes);
    renderMergedRules(nodes);
    renderCredList(window._credsRaw || [], window._nodeStatus || {});
  }
  updateOnboarding(nodes);
  updateDashFanin();
  renderMachineCert(); // settings identity card cert-state list follows the nodes poll (sig-guarded)
  return true;
}
function statusText(s) {
  if (s === 'Connected') return T('st-connected');
  if (s === 'Connecting') return T('st-connecting');
  if (s === 'Reconnecting') return T('st-reconnecting');
  if (s === 'PendingApproval') return AgI18n.t('views.st-pending');
  if (s === 'Blocked') return AgI18n.t('views.st-blocked');
  return T('st-disconnected');
}
function statusBadgeHtml(s) {
  if (s === 'Connected') return '<span class="badge b-ok">' + T('st-connected') + '</span>';
  if (s === 'Connecting') return '<span class="badge b-warn"><span class="pulse"></span>' + T('st-connecting') + '</span>';
  if (s === 'Reconnecting') return '<span class="badge b-warn"><span class="pulse"></span>' + T('st-reconnecting') + '</span>';
  // M4: certified-pending (amber, gated) / terminal block (red, reason in the card body)
  if (s === 'PendingApproval') return '<span class="badge b-warn">' + AgI18n.t('views.st-pending') + '</span>';
  if (s === 'Blocked') return '<span class="badge b-off">' + AgI18n.t('views.st-blocked') + '</span>';
  return '<span class="badge b-off">' + T('st-disconnected') + '</span>';
}

/* ---- Unified rules table (custom bypass/map + endpoint-pulled merged; type filter RL_FILTER stacks with search FILTERS.rules) ---- */
function ruleKey(r) { return (r.type + ':' + r.value).toLowerCase(); }
async function loadPaused(nodes) {
  const map = {};
  for (const n of nodes) {
    try { map[n.node_id] = new Set(await invoke('get_paused_rules', { nodeId: n.node_id })); }
    catch (e) { map[n.node_id] = new Set(); }
  }
  window._paused = map;
}
async function restorePaused(nodes) {
  let saved;
  try { saved = JSON.parse(localStorage.getItem('ag_paused_rules') || '{}'); } catch (e) { return; }
  for (const n of nodes) {
    if (restoredPaused.has(n.node_id)) continue;
    restoredPaused.add(n.node_id);
    const keys = saved[n.node_id];
    if (keys && keys.length) {
      try { await invoke('set_paused_rules', { nodeId: n.node_id, keys }); } catch (e) {}
    }
  }
}
function persistPaused() {
  const out = {};
  for (const [k, set] of Object.entries(window._paused || {})) out[k] = [...set];
  localStorage.setItem('ag_paused_rules', JSON.stringify(out));
}
function renderMergedRules(nodes) {
  const f = FILTERS.rules;
  const tf = RL_FILTER;
  const pausedMap = window._paused || {};
  const custom = window._custom || { bypass: [], hosts: [] };
  const hit = (...xs) => !f || xs.some(x => x && String(x).toLowerCase().includes(f));
  const rows = []; // {html, type, val, via, src} — sort keys ride along for the header click-sort
  // custom bypass (highest engine priority, listed first by default)
  if (tf === 'all' || tf === 'bypass') {
    for (const r of custom.bypass) {
      const wayKey = { direct: 'views.rule-direct', subscription: 'views.rule-via-sub', sysproxy: 'views.rule-sysproxy', tun: 'views.rule-tun' }[r.target] || 'views.rule-direct';
      const way = AgI18n.t(wayKey);
      if (!hit(r.pattern, AgI18n.t('views.rule-bypass'), way, AgI18n.t('views.src-custom'), AgI18n.t('views.src-preset'))) continue;
      const src = r.source === 'preset' ? AgI18n.t('views.src-preset') : AgI18n.t('views.src-custom');
      rows.push({
        type: 'bypass', val: r.pattern, via: r.target || 'direct', src,
        html: '<tr class="' + (r.enabled ? '' : 'rule-paused') + '">' +
          '<td><span class="badge b-ok">' + AgI18n.t('views.rule-bypass') + '</span></td>' +
          '<td class="mono">' + esc(r.pattern) + '</td>' +
          '<td>' + way + '</td>' +
          '<td class="dim">' + src + '</td>' +
          '<td><label class="switch"><input type="checkbox" data-cr="' + esc(r.id) + '"' + (r.enabled ? ' checked' : '') + '><span class="slider"></span></label></td>' +
          '<td><button class="danger small icon-btn" title="' + AgI18n.t('views.del-bypass-title') + '" data-crdel="' + esc(r.id) + '">' + AgIcon('trash-2', 13) + '</button></td></tr>',
      });
    }
  }
  // hosts mapping (user-created can be toggled/deleted; system entries read-only, no actions shown)
  if (tf === 'all' || tf === 'host') {
    for (const r of custom.hosts) {
      const sys = r.source === 'system';
      const src = sys ? AgI18n.t('views.src-system-hosts') : AgI18n.t('views.src-custom');
      if (!hit(r.hostname, r.ip, AgI18n.t('views.rule-map'), src)) continue;
      rows.push({
        type: 'map', val: r.hostname, via: r.ip, src,
        html: '<tr class="' + (r.enabled ? '' : 'rule-paused') + '">' +
          '<td><span class="badge b-gray">' + AgI18n.t('views.rule-map') + '</span></td>' +
          '<td class="mono">' + esc(r.hostname) + '</td>' +
          '<td class="mono">→ ' + esc(r.ip) + '</td>' +
          '<td class="dim">' + src + '</td>' +
          (sys
            ? '<td><span class="dim">' + AgI18n.t('views.readonly') + '</span></td><td></td>'
            : '<td><label class="switch"><input type="checkbox" data-cr="' + esc(r.id) + '"' + (r.enabled ? ' checked' : '') + '><span class="slider"></span></label></td>' +
              '<td><button class="danger small icon-btn" title="' + AgI18n.t('views.del-map-title') + '" data-crdel="' + esc(r.id) + '">' + AgIcon('trash-2', 13) + '</button></td>') +
          '</tr>',
      });
    }
  }
  // endpoint-pulled (source is the endpoint name; toggle uses existing pause semantics)
  if (tf === 'all' || tf === 'pulled') {
    for (const n of nodes) {
      const dot = n.status === 'Connected' ? 'ok' : (n.status === 'Disconnected' ? 'down' : 'warn');
      const pset = pausedMap[n.node_id] || new Set();
      // user-assigned fan-in alias wins over the peer's self-reported node name everywhere
      const nname = (((window._creds || {})[n.node_id] || {}).name || '').trim() || n.node_name;
      for (const r of (n.rules || [])) {
        const key = ruleKey(r);
        if (!hit(r.value, r.type, nname + ' ' + n.node_name)) continue;
        const paused = pset.has(key);
        rows.push({
          type: r.type, val: r.value, via: '', src: nname,
          html: '<tr class="' + (paused ? 'rule-paused' : '') + '"><td><span class="rdot ' + dot + '"></span><span class="badge b-ok">' + esc(r.type) + '</span></td>' +
            '<td class="mono">' + esc(r.value) + '</td>' +
            '<td class="dim">—</td>' +
            '<td class="dim">' + esc(nname) + '</td>' +
            '<td><label class="switch"><input type="checkbox" data-node="' + esc(n.node_id) + '" data-rule="' + esc(key) + '"' + (paused ? '' : ' checked') + '><span class="slider"></span></label></td>' +
            '<td></td></tr>',
        });
      }
    }
  }
  // header click-sort (AgTbl, persisted); default order encodes engine priority: bypass → hosts → pulled
  const st = AgTbl.sortState('rules');
  if (st) {
    const get = { type: r => r.type, val: r => r.val, via: r => r.via, src: r => String(r.src) }[st.id];
    if (get) rows.sort((a, b) => {
      const c = String(get(a)).toLowerCase().localeCompare(String(get(b)).toLowerCase());
      return st.dir === 'asc' ? c : -c;
    });
  }
  $('rules-body').innerHTML = rows.map(r => r.html).join('') || '<tr><td colspan="6" class="empty">' + ((f || tf !== 'all') ? AgI18n.t('views.no-match') : T('no-rules')) + '</td></tr>';
}
async function toggleRule(nodeId, key, paused) {
  try {
    await invoke('set_rule_paused', { nodeId, ruleKey: key, paused });
    const map = window._paused || (window._paused = {});
    const set = map[nodeId] || (map[nodeId] = new Set());
    if (paused) set.add(key); else set.delete(key);
    persistPaused();
    const tr = document.querySelector('input[data-node][data-rule="' + CSS.escape(key) + '"]');
    if (tr) tr.closest('tr').classList.toggle('rule-paused', paused);
    toast(paused ? AgI18n.t('views.rule-paused-toast') : AgI18n.t('views.rule-resumed-toast'), 'ok');
  } catch (e) {
    toast(friendlyError(e), 'err');
    refreshNodes(true);
  }
}

/* ================= Custom rules (bypass / hosts mapping) and combos =================
   Backend contract (apps/desktop/src/custom_rules.rs + lib.rs command layer; GUI local capability, hidden on Web remote panel):
   list_custom_rules() -> { bypass:[{id,pattern,target,enabled}],
                            hosts:[{id,hostname,ip,enabled,source}] } (source=user|system, system is read-only);
   combo rule_keys: custom = its id, pulled = ruleKey(r) (type:value lowercased).
   Pulled keys in combos are ignored by the engine; this module orchestrates them via the existing pause API (orchestrateCombo). */
let RL_FILTER = 'all';    // type filter (stacks with search): all | bypass | host | pulled
let CUSTOM_SIG = null;    // list_custom_rules polling change detection signature
let COMBO_ITEMS = [];
let COMBO_SIG = null;
let COMBO_EDIT_ID = null;
let CE_MEMBERS = new Set(); // combo edit modal member working set (search re-render doesn't lose selections)

/* ---- Custom rules data (10s polling + call after changes; no redraw when signature matches) ---- */
async function refreshCustomRules(force) {
  if (HTTP_MODE) return;
  let data;
  try { data = await invoke('list_custom_rules'); } catch (e) { return; }
  const sig = JSON.stringify(data);
  if (!force && sig === CUSTOM_SIG) return;
  CUSTOM_SIG = sig;
  window._custom = data;
  renderMergedRules(window._nodes || []);
}

/* ---- Per-rule toggle / delete (immediate effect; backend persists and hot-reloads engine) ---- */
async function toggleCustomRule(id, enabled, cb) {
  try {
    await invoke('set_custom_rule_enabled', { id, enabled });
    const c = window._custom;
    if (c) {
      const r = (c.bypass || []).find(x => x.id === id) || (c.hosts || []).find(x => x.id === id);
      if (r) { r.enabled = enabled; CUSTOM_SIG = JSON.stringify(c); }
    }
    const tr = cb.closest('tr');
    if (tr) tr.classList.toggle('rule-paused', !enabled);
    toast(enabled ? AgI18n.t('views.rule-enabled-toast') : AgI18n.t('views.rule-disabled-toast'), 'ok');
  } catch (e) {
    cb.checked = !enabled;
    toast(friendlyError(e), 'err');
  }
}
async function deleteCustomRule(id, btn) {
  if (btn.dataset.confirm === '1') {
    try {
      await invoke('remove_custom_rule', { id });
      toast(AgI18n.t('views.rule-deleted'), 'ok');
      refreshCustomRules(true);
      refreshCombos(true); // backend cascades removal of dead keys from combo members
    } catch (e) { toast(friendlyError(e), 'err'); }
    return;
  }
  btn.dataset.confirm = '1';
  const old = btn.innerHTML;
  btn.innerHTML = '<span style="font-size:11px">' + AgI18n.t('common.confirm') + '</span>';
  setTimeout(() => { if (btn.isConnected) { btn.dataset.confirm = ''; btn.innerHTML = old; } }, 2500);
}

/* ---- Frontend pre-validation (backend still the fallback; errors shown in-modal) ---- */
function validIPv4(ip) {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  return !!m && m.slice(1).every(o => +o <= 255);
}
function validIP(ip) {
  return validIPv4(ip) || (ip.includes(':') && /^[0-9a-fA-F:]+$/.test(ip));
}

/* ---- Combo data and list ---- */
async function refreshCombos(force) {
  if (HTTP_MODE) return;
  let items;
  try { items = await invoke('list_rule_combos'); } catch (e) { return; }
  const sig = JSON.stringify(items);
  if (!force && sig === COMBO_SIG) return;
  COMBO_SIG = sig;
  COMBO_ITEMS = items;
  renderComboList();
}
function renderComboList() {
  const list = $('combo-list');
  if (!COMBO_ITEMS.length) {
    list.innerHTML = '<div class="empty">' + AgI18n.t('views.combo-empty') + '</div>';
    return;
  }
  list.innerHTML = COMBO_ITEMS.map(c =>
    '<div class="node-card"><div class="info">' +
    '<div class="name">' + esc(c.name) + ' ' + (c.enabled ? '<span class="badge b-ok">' + AgI18n.t('common.enabled') + '</span>' : '<span class="badge b-gray">' + AgI18n.t('common.disabled') + '</span>') + '</div>' +
    '<div class="addr">' + AgI18n.t('views.combo-members', { n: c.rule_keys.length }) + '</div>' +
    '</div><div class="card-actions">' +
    '<label class="switch"><input type="checkbox" data-combo-toggle="' + esc(c.id) + '"' + (c.enabled ? ' checked' : '') + '><span class="slider"></span></label>' +
    '<button class="ghost small" data-combo-edit="' + esc(c.id) + '">' + AgI18n.t('common.edit') + '</button>' +
    '<button class="danger small" data-combo-del="' + esc(c.id) + '">' + AgI18n.t('common.delete') + '</button>' +
    '</div></div>').join('');
}

/* Combo toggle orchestration: pulled members in a combo (type:value keys) are ignored by the engine, handled by the
   frontend via the existing pause API -- enable -> unpause all pulled members; disable -> pause pulled members,
   but leave members still covered by another enabled combo untouched (cross-mesh semantics).
   Applies to endpoints currently holding the rule; window._paused cache synced and persisted locally. */
function comboPulledKeys(ruleKeys) {
  const ids = new Set();
  const c = window._custom;
  if (c) { (c.bypass || []).forEach(r => ids.add(r.id)); (c.hosts || []).forEach(r => ids.add(r.id)); }
  return (ruleKeys || []).filter(k => !ids.has(k));
}
async function orchestrateCombo(combo, enabling) {
  let keys = comboPulledKeys(combo.rule_keys);
  if (!keys.length) return;
  if (!enabling) {
    // cross-coverage protection: members still referenced by other enabled combos stay as-is
    const covered = new Set();
    for (const o of COMBO_ITEMS) {
      if (o.id !== combo.id && o.enabled) (o.rule_keys || []).forEach(k => covered.add(k));
    }
    keys = keys.filter(k => !covered.has(k));
    if (!keys.length) return;
  }
  const pausedMap = window._paused || (window._paused = {});
  for (const n of (window._nodes || [])) {
    const have = new Set((n.rules || []).map(ruleKey));
    const targets = keys.filter(k => have.has(k));
    if (!targets.length) continue;
    const set = pausedMap[n.node_id] || (pausedMap[n.node_id] = new Set());
    for (const k of targets) {
      try {
        await invoke('set_rule_paused', { nodeId: n.node_id, ruleKey: k, paused: !enabling });
        if (enabling) set.delete(k); else set.add(k);
      } catch (e) { /* single failure doesn't block orchestration of the remaining members */ }
    }
  }
  persistPaused();
}

async function toggleCombo(id, enabled, cb) {
  const combo = COMBO_ITEMS.find(c => c.id === id);
  if (!combo) { if (cb) cb.checked = !enabled; return; }
  try {
    await invoke('set_combo_enabled', { id, enabled });
    await refreshCombos(true);
    await orchestrateCombo(combo, enabled);
    renderMergedRules(window._nodes || []);
    toast(enabled ? AgI18n.t('views.combo-enabled-toast') : AgI18n.t('views.combo-disabled-toast'), 'ok');
  } catch (e) {
    if (cb) cb.checked = !enabled;
    toast(friendlyError(e), 'err');
  }
}
async function deleteCombo(id, btn) {
  if (btn.dataset.confirm === '1') {
    const combo = COMBO_ITEMS.find(c => c.id === id);
    try {
      await invoke('remove_combo', { id });
      await refreshCombos(true);
      // deleting an enabled combo ≈ disabling: its pulled members are paused under cross-coverage protection
      if (combo && combo.enabled) {
        await orchestrateCombo(combo, false);
        renderMergedRules(window._nodes || []);
      }
      if (COMBO_EDIT_ID === id) { $('combo-edit-modal').style.display = 'none'; COMBO_EDIT_ID = null; }
      toast(AgI18n.t('views.combo-deleted'), 'ok');
    } catch (e) { toast(friendlyError(e), 'err'); }
    return;
  }
  btn.dataset.confirm = '1';
  const old = btn.innerHTML;
  btn.innerHTML = '<span style="font-size:11px">' + AgI18n.t('common.confirm') + '</span>';
  setTimeout(() => { if (btn.isConnected) { btn.dataset.confirm = ''; btn.innerHTML = old; } }, 2500);
}

/* ---- Edit combo modal (name + checkbox compact list of all rules) ---- */
function comboEditOpen(c) {
  COMBO_EDIT_ID = c.id;
  CE_MEMBERS = new Set(c.rule_keys);
  $('ce-name').value = c.name;
  $('ce-search').value = '';
  $('ce-err').textContent = '';
  renderComboEditList('');
  // web.md §3.1: surface dangling member references (e.g. a deleted preset) instead of silently ignoring them
  const known = new Set(allRuleChoices().map(it => it.key));
  const dangling = [...CE_MEMBERS].filter(k => !known.has(k));
  if (dangling.length) {
    dangling.forEach(k => CE_MEMBERS.delete(k));
    $('ce-err').textContent = AgI18n.t('views.combo-dangling', { n: dangling.length });
    renderComboEditList('');
  }
  $('combo-edit-modal').style.display = 'flex';
  $('ce-name').focus();
}
/* Compact list of all rules (custom + pulled; system hosts read-only, not selectable; pulled deduped by key across endpoints;
   built-in presets excluded — they are system defaults, not combo members (web.md §3.1) */
function allRuleChoices() {
  const out = [];
  const c = window._custom || { bypass: [], hosts: [] };
  (c.bypass || []).forEach(r => {
    if (String(r.id).startsWith('preset-')) return;
    out.push({ key: r.id, badge: AgI18n.t('views.rule-bypass'), cls: 'b-ok', value: r.pattern, source: AgI18n.t('views.src-custom') });
  });
  (c.hosts || []).forEach(r => {
    if (r.source !== 'system') out.push({ key: r.id, badge: AgI18n.t('views.rule-map'), cls: 'b-gray', value: r.hostname + ' → ' + r.ip, source: AgI18n.t('views.src-custom') });
  });
  const seen = new Set(out.map(o => o.key));
  for (const n of (window._nodes || [])) {
    for (const r of (n.rules || [])) {
      const key = ruleKey(r);
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ key, badge: r.type, cls: 'b-ok', value: r.value, source: n.node_name });
    }
  }
  return out;
}
function renderComboEditList(f) {
  const items = allRuleChoices().filter(it => !f ||
    it.value.toLowerCase().includes(f) || it.badge.toLowerCase().includes(f) || it.source.toLowerCase().includes(f));
  $('ce-list').innerHTML = items.length ? items.map(it =>
    '<label class="combo-rule-row"><input type="checkbox" data-ce-key="' + esc(it.key) + '"' + (CE_MEMBERS.has(it.key) ? ' checked' : '') + '>' +
    '<span class="badge ' + it.cls + '">' + esc(it.badge) + '</span>' +
    '<span class="mono combo-rule-val">' + esc(it.value) + '</span>' +
    '<span class="combo-rule-src">' + esc(it.source) + '</span></label>').join('')
    : '<div class="empty">' + (f ? AgI18n.t('views.no-match') : AgI18n.t('views.combo-no-choices')) + '</div>';
}
async function comboEditSave() {
  const name = $('ce-name').value.trim();
  if (!name) { $('ce-err').textContent = AgI18n.t('views.combo-name-required'); return; }
  const combo = COMBO_ITEMS.find(c => c.id === COMBO_EDIT_ID);
  const before = new Set(combo ? combo.rule_keys : []);
  const btn = $('ce-ok');
  btn.disabled = true;
  try {
    await invoke('update_combo', { id: COMBO_EDIT_ID, name, ruleKeys: [...CE_MEMBERS] });
    $('combo-edit-modal').style.display = 'none';
    COMBO_EDIT_ID = null;
    await refreshCombos(true);
    // enabled combo membership change re-orchestrates: newly added pulled members unpaused, removed ones paused under cross-coverage protection
    if (combo && combo.enabled) {
      const added = [...CE_MEMBERS].filter(k => !before.has(k));
      const removed = [...before].filter(k => !CE_MEMBERS.has(k));
      if (added.length) await orchestrateCombo({ id: combo.id, rule_keys: added }, true);
      if (removed.length) await orchestrateCombo({ id: combo.id, rule_keys: removed }, false);
      if (added.length || removed.length) renderMergedRules(window._nodes || []);
    }
    toast(AgI18n.t('views.combo-saved'), 'ok');
  } catch (e) {
    $('ce-err').textContent = friendlyError(e);
  } finally {
    btn.disabled = false;
  }
}

/* ---- All rules-page event bindings (CSP forbids inline events; unified explicit binding/delegation) ---- */
function initRules() {
  agTabsBind($('rl-tabs'), (key) => { if (key === 'combo') refreshCombos(true); });
  // type filter chips (stack with search)
  $('rl-filter').addEventListener('click', (e) => {
    const b = e.target.closest('[data-rfilter]');
    if (!b || b.classList.contains('active')) return;
    RL_FILTER = b.dataset.rfilter;
    $('rl-filter').querySelectorAll('.agtab').forEach(t => t.classList.toggle('active', t === b));
    renderMergedRules(window._nodes || []);
  });
  // unified table event delegation: custom row toggle / delete (pulled row toggle bound in the startup section)
  $('rules-body').addEventListener('change', (e) => {
    const cb = e.target.closest('input[data-cr]');
    if (cb) toggleCustomRule(cb.dataset.cr, cb.checked, cb);
  });
  $('rules-body').addEventListener('click', (e) => {
    const btn = e.target.closest('[data-crdel]');
    if (btn) deleteCustomRule(btn.dataset.crdel, btn);
  });

  /* ---- Add bypass modal ---- */
  $('btn-add-bypass').onclick = () => {
    $('bp-pattern').value = '';
    $('bp-via').value = 'subscription'; // 默认订阅路由（与原「经过订阅」同语义）
    agSelectRefresh($('bp-via'));
    $('bp-err').textContent = '';
    $('bypass-modal').style.display = 'flex';
    $('bp-pattern').focus();
  };
  $('bp-cancel').onclick = () => { $('bypass-modal').style.display = 'none'; };
  $('bp-pattern').addEventListener('keydown', e => { if (e.key === 'Enter') $('bp-ok').click(); });
  $('bp-ok').onclick = async () => {
    const pattern = $('bp-pattern').value.trim();
    if (!pattern || /\s/.test(pattern)) { $('bp-err').textContent = AgI18n.t('views.bp-pattern-invalid'); return; }
    const btn = $('bp-ok');
    btn.disabled = true;
    try {
      await invoke('add_bypass_rule', { pattern, target: $('bp-via').value });
      $('bypass-modal').style.display = 'none';
      toast(AgI18n.t('views.bp-added'), 'ok');
      refreshCustomRules(true);
    } catch (e) {
      $('bp-err').textContent = friendlyError(e);
    } finally {
      btn.disabled = false;
    }
  };

  /* ---- Add mapping modal ---- */
  $('btn-add-host').onclick = () => {
    $('hm-name').value = '';
    $('hm-ip').value = '';
    $('hm-system').checked = true;
    $('hm-err').textContent = '';
    $('host-modal').style.display = 'flex';
    $('hm-name').focus();
  };
  $('hm-cancel').onclick = () => { $('host-modal').style.display = 'none'; };
  $('hm-ip').addEventListener('keydown', e => { if (e.key === 'Enter') $('hm-ok').click(); });
  $('hm-ok').onclick = async () => {
    const hostname = $('hm-name').value.trim().toLowerCase();
    const ip = $('hm-ip').value.trim();
    if (!hostname || /\s/.test(hostname) || hostname.includes('*') || hostname.includes('#')) {
      $('hm-err').textContent = AgI18n.t('views.hm-host-invalid'); return;
    }
    if (validIP(hostname)) { $('hm-err').textContent = AgI18n.t('views.hm-host-is-ip'); return; }
    if (!validIP(ip)) { $('hm-err').textContent = AgI18n.t('views.hm-ip-invalid'); return; }
    const btn = $('hm-ok');
    btn.disabled = true;
    try {
      const r = await invoke('add_host_mapping', { hostname, ip, toSystem: $('hm-system').checked });
      $('host-modal').style.display = 'none';
      toast(r.persisted === 'system' ? AgI18n.t('views.hm-added-system') : AgI18n.t('views.hm-added-local'), 'ok');
      refreshCustomRules(true);
    } catch (e) {
      $('hm-err').textContent = friendlyError(e);
    } finally {
      btn.disabled = false;
    }
  };

  /* ---- New combo modal ---- */
  $('btn-add-combo').onclick = () => {
    $('cb-name').value = '';
    $('cb-err').textContent = '';
    $('combo-modal').style.display = 'flex';
    $('cb-name').focus();
  };
  $('cb-cancel').onclick = () => { $('combo-modal').style.display = 'none'; };
  $('cb-name').addEventListener('keydown', e => { if (e.key === 'Enter') $('cb-ok').click(); });
  $('cb-ok').onclick = async () => {
    const name = $('cb-name').value.trim();
    if (!name) { $('cb-err').textContent = AgI18n.t('views.combo-name-required'); return; }
    const btn = $('cb-ok');
    btn.disabled = true;
    try {
      await invoke('add_combo', { name });
      $('combo-modal').style.display = 'none';
      toast(AgI18n.t('views.combo-created'), 'ok');
      refreshCombos(true);
    } catch (e) {
      $('cb-err').textContent = friendlyError(e);
    } finally {
      btn.disabled = false;
    }
  };

  /* ---- Combo list (toggle / edit / delete) and edit modal ---- */
  $('combo-list').addEventListener('change', (e) => {
    const cb = e.target.closest('input[data-combo-toggle]');
    if (cb) toggleCombo(cb.dataset.comboToggle, cb.checked, cb);
  });
  $('combo-list').addEventListener('click', (e) => {
    const eb = e.target.closest('[data-combo-edit]');
    if (eb) {
      const c = COMBO_ITEMS.find(x => x.id === eb.dataset.comboEdit);
      if (c) comboEditOpen(c);
      return;
    }
    const db = e.target.closest('[data-combo-del]');
    if (db) deleteCombo(db.dataset.comboDel, db);
  });
  $('ce-search').addEventListener('input', () => renderComboEditList($('ce-search').value.trim().toLowerCase()));
  $('ce-list').addEventListener('change', (e) => {
    const cb = e.target.closest('input[data-ce-key]');
    if (!cb) return;
    if (cb.checked) CE_MEMBERS.add(cb.dataset.ceKey); else CE_MEMBERS.delete(cb.dataset.ceKey);
  });
  $('ce-cancel').onclick = () => { $('combo-edit-modal').style.display = 'none'; COMBO_EDIT_ID = null; };
  $('ce-ok').onclick = comboEditSave;
}

async function disconnectNode(nodeId) {
  try {
    await invoke('disconnect_node', { nodeId });
    toast(T('disconnected'), 'ok');
    refreshNodes(true);
    refreshCreds();
    refreshProxy();
  } catch (e) { toast(friendlyError(e), 'err'); }
}

/** Connect with loading state */
async function connectWith(input, btn) {
  let originalText = null;
  if (btn) {
    originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>' + AgI18n.t('views.connecting');
  }
  try {
    const st = await invoke('connect_node', { input });
    toast(T('connected-toast').replace('{name}', st.issuer_node_name || st.node_name).replace('{n}', st.rules.length), 'ok');
    // auto-start proxy after successful connect if needed
    if (PREFS.autoproxy) {
      try {
        const ps = await invoke('proxy_status');
        if (!ps.running) {
          await invoke('start_proxy', { port: proxyPort() });
        }
      } catch (e) { /* proxy auto-start failure doesn't block the connection */ }
    }
    refreshNodes(true);
    refreshCreds();
    refreshProxy();
    return true;
  } catch (e) {
    toast(friendlyError(e), 'err');
    return false;
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = originalText;
    }
  }
}

/* ================= Admin console mode (embedded iframe hosts the admin SPA; no child window) ================= */
let ADMIN = null; // { label, url, origin }

const curTheme = () => localStorage.getItem('ag_theme') || 'light';

async function enterAdmin(nodeId, upstream, label) {
  let url;
  try {
    url = await invoke('console_url', { nodeId: nodeId || null, upstream: upstream || null, theme: curTheme() });
  } catch (e) { toast(friendlyError(e), 'err'); return; }
  ADMIN = { label, url, origin: new URL(url).origin };
  $('admin-frame').src = url;
  LogsView.stop(); // entering admin console = leaving logs page: stop polling
  document.querySelector('.content').classList.add('admin-mode');
  $('nav-client').style.display = 'none';
  $('nav-admin').style.display = 'flex';
  $('side-foot').style.display = 'none'; // sidebar footer belongs to client navigation
  $('bnav').style.display = 'none'; // narrow-screen bottom nav also belongs to client navigation
  document.querySelectorAll('.view').forEach(s => { s.hidden = s.id !== 'view-admin'; });
  adminNavActivate('dashboard');
  toast(AgI18n.t('views.admin-entered', { name: label }), 'ok');
}

function exitAdmin() {
  if (!ADMIN) return;
  $('admin-frame').src = 'about:blank';
  ADMIN = null;
  document.querySelector('.content').classList.remove('admin-mode');
  $('nav-admin').style.display = 'none';
  $('nav-client').style.display = 'flex';
  $('side-foot').style.display = '';
  $('bnav').style.display = ''; // hand back to CSS breakpoint control (HTTP_MODE has no admin console entry, no conflict)
  switchView('connect');
}

function adminNavActivate(v) {
  document.querySelectorAll('#nav-admin .nav-item[data-aview]').forEach(n =>
    n.classList.toggle('active', n.dataset.aview === v));
  if (ADMIN) {
    const f = $('admin-frame');
    if (f && f.contentWindow) f.contentWindow.postMessage({ type: 'ag-nav', view: v }, ADMIN.origin);
  }
}

/** Title-bar admin console entry: local server always first, manageable endpoints/fan-out sorted by name; grayed out when empty */
async function refreshAdminEntry() {
  const items = [];
  try {
    const st = await serverStatusFresh();
    if (st && st.running) items.push({ kind: 'local', label: AgI18n.t('views.admin-local'), sub: AgI18n.t('views.admin-local-sub') });
  } catch (e) {}
  const nodes = window._nodes || [];
  const remotes = [];
  // embedded server role: fan-out upstreams discovered via handshake v2 (manage the relay through this machine's fan-out)
  try {
    const ups = await invoke('server_manageable');
    for (const m of (ups || [])) {
      remotes.push({ kind: 'lup', up: m.node_name, label: m.node_name, sub: AgI18n.t('views.admin-lup-sub') });
    }
  } catch (e) {}
  for (const n of nodes) {
    // Manageable-console list shows the issuer's node name (the management target identity);
    // falls back to the link label when the config channel hasn't delivered the name yet
    if (n.admin_console && n.status === 'Connected') {
      remotes.push({ kind: 'node', id: n.node_id, label: n.issuer_node_name || n.node_name, sub: n.addr });
    }
    for (const m of (n.manageable || [])) {
      if (n.status === 'Connected') {
        remotes.push({ kind: 'up', id: n.node_id, up: m.node_name, label: m.node_name, sub: AgI18n.t('views.admin-up-sub', { name: n.issuer_node_name || n.node_name }) });
      }
    }
  }
  remotes.sort((a, b) => a.label.localeCompare(b.label, AgI18n.lang));
  items.push(...remotes);
  const btn = $('btn-admin');
  btn.classList.toggle('disabled', !items.length);
  const menu = $('admin-menu');
  menu.innerHTML = items.length
    ? items.map((it, i) =>
        '<button data-aitem="' + i + '">' + AgIcon('fingerprint', 13) + '<span class="aitem-label">' + esc(it.label) + '</span><span class="aitem-sub">' + esc(it.sub) + '</span></button>'
      ).join('')
    : '<button disabled>' + AgI18n.t('views.admin-none') + '</button>';
  menu._items = items;
}

function initAdminMode() {
  $('nav-admin-back').onclick = exitAdmin;
  document.querySelectorAll('#nav-admin .nav-item[data-aview]').forEach(n => {
    n.setAttribute('role', 'button');
    n.setAttribute('tabindex', '0');
    n.onclick = () => adminNavActivate(n.dataset.aview);
    n.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); adminNavActivate(n.dataset.aview); } };
  });
  // embedded admin console (SPA) toasts routed into Dynamic Island (origin-checked, only from the current admin iframe)
  window.addEventListener('message', async (e) => {
    if (!(ADMIN && e.origin === ADMIN.origin)) return;
    const d = e.data || {};
    if (d.type === 'ag-toast') {
      toast(String(d.msg || ''), typeof d.kind === 'string' ? d.kind : 'info');
      return;
    }
    // .anet bridge: the embedded console delegates native save/open dialogs to the host
    const f = $('admin-frame');
    if (d.type === 'ag-anet-save' && typeof d.content === 'string') {
      let ok = false;
      try { ok = !!(await invoke('anet_save_file', { suggested: String(d.name || 'credential.anet'), content: d.content })); } catch (_) {}
      if (f && f.contentWindow) f.contentWindow.postMessage({ type: 'ag-anet-saved', ok }, ADMIN.origin);
    }
    if (d.type === 'ag-anet-open') {
      let r = null;
      try { r = await invoke('anet_open_file'); } catch (_) {}
      if (f && f.contentWindow && r) f.contentWindow.postMessage({ type: 'ag-anet-open-result', name: r.name, content: r.content }, ADMIN.origin);
    }
  });
  const menu = $('admin-menu');
  $('btn-admin').onclick = (e) => {
    e.stopPropagation();
    if ($('btn-admin').classList.contains('disabled')) return;
    menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
  };
  document.addEventListener('click', (e) => {
    if (!e.target.closest('#admin-menu') && !e.target.closest('#btn-admin')) menu.style.display = 'none';
    const btn = e.target.closest('#admin-menu [data-aitem]');
    if (!btn) return;
    menu.style.display = 'none';
    const it = (menu._items || [])[+btn.dataset.aitem];
    if (!it) return;
    if (it.kind === 'local') enterAdmin(null, null, it.label);
    else if (it.kind === 'node') enterAdmin(it.id, null, it.label);
    else if (it.kind === 'lup') enterAdmin(null, it.up, it.label);
    else enterAdmin(it.id, it.up, it.label);
  });
}

/* ================= Console channel (manage this endpoint; embedded in main window) ================= */
async function openNodeConsole(nodeId) {
  const n = (window._nodes || []).find(x => x.node_id === nodeId);
  const label = n ? (n.issuer_node_name || n.node_name) : nodeId;
  await enterAdmin(nodeId, null, label);
}

/* ================= Phone QR sync (desktop → phone scan) ================= */
/* The phone is an independent device (own fingerprint + key + device proof). Scanning a QR
   is equivalent to pasting an anet://connect link — the phone goes through the normal import
   flow as a new consumer. The QR just saves manual copy/paste. Only fan-in credentials are
   listed: fan-out is a server-role identity, each device runs its own — there's nothing to
   "sync" from the desktop. */
async function openPhoneQr() {
  let creds = [];
  try { creds = await invoke('list_credentials'); } catch (e) {}
  if (!creds.length) { toast(AgI18n.t('phone.noConfig'), 'err'); return; }
  const items = creds.map(([key, c]) => ({
    key, label: c.name || c.label || key.split('@')[0],
  }));
  // build modal: config selector + QR display area
  const opts = items.map((it, i) => '<option value="' + i + '">' + esc(it.label) + '</option>').join('');
  openModal(AgI18n.t('phone.title'),
    '<select id="qr-sel" style="width:100%">' + opts + '</select>' +
    '<div id="qr-display" style="text-align:center;margin-top:14px;min-height:280px;display:flex;align-items:center;justify-content:center"></div>' +
    '<div class="hint" style="text-align:center;margin-top:8px">' + AgI18n.t('phone.scanTip') + '</div>',
    [{ label: AgI18n.t('common.close'), kind: 'ghost', fn: closeModal }]);
  agSelectEnhance($('qr-sel'));
  const renderQr = async () => {
    const idx = parseInt($('qr-sel').value, 10);
    const item = items[idx]; if (!item) return;
    const display = $('qr-display');
    display.innerHTML = '<span class="dim">' + AgI18n.t('common.loading') + '</span>';
    try {
      // Rust export_credential builds the full anet://connect URL (entries + fps + en + emode + ...)
      const url = await invoke('export_credential', { key: item.key });
      const b64 = await invoke('qr_generate', { url });
      display.innerHTML = '<img src="data:image/png;base64,' + b64 + '" style="max-width:280px;width:100%;border-radius:10px;border:1px solid var(--border)">';
    } catch (e) { display.innerHTML = '<span class="err">' + esc(friendlyError(e)) + '</span>'; }
  };
  $('qr-sel').addEventListener('change', renderQr);
  renderQr();
}

/* ================= Connect-link import ================= */
async function importUrl(url, btn) {
  url = (url || '').trim();
  if (!url) { toast(T('err-need-url'), 'err'); return; }
  // Shared parser gate (anet://); the Rust parser does the real conversion
  const p = AgLink.parse(url);
  if (p.error || p.role !== 'connect') { toast(T('err-bad-url'), 'err'); return; }
  // M4-T5: a topology-visibility clause rides the link — the user must acknowledge it first
  // (DOM modal only; window.confirm is forbidden)
  if (p.visibility === 'disclose' || p.visibility === 'approve') {
    const accepted = await askConfirm({
      title: AgI18n.t('import.visibility.title'),
      desc: AgI18n.t('import.visibility.' + p.visibility),
      icon: 'shield',
      okText: AgI18n.t('import.visibility.accept'),
    });
    if (!accepted) return;
  }
  try {
    const input = await invoke('parse_connect_url', { url });
    if (input.eadmin) toast(AgI18n.t('views.url-admin-note'), 'info');
    await connectWith(input, btn);
  } catch (e) { toast(friendlyError(e), 'err'); }
}

async function pasteFromClipboard() {
  try {
    const text = await navigator.clipboard.readText();
    const p = text && AgLink.parse(text.trim());
    if (p && !p.error && p.role === 'connect') {
      $('connect-url-hero') && ($('connect-url-hero').value = text.trim());
      $('connect-url') && ($('connect-url').value = text.trim());
      toast(T('clip-ok'), 'ok');
      await importUrl(text, null);
    } else {
      toast(T('clip-none'), 'err');
    }
  } catch (e) {
    toast(T('clip-fail'), 'err');
  }
}

/* ================= Proxy control ================= */
/* Local proxy port: proxy_status is authoritative while running; use locally saved value when stopped (default 57890).
   Port changes go through the proxy card listen-row inline-edit (bindInlineEdit); a change restarts the proxy to take effect. */
let PROXY_ST = { running: false, port: 0 };
let proxyAddrEdit = null;
function proxyPort() {
  if (PROXY_ST.running && PROXY_ST.port) return PROXY_ST.port;
  const p = parseInt(localStorage.getItem('ag_proxy_port') || '57890', 10);
  return p >= 1 && p <= 65535 ? p : 57890;
}
function validPort(v) {
  if (!/^\d+$/.test(v)) return AgI18n.t('views.port-not-number');
  const p = parseInt(v, 10);
  return (p >= 1 && p <= 65535) ? null : AgI18n.t('views.port-invalid-range');
}
async function refreshProxy() {
  try {
    const st = await invoke('proxy_status');
    PROXY_ST = st;
    // sync actual running port as the local baseline (stays aligned with external changes)
    if (st.running && st.port) localStorage.setItem('ag_proxy_port', String(st.port));
    const nodes = await invoke('list_nodes').catch(() => []);
    const degraded = nodes.filter(n => n.status !== 'Connected');
    let mode, text;
    if (nodes.length && degraded.length) {
      mode = 'warn';
      text = T('st-degraded') + ' ' + T('common.paren', { n: degraded.length });
    } else if (st.running) {
      mode = 'on';
      text = T('proxy-running') + ' 127.0.0.1:' + st.port;
    } else {
      mode = 'off';
      text = T('proxy-stopped');
    }
    Island.setStatus(mode, text, degraded);
    // sidebar footer: rates only (status text removed — Dynamic Island is the primary status surface)
    // dashboard proxy card: switch state / status badge / listen address (inline-edit does its own change detection)
    if ($('d-proxy').checked !== st.running) $('d-proxy').checked = st.running;
    setHtml('d-proxy-badge', st.running ? '<span class="badge b-ok">' + AgI18n.t('common.running') + '</span>' : '<span class="badge b-gray">' + AgI18n.t('views.not-started') + '</span>');
    if (proxyAddrEdit) proxyAddrEdit.refresh();
    const hint = st.running
      ? (CUR_PROXY_MODE === 'system'
        ? AgI18n.t('views.hint-sysproxy', { addr: '127.0.0.1:' + st.port })
        : AgI18n.t('views.hint-local-run', { addr: '127.0.0.1:' + st.port }))
      : AgI18n.t('views.hint-proxy-off');
    if ($('proxy-hint').textContent !== hint) $('proxy-hint').textContent = hint;
  } catch (e) {}
}
async function toggleProxy(e) {
  const on = e.target.checked;
  try {
    if (on) {
      const actual = await invoke('start_proxy', { port: proxyPort() });
      toast(T('proxy-on') + ' 127.0.0.1:' + actual, 'ok');
    } else {
      await invoke('stop_proxy');
      toast(T('proxy-off'), 'ok');
    }
    refreshProxy();
  } catch (err) {
    e.target.checked = !on;
    toast(friendlyError(err), 'err');
  }
}

/* ================= Dashboard: fan-in card (connected / saved overview + traffic trend) ================= */
// fan-in traffic rate series (accumulate one point per list_nodes poll; counters are per-session, reset to a new baseline on reconnect)
let _tfLast = null, _tfSeries = [];
function trackFaninTraffic(nodes) {
  const up = nodes.reduce((s, n) => s + (n.bytes_up || 0), 0);
  const down = nodes.reduce((s, n) => s + (n.bytes_down || 0), 0);
  const total = up + down;
  if (_tfLast !== null) {
    let delta = total - _tfLast;
    // session reconnect resets the counters: the new total is a fresh baseline, not traffic
    if (delta < 0) delta = 0;
    _tfSeries.push(delta);
    if (_tfSeries.length > 90) _tfSeries.shift();
  }
  _tfLast = total;
  window._tfTotals = { up, down };
}
function updateDashFanin() {
  const nodes = window._nodes || [];
  const saved = (window._credsRaw || []).length;
  const conn = nodes.filter(n => n.status === 'Connected').length;
  const trying = nodes.length - conn;
  setText('d-fanin-val', AgI18n.t('views.fanin-conn', { n: conn }));
  // saved-but-idle middle state (web.md §1.2): guide the next step instead of a hollow-looking card
  const idleHint = (conn === 0 && saved > 0) ? ' · ' + AgI18n.t('views.fanin-idle-hint') : '';
  setText('d-fanin-sub', AgI18n.t('views.fanin-saved', { n: saved }) + (trying ? AgI18n.t('views.fanin-trying', { n: trying }) : '') + idleHint);
  const tf = window._tfTotals || { up: 0, down: 0 };
  const has = tf.up + tf.down > 0;
  const tfEl = $('d-fanin-tf'), sparkEl = $('d-fanin-spark');
  if (tfEl) {
    tfEl.style.display = has ? '' : 'none';
    if (has) setText('d-fanin-tf', '↑ ' + fmtBytes(tf.up) + ' · ↓ ' + fmtBytes(tf.down));
  }
  if (sparkEl) {
    sparkEl.style.display = has ? '' : 'none';
    if (has) AgChart.sparkline(sparkEl, _tfSeries.length > 1 ? _tfSeries : [0, 0]);
  }
  /* Saved-node mini rows (≤3): status dot + name + addr + one-click connect (click delegation in app.js dash-grid handler) */
  const mini = $('d-fanin-mini');
  if (mini) {
    const statusMap = window._nodeStatus || {};
    const rows = (window._credsRaw || []).slice(0, 3);
    const msig = JSON.stringify([rows, statusMap, AgI18n.lang]);
    if (mini.dataset.sig !== msig) {
      mini.dataset.sig = msig;
      mini.style.display = rows.length ? '' : 'none';
      mini.innerHTML = rows.map(([key, c]) => {
        const st = statusMap[key];
        const on = st === 'Connected';
        const busy = st === 'Connecting' || st === 'Reconnecting' || st === 'PendingApproval';
        const name = (c.name && c.name.trim()) || (key.includes('@') ? key.slice(0, key.indexOf('@')) : key);
        const btn = on || st === 'Blocked' ? '' : '<button class="ghost small" data-mini-conn="' + esc(key) + '">' + AgI18n.t('views.connect') + '</button>';
        return '<div class="mini-row"><span class="mr-dot' + (on ? ' on' : (busy ? ' warn' : '')) + '"></span>' +
          '<span class="mr-name">' + esc(name) + '</span><span class="mr-addr">' + esc(c.addr) + '</span>' + btn + '</div>';
      }).join('') +
      // overflow tail: more than 3 saved fan-ins get a "{n} total" row that jumps to the fan-in page
      ((window._credsRaw || []).length > 3
        ? '<div class="mini-row" data-goto="nodes" style="cursor:pointer"><span class="mr-dot"></span><span class="mr-name dim">' + AgI18n.t('views.faninMore', { n: (window._credsRaw || []).length }) + '</span></div>'
        : '');
    }
  }
}

/* ================= Fan-in list (saved fan-ins as main body + unsaved active connections; connect/disconnect/export/delete) ================= */
async function refreshCreds() {
  try {
    const creds = await invoke('list_credentials');
    window._credsRaw = creds;
    window._creds = Object.fromEntries(creds);
    renderCredList(creds, window._nodeStatus || {});
    // web.md §3.2: reuse the cached nodes — refreshNodes already re-fetches on its own cadence
    updateOnboarding(window._nodes || []);
    updateDashFanin();
  } catch (e) {}
}
function renderCredList(creds, statusMap) {
  const list = $('creds-list');
  if (list.querySelector('.cred-rename-input')) return; // a rename edit is in flight — don't rebuild under it
  const ae = document.activeElement;
  if (ae && ae.classList && ae.classList.contains('pnote-input') && list.contains(ae)) return; // typing an appeal note — don't rebuild under it
  const f = FILTERS.creds;
  const nodeMap = Object.fromEntries((window._nodes || []).map(n => [n.node_id, n]));
  // unsaved active connections (manual connect without saving credential): appended after saved fan-ins, disconnect/manage only
  const savedKeys = new Set(creds.map(([k]) => k));
  const unsaved = (window._nodes || []).filter(n => !savedKeys.has(n.node_id));
  const live = (st) => st === 'Connected' || st === 'Connecting' || st === 'Reconnecting' || st === 'PendingApproval';
  const unreadNodes = window._notifyUnreadNodes || new Set();
  const match = (name, label, addr, st) => !f ||
    name.toLowerCase().includes(f) || (label || '').toLowerCase().includes(f) ||
    addr.toLowerCase().includes(f) || (st ? statusText(st) : AgI18n.t('common.disconnected')).includes(f);
  const shownCreds = creds.filter(([key, c]) =>
    match(key.includes('@') ? key.slice(0, key.indexOf('@')) : key, c.label, c.addr, statusMap[key])
    || (c.name && match(c.name, c.label, c.addr, statusMap[key])));
  const shownUnsaved = unsaved.filter(n => match(n.node_name, n.label, n.issuer_node_name, n.addr, n.status));
  // web.md §3.2: signature guard — identical inputs skip the full DOM rebuild (10s poll stability)
  const sig = JSON.stringify([creds, statusMap, f, window._nodes || [], [...unreadNodes], window._pnoteCount || {}]);
  if (list.dataset.sig === sig) return;
  list.dataset.sig = sig;
  if (!shownCreds.length && !shownUnsaved.length) {
    list.innerHTML = '<div class="empty">' + (f ? AgI18n.t('views.no-match') : T('no-creds')) + '</div>';
    return;
  }
  list.innerHTML = shownCreds.map(([key, c]) => {
    const st = statusMap[key];
    const n = nodeMap[key];
    const badge = st ? statusBadgeHtml(st) : '<span class="badge b-gray">' + AgI18n.t('common.disconnected') + '</span>';
    // M4-T2: Blocked is terminal — the action is re-import guidance, not a doomed reconnect
    const mainBtn = st === 'Blocked'
      ? '<button class="small" data-act="reimport" data-key="' + esc(key) + '">' + AgI18n.t('views.reimport') + '</button>'
      : st === 'Connected'
        ? '<button class="ghost small" data-act="disconnect" data-key="' + esc(key) + '">' + AgI18n.t('views.disconnect') + '</button>'
        : '<button class="small" data-act="reconnect" data-key="' + esc(key) + '">' + AgI18n.t(st ? 'views.reconnect' : 'views.connect') + '</button>';
    const epName = (c.name && c.name.trim()) || (key.includes('@') ? key.slice(0, key.indexOf('@')) : key);
    // E2E tier badge: 专线 (whole machine) vs 分流 (rule delivery); the entrust word (en_xxx)
    // marks the E2E tier. split silently degrades to catch-all when the config pull failed —
    // surface that honestly
    const splitFallback = !!(c.en && c.emode === 'split' && st === 'Connected'
      && n && (n.rules || []).some(r => r.value === '0.0.0.0/0'));
    const tierBadge = c.en
      ? ' <span class="badge ' + (splitFallback ? 'b-warn' : (c.emode === 'split' ? 'b-info' : 'b-off')) + '"' +
        (splitFallback ? ' title="' + AgI18n.t('views.tier-split-fallback-hint') + '"' : '') + '>' +
        AgI18n.t(splitFallback ? 'views.tier-split-fallback' : (c.emode === 'split' ? 'views.tier-split' : 'views.tier-dedicated')) + '</span>'
      : '';
    // failover: the live entry shown when connected
    const addrLine = (n && n.current_entry && st === 'Connected')
      ? esc(n.current_entry) + ' · <span class="dim">' + AgI18n.t('views.delegated-set', { n: (c.entries || []).length || 1 }) + '</span>'
      : esc(c.addr);
    // M4-T2: terminal block — mapped reason + the issuer's one-time notice (their own words)
    const blockLine = (st === 'Blocked' && n)
      ? '<div class="addr"><span class="badge b-off">' + esc(reasonText(n.block_reason)) + '</span>' +
        (n.block_message ? ' <span class="dim">' + esc(n.block_message) + '</span>' : '') + '</div>'
      : '';
    // M4-T2: unread inbox notice on an idle/down card (kick/notice arrived while not watching)
    const unreadLine = (!live(st) && st !== 'Blocked' && unreadNodes.has(key))
      ? '<div class="addr"><span class="badge b-info">' + AgI18n.t('views.unread-notice') + '</span></div>'
      : '';
    // M4-T3: pending certification — amber state + appeal composer (≤3 notes per session, local count)
    let pendLine = '';
    if (st === 'PendingApproval') {
      const cnt = ((window._pnoteCount || {})[key]) || 0;
      const capped = cnt >= 3;
      pendLine = '<div class="addr dim">' + AgI18n.t('views.pending-tip') + '</div>' +
        '<div class="pnote"><input class="pnote-input" maxlength="512" data-note-input="' + esc(key) + '"' +
        (capped ? ' disabled placeholder="' + esc(AgI18n.t('views.note-limit')) + '"' : ' placeholder="' + esc(AgI18n.t('views.note-ph')) + '"') + '>' +
        '<span class="pnote-count">' + cnt + '/3</span>' +
        '<button class="ghost small" data-act="send-note" data-key="' + esc(key) + '"' + (capped ? ' disabled' : '') + '>' + AgI18n.t('views.note-send') + '</button></div>';
    }
    return '<div class="node-card' + (live(st) ? '' : ' down') + '"><div class="info">' +
      '<div class="name"><span class="cred-name" data-rename="' + esc(key) + '" title="' + AgI18n.t('fanin.rename') + '">' + esc(epName) + '</span> ' + badge + tierBadge + '</div>' +
      '<div class="addr mono">' + addrLine + (c.insecure ? ' · <span class="badge b-warn">insecure</span>' : '') + '</div>' +
      (n && n.issuer_node_name ? '<div class="addr dim">' + AgI18n.t('views.srcLabel') + '：' + esc(n.issuer_node_name) + '</div>' : '') +
      blockLine + unreadLine + pendLine +
      '</div><div class="card-actions">' +
      '<button class="ghost small icon-btn" title="' + AgI18n.t('common.edit') + '" data-act="edit" data-key="' + esc(key) + '">' + AgIcon('pencil', 13) + '</button>' +
      (n && n.admin_console && st === 'Connected' && !HTTP_MODE
        ? '<button class="ghost small" data-act="console" data-id="' + esc(key) + '">' + AgIcon('monitor', 13) + ' ' + AgI18n.t('views.manage') + '</button>' : '') +
      mainBtn +
      '<button class="ghost small" data-act="share" data-key="' + esc(key) + '" title="' + AgI18n.t('views.share-title') + '">' + AgIcon('share-2', 13) + '</button>' +
      '<button class="danger small icon-btn" title="' + AgI18n.t('views.del-fanin-title') + '" data-act="delcred" data-key="' + esc(key) + '">' + AgIcon('trash-2', 13) + '</button>' +
      '</div></div>';
  }).join('') + shownUnsaved.map(n =>
    '<div class="node-card' + (live(n.status) ? '' : ' down') + '" data-node-id="' + esc(n.node_id) + '"><div class="info">' +
    '<div class="name">' + esc(n.node_name) + ' ' + statusBadgeHtml(n.status) + (n.issuer_node_name ? ' <span class="badge b-gray" title="' + AgI18n.t('views.srcHint', { name: n.issuer_node_name }) + '">' + esc(n.issuer_node_name) + '</span>' : '') + ' <span class="badge b-gray">' + AgI18n.t('views.unsaved') + '</span></div>' +
    '<div class="addr mono">' + esc(n.addr) + '</div>' +
    (n.issuer_node_name ? '<div class="addr dim">' + AgI18n.t('views.srcLabel') + '：' + esc(n.issuer_node_name) + '</div>' : '') +
    (n.status === 'Blocked'
      ? '<div class="addr"><span class="badge b-off">' + esc(reasonText(n.block_reason)) + '</span>' +
        (n.block_message ? ' <span class="dim">' + esc(n.block_message) + '</span>' : '') + '</div>'
      : '') +
    (n.status === 'PendingApproval' ? '<div class="addr dim">' + AgI18n.t('views.pending-tip') + '</div>' : '') +
    '</div><div class="card-actions">' +
    (n.admin_console && n.status === 'Connected' && !HTTP_MODE
      ? '<button class="ghost small" data-act="console" data-id="' + esc(n.node_id) + '">' + AgIcon('monitor', 13) + ' ' + AgI18n.t('views.manage') + '</button>' : '') +
    '<button class="danger small" data-act="disconnect" data-key="' + esc(n.node_id) + '">' + AgI18n.t('views.disconnect') + '</button></div></div>'
  ).join('');
}
async function reconnectSaved(key, btn) {
  const c = (window._creds || {})[key];
  if (!c) return;
  await connectWith({
    addr: c.addr, label: c.label, token: c.token,
    insecure: c.insecure, pinned_fingerprint: c.pinned_fingerprint || null,
    manage_hosts: false, save_credential: true,
    // keep the failover set and E2E fields on reconnect
    entries: c.entries || [], entry_fps: c.entry_fps || [], en: c.en || null, emode: c.emode || null, eadmin: !!c.eadmin,
    // M4: naming triplet (myname) + accepted visibility clause ride the reconnect too
    myname: c.myname || null, visibility: c.visibility || null,
  }, btn || null);
}
async function exportCred(key) {
  // credential export contains plaintext password: Web remote panel requires a second confirmation
  // (DOM modal — window.confirm is unreliable in embedded WebViews and must never gate secrets)
  if (HTTP_MODE && !(await askConfirm({ title: AgI18n.t('views.export-title'), desc: AgI18n.t('views.export-confirm'), icon: 'share-2', danger: true }))) return;
  try {
    const url = await invoke('export_credential', { key });
    await navigator.clipboard.writeText(url);
    toast(AgI18n.t('views.export-done'), 'ok');
  } catch (e) { toast(friendlyError(e), 'err'); }
}
async function deleteCred(key, btn) {
  if (btn.dataset.confirm === '1') {
    try {
      await invoke('delete_credential', { key });
      toast(AgI18n.t('views.fanin-deleted'), 'ok');
      refreshCreds();
    } catch (e) { toast(friendlyError(e), 'err'); }
    return;
  }
  btn.dataset.confirm = '1';
  const old = btn.innerHTML;
  btn.innerHTML = '<span style="font-size:11px">' + AgI18n.t('common.confirm') + '</span>';
  setTimeout(() => { if (btn.isConnected) { btn.dataset.confirm = ''; btn.innerHTML = old; } }, 2500);
}

/* Fan-in rename (user alias): click the name/pencil → inline input; Enter saves, Esc/blur cancels;
   empty or equal-to-derived clears the alias back to the node-id-derived name */
function startCredRename(span) {
  const list = $('creds-list');
  if (list.querySelector('.cred-rename-input')) return; // one edit at a time
  const key = span.dataset.rename;
  const c = (window._creds || {})[key];
  if (!c) return;
  const derived = key.includes('@') ? key.slice(0, key.indexOf('@')) : key;
  const input = document.createElement('input');
  input.className = 'cred-rename-input';
  input.value = (c.name && c.name.trim()) || derived;
  input.maxLength = 32;
  input.spellcheck = false;
  span.replaceWith(input);
  input.focus();
  input.select();
  let done = false;
  const cancel = () => { if (!done) { done = true; refreshCreds(); } };
  const save = async () => {
    if (done) return;
    done = true;
    const name = input.value.trim();
    try {
      await invoke('rename_credential', { key, name: name && name !== derived ? name : null });
      toast(AgI18n.t('fanin.renamed'), 'ok');
    } catch (err) { toast(friendlyError(err), 'err'); }
    refreshCreds();
  };
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); save(); }
    if (e.key === 'Escape') { e.preventDefault(); cancel(); }
  });
  input.addEventListener('blur', cancel);
}

/* ================= Notification center (node.md M4-T1: titlebar bell + sidebar 通知 page) =================
   Data: list_notifications → {items, unread} (persistent local inbox; engine pushes session
   notices / rejections / approval states). New entries also arrive instantly via the Tauri
   `ag-notify` broadcast (notify_watch); the 10s tick is the polling fallback. */
let NOTIFY_SIG = null;
let NOTIFY_ITEMS = [];

function fmtNotifyTs(ts) {
  return String(ts || '').replace('T', ' ').replace(/(\.\d+)?(Z|\+00:00)$/, '');
}

async function refreshNotify(force) {
  let data;
  try { data = await invoke('list_notifications'); } catch (e) { return; }
  const unread = data.unread || 0;
  const items = data.items || [];
  // unread badges (titlebar bell + sidebar item) — cheap change-detected writes
  const txt = unread > 99 ? '99+' : String(unread);
  ['notify-badge', 'nav-notify-badge'].forEach(id => {
    const el = $(id);
    if (!el) return;
    el.hidden = unread === 0;
    if (el.textContent !== txt) el.textContent = txt;
  });
  // unread node-bound notices also surface on disconnected fan-in cards (M4-T2)
  window._notifyUnreadNodes = new Set(items.filter(n => !n.read && n.node_id).map(n => n.node_id));
  const sig = JSON.stringify([items, unread]);
  if (!force && sig === NOTIFY_SIG) return;
  NOTIFY_SIG = sig;
  NOTIFY_ITEMS = items;
  renderNotifyList(items);
  renderCredList(window._credsRaw || [], window._nodeStatus || {});
}

function renderNotifyList(items) {
  const list = $('notify-list');
  if (!list) return;
  if (!items.length) {
    list.innerHTML = '<div class="empty">' + AgI18n.t('notify.empty') + '</div>';
    return;
  }
  list.innerHTML = items.map(n => {
    const ic = n.kind === 'approval' ? 'badge-check' : n.kind === 'session' ? 'triangle-alert' : 'info';
    const kindLabel = AgI18n.t(n.kind === 'approval' ? 'notify.kindApproval' : n.kind === 'session' ? 'notify.kindSession' : 'notify.kindSystem');
    const rc = n.reason_code
      ? '<span class="badge ' + (n.kind === 'session' ? 'b-off' : 'b-warn') + '">' + esc(reasonText(n.reason_code)) + '</span>'
      : '';
    return '<div class="ntf' + (n.read ? '' : ' unread') + '"' + (n.node_id ? ' data-nid="' + esc(n.node_id) + '"' : '') + ' data-id="' + esc(n.id) + '">' +
      '<span class="ntf-ic">' + AgIcon(ic, 15) + '</span>' +
      '<div class="ntf-main">' +
      '<div class="ntf-title">' + esc(n.title) + ' ' + rc + '</div>' +
      (n.body && n.body !== n.title && n.body !== n.reason_code ? '<div class="ntf-body">' + esc(n.body) + '</div>' : '') +
      '<div class="ntf-meta dim">' + esc(kindLabel) + ' · ' + esc(fmtNotifyTs(n.ts)) + '</div>' +
      '</div></div>';
  }).join('');
}

/* Notify view lifecycle: the "活动" (event center) tab moved here from logs; its pulse
   'logev' is mounted here and activated only when the tab is current + the view is visible. */
const NotifyView = {
  tab: 'inbox',
  enter() {
    if (this.tab === 'ev') AgPulse.setActive('logev', true);
  },
  switchTab(key) {
    if (this.tab === 'ev') AgPulse.setActive('logev', false);
    this.tab = key;
    if (key === 'ev') AgPulse.setActive('logev', true);
  },
};

function initNotify() {
  // Event center pulse (moved from logs view)
  AgPulse.mount($('pulse-logev'), { key: 'logev', defMs: 10000, options: [5000, 10000, 30000], onTick: () => LogsView.pollEvents() });
  agTabsBind($('nv-tabs'), (key) => NotifyView.switchTab(key));
  const bell = $('btn-notify'); if (bell) bell.onclick = () => switchView('notify');
  $('btn-notify-read-all').onclick = async () => {
    try { await invoke('notifications_read_all'); } catch (e) { toast(friendlyError(e), 'err'); }
    refreshNotify(true);
  };
  $('btn-notify-clear').onclick = async () => {
    const ok = await askConfirm({ title: AgI18n.t('common.clear'), desc: AgI18n.t('notify.clearConfirm'), icon: 'trash-2', danger: true, okText: AgI18n.t('common.clear') });
    if (!ok) return;
    try { await invoke('clear_notifications'); } catch (e) { toast(friendlyError(e), 'err'); }
    refreshNotify(true);
  };
  // Clicking a node-bound entry: mark that one notification read, jump to the fan-in page and
  // highlight the matching card (saved cards key = node_id; unsaved carry data-node-id)
  $('notify-list').addEventListener('click', async (e) => {
    const row = e.target.closest('.ntf[data-nid]');
    if (!row) return;
    if (!row.classList.contains('read')) {
      try { await invoke('notification_read', { id: row.dataset.id }); } catch (err) {}
      refreshNotify(true);
    }
    switchView('nodes');
    setTimeout(() => {
      const card = document.querySelector('#creds-list .node-card[data-node-id="' + CSS.escape(row.dataset.nid) + '"]')
        || (document.querySelector('.cred-name[data-rename="' + CSS.escape(row.dataset.nid) + '"]') || {}).closest?.('.node-card');
      if (!card) return;
      card.scrollIntoView({ behavior: 'smooth', block: 'center' });
      card.style.outline = '2px solid var(--accent)';
      card.style.outlineOffset = '2px';
      setTimeout(() => { card.style.outline = ''; card.style.outlineOffset = ''; }, 2000);
    }, 80);
  });
}

/* M4-T2: Blocked card guidance — delete the dead credential, then land in the import wizard */
async function reimportCred(key) {
  const ok = await askConfirm({
    title: AgI18n.t('views.reimport-title'),
    desc: AgI18n.t('views.reimport-desc'),
    icon: 'refresh-cw',
    danger: true,
    okText: AgI18n.t('views.reimport'),
  });
  if (!ok) return;
  try { await invoke('delete_credential', { key }); } catch (e) { toast(friendlyError(e), 'err'); return; }
  refreshCreds();
  refreshNotify(true);
  openUniversalImport();
}

/* M4-T3: appeal note to the issuer over the pending session (≤3 per session, locally counted) */
async function sendPendingNote(key, btn) {
  window._pnoteCount = window._pnoteCount || {};
  const cnt = window._pnoteCount[key] || 0;
  if (cnt >= 3) { toast(AgI18n.t('views.note-limit'), 'err'); return; }
  const input = $('creds-list').querySelector('input[data-note-input="' + CSS.escape(key) + '"]');
  const body = input ? input.value.trim() : '';
  if (!body) return;
  btn.disabled = true;
  try {
    await invoke('send_pending_note', { nodeId: key, body });
    window._pnoteCount[key] = cnt + 1;
    toast(AgI18n.t('views.note-sent'), 'ok');
    renderCredList(window._credsRaw || [], window._nodeStatus || {});
  } catch (e) {
    toast(friendlyError(e), 'err');
    btn.disabled = false;
  }
}

/* M4-T6: fan-in credential edit modal — 目标名称 (local alias) | 我的名称 (uploaded myname);
   remark semantics merge into the name field (no separate column). */
let CRED_EDIT_KEY = null;
function openCredEdit(key) {
  const c = (window._creds || {})[key];
  if (!c) return;
  CRED_EDIT_KEY = key;
  const derived = key.includes('@') ? key.slice(0, key.indexOf('@')) : key;
  $('cedit-name').value = (c.name && c.name.trim()) || derived;
  $('cedit-name').dataset.derived = derived;
  $('cedit-myname').value = c.myname || '';
  $('cedit-err').textContent = '';
  $('cred-edit-modal').style.display = 'flex';
  $('cedit-name').focus();
}
async function credEditSave() {
  const key = CRED_EDIT_KEY;
  if (!key) return;
  const name = $('cedit-name').value.trim();
  const myname = $('cedit-myname').value.trim();
  const btn = $('cedit-ok');
  btn.disabled = true;
  try {
    // empty or equal-to-derived clears the local alias (same semantics as inline rename)
    await invoke('rename_credential', { key, name: name && name !== $('cedit-name').dataset.derived ? name : null });
    await invoke('set_credential_myname', { key, myname: myname || null });
    $('cred-edit-modal').style.display = 'none';
    CRED_EDIT_KEY = null;
    toast(AgI18n.t('views.cred-saved'), 'ok');
    refreshCreds();
  } catch (e) {
    $('cedit-err').textContent = friendlyError(e);
  } finally {
    btn.disabled = false;
  }
}


/* ================= Fan-out connections (embedded node DB managed, changes hot-applied) ================= */
let FO_EDIT_ID = null;
let FO_ITEMS = [];

function foBadge(c) {
  const guard = c.guarded ? ' <span class="badge b-warn">' + AgI18n.t('guard.badge') + '</span>' : '';
  if (!c.enabled) return '<span class="badge b-off">' + AgI18n.t('common.disabled') + '</span>' + guard;
  const st = c.state;
  if (st === 'connected') return '<span class="badge b-ok">' + AgI18n.t('common.connected') + '</span>' + guard;
  if (st === 'connecting') return '<span class="badge b-warn"><span class="pulse"></span>' + AgI18n.t('views.st-connecting') + '</span>' + guard;
  if (st === 'reconnecting') return '<span class="badge b-warn"><span class="pulse"></span>' + AgI18n.t('views.st-reconnecting') + '</span>' + guard;
  if (st === 'disconnected') return '<span class="badge b-off">' + AgI18n.t('views.st-down') + '</span>' + guard;
  return '<span class="badge b-gray">' + AgI18n.t('views.not-started') + '</span>' + guard;
}

/* Deep Guard linkage (trust profile G2): pinning mandatory (save rejected without a
   fingerprint), insecure checkbox disabled, pushed groups cleared by default and each
   later opt-in needs an explicit confirm (DOM modal, never window.confirm). */
function foSyncGuard() {
  const on = $('fo-guard').checked;
  const ins = $('fo-insecure');
  ins.disabled = on;
  if (on) ins.checked = false;
}

/** ACL group set + push-group checkboxes: fetch local embedded node group list (keep current selections; failure doesn't block the list) */
async function foLoadGroups() {
  try {
    const groups = await invoke('list_embedded_groups');
    // Peer-ACL convergence: multi-group checkbox set (union), E2E groups disabled (delegation-only)
    const aclList = $('fo-acl-list');
    if (aclList) {
      const checked = FO_ACL_PENDING || new Set([...aclList.querySelectorAll('input:checked')].map(c => c.value));
      FO_ACL_PENDING = null;
      aclList.innerHTML = groups.length
        ? groups.map(g => '<label class="chk"><input type="checkbox" class="fo-acl" value="' + esc(g.id) + '"' + (checked.has(g.id) ? ' checked' : '') + (g.e2e_required ? ' disabled' : '') + '> <span>' + esc(g.name) + '</span>' + (g.adopted_node ? ' ' + srcBadge(g.adopted_node) : '') + (g.e2e_required ? ' <span class="badge b-warn">E2E</span>' : '') + '</label>').join('')
        : '<div class="hint">' + AgI18n.t('views.fo-no-group') + '</div>';
    }
    // Policy upload (federation P1): checkbox list, selections kept across re-renders
    const pushList = $('fo-push-list');
    if (pushList) {
      const checked = FO_PUSH_PENDING || new Set([...pushList.querySelectorAll('input:checked')].map(c => c.value));
      FO_PUSH_PENDING = null;
      pushList.innerHTML = groups.length
        ? groups.map(g => '<label class="chk"><input type="checkbox" class="fo-push" value="' + esc(g.id) + '"' + (checked.has(g.id) ? ' checked' : '') + '> <span>' + esc(g.name) + '</span>' + (g.adopted_node ? ' ' + srcBadge(g.adopted_node) : '') + '</label>').join('')
        : '<div class="hint">' + AgI18n.t('views.fo-push-empty') + '</div>';
    }
  } catch (e) { /* group list load failure doesn't block the fan-out list */ }
}

async function refreshUpstreams() {
  foLoadGroups();
  try {
    FO_ITEMS = await invoke('list_server_connectors');
  } catch (e) { $('fo-list').innerHTML = '<div class="empty">' + AgI18n.t('views.load-failed') + '</div>'; return false; }
  const sig = JSON.stringify(FO_ITEMS);
  const list = $('fo-list');
  if (list.dataset.sig === sig) return true; // signature guard: no repaint when unchanged
  list.dataset.sig = sig;
  if (!FO_ITEMS.length) {
    list.innerHTML = '<div class="empty">' + AgI18n.t('views.fo-empty') + '</div>';
    return true;
  }
  list.innerHTML = FO_ITEMS.map(c =>
    '<div class="node-card"><div class="info">' +
    '<div class="name">' + esc(c.name || c.upstream_addr) + ' ' + foBadge(c) + '</div>' +
    // live upstream identity (self-declared node name + TLS verification tier mark)
    (c.peer_node ? '<div class="addr mono">' + nodeBadge(c.peer_node, connAuthTier(c)) + '</div>' : '') +
    '<div class="addr mono">' + esc(c.upstream_addr) + ' · ' + esc(c.token_prefix) + ' · SNI ' + esc(c.sni_hostname) +
    (c.pinned_fingerprint ? ' · <span class="badge b-ok">pinned</span>' : '') +
    (c.insecure ? ' · <span class="badge b-warn">insecure</span>' : '') + '</div>' +
    '<div class="addr">' + ((c.groups || []).length
      ? c.groups.map(g => grpChip({ name: g.name, adopted: g.adopted_node })).join(' ')
      : '<span class="dim">' + AgI18n.t('views.fo-group-none') + '</span>') + '</div>' +
    // effective advertise (manual ∪ pushed-group rules) — the set the upstream route table carries
    ((c.effective_advertise || []).length
      ? '<div class="addr mono" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(c.effective_advertise.join(', ')) + '">' + AgI18n.t('views.fo-adv') + ' ' + esc(c.effective_advertise.join(' · ')) + '</div>'
      : '') +
    '</div><div class="card-actions">' +
    '<button class="ghost small" data-fo-edit="' + esc(c.id) + '">' + AgI18n.t('common.edit') + '</button>' +
    '<button class="danger small" data-fo-del="' + esc(c.id) + '">' + AgI18n.t('common.delete') + '</button>' +
    '</div></div>'
  ).join('');
  return true;
}

/* ---- New/edit fan-out modal (fields aligned with admin console 「新建扇出」; advertise one per line, comma-joined on save) ---- */
let FO_ACL_PENDING = null; // Set<groupId> applied to the ACL group-set list on its next render (null = keep selections)
let FO_PUSH_PENDING = null; // Set<groupId> applied to the push-group list on its next render (null = keep selections)
function foOpenModal(c) {
  FO_EDIT_ID = c ? c.id : null;
  $('fo-modal-title').textContent = c ? AgI18n.t('views.fo-title-edit') : AgI18n.t('views.fo-title-new');
  $('fo-ok').textContent = c ? AgI18n.t('common.save') : AgI18n.t('views.create');
  $('fo-token-hint').style.display = c ? '' : 'none';
  $('fo-paste').value = '';
  $('fo-paste-err').style.display = 'none';
  $('fo-name').value = c ? c.name : '';
  $('fo-myname').value = c ? (c.my_name || '') : '';
  $('fo-addr').value = c ? c.upstream_addr : '';
  $('fo-token').value = '';
  $('fo-sni').value = c ? c.sni_hostname : 'cdn.cloudflare.com';
  $('fo-fp').value = c ? (c.pinned_fingerprint || '') : '';
  $('fo-insecure').checked = c ? !!c.insecure : false;
  $('fo-guard').checked = c ? !!c.guarded : false;
  foSyncGuard();
  $('fo-advertise').value = c ? (c.advertise || '').split(',').filter(Boolean).join('\n') : '';
  // Peer-ACL convergence + policy upload selections (applied by foLoadGroups' list renders)
  FO_ACL_PENDING = new Set(c ? (c.group_id || '').split(',').filter(Boolean) : []);
  FO_PUSH_PENDING = new Set(c ? (c.push_groups || '').split(',').filter(Boolean) : []);
  foLoadGroups();
  $('fo-remark').value = c ? (c.remark || '') : '';
  $('fo-err').textContent = '';
  $('fo-modal').style.display = 'flex';
  $(c ? 'fo-name' : 'fo-addr').focus();
}
function foCloseModal() { $('fo-modal').style.display = 'none'; FO_EDIT_ID = null; }

function initUpstreams() {
  agTabsBind($('fo-tabs'), (key) => { if (key === 'issue') refreshDelegation(); });
  $('btn-fo-add').onclick = () => foOpenModal(null);
  $('fo-cancel').onclick = foCloseModal;
  // Paste-to-import (federation P1): the shared AgLink parser fills all technical fields from an
  // anet://fanout link; on failure the form stays manual with an inline error line.
  const foFill = () => {
    const raw = $('fo-paste').value.trim();
    if (!raw) return;
    const p = AgLink.parse(raw);
    const err = $('fo-paste-err');
    if (p.error || p.role !== 'fanout') {
      err.textContent = AgI18n.t('aglink.' + (p.role && p.role !== 'fanout' ? 'bad_role' : p.error));
      err.style.display = 'block';
      return;
    }
    err.style.display = 'none';
    foFillFields(p);
    $('fo-paste').value = '';
    toast(AgI18n.t('fanout.pasted'), 'ok');
  };
  // G2: enabling the guard clears pushed-group selections (upload becomes an explicit opt-in);
  // checking one while guarded asks for an explicit confirm
  $('fo-guard').addEventListener('change', () => {
    foSyncGuard();
    if ($('fo-guard').checked) document.querySelectorAll('.fo-push:checked').forEach(cb => { cb.checked = false; });
  });
  $('fo-push-list').addEventListener('change', async (e) => {
    const cb = e.target.closest('input.fo-push');
    if (!cb || !cb.checked || !$('fo-guard').checked || cb.dataset.guardOk === '1') return;
    cb.checked = false;
    const ok = await askConfirm({ icon: 'shield-alert', title: AgI18n.t('guard.label'), desc: AgI18n.t('guard.g2PushConfirm') });
    if (ok) cb.checked = true; // programmatic check fires no change event — no re-confirm loop
  });
  $('fo-paste').addEventListener('paste', () => setTimeout(foFill, 0));
  $('fo-paste').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); foFill(); } });
  $('fo-ok').onclick = async () => {
    const name = $('fo-name').value.trim();
    const addr = $('fo-addr').value.trim();
    const token = $('fo-token').value.trim();
    const sni = $('fo-sni').value.trim() || 'cdn.cloudflare.com';
    const fp = $('fo-fp').value.trim();
    const insecure = $('fo-insecure').checked;
    const groupId = [...document.querySelectorAll('.fo-acl:checked')].map(c => c.value).join(',') || null;
    const pushGroups = [...document.querySelectorAll('.fo-push:checked')].map(c => c.value);
    const advertise = $('fo-advertise').value.split('\n').map(s => s.trim()).filter(Boolean).join(',');
    const remark = $('fo-remark').value.trim();
    const myName = $('fo-myname').value.trim();
    if (!addr) { $('fo-err').textContent = AgI18n.t('views.fo-addr-required'); return; }
    if (!FO_EDIT_ID && !token) { $('fo-err').textContent = AgI18n.t('views.fo-token-required'); return; }
    const guarded = $('fo-guard').checked;
    if (guarded && !fp) { $('fo-err').textContent = AgI18n.t('guard.g2NeedPin'); return; }
    if (guarded && insecure) { $('fo-err').textContent = AgI18n.t('guard.g2NoInsecure'); return; }
    $('fo-err').textContent = '';
    try {
      if (FO_EDIT_ID) {
        await invoke('update_server_connector', { id: FO_EDIT_ID, name, upstreamAddr: addr, token, sniHostname: sni, insecure, pinnedFingerprint: fp, groupId, pushGroups, advertise, remark, myName, guarded });
        toast(AgI18n.t('views.fo-updated'), 'ok');
      } else {
        await invoke('add_server_connector', { name, upstreamAddr: addr, token, sniHostname: sni, insecure, pinnedFingerprint: fp, groupId, pushGroups, advertise, remark, myName, guarded });
        toast(AgI18n.t('views.fo-added'), 'ok');
      }
      foCloseModal();
      refreshUpstreams();
    } catch (e) { $('fo-err').textContent = friendlyError(e); }
  };
  $('fo-list').addEventListener('click', async (e) => {
    const editBtn = e.target.closest('[data-fo-edit]');
    const delBtn = e.target.closest('[data-fo-del]');
    if (editBtn) {
      const c = FO_ITEMS.find(x => x.id === editBtn.dataset.foEdit);
      if (c) foOpenModal(c);
      return;
    }
    if (delBtn) {
      // two-step confirm (same pattern as fan-in delete / token revoke): connectors are DB-backed
      if (delBtn.dataset.confirm === '1') {
        try {
          await invoke('remove_server_connector', { id: delBtn.dataset.foDel });
          toast(AgI18n.t('views.fo-deleted'), 'ok');
          if (FO_EDIT_ID === delBtn.dataset.foDel) foCloseModal();
          refreshUpstreams();
        } catch (err) { toast(friendlyError(err), 'err'); }
        return;
      }
      delBtn.dataset.confirm = '1';
      const old = delBtn.innerHTML;
      delBtn.innerHTML = '<span style="font-size:11px">' + AgI18n.t('common.confirm') + '</span>';
      setTimeout(() => { if (delBtn.isConnected) { delBtn.dataset.confirm = ''; delBtn.innerHTML = old; } }, 2500);
    }
  });
  initDelegation();
}

/* ================= Unified issuance (签发 tab): delegated tokens via the embedded node admin REST =================
   Four-dimension linkage dialog (entry × trust × route × concurrency), rules enforced in dtSync:
   - entry=direct locks trust=plain and hides the disaster set (direct TLS is already end-to-end);
   - trust=plain forces route=dedicated (the split vocabulary rides the E2E config channel);
   - trust=admin shows the scope select (ro/rules/full);
   - E2E trust narrows the group picker to e2e_required groups (every selected group must be E2E);
   - route=dedicated auto-selects every eligible group and collapses the picker. */
let DT_ITEMS = [];
let DT_GROUPS = []; // embedded node groups (with e2e_required flags)
let DT_STATE = { entry: 'direct', trust: 'plain', route: 'dedicated', conc: 'single', guard: false };
let DT_GROUPS_OPEN = false; // dedicated-route member-list expansion state

function dtBadges(t) {
  const b = [];
  b.push('<span class="badge ' + (t.entry_mode === 'direct' ? 'b-off' : 'b-info') + '">' + AgI18n.t(t.entry_mode === 'direct' ? 'dt.badgeDirect' : 'dt.badgeRelay') + '</span>');
  b.push('<span class="badge b-gray">' + (t.concurrency === 'multi' ? AgI18n.t('dt.badgeMulti', { n: t.max_sessions || 8 }) : AgI18n.t('dt.badgeSingle')) + '</span>');
  b.push('<span class="badge ' + (t.mode === 'split' ? 'b-info' : 'b-off') + '">' + AgI18n.t(t.mode === 'split' ? 'views.tier-split' : 'views.tier-dedicated') + '</span>');
  if ((t.hint_map || []).some(h => (h.hint || '').startsWith('en_'))) b.push('<span class="badge b-warn">E2E</span>');
  if (t.anti_correlate) b.push('<span class="badge b-warn">' + AgI18n.t('guard.badge') + '</span>');
  if (t.admin_scope) b.push('<span class="badge b-warn">' + AgI18n.t('dt.badgeAdmin', { scope: t.admin_scope }) + '</span>');
  if (t.lifecycle && t.lifecycle !== 'active') b.push('<span class="badge b-off">' + AgI18n.t('dt.life-' + t.lifecycle) + '</span>');
  return b.join(' ');
}

async function refreshDelegation() {
  if (HTTP_MODE) return false; // fan-out is a desktop-local capability
  const list = $('dt-list');
  if (!list) return false;
  let items;
  try {
    items = await invoke('list_delegated_tokens');
  } catch (e) {
    // typically "server role not running" — an actionable empty state with a path to the listener switch
    const msg = friendlyError(e);
    const html = '<div class="empty">' + esc(msg) +
      '<div style="margin-top:8px"><button class="ghost small" data-dt-goto-server><i data-sz="13" data-ic="git-fork"></i> ' + AgI18n.t('dt.gotoServer') + '</button></div></div>';
    if (list.dataset.sig !== msg) { list.dataset.sig = msg; list.innerHTML = html; AgIconHydrate(list); }
    return false;
  }
  DT_ITEMS = items;
  const sig = JSON.stringify(items);
  if (list.dataset.sig === sig) return true; // signature guard: no repaint when unchanged
  list.dataset.sig = sig;
  if (!items.length) { list.innerHTML = '<div class="empty">' + AgI18n.t('dt.empty') + '</div>'; return true; }
  list.innerHTML = items.map(t => {
    const groups = (t.groups || []).map(g => grpChip({ name: g.name, adopted: g.adopted_node, e2e: g.e2e_required })).join(' ');
    const regs = (t.regs || []).map(r =>
      esc(r.connector_name) + (r.is_primary ? ' <span class="badge b-info">' + AgI18n.t('dt.primary') + '</span>' : '') + ' <span class="dim">' + esc(r.state || 'offline') + '</span>').join(' · ');
    return '<div class="node-card"><div class="info">' +
      '<div class="name">' + esc(t.label) + ' ' + dtBadges(t) + '</div>' +
      '<div class="addr mono">' + esc(t.token_prefix || '') + ' · ' + groups +
      (regs ? ' · ' + AgI18n.t('dt.regsShort') + ' ' + regs : '') +
      ' · <span class="dim">' + esc((t.created_at || '').replace('T', ' ').replace(/\..*$/, '')) + '</span></div>' +
      '</div><div class="card-actions">' +
      '<button class="danger small icon-btn" title="' + AgI18n.t('dt.revokeTitle') + '" data-dt-revoke="' + esc(t.id) + '">' + AgIcon('trash-2', 13) + '</button>' +
      '</div></div>';
  }).join('');
  return true;
}

function dtEligibleGroups() {
  return DT_STATE.trust === 'plain' ? DT_GROUPS : DT_GROUPS.filter(g => g.e2e_required);
}

/* Apply the four-dimension linkage to the dialog controls (single source of truth = DT_STATE) */
function dtSync() {
  const s = DT_STATE;
  const trustBtns = [...$('dt-trust').querySelectorAll('.group-tab')];
  const routeBtns = [...$('dt-route').querySelectorAll('.group-tab')];
  // direct entry locks trust to plain (direct TLS is already end-to-end; deep guard adds nothing)
  trustBtns.forEach(b => { b.disabled = (s.entry === 'direct' && b.dataset.v !== 'plain'); });
  if (s.entry === 'direct') s.trust = 'plain';
  // Deep Guard (G1): forced E2E — the plain tier becomes unselectable and trust hops to e2e;
  // direct entry disables the guard entirely (its trust is locked to plain)
  const guardEl = $('dt-guard');
  if (guardEl) {
    guardEl.disabled = s.entry === 'direct';
    if (s.entry === 'direct') guardEl.checked = false;
    s.guard = guardEl.checked;
    if (s.guard) trustBtns.forEach(b => { if (b.dataset.v === 'plain') b.disabled = true; });
    if (s.guard && s.trust === 'plain') s.trust = 'e2e';
    $('dt-anti-row').style.display = s.guard ? '' : 'none';
    if (!s.guard) $('dt-anti').checked = false;
  }
  // ruling ①: the plaintext-tier warning shows whenever trust = plain (independent of the guard)
  const warnEl = $('dt-plain-warn');
  if (warnEl) warnEl.style.display = s.trust === 'plain' ? '' : 'none';
  // plain trust cannot do split (vocabulary delivery requires the E2E config channel)
  routeBtns.forEach(b => { b.disabled = (s.trust === 'plain' && b.dataset.v === 'split'); });
  if (s.trust === 'plain') s.route = 'dedicated';
  $('dt-entry').querySelectorAll('.group-tab').forEach(b => b.classList.toggle('active', b.dataset.v === s.entry));
  trustBtns.forEach(b => b.classList.toggle('active', b.dataset.v === s.trust));
  routeBtns.forEach(b => b.classList.toggle('active', b.dataset.v === s.route));
  $('dt-conc').querySelectorAll('.group-tab').forEach(b => b.classList.toggle('active', b.dataset.v === s.conc));
  $('dt-regs-row').style.display = s.entry === 'relay' ? '' : 'none';
  $('dt-scope-row').style.display = s.trust === 'admin' ? '' : 'none';
  const entryHint = s.entry === 'direct' ? AgI18n.t('dt.entryDirectHint') : AgI18n.t('dt.entryRelayHint');
  if ($('dt-entry-hint').textContent !== entryHint) $('dt-entry-hint').textContent = entryHint;
  // groups: dedicated collapses the picker into an expandable summary (click lists the exact members);
  // split shows the picker
  const eligible = dtEligibleGroups();
  const list = $('dt-groups-list'), summary = $('dt-groups-summary');
  if (s.route === 'dedicated') {
    list.style.display = 'none';
    summary.style.display = '';
    summary.style.cursor = 'pointer';
    summary.innerHTML = AgI18n.t('dt.groupsAll', { n: eligible.length }) +
      (DT_GROUPS_OPEN ? ' <i data-ic="chevron-up" data-sz="11"></i>' : ' <i data-ic="chevron-down" data-sz="11"></i>') +
      (DT_GROUPS_OPEN && eligible.length
        ? '<div style="margin-top:6px;display:flex;flex-wrap:wrap;gap:4px">' +
          eligible.map(g => '<span class="badge b-gray">' + esc(g.name) + (g.e2e_required ? ' · E2E' : '') + '</span>').join('') + '</div>'
        : '');
    AgIconHydrate(summary);
    summary.onclick = () => { DT_GROUPS_OPEN = !DT_GROUPS_OPEN; dtSync(); };
  } else {
    summary.style.display = 'none';
    summary.onclick = null;
    list.style.display = '';
    list.innerHTML = eligible.length
      ? eligible.map(g => '<label class="chk"><input type="checkbox" class="dt-grp" value="' + esc(g.id) + '"> <span>' + esc(g.name) + '</span>' + (g.adopted_node ? ' ' + srcBadge(g.adopted_node) : '') + (g.e2e_required ? ' <span class="badge b-warn">E2E</span>' : '') + '</label>').join('')
      : '<div class="hint">' + AgI18n.t('dt.noGroups') + '</div>';
  }
  $('dt-groups-hint').textContent = AgI18n.t(s.trust === 'plain' ? 'dt.groupsHintPlain' : 'dt.groupsHintE2e');
}

async function dtOpenModal() {
  DT_STATE = { entry: 'direct', trust: 'plain', route: 'dedicated', conc: 'single', guard: false };
  $('dt-label').value = '';
  const mn = $('dt-myname'); if (mn) mn.value = '';
  $('dt-err').textContent = '';
  $('dt-scope').value = 'ro';
  $('dt-guard').checked = false;
  $('dt-anti').checked = false;
  agSelectRefresh($('dt-scope'));
  try { DT_GROUPS = await invoke('list_embedded_groups'); } catch (e) { DT_GROUPS = []; }
  let conns = [];
  try { conns = await invoke('list_server_connectors'); } catch (e) {}
  $('dt-regs-list').innerHTML = conns.length
    ? conns.map(c =>
        '<div class="row" style="gap:12px;margin:2px 0">' +
        '<label class="chk"><input type="checkbox" class="dt-reg" value="' + esc(c.id) + '"> <span>' + esc(c.name || c.upstream_addr) + '</span> <span class="dim mono">' + esc(c.upstream_addr) + '</span></label>' +
        '<label class="chk"><input type="radio" name="dt-primary" value="' + esc(c.id) + '"> <span class="hint inline">' + AgI18n.t('dt.primary') + '</span></label>' +
        '</div>').join('')
    : '<div class="hint">' + AgI18n.t('dt.noRegs') + '</div>';
  dtSync();
  $('dt-modal').style.display = 'flex';
  $('dt-label').focus();
}
function dtCloseModal() { $('dt-modal').style.display = 'none'; }

async function dtSubmit() {
  const s = DT_STATE;
  const err = $('dt-err');
  const label = $('dt-label').value.trim();
  if (!label) { err.textContent = AgI18n.t('dt.labelRequired'); return; }
  const eligible = dtEligibleGroups();
  const groupIds = s.route === 'dedicated'
    ? eligible.map(g => g.id)
    : [...document.querySelectorAll('.dt-grp:checked')].map(c => c.value);
  if (!groupIds.length) { err.textContent = AgI18n.t('dt.groupsRequired'); return; }
  const regs = [];
  if (s.entry === 'relay') {
    const checked = [...document.querySelectorAll('.dt-reg:checked')].map(c => c.value);
    const primary = (document.querySelector('input[name="dt-primary"]:checked') || {}).value;
    if (!checked.length) { err.textContent = AgI18n.t('dt.regsRequired'); return; }
    if (!primary || !checked.includes(primary)) { err.textContent = AgI18n.t('dt.primaryRequired'); return; }
    for (const id of checked) regs.push({ connector_id: id, is_primary: id === primary });
  }
  err.textContent = '';
  const myName = ($('dt-myname') || {}).value?.trim() || '';
  const body = {
    label, group_ids: groupIds, regs,
    mode: s.route,
    admin_scope: s.trust === 'admin' ? $('dt-scope').value : '',
    entry_mode: s.entry,
    concurrency: s.conc,
    my_name: myName,
    anti_correlate: s.guard && $('dt-anti').checked,
  };
  const btn = $('dt-ok');
  btn.disabled = true;
  try {
    const t = await invoke('issue_delegated_token', { request: body });
    dtCloseModal();
    refreshDelegation();
    dtShowIssued(t);
  } catch (e) {
    err.textContent = friendlyError(e);
  } finally {
    btn.disabled = false;
  }
}

/* One-time plaintext share card (link / token tabs copy; the server never echoes it again) */
function dtShowIssued(t) {
  anetModal({
    title: AgI18n.t('dt.issuedTitle'),
    sub: t.label || '',
    okLabel: AgI18n.t('common.close'),
    bodyHtml:
      '<div class="hint" style="color:var(--warn);margin-top:0">' + AgI18n.t('dt.onceHint') + '</div>' +
      '<label>' + AgI18n.t('dt.shareUrl') + '</label>' +
      '<div class="row" style="gap:6px"><input class="mono grow" id="dt-share" readonly>' +
      '<button class="ghost small icon-btn" id="dt-share-copy" title="' + AgI18n.t('common.copy') + '">' + AgIcon('copy', 13) + '</button></div>' +
      '<label>' + AgI18n.t('dt.tokenOnly') + '</label>' +
      '<div class="row" style="gap:6px"><input class="mono grow" id="dt-token" readonly>' +
      '<button class="ghost small icon-btn" id="dt-token-copy" title="' + AgI18n.t('common.copy') + '">' + AgIcon('copy', 13) + '</button></div>',
    onOk: async () => anetCloseModal(),
  });
  $('dt-share').value = t.share_url || '';
  $('dt-token').value = t.token || '';
  $('dt-share-copy').onclick = async () => { await navigator.clipboard.writeText($('dt-share').value); toast(AgI18n.t('common.copied'), 'ok'); };
  $('dt-token-copy').onclick = async () => { await navigator.clipboard.writeText($('dt-token').value); toast(AgI18n.t('common.copied'), 'ok'); };
  $('dt-share').onclick = (e) => e.target.select();
  $('dt-token').onclick = (e) => e.target.select();
}

function initDelegation() {
  $('btn-dt-add').onclick = dtOpenModal;
  $('dt-cancel').onclick = dtCloseModal;
  $('dt-modal').onclick = (e) => { if (e.target === $('dt-modal')) dtCloseModal(); };
  $('dt-guard').addEventListener('change', () => dtSync());
  // segmented selectors (entry / trust / route / concurrency) — dtSync re-applies the linkage
  [['dt-entry', 'entry'], ['dt-trust', 'trust'], ['dt-route', 'route'], ['dt-conc', 'conc']].forEach(([id, key]) => {
    $(id).querySelectorAll('.group-tab').forEach(b => {
      b.onclick = () => { if (b.disabled) return; DT_STATE[key] = b.dataset.v; dtSync(); };
    });
  });
  // checking a disaster-set entry auto-marks it primary when none is chosen yet
  $('dt-regs-list').addEventListener('change', (e) => {
    const cb = e.target.closest('input.dt-reg');
    if (cb && cb.checked && !$('dt-regs-list').querySelector('input[name="dt-primary"]:checked')) {
      const r = $('dt-regs-list').querySelector('input[name="dt-primary"][value="' + CSS.escape(cb.value) + '"]');
      if (r) r.checked = true;
    }
  });
  $('dt-ok').onclick = dtSubmit;
  // empty-state escape hatch: jump to the fan-out listen tab (the server role lives there)
  $('dt-list').addEventListener('click', (e) => {
    if (!e.target.closest('[data-dt-goto-server]')) return;
    switchView('upstreams');
    const listen = $('fo-tabs').querySelector('[data-agtab="listen"]');
    if (listen) listen.click();
  });
  // revoke with two-step confirm (same pattern as fan-in delete)
  $('dt-list').addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-dt-revoke]');
    if (!btn) return;
    if (btn.dataset.confirm === '1') {
      try {
        await invoke('revoke_delegated_token', { id: btn.dataset.dtRevoke });
        toast(AgI18n.t('dt.revoked'), 'ok');
        refreshDelegation();
      } catch (err) { toast(friendlyError(err), 'err'); }
      return;
    }
    btn.dataset.confirm = '1';
    const old = btn.innerHTML;
    btn.innerHTML = '<span style="font-size:11px">' + AgI18n.t('common.confirm') + '</span>';
    setTimeout(() => { if (btn.isConnected) { btn.dataset.confirm = ''; btn.innerHTML = old; } }, 2500);
  });
}

/* Dashboard fan-out card: listening status badge + connected count + API/Relay address summary (10s polling + call after changes) */
async function renderDashFanout() {
  if (HTTP_MODE) return;
  let st = null, conns = [];
  try { st = await serverStatusFresh(); } catch (e) {}
  try { conns = await invoke('list_server_connectors'); } catch (e) {}
  const running = !!(st && st.running);
  const total = conns.length;
  const ok = conns.filter(c => c.enabled && c.state === 'connected').length;
  setHtml('d-server-badge', running ? '<span class="badge b-ok">' + AgI18n.t('views.fo-listening') + '</span>' : '<span class="badge b-gray">' + AgI18n.t('views.fo-off') + '</span>');
  setText('d-fanout-val', total ? AgI18n.t('views.dash-fo-count', { ok, total }) : AgI18n.t('views.dash-fo-none'));
  setText('d-fanout-sub', running
    ? 'API ' + (st.api_addr || '-') + ' · Relay ' + (st.relay_addr || '-')
    : (total ? AgI18n.t('views.dash-fo-off-count', { n: total }) : AgI18n.t('views.dash-fo-off')));
}


/* ================= .anet credential file (federation P1 §2.8): export/import dialogs + entries ================= */
function anetModal(opts) {
  $('anet-title').textContent = opts.title;
  $('anet-sub').textContent = opts.sub || '';
  $('anet-body').innerHTML = opts.bodyHtml;
  $('anet-ok').textContent = opts.okLabel;
  $('anet-modal').style.display = 'flex';
  $('anet-ok').onclick = async () => { await opts.onOk(); };
  $('anet-cancel').onclick = anetCloseModal;
}
function anetCloseModal() { $('anet-modal').style.display = 'none'; }
function anetErrText(code) {
  const map = { bad_json: 'badFile', bad_magic: 'badFile', bad_version: 'badFile', bad_role: 'badFile', bad_payload: 'badFile', bad_enc: 'badFile', decrypt: 'badPin', bad_pin: 'badPin', need_pin: 'badPin', no_crypto: 'noCrypto' };
  return AgI18n.t('anet.' + (map[code] || 'badFile'));
}

/* Export (fan-in credential): note + PIN (default recommended) -> AgAnet.build -> native save dialog */
async function exportCredAnet(key) {
  const c = (window._creds || {})[key];
  if (!c) return;
  let url;
  try { url = await invoke('export_credential', { key }); } catch (e) { toast(friendlyError(e), 'err'); return; }
  const parsed = AgLink.parse(url);
  if (parsed.error) { toast(AgI18n.t('anet.badFile'), 'err'); return; }
  const issuer = key.includes('@') ? key.slice(0, key.indexOf('@')) : key;
  const cryptoOk = AgAnet.canEncrypt();
  anetModal({
    title: AgI18n.t('anet.exportTitle'),
    okLabel: AgI18n.t('anet.export'),
    bodyHtml:
      '<label>' + AgI18n.t('anet.note') + '</label><input id="ax-note" style="width:100%" value="' + esc(c.label || '') + '">' +
      '<label class="chk" style="margin-top:10px"><input type="checkbox" id="ax-pin-on" ' + (cryptoOk ? 'checked' : 'disabled') + '> <span>' + AgI18n.t('anet.pinLabel') + '</span></label>' +
      '<div id="ax-pin-row"><input id="ax-pin" class="mono" style="width:140px" maxlength="4" inputmode="numeric" placeholder="' + AgI18n.t('anet.pinPh') + '">' +
      '<div class="hint">' + AgI18n.t('anet.pinHint') + '</div></div>' +
      (cryptoOk ? '' : '<div class="hint" style="color:var(--warn)">' + AgI18n.t('anet.noCrypto') + '</div>'),
    onOk: async () => {
      const note = $('ax-note').value.trim();
      const pinOn = $('ax-pin-on').checked;
      const pin = pinOn ? $('ax-pin').value.trim() : '';
      if (pinOn && !/^\d{4}$/.test(pin)) { toast(AgI18n.t('anet.pinNeed4'), 'err'); return; }
      try {
        const text = await AgAnet.build({ role: 'connect', issuer, note }, { ...parsed, link: url }, pin);
        const name = AgAnet.suggestName(issuer, note || c.label);
        // Web remote panel (no Tauri IPC): blob download fallback; desktop: native save dialog
        const saved = HTTP_MODE
          ? anetSaveBlob(name, text)
          : await invoke('anet_save_file', { suggested: name, content: text });
        if (saved) { anetCloseModal(); toast(AgI18n.t('anet.exported'), 'ok'); }
      } catch (e) { toast(typeof e === 'string' ? e : anetErrText(e && e.code), 'err'); }
    },
  });
  $('ax-pin-on').onchange = (e) => { $('ax-pin-row').style.display = e.target.checked ? 'block' : 'none'; };
}

/* Browser save fallback (Web remote panel has no native dialog) */
function anetSaveBlob(name, content) {
  const blob = new Blob([content], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  return true;
}

/* Import (three entries funnel here: file picker / drag-drop / file association):
   envelope meta preview first, PIN when encrypted, then apply by role */
function anetImportDialog(text, fileName) {
  let parsed;
  try { parsed = AgAnet.parse(text); } catch (e) { toast(anetErrText(e.code), 'err'); return; }
  const env = parsed.envelope;
  anetModal({
    title: AgI18n.t('anet.importTitle'),
    sub: fileName || '',
    okLabel: AgI18n.t('anet.apply'),
    bodyHtml:
      '<div class="kv"><span class="k">' + AgI18n.t('anet.metaRole') + '</span><span><span class="badge b-info">' + AgI18n.t(env.role === 'fanout' ? 'anet.roleFanout' : 'anet.roleConnect') + '</span> ' +
        (parsed.needPin ? '<span class="badge b-warn">' + AgI18n.t('anet.encrypted') + '</span>' : '<span class="badge b-gray">' + AgI18n.t('anet.plaintext') + '</span>') + '</span></div>' +
      '<div class="kv"><span class="k">' + AgI18n.t('anet.metaIssuer') + '</span><span>' + esc(env.issuer || '-') + '</span></div>' +
      '<div class="kv"><span class="k">' + AgI18n.t('anet.metaTime') + '</span><span>' + esc((env.created_at || '').replace('T', ' ').replace(/\..*$/, '')) + '</span></div>' +
      '<div class="kv"><span class="k">' + AgI18n.t('anet.metaNote') + '</span><span>' + esc(env.note || '-') + '</span></div>' +
      (parsed.needPin ? '<label style="margin-top:10px">' + AgI18n.t('anet.pinNeed') + '</label><input id="ai-pin" class="mono" style="width:140px" maxlength="4" inputmode="numeric">' : ''),
    onOk: async () => {
      let payload;
      if (parsed.needPin) {
        try { payload = await AgAnet.decrypt(env, $('ai-pin').value.trim()); }
        catch (e) { toast(anetErrText(e.code), 'err'); return; }
      } else {
        payload = env.payload;
      }
      anetCloseModal();
      applyAnetPayload(env.role, payload);
    },
  });
}
function applyAnetPayload(role, payload) {
  payload = payload || {};
  if (role === 'fanout') {
    switchView('upstreams');
    foOpenModal(null);
    foFillFields(payload);
    toast(AgI18n.t('anet.appliedFanout'), 'ok');
    return;
  }
  // connect: the embedded link is authoritative (rebuilt from fields when absent)
  const link = payload.link || AgLink.buildConnect(payload);
  switchView('connect');
  importUrl(link, null);
}

/* Fan-out technical-field fill (paste import / .anet import / deep link share one path) */
function foFillFields(p) {
  $('fo-addr').value = p.addr || '';
  if (p.token) $('fo-token').value = p.token;
  $('fo-sni').value = p.sni || '';
  $('fo-fp').value = p.fp || '';
  $('fo-insecure').checked = !!p.insecure;
  // 我的名称 suggestion from the link prefills the upload name (M4-T6)
  if (p.myname) $('fo-myname').value = p.myname;
}

/* ================= Universal import wizard (blind-plug; titlebar link button) =================
   One dialog for every credential carrier: anet:// link (fan-in/fan-out/delegated) paste,
   .anet file, QR image. Shared component agimport.js; this is the desktop adapter.
   Fan-out rides the local embedded node — the wizard's details step offers a one-click
   server-role start when it is off (admin password bootstrap included, same as the settings toggle). */
function openUniversalImport() {
  AgImport.open({
    context: 'desktop',
    // Fan-out is a local embedded-node capability; the browser remote panel imports fan-in only
    fanoutApplicable: !HTTP_MODE,
    pickAnetFile: async () => {
      if (HTTP_MODE) {
        return await new Promise((resolve) => {
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
      try { return await invoke('anet_open_file'); } catch (e) { toast(friendlyError(e), 'err'); return null; }
    },
    // QR image pick + rqrr decode (Rust); the browser remote panel has no decoder — button hidden
    pickQrImage: HTTP_MODE ? undefined : async () => {
      try { return await invoke('qr_pick_decode'); } catch (e) { toast(friendlyError(e), 'err'); return null; }
    },
    checkFanoutReady: HTTP_MODE ? undefined : async () => {
      let st = null;
      try { st = await invoke('server_status'); } catch (e) { return { ready: true }; }
      if (st && st.running) return { ready: true };
      return {
        ready: false,
        start: async () => {
          try {
            const cur = await invoke('server_status');
            if (!cur.has_admin) {
              // First enable forces setting an admin password (same flow as the settings toggle)
              const cred = await askPassword({
                title: AgI18n.t('settings.pwd-server-title'),
                desc: AgI18n.t('settings.pwd-server-desc'),
                showUser: true,
              });
              if (!cred) return AgI18n.t('common.cancel');
              await invoke('init_server_admin', { username: cred.user, password: cred.pass });
            }
            await invoke('set_server_role', { enabled: true });
            syncServerSwitch(true);
            refreshServerPanel();
            refreshAdminEntry();
            renderDashFanout();
            toast(AgI18n.t('settings.server-on'), 'ok');
            return true;
          } catch (e) { return friendlyError(e); }
        },
      };
    },
    applyConnect: async ({ link }) => {
      // Same path as the connect-view import (shared parse gate + admin-capability note + connect)
      try {
        const input = await invoke('parse_connect_url', { url: link });
        if (input.eadmin) toast(AgI18n.t('views.url-admin-note'), 'info');
        return (await connectWith(input, null)) ? true : AgI18n.t('common.failed');
      } catch (e) { return friendlyError(e); }
    },
    applyFanout: async ({ parsed }, details) => {
      try {
        await invoke('add_server_connector', {
          name: details.name, upstreamAddr: parsed.addr, token: parsed.token,
          sniHostname: parsed.sni || 'cdn.cloudflare.com', insecure: !!parsed.insecure,
          pinnedFingerprint: parsed.fp || '', groupId: null, pushGroups: [], advertise: '', remark: details.remark,
          myName: details.myname || null,
        });
        toast(AgI18n.t('views.fo-added'), 'ok');
        refreshUpstreams();
        renderDashFanout();
        return true;
      } catch (e) { return friendlyError(e); }
    },
    onDone: () => { refreshCreds(); refreshNodes(true); },
    toast: (m, k) => toast(m, k),
  });
}


/* Language switch: dynamically rendered areas (lists/badges/hints) force re-render in the new language (polling signature unchanged won't self-update; must force) */
if (window.AgI18n) AgI18n.onChange(() => {
  refreshNodes(true);
  refreshProxy();
  refreshCreds();
  refreshCombos(true);
  refreshCustomRules(true);
  NOTIFY_SIG = null; // notify list + cred-card notice lines re-render in the new language
  refreshNotify(true);
  if (!HTTP_MODE) { refreshUpstreams(); refreshDelegation(); }
  renderDashFanout();
});
