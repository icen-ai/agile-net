'use strict';
/* Split from app.js: fan-in/fan-out/rules/custom rules/combos/admin console/proxy control/dashboard cards (pure move, zero logic change) */

/* ================= Empty state guide ================= */
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
  } catch (e) { toast(friendlyError(e), 'err'); updateOnboarding([]); return; }
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
}
function statusText(s) {
  if (s === 'Connected') return T('st-connected');
  if (s === 'Connecting') return T('st-connecting');
  if (s === 'Reconnecting') return T('st-reconnecting');
  return T('st-disconnected');
}
function statusBadgeHtml(s) {
  if (s === 'Connected') return '<span class="badge b-ok">' + T('st-connected') + '</span>';
  if (s === 'Connecting') return '<span class="badge b-warn"><span class="pulse"></span>' + T('st-connecting') + '</span>';
  if (s === 'Reconnecting') return '<span class="badge b-warn"><span class="pulse"></span>' + T('st-reconnecting') + '</span>';
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
  const rows = [];
  // custom bypass (highest engine priority, listed first)
  if (tf === 'all' || tf === 'bypass') {
    for (const r of custom.bypass) {
      const way = r.via_subscription ? AgI18n.t('views.rule-via-sub') : AgI18n.t('views.rule-direct');
      if (!hit(r.pattern, AgI18n.t('views.rule-bypass'), way, AgI18n.t('views.src-custom'))) continue;
      rows.push('<tr class="' + (r.enabled ? '' : 'rule-paused') + '">' +
        '<td><span class="badge b-ok">' + AgI18n.t('views.rule-bypass') + '</span></td>' +
        '<td class="mono">' + esc(r.pattern) + '</td>' +
        '<td>' + way + '</td>' +
        '<td class="dim">' + AgI18n.t('views.src-custom') + '</td>' +
        '<td><label class="switch"><input type="checkbox" data-cr="' + esc(r.id) + '"' + (r.enabled ? ' checked' : '') + '><span class="slider"></span></label></td>' +
        '<td><button class="danger small icon-btn" title="' + AgI18n.t('views.del-bypass-title') + '" data-crdel="' + esc(r.id) + '">' + AgIcon('trash-2', 13) + '</button></td></tr>');
    }
  }
  // hosts mapping (user-created can be toggled/deleted; system entries read-only, no actions shown)
  if (tf === 'all' || tf === 'host') {
    for (const r of custom.hosts) {
      const sys = r.source === 'system';
      const src = sys ? AgI18n.t('views.src-system-hosts') : AgI18n.t('views.src-custom');
      if (!hit(r.hostname, r.ip, AgI18n.t('views.rule-map'), src)) continue;
      rows.push('<tr class="' + (r.enabled ? '' : 'rule-paused') + '">' +
        '<td><span class="badge b-gray">' + AgI18n.t('views.rule-map') + '</span></td>' +
        '<td class="mono">' + esc(r.hostname) + '</td>' +
        '<td class="mono">→ ' + esc(r.ip) + '</td>' +
        '<td class="dim">' + src + '</td>' +
        (sys
          ? '<td><span class="dim">' + AgI18n.t('views.readonly') + '</span></td><td></td>'
          : '<td><label class="switch"><input type="checkbox" data-cr="' + esc(r.id) + '"' + (r.enabled ? ' checked' : '') + '><span class="slider"></span></label></td>' +
            '<td><button class="danger small icon-btn" title="' + AgI18n.t('views.del-map-title') + '" data-crdel="' + esc(r.id) + '">' + AgIcon('trash-2', 13) + '</button></td>') +
        '</tr>');
    }
  }
  // endpoint-pulled (source is the endpoint name; toggle uses existing pause semantics)
  if (tf === 'all' || tf === 'pulled') {
    for (const n of nodes) {
      const dot = n.status === 'Connected' ? 'ok' : (n.status === 'Disconnected' ? 'down' : 'warn');
      const pset = pausedMap[n.node_id] || new Set();
      for (const r of (n.rules || [])) {
        const key = ruleKey(r);
        if (!hit(r.value, r.type, n.node_name)) continue;
        const paused = pset.has(key);
        rows.push('<tr class="' + (paused ? 'rule-paused' : '') + '"><td><span class="rdot ' + dot + '"></span><span class="badge b-ok">' + esc(r.type) + '</span></td>' +
          '<td class="mono">' + esc(r.value) + '</td>' +
          '<td class="dim">—</td>' +
          '<td class="dim">' + esc(n.node_name) + '</td>' +
          '<td><label class="switch"><input type="checkbox" data-node="' + esc(n.node_id) + '" data-rule="' + esc(key) + '"' + (paused ? '' : ' checked') + '><span class="slider"></span></label></td>' +
          '<td></td></tr>');
      }
    }
  }
  $('rules-body').innerHTML = rows.join('') || '<tr><td colspan="6" class="empty">' + ((f || tf !== 'all') ? AgI18n.t('views.no-match') : T('no-rules')) + '</td></tr>';
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
   list_custom_rules() -> { bypass:[{id,pattern,via_subscription,enabled}],
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
  $('combo-edit-modal').style.display = 'flex';
  $('ce-name').focus();
}
/* Compact list of all rules (custom + pulled; system hosts read-only, not selectable; pulled deduped by key across endpoints) */
function allRuleChoices() {
  const out = [];
  const c = window._custom || { bypass: [], hosts: [] };
  (c.bypass || []).forEach(r => out.push({ key: r.id, badge: AgI18n.t('views.rule-bypass'), cls: 'b-ok', value: r.pattern, source: AgI18n.t('views.src-custom') }));
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
    $('bp-via').value = 'direct';
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
      await invoke('add_bypass_rule', { pattern, viaSubscription: $('bp-via').value === 'sub' });
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
    toast(T('connected-toast').replace('{name}', st.node_name).replace('{n}', st.rules.length), 'ok');
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
    const st = await invoke('server_status');
    if (st && st.running) items.push({ kind: 'local', label: AgI18n.t('views.admin-local'), sub: AgI18n.t('views.admin-local-sub') });
  } catch (e) {}
  const nodes = window._nodes || [];
  const remotes = [];
  for (const n of nodes) {
    if (n.admin_console && n.status === 'Connected') {
      remotes.push({ kind: 'node', id: n.node_id, label: n.node_name + (n.username ? ' · ' + n.username : ''), sub: n.addr });
    }
    for (const m of (n.manageable || [])) {
      if (n.status === 'Connected') {
        remotes.push({ kind: 'up', id: n.node_id, up: m.node_name, label: m.node_name, sub: AgI18n.t('views.admin-up-sub', { name: n.node_name }) });
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
    n.onclick = () => adminNavActivate(n.dataset.aview);
  });
  // embedded admin console (SPA) toasts routed into Dynamic Island (origin-checked, only from the current admin iframe)
  window.addEventListener('message', (e) => {
    if (ADMIN && e.origin === ADMIN.origin && e.data && e.data.type === 'ag-toast') {
      toast(String(e.data.msg || ''), typeof e.data.kind === 'string' ? e.data.kind : 'info');
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
    else enterAdmin(it.id, it.up, it.label);
  });
}

/* ================= Console channel (manage this endpoint; embedded in main window) ================= */
async function openNodeConsole(nodeId) {
  const n = (window._nodes || []).find(x => x.node_id === nodeId);
  const label = n ? n.node_name + (n.username ? ' · ' + n.username : '') : nodeId;
  await enterAdmin(nodeId, null, label);
}

/* ================= Connect-link import ================= */
async function importUrl(url, btn) {
  url = (url || '').trim();
  if (!url) { toast(T('err-need-url'), 'err'); return; }
  if (!url.startsWith('agilenet://connect?')) { toast(T('err-bad-url'), 'err'); return; }
  try {
    const input = await invoke('parse_connect_url', { url });
    if (input.admin) toast(AgI18n.t('views.url-admin-note'), 'info');
    await connectWith(input, btn);
  } catch (e) { toast(friendlyError(e), 'err'); }
}

async function pasteFromClipboard() {
  try {
    const text = await navigator.clipboard.readText();
    if (text && text.trim().startsWith('agilenet://connect?')) {
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
      text = T('st-degraded') + '（' + degraded.length + '）';
    } else if (st.running) {
      mode = 'on';
      text = T('proxy-running') + ' 127.0.0.1:' + st.port;
    } else {
      mode = 'off';
      text = T('proxy-stopped');
    }
    Island.setStatus(mode, text, degraded);
    // sidebar footer proxy status row (same data source as Dynamic Island)
    setText('sf-status', st.running ? AgI18n.t('views.sf-proxy-running', { addr: '127.0.0.1:' + st.port }) : AgI18n.t('views.proxy-off-state'));
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
    if (delta < 0) delta = total; // session reconnect resets counters: negative delta uses new baseline
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
  setText('d-fanin-sub', AgI18n.t('views.fanin-saved', { n: saved }) + (trying ? AgI18n.t('views.fanin-trying', { n: trying }) : ''));
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
}

/* ================= Fan-in list (saved fan-ins as main body + unsaved active connections; connect/disconnect/export/delete) ================= */
async function refreshCreds() {
  try {
    const creds = await invoke('list_credentials');
    window._credsRaw = creds;
    window._creds = Object.fromEntries(creds);
    renderCredList(creds, window._nodeStatus || {});
    invoke('list_nodes').then(nodes => updateOnboarding(nodes)).catch(() => {});
    updateDashFanin();
  } catch (e) {}
}
function renderCredList(creds, statusMap) {
  const list = $('creds-list');
  const f = FILTERS.creds;
  const nodeMap = Object.fromEntries((window._nodes || []).map(n => [n.node_id, n]));
  // unsaved active connections (manual connect without saving credential): appended after saved fan-ins, disconnect/manage only
  const savedKeys = new Set(creds.map(([k]) => k));
  const unsaved = (window._nodes || []).filter(n => !savedKeys.has(n.node_id));
  const live = (st) => st === 'Connected' || st === 'Connecting' || st === 'Reconnecting';
  const match = (name, username, addr, st) => !f ||
    name.toLowerCase().includes(f) || (username || '').toLowerCase().includes(f) ||
    addr.toLowerCase().includes(f) || (st ? statusText(st) : AgI18n.t('common.disconnected')).includes(f);
  const shownCreds = creds.filter(([key, c]) =>
    match(key.includes('@') ? key.slice(0, key.indexOf('@')) : key, c.username, c.addr, statusMap[key]));
  const shownUnsaved = unsaved.filter(n => match(n.node_name, n.username, n.addr, n.status));
  if (!shownCreds.length && !shownUnsaved.length) {
    list.innerHTML = '<div class="empty">' + (f ? AgI18n.t('views.no-match') : T('no-creds')) + '</div>';
    return;
  }
  list.innerHTML = shownCreds.map(([key, c]) => {
    const st = statusMap[key];
    const n = nodeMap[key];
    const badge = st ? statusBadgeHtml(st) : '<span class="badge b-gray">' + AgI18n.t('common.disconnected') + '</span>';
    const mainBtn = st === 'Connected'
      ? '<button class="ghost small" data-act="disconnect" data-key="' + esc(key) + '">' + AgI18n.t('views.disconnect') + '</button>'
      : '<button class="small" data-act="reconnect" data-key="' + esc(key) + '">' + AgI18n.t(st ? 'views.reconnect' : 'views.connect') + '</button>';
    const epName = key.includes('@') ? key.slice(0, key.indexOf('@')) : key;
    return '<div class="node-card' + (live(st) ? '' : ' down') + '"><div class="info">' +
      '<div class="name">' + esc(epName) + ' <span class="dim">· ' + esc(c.username) + '</span> ' + badge + '</div>' +
      '<div class="addr mono">' + esc(c.addr) + (c.insecure ? ' · <span class="badge b-warn">insecure</span>' : '') + '</div>' +
      '</div><div class="card-actions">' +
      (n && n.admin_console && st === 'Connected' && !HTTP_MODE
        ? '<button class="ghost small" data-act="console" data-id="' + esc(key) + '">' + AgIcon('monitor', 13) + ' ' + AgI18n.t('views.manage') + '</button>' : '') +
      mainBtn +
      '<button class="ghost small icon-btn" title="' + AgI18n.t('views.export-title') + '" data-act="export" data-key="' + esc(key) + '">' + AgIcon('share-2', 13) + '</button>' +
      '<button class="danger small icon-btn" title="' + AgI18n.t('views.del-fanin-title') + '" data-act="delcred" data-key="' + esc(key) + '">' + AgIcon('trash-2', 13) + '</button>' +
      '</div></div>';
  }).join('') + shownUnsaved.map(n =>
    '<div class="node-card' + (live(n.status) ? '' : ' down') + '"><div class="info">' +
    '<div class="name">' + esc(n.node_name) + (n.username ? ' <span class="dim">· ' + esc(n.username) + '</span>' : '') + ' ' + statusBadgeHtml(n.status) + ' <span class="badge b-gray">' + AgI18n.t('views.unsaved') + '</span></div>' +
    '<div class="addr mono">' + esc(n.addr) + '</div>' +
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
    addr: c.addr, username: c.username, password: c.password,
    insecure: c.insecure, pinned_cert_path: null, pinned_fingerprint: c.pinned_fingerprint || null,
    manage_hosts: false, save_credential: true,
  }, btn || null);
}
async function exportCred(key) {
  // credential export contains plaintext password: Web remote panel requires a second confirmation
  if (HTTP_MODE && !window.confirm(AgI18n.t('views.export-confirm'))) return;
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

/* ================= Fan-out connections (embedded node DB managed, changes hot-applied) ================= */
let FO_EDIT_ID = null;
let FO_ITEMS = [];

function foBadge(c) {
  if (!c.enabled) return '<span class="badge b-off">' + AgI18n.t('common.disabled') + '</span>';
  const st = c.state;
  if (st === 'connected') return '<span class="badge b-ok">' + AgI18n.t('common.connected') + '</span>';
  if (st === 'connecting') return '<span class="badge b-warn"><span class="pulse"></span>' + AgI18n.t('views.st-connecting') + '</span>';
  if (st === 'reconnecting') return '<span class="badge b-warn"><span class="pulse"></span>' + AgI18n.t('views.st-reconnecting') + '</span>';
  if (st === 'disconnected') return '<span class="badge b-off">' + AgI18n.t('views.st-down') + '</span>';
  return '<span class="badge b-gray">' + AgI18n.t('views.not-started') + '</span>';
}

/** Group dropdown: fetch local embedded node group list (keep current selection; failure doesn't block the list) */
async function foLoadGroups() {
  try {
    const groups = await invoke('list_embedded_groups');
    const cur = $('fo-group').value;
    $('fo-group').innerHTML = '<option value="">' + AgI18n.t('views.fo-no-group') + '</option>' +
      groups.map(g => '<option value="' + esc(g.id) + '">' + esc(g.name) + '</option>').join('');
    if (groups.some(g => g.id === cur)) $('fo-group').value = cur;
    agSelectRefresh($('fo-group'));
  } catch (e) { /* group list load failure doesn't block the fan-out list */ }
}

async function refreshUpstreams() {
  foLoadGroups();
  try {
    FO_ITEMS = await invoke('list_server_connectors');
  } catch (e) { $('fo-list').innerHTML = '<div class="empty">' + AgI18n.t('views.load-failed') + '</div>'; return; }
  if (!FO_ITEMS.length) {
    $('fo-list').innerHTML = '<div class="empty">' + AgI18n.t('views.fo-empty') + '</div>';
    return;
  }
  $('fo-list').innerHTML = FO_ITEMS.map(c =>
    '<div class="node-card"><div class="info">' +
    '<div class="name">' + esc(c.name || c.upstream_addr) + ' ' + foBadge(c) + '</div>' +
    '<div class="addr mono">' + esc(c.upstream_addr) + ' · ' + esc(c.token_prefix) + ' · SNI ' + esc(c.sni_hostname) +
    (c.insecure ? ' · <span class="badge b-warn">insecure</span>' : '') +
    AgI18n.t('views.fo-group-fmt', { name: c.group_name ? esc(c.group_name) : AgI18n.t('views.fo-group-none') }) + '</div>' +
    '</div><div class="card-actions">' +
    '<button class="ghost small" data-fo-edit="' + esc(c.id) + '">' + AgI18n.t('common.edit') + '</button>' +
    '<button class="danger small" data-fo-del="' + esc(c.id) + '">' + AgI18n.t('common.delete') + '</button>' +
    '</div></div>'
  ).join('');
}

/* ---- New/edit fan-out modal (fields aligned with admin console 「新建扇出」; advertise one per line, comma-joined on save) ---- */
function foOpenModal(c) {
  FO_EDIT_ID = c ? c.id : null;
  $('fo-modal-title').textContent = c ? AgI18n.t('views.fo-title-edit') : AgI18n.t('views.fo-title-new');
  $('fo-ok').textContent = c ? AgI18n.t('common.save') : AgI18n.t('views.create');
  $('fo-token-hint').style.display = c ? '' : 'none';
  $('fo-name').value = c ? c.name : '';
  $('fo-addr').value = c ? c.upstream_addr : '';
  $('fo-token').value = '';
  $('fo-sni').value = c ? c.sni_hostname : 'cdn.cloudflare.com';
  $('fo-insecure').checked = c ? !!c.insecure : false;
  $('fo-advertise').value = c ? (c.advertise || '').split(',').filter(Boolean).join('\n') : '';
  $('fo-group').value = c ? (c.group_id || '') : '';
  agSelectRefresh($('fo-group'));
  $('fo-remark').value = c ? (c.remark || '') : '';
  $('fo-err').textContent = '';
  $('fo-modal').style.display = 'flex';
  $(c ? 'fo-name' : 'fo-addr').focus();
}
function foCloseModal() { $('fo-modal').style.display = 'none'; FO_EDIT_ID = null; }

function initUpstreams() {
  agTabsBind($('fo-tabs'));
  $('btn-fo-refresh').onclick = refreshUpstreams;
  $('btn-fo-add').onclick = () => foOpenModal(null);
  $('fo-cancel').onclick = foCloseModal;
  $('fo-ok').onclick = async () => {
    const name = $('fo-name').value.trim();
    const addr = $('fo-addr').value.trim();
    const token = $('fo-token').value.trim();
    const sni = $('fo-sni').value.trim() || 'cdn.cloudflare.com';
    const insecure = $('fo-insecure').checked;
    const groupId = $('fo-group').value || null;
    const advertise = $('fo-advertise').value.split('\n').map(s => s.trim()).filter(Boolean).join(',');
    const remark = $('fo-remark').value.trim();
    if (!addr) { $('fo-err').textContent = AgI18n.t('views.fo-addr-required'); return; }
    if (!FO_EDIT_ID && !token) { $('fo-err').textContent = AgI18n.t('views.fo-token-required'); return; }
    $('fo-err').textContent = '';
    try {
      if (FO_EDIT_ID) {
        await invoke('update_server_connector', { id: FO_EDIT_ID, name, upstreamAddr: addr, token, sniHostname: sni, insecure, groupId, advertise, remark });
        toast(AgI18n.t('views.fo-updated'), 'ok');
      } else {
        await invoke('add_server_connector', { name, upstreamAddr: addr, token, sniHostname: sni, insecure, groupId, advertise, remark });
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
      try {
        await invoke('remove_server_connector', { id: delBtn.dataset.foDel });
        toast(AgI18n.t('views.fo-deleted'), 'ok');
        if (FO_EDIT_ID === delBtn.dataset.foDel) foCloseModal();
        refreshUpstreams();
      } catch (err) { toast(friendlyError(err), 'err'); }
    }
  });
}

/* Dashboard fan-out card: listening status badge + connected count + API/Relay address summary (10s polling + call after changes) */
async function renderDashFanout() {
  if (HTTP_MODE) return;
  let st = null, conns = [];
  try { st = await invoke('server_status'); } catch (e) {}
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


/* Language switch: dynamically rendered areas (lists/badges/hints) force re-render in the new language (polling signature unchanged won't self-update; must force) */
if (window.AgI18n) AgI18n.onChange(() => {
  refreshNodes(true);
  refreshProxy();
  refreshCreds();
  refreshCombos(true);
  refreshCustomRules(true);
  if (!HTTP_MODE) refreshUpstreams();
  renderDashFanout();
});
