'use strict';
/* 从 app.js 拆分：扇入/扇出/规则/自定义规则/组合/管理端/代理控制/仪表盘卡（纯搬运，零逻辑变更） */

/* ================= 空状态引导 ================= */
function updateOnboarding(nodes) {
  // 无任何活跃连接且未保存扇入 = 空状态：只显示接入引导；有数据后显示仪表盘卡片网格
  const empty = (!nodes || nodes.length === 0) && !(window._credsRaw || []).length;
  $('onboarding').style.display = empty ? 'block' : 'none';
  const dg = $('dash-grid');
  if (dg) dg.style.display = empty ? 'none' : '';
}

/* ================= 列表过滤（搜索） ================= */
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

/* ================= 节点管理 ================= */
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

/* ---- 规则统一表格（自定义 放行/映射 + 端点拉取合并；类型过滤 RL_FILTER 与搜索 FILTERS.rules 叠加） ---- */
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
  // 自定义放行（引擎优先级最高，排在最前）
  if (tf === 'all' || tf === 'bypass') {
    for (const r of custom.bypass) {
      const way = r.via_subscription ? '经过订阅' : '直连';
      if (!hit(r.pattern, '放行', way, '自定义')) continue;
      rows.push('<tr class="' + (r.enabled ? '' : 'rule-paused') + '">' +
        '<td><span class="badge b-ok">放行</span></td>' +
        '<td class="mono">' + esc(r.pattern) + '</td>' +
        '<td>' + way + '</td>' +
        '<td class="dim">自定义</td>' +
        '<td><label class="switch"><input type="checkbox" data-cr="' + esc(r.id) + '"' + (r.enabled ? ' checked' : '') + '><span class="slider"></span></label></td>' +
        '<td><button class="danger small icon-btn" title="删除该放行规则" data-crdel="' + esc(r.id) + '">' + AgIcon('trash-2', 13) + '</button></td></tr>');
    }
  }
  // hosts 映射（用户自建可启停/删除；系统既有只读不显示操作）
  if (tf === 'all' || tf === 'host') {
    for (const r of custom.hosts) {
      const sys = r.source === 'system';
      const src = sys ? '系统 hosts' : '自定义';
      if (!hit(r.hostname, r.ip, '映射', src)) continue;
      rows.push('<tr class="' + (r.enabled ? '' : 'rule-paused') + '">' +
        '<td><span class="badge b-gray">映射</span></td>' +
        '<td class="mono">' + esc(r.hostname) + '</td>' +
        '<td class="mono">→ ' + esc(r.ip) + '</td>' +
        '<td class="dim">' + src + '</td>' +
        (sys
          ? '<td><span class="dim">只读</span></td><td></td>'
          : '<td><label class="switch"><input type="checkbox" data-cr="' + esc(r.id) + '"' + (r.enabled ? ' checked' : '') + '><span class="slider"></span></label></td>' +
            '<td><button class="danger small icon-btn" title="删除该映射" data-crdel="' + esc(r.id) + '">' + AgIcon('trash-2', 13) + '</button></td>') +
        '</tr>');
    }
  }
  // 端点拉取（来源即端点名；启停走既有暂停语义）
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
  $('rules-body').innerHTML = rows.join('') || '<tr><td colspan="6" class="empty">' + ((f || tf !== 'all') ? '无匹配结果' : T('no-rules')) + '</td></tr>';
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
    toast(paused ? '已暂停该规则（立即生效）' : '已恢复该规则', 'ok');
  } catch (e) {
    toast(friendlyError(e), 'err');
    refreshNodes(true);
  }
}

/* ================= 自定义规则（放行 / hosts 映射）与组合 =================
   后端契约（apps/desktop/src/custom_rules.rs + lib.rs 命令层，GUI 本机能力，Web 远程面隐藏）：
   list_custom_rules() -> { bypass:[{id,pattern,via_subscription,enabled}],
                            hosts:[{id,hostname,ip,enabled,source}] }（source=user|system，system 只读）；
   组合 rule_keys：自定义 = 其 id，拉取 = ruleKey(r)（type:value 小写）。
   组合中的拉取 key 引擎忽略，由本模块经既有暂停接口编排（orchestrateCombo）。 */
let RL_FILTER = 'all';    // 类型过滤（与搜索叠加）：all | bypass | host | pulled
let CUSTOM_SIG = null;    // list_custom_rules 轮询变更检测签名
let COMBO_ITEMS = [];
let COMBO_SIG = null;
let COMBO_EDIT_ID = null;
let CE_MEMBERS = new Set(); // 组合编辑弹窗成员工作集（搜索重渲染不丢勾选）

/* ---- 自定义规则数据（10s 轮询 + 变更后调用；签名一致不重绘） ---- */
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

/* ---- 单条启停 / 删除（立即生效；后端落盘并热更引擎） ---- */
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
    toast(enabled ? '规则已启用（立即生效）' : '规则已停用（立即生效）', 'ok');
  } catch (e) {
    cb.checked = !enabled;
    toast(friendlyError(e), 'err');
  }
}
async function deleteCustomRule(id, btn) {
  if (btn.dataset.confirm === '1') {
    try {
      await invoke('remove_custom_rule', { id });
      toast('规则已删除', 'ok');
      refreshCustomRules(true);
      refreshCombos(true); // 后端级联清理组合成员中的失效 key
    } catch (e) { toast(friendlyError(e), 'err'); }
    return;
  }
  btn.dataset.confirm = '1';
  const old = btn.innerHTML;
  btn.innerHTML = '<span style="font-size:11px">确认</span>';
  setTimeout(() => { if (btn.isConnected) { btn.dataset.confirm = ''; btn.innerHTML = old; } }, 2500);
}

/* ---- 前端预校验（后端仍兜底；错误就地展示在弹窗内） ---- */
function validIPv4(ip) {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  return !!m && m.slice(1).every(o => +o <= 255);
}
function validIP(ip) {
  return validIPv4(ip) || (ip.includes(':') && /^[0-9a-fA-F:]+$/.test(ip));
}

/* ---- 组合数据与列表 ---- */
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
    list.innerHTML = '<div class="empty">尚未创建组合（组合 = 成组启停的命名规则集合）</div>';
    return;
  }
  list.innerHTML = COMBO_ITEMS.map(c =>
    '<div class="node-card"><div class="info">' +
    '<div class="name">' + esc(c.name) + ' ' + (c.enabled ? '<span class="badge b-ok">已启用</span>' : '<span class="badge b-gray">已停用</span>') + '</div>' +
    '<div class="addr">成员 ' + c.rule_keys.length + ' 条</div>' +
    '</div><div class="card-actions">' +
    '<label class="switch"><input type="checkbox" data-combo-toggle="' + esc(c.id) + '"' + (c.enabled ? ' checked' : '') + '><span class="slider"></span></label>' +
    '<button class="ghost small" data-combo-edit="' + esc(c.id) + '">编辑</button>' +
    '<button class="danger small" data-combo-del="' + esc(c.id) + '">删除</button>' +
    '</div></div>').join('');
}

/* 组合启停编排：组合中的拉取成员（type:value key）引擎忽略，由前端经既有暂停接口处理——
   启用 → 拉取成员全部取消暂停；停用 → 拉取成员暂停，
   但成员同时被另一个已启用组合覆盖则不动（交叉组网语义）。
   作用于当前持有该规则的端点；window._paused 缓存同步并本地持久。 */
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
    // 交叉覆盖保护：仍被其他已启用组合引用的成员保持现状
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
      } catch (e) { /* 单条失败不阻断其余成员编排 */ }
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
    toast(enabled ? '组合已启用（成员规则生效）' : '组合已停用（拉取成员已暂停）', 'ok');
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
      // 删除已启用组合 ≈ 停用：其拉取成员按交叉覆盖保护暂停
      if (combo && combo.enabled) {
        await orchestrateCombo(combo, false);
        renderMergedRules(window._nodes || []);
      }
      if (COMBO_EDIT_ID === id) { $('combo-edit-modal').style.display = 'none'; COMBO_EDIT_ID = null; }
      toast('组合已删除', 'ok');
    } catch (e) { toast(friendlyError(e), 'err'); }
    return;
  }
  btn.dataset.confirm = '1';
  const old = btn.innerHTML;
  btn.innerHTML = '<span style="font-size:11px">确认</span>';
  setTimeout(() => { if (btn.isConnected) { btn.dataset.confirm = ''; btn.innerHTML = old; } }, 2500);
}

/* ---- 编辑组合弹窗（名称 + 全部规则简洁清单复选） ---- */
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
/* 全部规则简洁清单（自定义 + 拉取；系统 hosts 只读不可选；拉取跨端点同 key 去重） */
function allRuleChoices() {
  const out = [];
  const c = window._custom || { bypass: [], hosts: [] };
  (c.bypass || []).forEach(r => out.push({ key: r.id, badge: '放行', cls: 'b-ok', value: r.pattern, source: '自定义' }));
  (c.hosts || []).forEach(r => {
    if (r.source !== 'system') out.push({ key: r.id, badge: '映射', cls: 'b-gray', value: r.hostname + ' → ' + r.ip, source: '自定义' });
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
    : '<div class="empty">' + (f ? '无匹配结果' : '暂无可选规则（先连接扇入或新建放行/映射）') + '</div>';
}
async function comboEditSave() {
  const name = $('ce-name').value.trim();
  if (!name) { $('ce-err').textContent = '组合名称不能为空'; return; }
  const combo = COMBO_ITEMS.find(c => c.id === COMBO_EDIT_ID);
  const before = new Set(combo ? combo.rule_keys : []);
  const btn = $('ce-ok');
  btn.disabled = true;
  try {
    await invoke('update_combo', { id: COMBO_EDIT_ID, name, ruleKeys: [...CE_MEMBERS] });
    $('combo-edit-modal').style.display = 'none';
    COMBO_EDIT_ID = null;
    await refreshCombos(true);
    // 已启用组合成员变更同步编排：新增拉取成员取消暂停，移除的按交叉覆盖保护暂停
    if (combo && combo.enabled) {
      const added = [...CE_MEMBERS].filter(k => !before.has(k));
      const removed = [...before].filter(k => !CE_MEMBERS.has(k));
      if (added.length) await orchestrateCombo({ id: combo.id, rule_keys: added }, true);
      if (removed.length) await orchestrateCombo({ id: combo.id, rule_keys: removed }, false);
      if (added.length || removed.length) renderMergedRules(window._nodes || []);
    }
    toast('组合已保存', 'ok');
  } catch (e) {
    $('ce-err').textContent = friendlyError(e);
  } finally {
    btn.disabled = false;
  }
}

/* ---- 规则页全部事件绑定（CSP 禁内联事件，统一显式绑定/委托） ---- */
function initRules() {
  agTabsBind($('rl-tabs'), (key) => { if (key === 'combo') refreshCombos(true); });
  // 类型过滤 chips（与搜索叠加）
  $('rl-filter').addEventListener('click', (e) => {
    const b = e.target.closest('[data-rfilter]');
    if (!b || b.classList.contains('active')) return;
    RL_FILTER = b.dataset.rfilter;
    $('rl-filter').querySelectorAll('.agtab').forEach(t => t.classList.toggle('active', t === b));
    renderMergedRules(window._nodes || []);
  });
  // 统一表格事件委托：自定义行启停 / 删除（拉取行启停见启动区既有绑定）
  $('rules-body').addEventListener('change', (e) => {
    const cb = e.target.closest('input[data-cr]');
    if (cb) toggleCustomRule(cb.dataset.cr, cb.checked, cb);
  });
  $('rules-body').addEventListener('click', (e) => {
    const btn = e.target.closest('[data-crdel]');
    if (btn) deleteCustomRule(btn.dataset.crdel, btn);
  });

  /* ---- 新增放行弹窗 ---- */
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
    if (!pattern || /\s/.test(pattern)) { $('bp-err').textContent = '匹配值不能为空且不含空白字符'; return; }
    const btn = $('bp-ok');
    btn.disabled = true;
    try {
      await invoke('add_bypass_rule', { pattern, viaSubscription: $('bp-via').value === 'sub' });
      $('bypass-modal').style.display = 'none';
      toast('放行规则已添加（默认启用，立即生效）', 'ok');
      refreshCustomRules(true);
    } catch (e) {
      $('bp-err').textContent = friendlyError(e);
    } finally {
      btn.disabled = false;
    }
  };

  /* ---- 新增映射弹窗 ---- */
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
      $('hm-err').textContent = '主机名不合法（不含空白、*、#）'; return;
    }
    if (validIP(hostname)) { $('hm-err').textContent = '主机名不能是 IP'; return; }
    if (!validIP(ip)) { $('hm-err').textContent = 'IP 地址不合法'; return; }
    const btn = $('hm-ok');
    btn.disabled = true;
    try {
      const r = await invoke('add_host_mapping', { hostname, ip, toSystem: $('hm-system').checked });
      $('host-modal').style.display = 'none';
      toast(r.persisted === 'system' ? '映射已添加，已写入系统 hosts' : '映射已添加，仅本软件内生效（无系统 hosts 写权限）', 'ok');
      refreshCustomRules(true);
    } catch (e) {
      $('hm-err').textContent = friendlyError(e);
    } finally {
      btn.disabled = false;
    }
  };

  /* ---- 新建组合弹窗 ---- */
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
    if (!name) { $('cb-err').textContent = '请填写组合名称'; return; }
    const btn = $('cb-ok');
    btn.disabled = true;
    try {
      await invoke('add_combo', { name });
      $('combo-modal').style.display = 'none';
      toast('组合已创建，点「编辑」勾选成员', 'ok');
      refreshCombos(true);
    } catch (e) {
      $('cb-err').textContent = friendlyError(e);
    } finally {
      btn.disabled = false;
    }
  };

  /* ---- 组合列表（启停 / 编辑 / 删除）与编辑弹窗 ---- */
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

/** 带加载状态的连接执行 */
async function connectWith(input, btn) {
  let originalText = null;
  if (btn) {
    originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>连接中…';
  }
  try {
    const st = await invoke('connect_node', { input });
    toast(T('connected-toast').replace('{name}', st.node_name).replace('{n}', st.rules.length), 'ok');
    // 连接成功后按需自动启动代理
    if (PREFS.autoproxy) {
      try {
        const ps = await invoke('proxy_status');
        if (!ps.running) {
          await invoke('start_proxy', { port: proxyPort() });
        }
      } catch (e) { /* 代理自启失败不阻塞连接 */ }
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

/* ================= 管理端模式（内嵌 iframe 承载管理 SPA；不开子窗口） ================= */
let ADMIN = null; // { label, url, origin }

const curTheme = () => localStorage.getItem('ag_theme') || 'light';

async function enterAdmin(nodeId, upstream, label) {
  let url;
  try {
    url = await invoke('console_url', { nodeId: nodeId || null, upstream: upstream || null, theme: curTheme() });
  } catch (e) { toast(friendlyError(e), 'err'); return; }
  ADMIN = { label, url, origin: new URL(url).origin };
  $('admin-frame').src = url;
  LogsView.stop(); // 进入管理端等同离开日志页：停轮询
  document.querySelector('.content').classList.add('admin-mode');
  $('nav-client').style.display = 'none';
  $('nav-admin').style.display = 'flex';
  $('side-foot').style.display = 'none'; // 侧栏底部区属于客户端导航
  $('bnav').style.display = 'none'; // 窄屏底部导航同属客户端导航
  document.querySelectorAll('.view').forEach(s => { s.hidden = s.id !== 'view-admin'; });
  adminNavActivate('dashboard');
  toast('已进入管理端：' + label, 'ok');
}

function exitAdmin() {
  if (!ADMIN) return;
  $('admin-frame').src = 'about:blank';
  ADMIN = null;
  document.querySelector('.content').classList.remove('admin-mode');
  $('nav-admin').style.display = 'none';
  $('nav-client').style.display = 'flex';
  $('side-foot').style.display = '';
  $('bnav').style.display = ''; // 交还 CSS 断点控制（HTTP_MODE 无管理端入口，无冲突）
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

/** 标题栏管理端入口：本机服务端恒第一，可管理端点/扇出按名称排序；无项置灰 */
async function refreshAdminEntry() {
  const items = [];
  try {
    const st = await invoke('server_status');
    if (st && st.running) items.push({ kind: 'local', label: '本机服务端', sub: '内嵌端点' });
  } catch (e) {}
  const nodes = window._nodes || [];
  const remotes = [];
  for (const n of nodes) {
    if (n.admin_console && n.status === 'Connected') {
      remotes.push({ kind: 'node', id: n.node_id, label: n.node_name + (n.username ? ' · ' + n.username : ''), sub: n.addr });
    }
    for (const m of (n.manageable || [])) {
      if (n.status === 'Connected') {
        remotes.push({ kind: 'up', id: n.node_id, up: m.node_name, label: m.node_name, sub: '扇出 · 经 ' + n.node_name });
      }
    }
  }
  remotes.sort((a, b) => a.label.localeCompare(b.label, 'zh'));
  items.push(...remotes);
  const btn = $('btn-admin');
  btn.classList.toggle('disabled', !items.length);
  const menu = $('admin-menu');
  menu.innerHTML = items.length
    ? items.map((it, i) =>
        '<button data-aitem="' + i + '">' + AgIcon('fingerprint', 13) + '<span class="aitem-label">' + esc(it.label) + '</span><span class="aitem-sub">' + esc(it.sub) + '</span></button>'
      ).join('')
    : '<button disabled>暂无可管理端点</button>';
  menu._items = items;
}

function initAdminMode() {
  $('nav-admin-back').onclick = exitAdmin;
  document.querySelectorAll('#nav-admin .nav-item[data-aview]').forEach(n => {
    n.onclick = () => adminNavActivate(n.dataset.aview);
  });
  // 内嵌管理端（SPA）toast 统一接入灵动岛（origin 校验，只收当前管理 iframe）
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

/* ================= 控制台通道（管理此端点；内嵌进主窗口） ================= */
async function openNodeConsole(nodeId) {
  const n = (window._nodes || []).find(x => x.node_id === nodeId);
  const label = n ? n.node_name + (n.username ? ' · ' + n.username : '') : nodeId;
  await enterAdmin(nodeId, null, label);
}

/* ================= 接入链接导入 ================= */
async function importUrl(url, btn) {
  url = (url || '').trim();
  if (!url) { toast(T('err-need-url'), 'err'); return; }
  if (!url.startsWith('agilenet://connect?')) { toast(T('err-bad-url'), 'err'); return; }
  try {
    const input = await invoke('parse_connect_url', { url });
    if (input.admin) toast('该链接为管理版：连接后可在端点卡片管理此端点', 'info');
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

/* ================= 代理控制 ================= */
/* 本地代理端口：运行中以 proxy_status 为准；未运行取本地保存值（默认 57890）。
   端口修改走代理卡监听行 inline-edit（bindInlineEdit），变更即重启代理生效。 */
let PROXY_ST = { running: false, port: 0 };
let proxyAddrEdit = null;
function proxyPort() {
  if (PROXY_ST.running && PROXY_ST.port) return PROXY_ST.port;
  const p = parseInt(localStorage.getItem('ag_proxy_port') || '57890', 10);
  return p >= 1 && p <= 65535 ? p : 57890;
}
function validPort(v) {
  if (!/^\d+$/.test(v)) return '端口须为 1-65535 的数字';
  const p = parseInt(v, 10);
  return (p >= 1 && p <= 65535) ? null : '端口须为 1-65535';
}
async function refreshProxy() {
  try {
    const st = await invoke('proxy_status');
    PROXY_ST = st;
    // 运行中的实际端口同步为本地基准（外部变更也能对齐）
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
    // 侧栏底部代理状态行（与灵动岛同一数据源）
    setText('sf-status', st.running ? '代理 127.0.0.1:' + st.port : '代理已停止');
    // 仪表盘代理卡：开关态 / 状态徽标 / 监听地址（inline-edit 自行变更检测）
    if ($('d-proxy').checked !== st.running) $('d-proxy').checked = st.running;
    setHtml('d-proxy-badge', st.running ? '<span class="badge b-ok">运行中</span>' : '<span class="badge b-gray">未启动</span>');
    if (proxyAddrEdit) proxyAddrEdit.refresh();
    const hint = st.running
      ? (CUR_PROXY_MODE === 'system'
        ? '已接管系统代理 127.0.0.1:' + st.port + '，浏览器即开即用'
        : '本地代理运行中，应用手动指向 127.0.0.1:' + st.port + ' 即可')
      : '系统代理：自动接管系统流量（推荐）；本地代理：仅监听端口，需手动配置应用';
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

/* ================= 仪表盘：扇入卡（已连接 / 已保存概览 + 流量趋势） ================= */
// 扇入流量速率序列（list_nodes 每次轮询累一点；计数为当前会话语义，重连归零按新基准）
let _tfLast = null, _tfSeries = [];
function trackFaninTraffic(nodes) {
  const up = nodes.reduce((s, n) => s + (n.bytes_up || 0), 0);
  const down = nodes.reduce((s, n) => s + (n.bytes_down || 0), 0);
  const total = up + down;
  if (_tfLast !== null) {
    let delta = total - _tfLast;
    if (delta < 0) delta = total; // 会话重连计数归零：负差按新基准
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
  setText('d-fanin-val', conn + ' 已连接');
  setText('d-fanin-sub', saved + ' 个已保存' + (trying ? ' · ' + trying + ' 个连接中/重连中' : ''));
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

/* ================= 扇入列表（已保存扇入为主体 + 未保存的活跃连接；连接/断开/导出/删除） ================= */
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
  // 未保存的活跃连接（手动连接未勾选保存凭据）：附在已保存扇入之后，仅可断开/管理
  const savedKeys = new Set(creds.map(([k]) => k));
  const unsaved = (window._nodes || []).filter(n => !savedKeys.has(n.node_id));
  const live = (st) => st === 'Connected' || st === 'Connecting' || st === 'Reconnecting';
  const match = (name, username, addr, st) => !f ||
    name.toLowerCase().includes(f) || (username || '').toLowerCase().includes(f) ||
    addr.toLowerCase().includes(f) || (st ? statusText(st) : '未连接').includes(f);
  const shownCreds = creds.filter(([key, c]) =>
    match(key.includes('@') ? key.slice(0, key.indexOf('@')) : key, c.username, c.addr, statusMap[key]));
  const shownUnsaved = unsaved.filter(n => match(n.node_name, n.username, n.addr, n.status));
  if (!shownCreds.length && !shownUnsaved.length) {
    list.innerHTML = '<div class="empty">' + (f ? '无匹配结果' : T('no-creds')) + '</div>';
    return;
  }
  list.innerHTML = shownCreds.map(([key, c]) => {
    const st = statusMap[key];
    const n = nodeMap[key];
    const badge = st ? statusBadgeHtml(st) : '<span class="badge b-gray">未连接</span>';
    const mainBtn = st === 'Connected'
      ? '<button class="ghost small" data-act="disconnect" data-key="' + esc(key) + '">断开</button>'
      : '<button class="small" data-act="reconnect" data-key="' + esc(key) + '">' + (st ? '重连' : '连接') + '</button>';
    const epName = key.includes('@') ? key.slice(0, key.indexOf('@')) : key;
    return '<div class="node-card' + (live(st) ? '' : ' down') + '"><div class="info">' +
      '<div class="name">' + esc(epName) + ' <span class="dim">· ' + esc(c.username) + '</span> ' + badge + '</div>' +
      '<div class="addr mono">' + esc(c.addr) + (c.insecure ? ' · <span class="badge b-warn">insecure</span>' : '') + '</div>' +
      '</div><div class="card-actions">' +
      (n && n.admin_console && st === 'Connected' && !HTTP_MODE
        ? '<button class="ghost small" data-act="console" data-id="' + esc(key) + '">' + AgIcon('monitor', 13) + ' 管理</button>' : '') +
      mainBtn +
      '<button class="ghost small icon-btn" title="导出接入链接（复制到剪贴板）" data-act="export" data-key="' + esc(key) + '">' + AgIcon('share-2', 13) + '</button>' +
      '<button class="danger small icon-btn" title="删除该扇入" data-act="delcred" data-key="' + esc(key) + '">' + AgIcon('trash-2', 13) + '</button>' +
      '</div></div>';
  }).join('') + shownUnsaved.map(n =>
    '<div class="node-card' + (live(n.status) ? '' : ' down') + '"><div class="info">' +
    '<div class="name">' + esc(n.node_name) + (n.username ? ' <span class="dim">· ' + esc(n.username) + '</span>' : '') + ' ' + statusBadgeHtml(n.status) + ' <span class="badge b-gray">未保存</span></div>' +
    '<div class="addr mono">' + esc(n.addr) + '</div>' +
    '</div><div class="card-actions">' +
    (n.admin_console && n.status === 'Connected' && !HTTP_MODE
      ? '<button class="ghost small" data-act="console" data-id="' + esc(n.node_id) + '">' + AgIcon('monitor', 13) + ' 管理</button>' : '') +
    '<button class="danger small" data-act="disconnect" data-key="' + esc(n.node_id) + '">断开</button></div></div>'
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
  // 凭据导出含明文密码：Web 远程面需二次确认
  if (HTTP_MODE && !window.confirm('导出的接入链接包含明文密码，确定导出到剪贴板吗？')) return;
  try {
    const url = await invoke('export_credential', { key });
    await navigator.clipboard.writeText(url);
    toast('接入链接已复制到剪贴板（含明文密码，谨慎分享）', 'ok');
  } catch (e) { toast(friendlyError(e), 'err'); }
}
async function deleteCred(key, btn) {
  if (btn.dataset.confirm === '1') {
    try {
      await invoke('delete_credential', { key });
      toast('已删除保存的扇入', 'ok');
      refreshCreds();
    } catch (e) { toast(friendlyError(e), 'err'); }
    return;
  }
  btn.dataset.confirm = '1';
  const old = btn.innerHTML;
  btn.innerHTML = '<span style="font-size:11px">确认</span>';
  setTimeout(() => { if (btn.isConnected) { btn.dataset.confirm = ''; btn.innerHTML = old; } }, 2500);
}

/* ================= 扇出连接（内嵌节点 DB 管理，变更热生效） ================= */
let FO_EDIT_ID = null;
let FO_ITEMS = [];

function foBadge(c) {
  if (!c.enabled) return '<span class="badge b-off">已禁用</span>';
  const st = c.state;
  if (st === 'connected') return '<span class="badge b-ok">已连接</span>';
  if (st === 'connecting') return '<span class="badge b-warn"><span class="pulse"></span>连接中</span>';
  if (st === 'reconnecting') return '<span class="badge b-warn"><span class="pulse"></span>重连中</span>';
  if (st === 'disconnected') return '<span class="badge b-off">已断开</span>';
  return '<span class="badge b-gray">未启动</span>';
}

/** 权限组下拉：拉本机内嵌节点组清单（保留当前选择；失败不阻断列表） */
async function foLoadGroups() {
  try {
    const groups = await invoke('list_embedded_groups');
    const cur = $('fo-group').value;
    $('fo-group').innerHTML = '<option value="">不收敛（放行一切）</option>' +
      groups.map(g => '<option value="' + esc(g.id) + '">' + esc(g.name) + '</option>').join('');
    if (groups.some(g => g.id === cur)) $('fo-group').value = cur;
    agSelectRefresh($('fo-group'));
  } catch (e) { /* 组清单加载失败不阻断扇出列表 */ }
}

async function refreshUpstreams() {
  foLoadGroups();
  try {
    FO_ITEMS = await invoke('list_server_connectors');
  } catch (e) { $('fo-list').innerHTML = '<div class="empty">加载失败</div>'; return; }
  if (!FO_ITEMS.length) {
    $('fo-list').innerHTML = '<div class="empty">尚未配置扇出连接（添加后内嵌端点将扇出到目标端点）</div>';
    return;
  }
  $('fo-list').innerHTML = FO_ITEMS.map(c =>
    '<div class="node-card"><div class="info">' +
    '<div class="name">' + esc(c.name || c.upstream_addr) + ' ' + foBadge(c) + '</div>' +
    '<div class="addr mono">' + esc(c.upstream_addr) + ' · ' + esc(c.token_prefix) + ' · SNI ' + esc(c.sni_hostname) +
    (c.insecure ? ' · <span class="badge b-warn">insecure</span>' : '') +
    ' · 组 ' + (c.group_name ? esc(c.group_name) : '不收敛') + '</div>' +
    '</div><div class="card-actions">' +
    '<button class="ghost small" data-fo-edit="' + esc(c.id) + '">编辑</button>' +
    '<button class="danger small" data-fo-del="' + esc(c.id) + '">删除</button>' +
    '</div></div>'
  ).join('');
}

/* ---- 新建/编辑扇出模态（字段对齐管理端「新建扇出」；advertise 每行一条，逗号拼接入库） ---- */
function foOpenModal(c) {
  FO_EDIT_ID = c ? c.id : null;
  $('fo-modal-title').textContent = c ? '编辑扇出' : '新建扇出';
  $('fo-ok').textContent = c ? '保存' : '创建';
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
    if (!addr) { $('fo-err').textContent = '请填写目标地址'; return; }
    if (!FO_EDIT_ID && !token) { $('fo-err').textContent = '请填写 Relay Token'; return; }
    $('fo-err').textContent = '';
    try {
      if (FO_EDIT_ID) {
        await invoke('update_server_connector', { id: FO_EDIT_ID, name, upstreamAddr: addr, token, sniHostname: sni, insecure, groupId, advertise, remark });
        toast('扇出连接已更新（热生效）', 'ok');
      } else {
        await invoke('add_server_connector', { name, upstreamAddr: addr, token, sniHostname: sni, insecure, groupId, advertise, remark });
        toast('扇出连接已添加（热生效）', 'ok');
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
        toast('扇出连接已删除（热生效）', 'ok');
        if (FO_EDIT_ID === delBtn.dataset.foDel) foCloseModal();
        refreshUpstreams();
      } catch (err) { toast(friendlyError(err), 'err'); }
    }
  });
}

/* 仪表盘扇出卡：监听状态徽标 + 连通数 + API/Relay 地址简述（10s 轮询 + 变更后调用） */
async function renderDashFanout() {
  if (HTTP_MODE) return;
  let st = null, conns = [];
  try { st = await invoke('server_status'); } catch (e) {}
  try { conns = await invoke('list_server_connectors'); } catch (e) {}
  const running = !!(st && st.running);
  const total = conns.length;
  const ok = conns.filter(c => c.enabled && c.state === 'connected').length;
  setHtml('d-server-badge', running ? '<span class="badge b-ok">监听中</span>' : '<span class="badge b-gray">未开启</span>');
  setText('d-fanout-val', total ? ok + ' / ' + total + ' 连通' : '未扇出');
  setText('d-fanout-sub', running
    ? 'API ' + (st.api_addr || '-') + ' · Relay ' + (st.relay_addr || '-')
    : (total ? '扇出监听未开启 · ' + total + ' 条扇出已配置' : '扇出监听未开启'));
}
