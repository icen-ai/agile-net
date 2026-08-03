'use strict';
/* 从 app.js 拆分：日志视图 / 连接详情 / 事件中心（纯搬运，零逻辑变更） */

/* ================= 日志视图（订阅内核可观测：实时连接 / 实时日志 / 命中追踪） =================
   仅在本页打开时轮询（连接/日志 1s、命中 2s，单一定时器按页签分派），离开即停；
   连接表签名对比整表重绘，日志流增量追加（上限 500 行 DOM 裁剪），渲染防频闪。 */

/* ---- 日志行渲染（级别归一 + 关键字 mark.logv-hl 高亮；先 esc 再高亮，替换串同为转义文本） ---- */
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
  connSig: '', hitsSig: '', evSig: '',
  connMap: {},        // 最近一次连接数据 id → {c, live}（详情展开/重绘恢复的数据源）
  connDetailId: null, // 展开中的连接详情行 id（同时只开一行；行消失即收起）
  entries: [],      // 实时日志缓存（过滤变更时全量重渲染的数据源）
  logCursor: null,  // 已渲染最后一条 {time,level,payload}（增量游标；丢失 = 缓冲轮换，全量重绘）
  follow: true,     // 自动滚底（用户上滚暂停跟随，回底恢复）
  enter() {
    this.stop();
    this.tick = 0;
    this.pollNow();
    this.timer = setInterval(() => this.onTick(), 1000);
  },
  stop() { if (this.timer) { clearInterval(this.timer); this.timer = null; } },
  onTick() {
    this.tick++;
    if (this.tab === 'hits') { if (this.tick % 2 === 0) this.pollHits(); return; }
    if (this.tab === 'ev') { if (this.tick % 10 === 0) this.pollEvents(); return; } // 事件低频：10s
    if (this.tab === 'log') this.pollLogs();
    else this.pollConns();
  },
  pollNow() {
    if (this.tab === 'log') this.pollLogs();
    else if (this.tab === 'hits') this.pollHits();
    else if (this.tab === 'ev') this.pollEvents();
    else this.pollConns();
  },

  /* ---- 实时连接（1s；签名对比，活跃置顶 + 已关闭灰显在后，上限 100 行已关闭） ---- */
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
      body.innerHTML = '<tr><td colspan="7" class="empty">内核未运行或暂无连接</td></tr>';
      return;
    }
    body.innerHTML = act.map(c => connRowHtml(c, true)).join('') +
      closed.map(c => connRowHtml(c, false)).join('');
    this.restoreConnDetail(); // 整表重绘后恢复展开行（最新数据即详情实时刷新；行没了则收起）
  },

  /* 展开/收起连接详情（再点同一行或点其他行收起；同时只开一行） */
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
    if (!rec) { this.connDetailId = null; return; } // 行已消失：收起
    let anchor = null;
    $('lg-conn-body').querySelectorAll('tr[data-cid]').forEach(r => { if (r.dataset.cid === id) anchor = r; });
    if (!anchor) { this.connDetailId = null; return; }
    anchor.insertAdjacentHTML('afterend', connDetailRowHtml(rec.c, rec.live));
  },

  /* ---- 实时日志（1s；增量追加，缓冲轮换/过滤变更时全量重绘） ---- */
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
    if (!entries.length) { // 已清空或内核未运行
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

  /* ---- 命中追踪（2s；签名对比整表重绘） ---- */
  async pollHits() {
    if (HTTP_MODE) return;
    let hits;
    try { hits = await invoke('sub_rule_hits'); } catch (e) { return; }
    const sig = JSON.stringify(hits);
    if (sig === this.hitsSig) return;
    this.hitsSig = sig;
    const body = $('lg-hits-body');
    if (!hits || !hits.length) {
      body.innerHTML = '<tr><td colspan="5" class="empty">内核未运行或暂无命中记录</td></tr>';
      return;
    }
    body.innerHTML = hits.map(h =>
      '<tr><td class="mono">' + esc(h.rule || '—') + '</td>' +
      '<td class="mono">' + esc(h.payload || '—') + '</td>' +
      '<td class="mono">' + h.count + '</td>' +
      '<td class="mono">' + esc(h.last_host || '—') + '</td>' +
      '<td class="dim">' + esc(fmtAgo(h.last_seen)) + '</td></tr>').join('');
  },

  /* ---- 事件中心（低频：进页签拉一次 + onTick 10s + 手动刷新；签名对比，上限 50 条） ---- */
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
        '<div class="empty-t">暂无事件</div>' +
        '<div class="empty-d">本机操作与系统事件会记录在这里</div></div>';
      return;
    }
    list.innerHTML = evs.map(evRowHtml).join('');
  },
};

/* 事件类型 → pill 映射（未识别 kind 兜底 pill-dim + 原始 kind 名） */
const EV_KIND = {
  role_toggle: ['pill-dim', '开关'],
  kernel: ['pill-ok', '内核'],
  sysproxy: ['pill-warn', '系统代理'],
  custom_rule: ['pill-dim', '规则'],
  sub_script: ['pill-warn', '脚本'],
  doctor: ['pill-ok', '诊断'],
  install: ['pill-dim', '安装'],
  uninstall: ['pill-danger', '卸载'],
  connector: ['pill-dim', '扇出'],
};
/* 事件时间：今天 HH:MM:SS；非今天 MM-DD HH:MM */
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
  const k = EV_KIND[e.kind] || ['pill-dim', e.kind || '事件'];
  return '<div class="ev-row"><span class="ev-time">' + evTimeFmt(e.ts) + '</span>' +
    '<span class="pill ' + k[0] + '">' + esc(k[1]) + '</span>' +
    '<span class="ev-detail" title="' + esc(e.detail) + '">' + esc(e.detail) + '</span></div>';
}

/* 连接行 HTML：活跃行左 3px accent 条（var token，无硬编码色值），已关闭整行灰显 */
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

/* 链路迷你拓扑（纯 HTML flex，零依赖无 SVG）：本机 → chains 倒序各中继 → 目标 host
   （chains[0] 是出口，链路顺序 = 本机 + chains.slice().reverse() + host；chains 空则 本机→host 两点）。
   圆点语义色全走 var token（本机 accent / 中继 dim2 / 目标 ok-text），连线与右箭头用 --border2；
   节点名 10px 居中，超 8 字截断加省略号，全名挂 title。 */
function connTopoHtml(c) {
  const cut = (s) => s.length > 8 ? s.slice(0, 8) + '…' : s;
  const node = (name, color) =>
    '<div style="flex-shrink:0;display:flex;flex-direction:column;align-items:center;max-width:90px" title="' + esc(name) + '">' +
    '<span style="width:9px;height:9px;border-radius:50%;background:' + color + '"></span>' +
    '<span class="dim" style="margin-top:3px;font-size:10px;line-height:1.3;max-width:90px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(cut(name)) + '</span></div>';
  const link = '<div style="flex:1;min-width:24px;height:9px;display:flex;align-items:center">' +
    '<span style="flex:1;height:1px;background:var(--border2)"></span>' +
    '<span style="width:0;height:0;border-top:3.5px solid transparent;border-bottom:3.5px solid transparent;border-left:5px solid var(--border2)"></span></div>';
  const nodes = [['本机', 'var(--accent)']];
  (c.chains || []).slice().reverse().forEach(n => nodes.push([String(n), 'var(--dim2)']));
  nodes.push([c.host || '—', 'var(--ok-text)']);
  return '<div style="display:flex;align-items:flex-start;margin-bottom:7px">' +
    nodes.map((n, i) => (i ? link : '') + node(n[0], n[1])).join('') + '</div>';
}

/* 连接详情展开行（标杆 Surge：链路拓扑 + 两行内布局；样式全走内联，CSS 无此类）。
   拓扑行 = 本机 → 中继链 → 目标（connTopoHtml）；第一行 = 完整出站链 + 命中规则；
   第二行 = 进程 / 开始时间 / 累计流量 / 状态 pill。
   数据随 pollConns 整表重绘原位重插，即实时刷新。 */
function connDetailRowHtml(c, live) {
  const chains = (c.chains && c.chains.length) ? c.chains.join(' → ') : '—';
  const rule = c.rule
    ? esc(c.rule) + (c.rule_payload ? ' <span class="dim">' + esc(c.rule_payload) + '</span>' : '')
    : '<span class="dim">未命中（最终出口）</span>';
  const d = c.start ? new Date(c.start * 1000) : null;
  const pad = (n) => String(n).padStart(2, '0');
  const startTxt = d ? pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()) : '—';
  return '<tr class="conn-detail-row">' +
    '<td colspan="7" style="padding:8px 14px 10px;border-top:none">' +
    connTopoHtml(c) +
    '<div style="font-size:12px;line-height:1.7;word-break:break-all">' +
    '<span class="mono" style="font-size:11.5px">' + esc(chains) + '</span>' +
    '<span class="dim">　规则　</span>' + rule + '</div>' +
    '<div class="dim" style="margin-top:3px;font-size:12px;display:flex;gap:14px;flex-wrap:wrap;align-items:center">' +
    '<span>进程 ' + esc(c.process || '—') + '</span>' +
    '<span>开始 ' + startTxt + '</span>' +
    '<span>累计 ↓ ' + fmtBytes(c.download) + '</span>' +
    '<span>累计 ↑ ' + fmtBytes(c.upload) + '</span>' +
    '<span class="pill ' + (live ? 'pill-ok' : 'pill-dim') + '">' + (live ? '活跃' : '已关闭') + '</span>' +
    '</div></td></tr>';
}

/* 一键加规则：主机直连放行 / 经订阅出口（后端去 scheme/端口并幂等） */
async function addRuleForHost(host, target) {
  try {
    await invoke('sub_add_rule_for_host', { host, target });
    toast(target === 'direct' ? '已添加直连规则：' + host : '已添加经订阅规则：' + host, 'ok');
    refreshCustomRules(true);
  } catch (err) { toast(friendlyError(err), 'err'); }
}

function initLogs() {
  agTabsBind($('lg-tabs'), (key) => { LogsView.tab = key; LogsView.tick = 0; LogsView.pollNow(); });
  // 日志流跟随：上滚暂停自动滚底，回底恢复
  const view = $('lg-log-view');
  view.addEventListener('scroll', () => {
    LogsView.follow = view.scrollTop + view.clientHeight >= view.scrollHeight - 30;
  });
  // 过滤变更：以缓存 entries 全量重渲染
  $('lg-log-filter').addEventListener('input', () => LogsView.renderLogs(true));
  $('lg-log-level').addEventListener('change', () => LogsView.renderLogs(true));
  $('btn-lg-clear').onclick = async () => {
    try {
      await invoke('sub_clear_logs');
      LogsView.entries = [];
      LogsView.logCursor = null;
      view.innerHTML = '';
      toast('日志已清空', 'ok');
    } catch (err) { toast(friendlyError(err), 'err'); }
  };
  $('btn-hits-clear').onclick = async () => {
    try {
      await invoke('sub_clear_logs');
      LogsView.hitsSig = '';
      LogsView.pollHits();
      toast('命中记录已清空', 'ok');
    } catch (err) { toast(friendlyError(err), 'err'); }
  };
  // 事件中心手动刷新（清签名强制重拉重绘）
  $('btn-ev-refresh').onclick = () => { LogsView.evSig = ''; LogsView.pollEvents(); };
  // 连接行点击展开/收起详情（再点同一行或点其他行收起，同时只开一行）；
  // 详情行内点击/右键不外溢（不触发展开切换与行右键菜单）
  $('lg-conn-body').addEventListener('click', (e) => {
    if (e.target.closest('.conn-detail-row')) { e.stopPropagation(); return; }
    const tr = e.target.closest('tr[data-cid]');
    if (tr) LogsView.toggleConnDetail(tr.dataset.cid);
  });
  // 连接行右键菜单：强制打断（仅活跃）/ 直连该域名 / 走订阅该域名
  $('lg-conn-body').addEventListener('contextmenu', (e) => {
    if (e.target.closest('.conn-detail-row')) { e.preventDefault(); e.stopPropagation(); return; }
    const tr = e.target.closest('tr[data-cid]');
    if (!tr) return;
    e.preventDefault();
    e.stopPropagation();
    const id = tr.dataset.cid, host = tr.dataset.host;
    const items = [];
    if (tr.dataset.live === '1') {
      items.push({ label: '强制打断', danger: true, fn: async () => {
        try {
          await invoke('sub_close_connection', { id });
          toast('连接已打断', 'ok');
          LogsView.pollConns();
        } catch (err) { toast(friendlyError(err), 'err'); }
      } });
    }
    if (host) {
      if (items.length) items.push('-');
      items.push({ label: '直连该域名', fn: () => addRuleForHost(host, 'direct') });
      items.push({ label: '走订阅该域名', fn: () => addRuleForHost(host, 'subscription') });
    }
    if (items.length) ctxShow(e.clientX, e.clientY, items);
  });
}
