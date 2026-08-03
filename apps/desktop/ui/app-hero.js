'use strict';
/* 从 app.js 拆分：中控台英雄卡 / 新手检查单 / 侧栏底部 / 网络检测（纯搬运，零逻辑变更） */

/* ---------- 侧栏底部状态区（订阅内核速率 + 代理状态；2s 轮询驱动，变更检测写入） ---------- */
function renderSideFoot() {
  const up = $('sf-up');
  if (!up) return;
  const running = !!window._subRunning;
  const r = SubTraffic.rates || { up: 0, down: 0 };
  // 显隐先行（不受变更检测拦截）
  up.style.display = running ? '' : 'none';
  $('sf-down').style.display = running ? '' : 'none';
  $('sf-idle').style.display = running ? 'none' : '';
  if (!running) return;
  setText('sf-up', fmtBytes(r.up) + '/s');
  setText('sf-down', fmtBytes(r.down) + '/s');
}

/* ================= 中控台英雄卡（竞品标杆：FlClash 大开关 + 速率曲线、Stash 中控台摘要） =================
   数据源：proxy_power / proxy_power_toggle（10s 主轮询；HTTP_MODE 回落 proxy_status+start/stop_proxy）；
   速率曲线吃 SubTraffic 2s 差分速率（60 点环形缓冲，同 tray.js down60/up60 思路，onTraffic 钩子驱动）；
   活跃连接 sub_connections active.length（10s 主轮询挂一次，1s 高频归日志视图）；
   当前模式读 proxy_power.on + window._rolesCache（initRoles 缓存 get_role_settings，各变更点同步更新）。
   anet 代理流量无计数器：内核未运行曲线区空态「订阅内核未运行，暂无速率数据」，不造假。全部签名对比。 */
const Hero = {
  power: null,          // { on, detail }：detail = '127.0.0.1:57890' / '已停止'
  down60: [], up60: [], // 60 点速率环形缓冲（B/s）
  _powerSig: '',
  async pollPower() {
    if (HTTP_MODE) {
      this.power = { on: PROXY_ST.running, detail: PROXY_ST.running ? '127.0.0.1:' + PROXY_ST.port : '已停止' };
    } else {
      try { this.power = await invoke('proxy_power'); } catch (e) { return; }
    }
    this.renderPower();
    this.renderMode(); // 模式文案随 power 即时翻转（运行中 ↔ 已停止）
  },
  renderPower() {
    const p = this.power;
    const on = !!(p && p.on);
    const tunLocked = !HTTP_MODE && TUN_ON;
    const clientOff = !$('r-client').checked;
    const sig = on + '|' + (p ? p.detail : '') + '|' + tunLocked + '|' + clientOff;
    if (sig === this._powerSig) return;
    this._powerSig = sig;
    const btn = $('btn-power');
    btn.classList.toggle('on', on);
    btn.disabled = tunLocked || clientOff;
    btn.style.opacity = (tunLocked || clientOff) ? '.45' : '';
    setText('hero-power-state', on ? '运行中 ' + p.detail : (p ? p.detail : '已停止'));
    const hint = tunLocked ? 'TUN 模式运行中，总开关不可用' : (clientOff ? '请先在首页开启扇入' : '');
    $('hero-power-hint').style.display = hint ? '' : 'none';
    setText('hero-power-hint', hint);
    btn.title = hint || '代理总开关';
  },
  async toggle() {
    const btn = $('btn-power');
    btn.disabled = true;
    try {
      if (HTTP_MODE) {
        if (PROXY_ST.running) await invoke('stop_proxy');
        else await invoke('start_proxy', { port: proxyPort() });
      } else {
        // TUN 运行中后端 Err「TUN 模式运行中，请先关闭 TUN」→ friendlyError 上岛
        this.power = await invoke('proxy_power_toggle');
        this.renderPower();
      }
    } catch (err) { toast(friendlyError(err), 'err'); }
    btn.disabled = false;
    this.pollPower();
    refreshProxy(); // 代理卡 / 灵动岛 / 侧栏底部同步
  },
  /* SubTraffic 2s 钩子：速率缓冲 + 双序列曲线（下行为主 --chart-down / 上行 --chart-up）+ 今日已用（含上下行拆分小字） */
  onTraffic() {
    const running = !!window._subRunning;
    const r = SubTraffic.rates || { up: 0, down: 0 };
    if (running) {
      this.down60.push(r.down); if (this.down60.length > 60) this.down60.shift();
      this.up60.push(r.up); if (this.up60.length > 60) this.up60.shift();
    } else if (this.down60.length) {
      this.down60 = []; this.up60 = []; // 内核停止即清缓冲：重启后曲线不拖旧尾巴
    }
    const chart = $('hero-chart'), empty = $('hero-chart-empty');
    chart.style.display = running ? '' : 'none';
    empty.style.display = running ? 'none' : '';
    odoSet($('hero-rate-down'), running ? fmtBytes(r.down) + '/s' : '-');
    odoSet($('hero-rate-up'), running ? fmtBytes(r.up) + '/s' : '-');
    const t = SubTraffic.data;
    odoSet($('hero-traffic'), running && t ? fmtBytes(t.up_total + t.down_total) : '-');
    setText('hero-traffic-split', running && t ? '↑ ' + fmtBytes(t.up_total) + ' · ↓ ' + fmtBytes(t.down_total) : '');
    if (!running) return;
    AgChart.sparkline(chart, [
      { name: '下行', values: this.down60.slice(), color: 'var(--chart-down)' },
      { name: '上行', values: this.up60.slice(), color: 'var(--chart-up)' },
    ]);
  },
  /* 活跃连接：10s 主轮询挂一次（sub_connections 的 1s 高频轮询归日志视图，不重复起） */
  async pollConns() {
    if (HTTP_MODE) return;
    let n = 0;
    try { n = ((await invoke('sub_connections')).active || []).length; } catch (e) { return; }
    odoSet($('hero-conns'), window._subRunning ? String(n) : '-');
  },
  /* 当前模式：proxy_power.on + _rolesCache（get_role_settings 前端缓存，变更点同步，不重复拉取）。
     映射：关→已停止；tun_mode→TUN · 出站（§2.5 互斥固定 rule）；否则 系统代理/本地代理 · 出站模式 */
  renderMode() {
    if (HTTP_MODE) { setText('hero-mode', '-'); return; }
    const on = !!(this.power && this.power.on);
    const r = window._rolesCache || {};
    const sub = { rule: '规则', global: '全局', direct: '直连' }[r.sub_mode || 'rule'] || '规则';
    setText('hero-mode', !on ? '已停止'
      : r.tun_mode ? 'TUN · ' + sub
      : (r.system_proxy !== false ? '系统代理' : '本地代理') + ' · ' + sub);
  },
  /* 10s 主轮询条目：先落总开关（Onboarding 步骤③依赖；pollPower 内已联动 renderPower/renderMode），再刷连接/检查单 */
  async tick10s() {
    await this.pollPower();
    this.pollConns();
    Onboarding.refresh();
  },
};
function initHero() {
  $('btn-power').onclick = () => Hero.toggle();
  Hero.onTraffic();  // 首帧空态/速率读数
  Hero.tick10s();
}

/* ================= 新手检查单（首次成功路径显性化；全部就绪 5s 后淡出隐藏） =================
   判定：① get_role_settings().subscription_feature ② list_subscriptions 非空
        ③ proxy_power.on（HTTP_MODE 回落 PROXY_ST）④ NetProbe.data 经出口（via）且未失败。
   localStorage ag_ob_dismissed / ag_ob_done 任一标记在 = 整张卡不渲染（display:none）。 */
const OB_STEPS = [
  { label: '激活订阅功能', desc: '设置页安装内核并激活，解锁订阅与节点页', goto: 'settings' },
  { label: '添加一个订阅', desc: '导入 Clash 系订阅链接，或拖拽 YAML 文件到订阅页', goto: 'subscription' },
  { label: '开启本地代理', desc: '点本页左侧总开关，系统流量经 AgileNet 分流', goto: '' },
  { label: '出口探测成功', desc: '网络检测卡验证流量真实经订阅节点出口', goto: '' },
];
const Onboarding = {
  _sig: '', _doneTimer: 0,
  dismissed() { return localStorage.getItem('ag_ob_dismissed') === '1' || localStorage.getItem('ag_ob_done') === '1'; },
  async refresh() {
    const card = $('ob-card');
    if (HTTP_MODE || this.dismissed()) { card.style.display = 'none'; return; }
    let settings = {}, subs = [];
    try { settings = await invoke('get_role_settings'); } catch (e) {}
    try { subs = await invoke('list_subscriptions'); } catch (e) {}
    let power = Hero.power;
    if (!power) { try { power = await invoke('proxy_power'); } catch (e) {} }
    const np = NetProbe.data;
    const done = [
      !!settings.subscription_feature,
      subs.length > 0,
      !!(power && power.on),
      !!(np && np.via && !np.fail),
    ];
    const all = done.every(Boolean);
    const sig = JSON.stringify(done);
    card.style.display = '';
    if (sig !== this._sig) {
      this._sig = sig;
      $('ob-list').innerHTML = OB_STEPS.map((s, i) =>
        '<div class="role-row">' +
        '<div class="role-info"><b><input type="checkbox" disabled' + (done[i] ? ' checked' : '') + '> ' + esc(s.label) + '</b>' +
        '<span class="hint">' + esc(s.desc) + '</span></div>' +
        (!done[i] && s.goto ? '<button class="ghost small" data-ob-goto="' + s.goto + '">去完成</button>' : '') +
        '</div>').join('');
    }
    if (all && !this._doneTimer) {
      setText('ob-title', '全部就绪');
      this._doneTimer = setTimeout(() => {
        localStorage.setItem('ag_ob_done', '1');
        card.style.transition = 'opacity .5s ease';
        card.style.opacity = '0';
        setTimeout(() => { card.style.display = 'none'; }, 500);
      }, 5000);
    }
  },
  init() {
    const card = $('ob-card');
    if (HTTP_MODE || this.dismissed()) { card.style.display = 'none'; return; }
    $('ob-dismiss').onclick = () => {
      localStorage.setItem('ag_ob_dismissed', '1');
      card.style.display = 'none';
    };
    // 「去完成」跳对应视图（事件委托，无内联事件）
    $('ob-list').addEventListener('click', (e) => {
      const b = e.target.closest('[data-ob-goto]');
      if (b) switchView(b.dataset.obGoto);
    });
    this.refresh();
  },
};

/* ================= 网络检测（出口 IP / 文字归属地 / 内网 IP） =================
   JS 侧缓存结果：30s 轮询 + 内核状态翻转/手动刷新时重探；签名对比，不变不重绘。
   订阅内核运行时经 mihomo mixed 出口探测（验证订阅代理真实生效），否则直连。 */
const NetProbe = {
  data: null,   // { ip, country, country_code, via } 或 { fail: true, via }
  lan: '',
  _sig: '',
  _busy: false,
  async refresh(force) {
    if (HTTP_MODE || (this._busy && !force)) return;
    this._busy = true;
    const via = !!window._subRunning;
    try {
      const r = await invoke('fetch_exit_ip', { viaProxy: via });
      this.data = { ip: r.ip, country: r.country, country_code: r.country_code, via };
    } catch (e) {
      this.data = { fail: true, via };
    }
    this._busy = false;
    this.render();
  },
  async refreshLan() {
    if (HTTP_MODE) return;
    try {
      const r = await invoke('lan_ip');
      this.lan = r.ip + (r.iface ? '（' + r.iface + '）' : '');
    } catch (e) { this.lan = ''; }
    this.render();
  },
  render() {
    const sig = JSON.stringify(this.data) + '|' + this.lan + '|' + window._subRunning;
    if (sig === this._sig) return;
    this._sig = sig;
    const d = this.data;
    const geo = (x) => [x.country_code, x.country].filter(Boolean).join(' · ');
    // 首页网络检测卡：失败仅显示「探测失败」，不占位报错
    setText('d-net-ip', !d ? '探测中…' : (d.fail ? '探测失败' : d.ip));
    setText('d-net-geo', !d ? '' : (d.fail
      ? (d.via ? '经 mihomo 出口探测失败' : '直连出口探测失败')
      : (geo(d) || '归属地未知') + ' · ' + (d.via ? '经 mihomo 出口' : '直连出口')));
    setText('d-net-lan', this.lan || '-');
    // 订阅页：内核运行时同显出口（验证 mihomo 是否代理成功），只采用经内核出口的探测结果
    if ($('sub-exit-ip')) {
      if (!window._subRunning) {
        setText('sub-exit-ip', '内核未运行');
        setText('sub-exit-geo', '');
      } else if (d && d.via && !d.fail) {
        setText('sub-exit-ip', d.ip);
        setText('sub-exit-geo', (geo(d) || '归属地未知') + ' · 经 mihomo 出口');
      } else if (d && d.via && d.fail) {
        setText('sub-exit-ip', '探测失败');
        setText('sub-exit-geo', '经 mihomo 出口探测失败');
      } else {
        setText('sub-exit-ip', '探测中…');
        setText('sub-exit-geo', '');
      }
    }
  },
};
