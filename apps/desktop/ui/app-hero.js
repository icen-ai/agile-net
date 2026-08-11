'use strict';
/* Split from app.js: dashboard hero card / onboarding checklist / sidebar footer / net probe (pure move, zero logic change) */

/* ---------- Sidebar footer status area (subscription kernel rates + proxy status; 2s polling driven, change detection writes) ---------- */
function renderSideFoot() {
  const up = $('sf-up');
  if (!up) return;
  const running = !!(window._subRunning || window._anetProxyOn);
  const r = SubTraffic.rates || { up: 0, down: 0 };
  // show/hide first (not blocked by change detection)
  up.style.display = running ? '' : 'none';
  $('sf-down').style.display = running ? '' : 'none';
  $('sf-idle').style.display = running ? 'none' : '';
  if (!running) return;
  setText('sf-up', fmtBytes(r.up) + '/s');
  setText('sf-down', fmtBytes(r.down) + '/s');
}

/* ================= Dashboard hero card (benchmarks: FlClash big switch + rate chart, Stash dashboard summary) =================
   Data source: proxy_power / proxy_power_toggle (10s main polling; HTTP_MODE falls back to proxy_status+start/stop_proxy);
   rate chart feeds on SubTraffic 2s delta rates (60-point ring buffer, same idea as tray.js down60/up60, onTraffic hook driven);
   active connections sub_connections active.length (hooked once into 10s main polling; 1s high-freq belongs to logs view);
   current mode reads proxy_power.on + window._rolesCache (initRoles caches get_role_settings, synced at each change point).
   anet proxy traffic has no counter: kernel stopped -> chart area empty state 「订阅内核未运行，暂无速率数据」, no faking. All signature-compared. */
/* Dashboard card off-state (content-surface v2): cards whose head switch is off dim to keep the visual field quiet;
   the head switch itself stays full-contrast (it is the turn-on entry). Wired in initHero (change delegation + first sync)
   and re-synced in Hero.tick10s (programmatic .checked reverts don't fire change events). */
function syncDashOff() {
  const grid = $('dash-grid');
  if (!grid) return;
  grid.querySelectorAll('.dcard').forEach(card => {
    const sw = card.querySelector('.dc-head input[type="checkbox"]');
    if (sw) card.classList.toggle('off', !sw.checked);
  });
}

const Hero = {
  power: null,          // { on, detail }: detail = '127.0.0.1:57890' / '已停止'
  down60: [], up60: [], // 60-point rate ring buffer (B/s)
  _powerSig: '',
  async pollPower() {
    if (HTTP_MODE) {
      this.power = { on: PROXY_ST.running, detail: PROXY_ST.running ? '127.0.0.1:' + PROXY_ST.port : AgI18n.t('common.stopped') };
    } else {
      try { this.power = await invoke('proxy_power'); } catch (e) { return; }
    }
    this.renderPower();
    this.renderMode(); // mode text flips with power immediately (运行中 ↔ 已停止)
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
    window._anetProxyOn = on; // rates/probe fallback source flag (mihomo-independent data plane)
    $('hero-card').classList.toggle('off', !on); // master card off-state: data zones dim, power key stays lit
    btn.disabled = tunLocked || clientOff;
    btn.style.opacity = (tunLocked || clientOff) ? '.45' : '';
    setText('hero-power-state', on ? AgI18n.t('common.running') + ' ' + p.detail : (p ? p.detail : AgI18n.t('common.stopped')));
    const hint = tunLocked ? AgI18n.t('hero.powerTunLocked') : (clientOff ? AgI18n.t('hero.powerNeedFanin') : '');
    $('hero-power-hint').style.display = hint ? '' : 'none';
    setText('hero-power-hint', hint);
    btn.title = hint || AgI18n.t('hero.powerTitle');
  },
  async toggle() {
    const btn = $('btn-power');
    btn.disabled = true;
    try {
      if (HTTP_MODE) {
        if (PROXY_ST.running) await invoke('stop_proxy');
        else await invoke('start_proxy', { port: proxyPort() });
      } else {
        // while TUN runs, backend Err「TUN 模式运行中，请先关闭 TUN」-> friendlyError onto Dynamic Island
        this.power = await invoke('proxy_power_toggle');
        this.renderPower();
      }
    } catch (err) { toast(friendlyError(err), 'err'); }
    btn.disabled = false;
    this.pollPower();
    refreshProxy(); // proxy card / Dynamic Island / sidebar footer sync
  },
  /* SubTraffic 2s hook: rate buffers + dual-series chart (down primary --chart-down / up --chart-up) + today usage (with up/down split subtext) */
  onTraffic() {
    const running = !!(window._subRunning || window._anetProxyOn); // rates flow from whichever data plane is up
    const r = SubTraffic.rates || { up: 0, down: 0 };
    if (running) {
      this.down60.push(r.down); if (this.down60.length > 60) this.down60.shift();
      this.up60.push(r.up); if (this.up60.length > 60) this.up60.shift();
    } else if (this.down60.length) {
      this.down60 = []; this.up60 = []; // clear buffers on kernel stop: chart won't drag a stale tail after restart
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
      { name: AgI18n.t('hero.down'), values: this.down60.slice(), color: 'var(--chart-down)' },
      { name: AgI18n.t('hero.up'), values: this.up60.slice(), color: 'var(--chart-up)' },
    ]);
  },
  /* Active connections: hooked once into 10s main polling (sub_connections 1s high-freq polling belongs to logs view; not duplicated) */
  /* Active connections: kernel's table while it runs; the anet inbound's counter otherwise (10s main polling) */
  async pollConns() {
    if (HTTP_MODE) return;
    if (window._subRunning) {
      let n = 0;
      try { n = ((await invoke('sub_connections')).active || []).length; } catch (e) { return; }
      odoSet($('hero-conns'), String(n));
      return;
    }
    if (window._anetProxyOn) {
      try {
        const t = await invoke('proxy_traffic');
        odoSet($('hero-conns'), String(t.active));
      } catch (e) { /* keep last reading */ }
      return;
    }
    odoSet($('hero-conns'), '-');
  },
  /* Current mode: proxy_power.on + _rolesCache (frontend cache of get_role_settings, synced at change points, no re-fetch).
     Mapping: off -> 已停止; tun_mode -> TUN · outbound (§2.5 mutual exclusion pins rule); else system proxy/local proxy · outbound mode */
  renderMode() {
    if (HTTP_MODE) { setText('hero-mode', '-'); return; }
    const on = !!(this.power && this.power.on);
    const r = window._rolesCache || {};
    const sub = { rule: AgI18n.t('sub.modeRule'), global: AgI18n.t('sub.modeGlobal'), direct: AgI18n.t('sub.modeDirect') }[r.sub_mode || 'rule'] || AgI18n.t('sub.modeRule');
    setText('hero-mode', !on ? AgI18n.t('common.stopped')
      : r.tun_mode ? AgI18n.t('hero.modeTun', { mode: sub })
      : (r.system_proxy !== false ? AgI18n.t('hero.modeSysProxy') : AgI18n.t('hero.modeLocalProxy')) + ' · ' + sub);
  },
  /* 10s main polling entry: settle main switch first (Onboarding step ③ depends on it; pollPower already cascades renderPower/renderMode), then refresh connections/checklist */
  async tick10s() {
    await this.pollPower();
    this.pollConns();
    this.renderRoles();
    Onboarding.refresh();
    syncDashOff(); // re-sync card off-states (programmatic .checked reverts by toggle handlers don't fire change)
  },
  /* Role overview bar: 4 compact role indicators (client/server/subscription/web) that jump to the toggle on click */
  _rolesSig: '',
  renderRoles() {
    if (HTTP_MODE) return;
    const r = window._rolesCache || {};
    const sig = JSON.stringify([r.client, r.server, r.subscription, r.web, r.subscription_feature, AgI18n.lang]);
    if (sig === this._rolesSig) return;
    this._rolesSig = sig;
    const bar = $('hero-roles'); if (!bar) return;
    const item = (on, label, view) => '<button class="role-pill' + (on ? ' on' : '') + '" data-goto="' + view + '">' +
      '<span class="role-dot' + (on ? ' on' : '') + '"></span>' + esc(label) + '</button>';
    bar.innerHTML =
      item(!!r.client, AgI18n.t('term.fanin'), 'connect') +
      item(!!r.server, AgI18n.t('term.fanout'), 'upstreams') +
      (r.subscription_feature ? item(!!r.subscription, AgI18n.t('term.subscription'), 'subscription') : '') +
      item(!!r.web, AgI18n.t('hero.roleWeb'), 'connect');
  },
};
function initHero() {
  $('btn-power').onclick = () => Hero.toggle();
  /* Dashboard card off-state: instant sync on any head-switch toggle (optimistic; tick10s re-syncs after programmatic reverts) */
  const grid = $('dash-grid');
  if (grid) grid.addEventListener('change', () => syncDashOff());
  syncDashOff();
  /* i18n: force re-render of this domain on language switch (signatures cleared so change detection won't block old-language text) */
  AgI18n.onChange(() => {
    Hero._powerSig = ''; Hero._rolesSig = ''; NetProbe._sig = ''; Onboarding._sig = '';
    Hero.pollPower(); Hero.onTraffic(); NetProbe.render(); Onboarding.refresh();
  });
  Hero.onTraffic();  // first-frame empty state / rate readings
  Hero.tick10s();
}

/* ================= Onboarding checklist (first-success path made explicit; fades out and hides 5s after all done) =================
   Checks: ① get_role_settings().subscription_feature ② list_subscriptions non-empty
           ③ proxy_power.on (HTTP_MODE falls back to PROXY_ST) ④ NetProbe.data via egress (via) and not failed.
   localStorage ag_ob_dismissed / ag_ob_done either flag set = whole card not rendered (display:none). */
const OB_STEPS = [
  { label: 'hero.ob1Label', desc: 'hero.ob1Desc', goto: 'settings' },
  { label: 'hero.ob2Label', desc: 'hero.ob2Desc', goto: 'subscription' },
  { label: 'hero.ob3Label', desc: 'hero.ob3Desc', goto: '' },
  { label: 'hero.ob4Label', desc: 'hero.ob4Desc', goto: '' },
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
      // Horizontal step band (v2): done steps get a filled check + grayed title; undone steps keep the 「去完成」 jump
      $('ob-list').innerHTML = OB_STEPS.map((s, i) =>
        '<div class="ob-step' + (done[i] ? ' done' : '') + '">' +
        '<span class="ob-check">' + AgIcon('check', 11) + '</span>' +
        '<div class="ob-text"><span class="ob-t">' + esc(AgI18n.t(s.label)) + '</span>' +
        '<span class="ob-d">' + esc(AgI18n.t(s.desc)) + '</span>' +
        (!done[i] && s.goto ? '<button class="ghost small" data-ob-goto="' + s.goto + '">' + AgI18n.t('hero.obGo') + '</button>' : '') +
        '</div></div>').join('');
    }
    if (all && !this._doneTimer) {
      setText('ob-title', AgI18n.t('hero.obAllDone'));
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
    // 「去完成」jumps to the matching view (event delegation, no inline events)
    $('ob-list').addEventListener('click', (e) => {
      const b = e.target.closest('[data-ob-goto]');
      if (b) switchView(b.dataset.obGoto);
    });
    this.refresh();
  },
};

/* ================= Net probe (egress IP / text geolocation / LAN IP) =================
   JS caches results: 30s polling + re-probe on kernel state flip / manual refresh; signature compare, no redraw when unchanged.
   While subscription kernel runs, probe via mihomo mixed egress (verify the subscription proxy truly works), else direct. */
const NetProbe = {
  data: null,   // { ip, country, country_code, via } or { fail: true, via }
  lan: '',
  _sig: '',
  _busy: false,
  async refresh(force) {
    if (HTTP_MODE || (this._busy && !force)) return;
    this._busy = true;
    // Egress probe path: kernel egress while it runs (verifies the subscription path), the anet local
    // proxy otherwise (verifies the real egress users' traffic takes); direct only when both are off
    const via = window._subRunning ? 'mihomo' : (window._anetProxyOn ? 'anet' : 'direct');
    try {
      const r = await invoke('fetch_exit_ip', { viaProxy: via !== 'direct' });
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
      this.lan = r.ip + (r.iface ? ' ' + T('common.paren', { n: r.iface }) : '');
    } catch (e) { this.lan = ''; }
    this.render();
  },
  render() {
    const sig = JSON.stringify(this.data) + '|' + this.lan + '|' + window._subRunning + '|' + !!window._anetProxyOn;
    if (sig === this._sig) return;
    this._sig = sig;
    const d = this.data;
    const geo = (x) => [x.country_code, x.country].filter(Boolean).join(' · ');
    const viaTxt = (v) => v === 'mihomo' ? AgI18n.t('hero.viaMihomo') : v === 'anet' ? AgI18n.t('hero.viaAnet') : AgI18n.t('hero.viaDirect');
    // home net-probe card: on failure show only 「探测失败」, no placeholder error
    setText('d-net-ip', !d ? AgI18n.t('hero.probeLoading') : (d.fail ? AgI18n.t('hero.probeFailed') : d.ip));
    setText('d-net-geo', !d ? '' : (d.fail
      ? (d.via === 'direct' ? AgI18n.t('hero.probeFailDirect') : AgI18n.t('hero.probeFailVia'))
      : (geo(d) || AgI18n.t('hero.geoUnknown')) + ' · ' + viaTxt(d.via)));
    setText('d-net-lan', this.lan || '-');
    // subscription page: while kernel runs also show egress (verify mihomo proxying works); only use probe results via kernel egress
    if ($('sub-exit-ip')) {
      if (!window._subRunning) {
        setText('sub-exit-ip', AgI18n.t('tun.kernelNotRunning'));
        setText('sub-exit-geo', '');
      } else if (d && d.via === 'mihomo' && !d.fail) {
        setText('sub-exit-ip', d.ip);
        setText('sub-exit-geo', (geo(d) || AgI18n.t('hero.geoUnknown')) + ' · ' + AgI18n.t('hero.viaMihomo'));
      } else if (d && d.via === 'mihomo' && d.fail) {
        setText('sub-exit-ip', AgI18n.t('hero.probeFailed'));
        setText('sub-exit-geo', AgI18n.t('hero.probeFailVia'));
      } else {
        setText('sub-exit-ip', AgI18n.t('hero.probeLoading'));
        setText('sub-exit-geo', '');
      }
    }
  },
};
