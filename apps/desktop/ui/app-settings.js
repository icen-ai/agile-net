'use strict';
/* 从 app.js 拆分：三路角色开关 / 系统代理托管 / 设置页 / 自我诊断 / 同步与备份（纯搬运，零逻辑变更） */

/* ================= 三路角色开关 ================= */
let pwdResolver = null;

/** 强制设置管理密码弹窗（Promise 化；取消 resolve null） */
function askPassword(opts) {
  return new Promise((resolve) => {
    $('pwd-title').innerHTML = AgIcon('shield', 16) + ' ' + esc(opts.title);
    $('pwd-desc').textContent = opts.desc;
    $('pwd-user-row').style.display = opts.showUser ? 'block' : 'none';
    $('pwd-pass').value = ''; $('pwd-pass2').value = '';
    $('pwd-modal').style.display = 'flex';
    $('pwd-pass').focus();
    pwdResolver = resolve;
  });
}
function closePwdModal(result) {
  $('pwd-modal').style.display = 'none';
  if (pwdResolver) { const r = pwdResolver; pwdResolver = null; r(result); }
}
function applyClientRole(on) {
  $('role-banner').style.display = on ? 'none' : 'flex';
  const off = $('d-fanin-off');
  if (off) off.style.display = on ? 'none' : '';
}
async function refreshServerPanel() {
  let st = null;
  try { st = await invoke('server_status'); } catch (e) { return; }
  window._serverStatus = st;
  const on = $('r-server').checked || st.running;
  $('server-panel').style.display = on ? 'block' : 'none';
  $('sv-api').textContent = st.api_addr || '-';
  $('sv-relay').textContent = st.relay_addr || '-';
}

/* 扇出监听开关（扇出页 r-server 与仪表盘 d-server 双入口同一逻辑，状态互相同步） */
function syncServerSwitch(v) {
  $('r-server').checked = v;
  const d = $('d-server');
  if (d) d.checked = v;
}
async function serverToggle(on, el) {
  try {
    if (on) {
      // 首开强制设管理密码
      const st = await invoke('server_status');
      if (!st.has_admin) {
        el.checked = false;
        const cred = await askPassword({
          title: '设置服务端管理密码',
          desc: '首开服务端角色须先设置内嵌端点管理员，该密码用于登录控制台。',
          showUser: true,
        });
        if (!cred) return;
        await invoke('init_server_admin', { username: cred.user, password: cred.pass });
        el.checked = true;
        toast('管理员已创建', 'ok');
      }
    }
    await invoke('set_server_role', { enabled: on });
    syncServerSwitch(on);
    await refreshServerPanel();
    refreshAdminEntry();
    renderDashFanout();
    toast(on ? '服务端角色已开启（内嵌端点运行中）' : '服务端角色已关闭', 'ok');
  } catch (err) {
    syncServerSwitch(false);
    toast(friendlyError(err), 'err');
    refreshServerPanel();
    renderDashFanout();
  }
}
function refreshWebPanel() {
  const on = $('r-web').checked;
  $('web-panel').style.display = on ? 'block' : 'none';
  $('web-status').textContent = on ? '监听地址保存后生效；浏览器访问需输入管理密码' : '';
}
/* Web 远程面监听地址（inline-edit 数据源；initRoles 自 get_role_settings 载入） */
let WEB_LISTEN = '127.0.0.1:59291';
function validListenAddr(v) {
  const m = v.match(/^(.+):(\d+)$/);
  if (!m || !m[1].trim()) return '监听地址格式须为 IP:端口';
  const p = parseInt(m[2], 10);
  return (p >= 1 && p <= 65535) ? null : '端口须为 1-65535';
}
/* 代理卡监听行 / 远程卡监听地址：统一 inline-edit（显示 ip:port [修改] → 输入框 + [保存]） */
function initInlineEdits() {
  proxyAddrEdit = bindInlineEdit($('d-proxy-addr'), {
    get: () => '127.0.0.1:' + proxyPort(),
    editValue: () => String(proxyPort()),
    validate: validPort,
    set: async (v) => {
      const port = parseInt(v, 10);
      localStorage.setItem('ag_proxy_port', String(port));
      const st = await invoke('proxy_status');
      if (st.running && st.port !== port) {
        await invoke('stop_proxy');
        const actual = await invoke('start_proxy', { port });
        toast('端口已修改为 ' + actual + '，代理已重启生效', 'ok');
      } else {
        toast(st.running ? '端口未变更' : '端口已保存，下次启动代理生效', 'ok');
      }
      refreshProxy();
      refreshSysproxy();
    },
  });
  bindInlineEdit($('web-listen'), {
    get: () => WEB_LISTEN,
    validate: validListenAddr,
    set: async (v) => {
      await invoke('set_web_role', { enabled: $('r-web').checked, listen: v });
      WEB_LISTEN = v;
      toast('监听地址已保存', 'ok');
    },
  });
}
/* 悬浮球气泡通知行：悬浮球未开启时置灰禁用（跟随 s-float-ball 勾选态联动） */
function syncNotifyFloatRow() {
  const fb = $('s-float-ball'), row = $('row-notify-float'), sw = $('s-notify-float');
  if (!fb || !row || !sw) return;
  row.style.opacity = fb.checked ? '' : '.5';
  sw.disabled = !fb.checked;
}
async function initRoles() {
  let settings = { client: true, server: false, web: false, web_listen: '127.0.0.1:59291' };
  try { settings = await invoke('get_role_settings'); } catch (e) {}
  window._rolesCache = settings; // Hero 当前模式摘要数据源（system_proxy/tun_mode/sub_mode；各变更点同步更新，不重复拉取）
  $('r-client').checked = settings.client;
  $('r-server').checked = settings.server;
  $('d-server').checked = settings.server;
  $('r-web').checked = settings.web;
  // TUN 初值（详细状态由 refreshTun 轮询同步；此处先落开关）
  TUN_UPSTREAM = settings.external_upstream || TUN_UPSTREAM;
  $('tun-mode').checked = !!settings.tun_mode;
  const subMode = settings.sub_mode || 'rule';
  $('sub-mode').value = subMode;
  $('sub-mode').dataset.prev = subMode;
  applySubFeature(!!settings.subscription_feature);
  // 设置页本机开关初值（系统代理锁定 / 桌面悬浮球 / 悬浮球气泡通知 / 性能模式）
  $('s-sysproxy-lock').checked = !!settings.sysproxy_lock;
  $('s-float-ball').checked = !!settings.float_ball;
  $('s-notify-float').checked = !!settings.notify_float_ball;
  syncNotifyFloatRow();
  // 性能模式：get_role_settings().reduce_effects 校正启动时 localStorage 预应用的值
  const reduceFx = !!settings.reduce_effects;
  $('s-reduce-effects').checked = reduceFx;
  localStorage.setItem('ag_reduce_fx', reduceFx ? '1' : '0');
  applyReduceEffects(reduceFx);
  WEB_LISTEN = settings.web_listen;
  applyClientRole(settings.client);
  refreshServerPanel();
  refreshWebPanel();

  $('r-client').onchange = async (e) => {
    try {
      await invoke('set_client_role', { enabled: e.target.checked });
      applyClientRole(e.target.checked);
      toast(e.target.checked ? '扇入已开启' : '扇入已停用（已断开全部端点）', 'ok');
      if (e.target.checked) { refreshNodes(true); refreshProxy(); refreshCreds(); }
    } catch (err) {
      e.target.checked = !e.target.checked;
      toast(friendlyError(err), 'err');
    }
  };

  $('r-server').onchange = (e) => serverToggle(e.target.checked, e.target);
  $('d-server').onchange = (e) => serverToggle(e.target.checked, e.target);

  $('r-web').onchange = async (e) => {
    const on = e.target.checked;
    try {
      if (on && !(await invoke('has_web_password'))) {
        e.target.checked = false;
        const cred = await askPassword({
          title: '设置 Web 远程面管理密码',
          desc: '开启 Web 远程面前须先设置管理密码；从浏览器访问本机管理界面时需输入。',
          showUser: false,
        });
        if (!cred) return;
        await invoke('set_web_password', { password: cred.pass });
        e.target.checked = true;
        toast('管理密码已设置', 'ok');
      }
      await invoke('set_web_role', { enabled: on, listen: WEB_LISTEN || null });
      refreshWebPanel();
      toast(on ? 'Web 远程面已开启' : 'Web 远程面已关闭', 'ok');
    } catch (err) {
      e.target.checked = !on;
      toast(friendlyError(err), 'err');
    }
  };

  $('btn-open-console').onclick = () => enterAdmin(null, null, '本机服务端');

  /* 设置页本机开关：锁定系统代理 / 桌面悬浮球（失败回滚勾选） */
  $('s-sysproxy-lock').onchange = async (e) => {
    const on = e.target.checked;
    try {
      await invoke('set_sysproxy_lock', { on });
      if (window._rolesCache) window._rolesCache.sysproxy_lock = on;
      toast(on ? '已锁定系统代理（被抢占将自动收回）' : '已解锁系统代理', 'ok');
    } catch (err) {
      e.target.checked = !on;
      toast(friendlyError(err), 'err');
    }
  };
  $('s-float-ball').onchange = async (e) => {
    const on = e.target.checked;
    try {
      await invoke('set_float_ball', { on });
      toast(on ? '桌面悬浮球已开启' : '桌面悬浮球已关闭', 'ok');
    } catch (err) {
      e.target.checked = !on;
      toast(friendlyError(err), 'err');
    }
    syncNotifyFloatRow(); // 悬浮球关闭时气泡通知行置灰禁用
  };
  $('s-notify-float').onchange = async (e) => {
    const on = e.target.checked;
    try {
      await invoke('set_notify_float_ball', { on });
      toast(on ? '悬浮球气泡通知已开启' : '悬浮球气泡通知已关闭（事件仍记录在日志页事件签）', 'ok');
    } catch (err) {
      e.target.checked = !on;
      toast(friendlyError(err), 'err');
    }
  };
  $('s-reduce-effects').onchange = async (e) => {
    const on = e.target.checked;
    try {
      await invoke('set_reduce_effects', { on });
      applyReduceEffects(on);
      localStorage.setItem('ag_reduce_fx', on ? '1' : '0');
      toast(on ? '性能模式已开启（毛玻璃与动画特效已关闭）' : '性能模式已关闭', 'ok');
    } catch (err) {
      e.target.checked = !on;
      toast(friendlyError(err), 'err');
    }
  };

  $('pwd-cancel').onclick = () => closePwdModal(null);
  $('pwd-ok').onclick = () => {
    const user = $('pwd-user').value.trim();
    const p1 = $('pwd-pass').value, p2 = $('pwd-pass2').value;
    if ($('pwd-user-row').style.display !== 'none' && !user) { toast('请填写管理员账号', 'err'); return; }
    if (p1.length < 10) { toast('管理密码至少 10 位', 'err'); return; }
    if (p1 !== p2) { toast('两次输入的密码不一致', 'err'); return; }
    closePwdModal({ user, pass: p1 });
  };
}

/* ================= 系统代理托管 ================= */
let _spConflict = false;
let CUR_PROXY_MODE = 'system'; // system=接管系统代理（默认） / local=仅监听端口
async function refreshSysproxy() {
  let st;
  try { st = await invoke('sysproxy_status'); } catch (e) { return; }
  CUR_PROXY_MODE = st.managed ? 'system' : 'local';
  document.querySelectorAll('#proxy-mode .group-tab').forEach(b =>
    b.classList.toggle('active', b.dataset.proxyMode === CUR_PROXY_MODE));
  const banner = $('sysproxy-banner');
  // TUN 模式下冲突由后端巡检 30s 内自动收回（§2.6），不打扰用户
  if (st.managed && st.conflict && !TUN_ON) {
    banner.style.display = 'flex';
    $('sysproxy-banner-text').textContent = '系统代理已被外部修改（当前 ' + (st.current || '未启用') + '，期望 ' + st.expected + '）';
    if (!_spConflict) { _spConflict = true; toast('系统代理已被外部修改，可在「首页」收回', 'err'); }
  } else {
    banner.style.display = 'none';
    _spConflict = false;
  }
}
function initSysproxy() {
  $('proxy-mode').addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-proxy-mode]');
    if (!btn || btn.classList.contains('active')) return;
    try {
      if (btn.dataset.proxyMode === 'system') {
        // 代理未启动则先按当前端口启动（后端 set_system_proxy 亦会兜底拉起）
        const st = await invoke('proxy_status');
        if (!st.running) {
          await invoke('start_proxy', { port: proxyPort() });
        }
        await invoke('set_system_proxy', { enabled: true });
        toast('已切换到系统代理（自动接管系统流量）', 'ok');
      } else {
        await invoke('set_system_proxy', { enabled: false });
        toast('已切换到本地代理（手动指向 127.0.0.1:' + proxyPort() + '）', 'ok');
      }
      if (window._rolesCache) window._rolesCache.system_proxy = btn.dataset.proxyMode === 'system';
      refreshSysproxy();
      refreshProxy();
    } catch (err) { toast(friendlyError(err), 'err'); }
  });
  $('btn-sysproxy-reclaim').onclick = async () => {
    try { await invoke('reclaim_sysproxy'); toast('已收回系统代理', 'ok'); refreshSysproxy(); }
    catch (err) { toast(friendlyError(err), 'err'); }
  };
}

/* ================= 自我诊断（run_doctor 逐项扫描；逐项淡入展示，fixed 项标注「已自动修复」） ================= */
const DOCTOR_PILL = {
  ok: ['pill-ok', '正常'], info: ['pill-dim', '提示'], warn: ['pill-warn', '警告'],
  err: ['pill-danger', '错误'], fixed: ['pill-ok', '已自动修复'],
};
function doctorPill(status) {
  const p = DOCTOR_PILL[status] || DOCTOR_PILL.info;
  return '<span class="pill ' + p[0] + '">' + p[1] + '</span>';
}
function doctorSectionHtml(sec) {
  return '<div style="margin-bottom:4px"><b>' + esc(sec.title) + '</b></div>' +
    '<div class="role-list">' +
    (sec.items || []).map(it =>
      '<div class="role-row" style="align-items:flex-start;padding:6px 0">' +
      '<div class="role-info"><b>' + doctorPill(it.status) + ' ' + esc(it.label) + '</b>' +
      (it.detail ? '<span class="hint">' + esc(it.detail) + '</span>' : '') +
      (it.suggestion ? '<span class="hint" style="opacity:.65">' + esc(it.suggestion) + '</span>' : '') +
      '</div></div>').join('') +
    '</div>';
}
function doctorSummaryHtml(res) {
  const sum = res.summary || {};
  const pills = [];
  if (sum.ok) pills.push('<span class="pill pill-ok">通过 ' + sum.ok + '</span>');
  if (sum.warn) pills.push('<span class="pill pill-warn">警告 ' + sum.warn + '</span>');
  if (sum.err) pills.push('<span class="pill pill-danger">错误 ' + sum.err + '</span>');
  if (sum.fixed) pills.push('<span class="pill pill-ok">已修复 ' + sum.fixed + '</span>');
  const dur = typeof res.duration_ms === 'number'
    ? (res.duration_ms >= 1000 ? (res.duration_ms / 1000).toFixed(1) + 's' : res.duration_ms + 'ms') : '';
  return (pills.join('') || '<span class="pill pill-dim">无检查项</span>') +
    (dur ? '<span class="hint" style="margin-top:0">耗时 ' + esc(dur) + '</span>' : '');
}
/* 块级淡入辅助（流式与整渲共用） */
function doctorFadeIn(el, delay) {
  el.style.opacity = '0';
  el.style.transform = 'translateY(4px)';
  el.style.transition = 'opacity .3s ease, transform .3s ease';
  setTimeout(() => {
    if (!el.isConnected) return;
    el.style.opacity = '1';
    el.style.transform = 'translateY(0)';
  }, delay || 0);
}
async function runDoctor() {
  const btn = $('btn-doctor-run');
  const panel = $('doctor-panel');
  btn.disabled = true;
  panel.style.display = '';
  panel.innerHTML = '<div class="hint" style="margin-top:10px"><span class="spinner"></span>正在准备诊断…</div>';
  let unlisten = [], streamed = false;
  const cleanup = () => { unlisten.forEach(u => { try { u && u(); } catch (e) {} }); unlisten = []; };
  try {
    if (TAURI && TAURI.event) {
      // 流式：begin 带检查节计划渲染骨架（逐节「诊断中…」），section 事件到达即原位替换
      unlisten.push(await TAURI.event.listen('ag-doctor-begin', (ev) => {
        const plan = ev.payload || [];
        panel.innerHTML = '<div class="doctor-block" id="doctor-summary" style="display:flex;gap:6px;align-items:center;flex-wrap:wrap"></div>' +
          plan.map(p =>
            '<div class="doctor-block" data-sec="' + esc(p[0]) + '" style="margin-top:14px">' +
            '<div style="margin-bottom:4px"><b>' + esc(p[1]) + '</b></div>' +
            '<div class="hint" style="margin-top:0"><span class="spinner"></span>诊断中…</div></div>').join('');
        [...panel.querySelectorAll('.doctor-block')].forEach((b, i) => doctorFadeIn(b, i * 100));
      }));
      unlisten.push(await TAURI.event.listen('ag-doctor-section', (ev) => {
        const sec = ev.payload;
        if (!sec || !sec.id) return;
        const slot = panel.querySelector('.doctor-block[data-sec="' + sec.id + '"]');
        if (!slot) return; // begin 未到时忽略，最终整体渲染兜底
        streamed = true;
        slot.innerHTML = doctorSectionHtml(sec);
        doctorFadeIn(slot, 0);
      }));
    }
    const res = await invoke('run_doctor');
    const sumEl = $('doctor-summary');
    if (streamed && sumEl) {
      // 流式完成：顶部落定汇总（骨架已逐节替换为真实结果）
      sumEl.innerHTML = doctorSummaryHtml(res);
      doctorFadeIn(sumEl, 0);
    } else {
      renderDoctor(res); // 无事件通路（或事件丢失）：整体渲染兜底
    }
  } catch (e) {
    panel.innerHTML = '<div class="hint" style="margin-top:10px">诊断服务未就绪（' + esc(friendlyError(e)) + '）</div>';
  } finally {
    cleanup();
    btn.disabled = false;
  }
}
function renderDoctor(res) {
  const panel = $('doctor-panel');
  const secs = res.sections || [];
  let html = '<div class="doctor-block" style="margin-top:12px;display:flex;gap:6px;align-items:center;flex-wrap:wrap">' +
    doctorSummaryHtml(res) + '</div>';
  html += secs.map(sec =>
    '<div class="doctor-block" style="margin-top:14px">' + doctorSectionHtml(sec) + '</div>').join('');
  panel.innerHTML = html;
  [...panel.querySelectorAll('.doctor-block')].forEach((b, i) => doctorFadeIn(b, i * 150));
}

/* ================= 设置 ================= */
async function loadSettings() {
  $('s-autoproxy').checked = PREFS.autoproxy;
  $('s-autoreconnect').checked = PREFS.autoreconnect;
  try {
    $('s-autostart').checked = await invoke('get_autostart');
  } catch (e) {}

  $('s-autoproxy').onchange = (e) => { PREFS.autoproxy = e.target.checked; };
  $('s-autoreconnect').onchange = (e) => { PREFS.autoreconnect = e.target.checked; };
  $('s-autostart').onchange = async (e) => {
    try {
      await invoke('set_autostart', { enabled: e.target.checked });
      toast(e.target.checked ? '已开启开机自启' : '已关闭开机自启', 'ok');
    } catch (err) {
      e.target.checked = !e.target.checked;
      toast(friendlyError(err), 'err');
    }
  };

  // 自我诊断（可重复点击重新诊断）
  $('btn-doctor-run').onclick = runDoctor;

  // 同步与备份：通道切换显隐配置区；PIN 输入数字过滤；各按钮绑定（内部均防重入）
  $('sync-target').onchange = () => syncShowTarget($('sync-target').value);
  $('sync-pin').addEventListener('input', e => { e.target.value = e.target.value.replace(/\D/g, ''); });
  $('btn-sync-save').onclick = syncSave;
  $('btn-sync-check').onclick = syncCheck;
  $('btn-sync-upload').onclick = syncUpload;
  $('btn-sync-restore').onclick = syncRestoreAsk;
  $('btn-sync-export').onclick = syncExportFile;
  $('btn-sync-import').onclick = syncImportAsk;
  $('sync-restore-cancel').onclick = () => { $('sync-restore-modal').style.display = 'none'; };
  $('sync-restore-ok').onclick = syncRestoreDo;
}

/* ================= 同步与备份（WebDAV/S3/手动文件；PIN 不落盘，每次操作取卡上输入框） =================
   后端 apps/desktop/src/sync.rs：按版本号比对新旧（上传 = max(远端,本地)+1）；恢复/导入成功后 500ms 应用自动重启。
   set_sync_config 入参为嵌套结构 {target, webdav:{url,user,pass}, s3:{endpoint,bucket,ak,sk,region,prefix}, pin_set}，
   pass/sk 传空串 = 保留原值（回显掩码如 **ab，重新编辑时留空即可）。 */
let SYNC_CFG = null;     // get_sync_config 缓存（掩码回显 / pin_set 保留 / 状态行）
let SYNC_RESTORE = null; // 恢复确认弹窗上下文 {kind:'remote', st} | {kind:'file', path}

function syncPin() { return $('sync-pin').value.trim(); }
/* PIN 校验：空 或正好 4 位数字；非法 toast 并返回 null（空串是有效值，勿用 falsy 判断） */
function syncPinValid() {
  const p = syncPin();
  if (p && !/^\d{4}$/.test(p)) { toast('PIN 须为 4 位数字或留空', 'err'); return null; }
  return p;
}
/* 后端 target 仅 none/webdav/s3；「手动导入导出」为前端纯文件通道，落盘 none（UI 选择另记 localStorage） */
function syncTargetBackend() {
  const v = $('sync-target').value;
  return v === 'file' ? 'none' : v;
}
function syncShowTarget(v) {
  $('sync-cfg-webdav').style.display = v === 'webdav' ? 'block' : 'none';
  $('sync-cfg-s3').style.display = v === 's3' ? 'block' : 'none';
  $('sync-cfg-file').style.display = v === 'file' ? 'block' : 'none';
  // 检查/上传/拉取仅网络通道有意义；文件通道用配置区内的导出/导入按钮
  const ops = v === 'webdav' || v === 's3';
  ['btn-sync-check', 'btn-sync-upload', 'btn-sync-restore'].forEach(id => { $(id).style.display = ops ? '' : 'none'; });
}
/* 按钮防重入：进行中 disabled + spinner，结束还原原 innerHTML（含图标） */
function syncBusy(btn, on, text) {
  if (!btn) return;
  btn.disabled = on;
  if (on) { btn._html = btn.innerHTML; btn.innerHTML = '<span class="spinner"></span>' + text; }
  else if (btn._html) { btn.innerHTML = btn._html; btn._html = null; }
}

/* 进设置视图时渲染：target 选中、字段回填（掩码进 placeholder）、状态行 */
async function loadSyncConfig() {
  if (HTTP_MODE) return; // 整卡已隐藏，且 Web 远程面无此命令
  let cfg;
  try { cfg = await invoke('get_sync_config'); } catch (e) { return; }
  SYNC_CFG = cfg;
  let ui = ['none', 'webdav', 's3'].includes(cfg.target) ? cfg.target : 'none';
  if (ui === 'none' && localStorage.getItem('ag_sync_target_ui') === 'file') ui = 'file';
  const sel = $('sync-target');
  if (sel.value !== ui) { sel.value = ui; agSelectRefresh(sel); }
  syncShowTarget(ui);
  $('sync-wd-url').value = cfg.webdav_url || '';
  $('sync-wd-user').value = cfg.webdav_user || '';
  $('sync-wd-pass').value = '';
  $('sync-wd-pass').placeholder = cfg.webdav_pass_mask ? '已配置（' + cfg.webdav_pass_mask + '），留空保持不变' : '留空保持不变';
  $('sync-s3-endpoint').value = cfg.s3_endpoint || '';
  $('sync-s3-bucket').value = cfg.s3_bucket || '';
  $('sync-s3-ak').value = cfg.s3_ak || '';
  $('sync-s3-sk').value = '';
  $('sync-s3-sk').placeholder = cfg.s3_sk_mask ? '已配置（' + cfg.s3_sk_mask + '），留空保持不变' : '留空保持不变';
  $('sync-s3-region').value = cfg.s3_region || '';
  $('sync-s3-prefix').value = cfg.s3_prefix || '';
  renderSyncState(cfg);
  $('sync-check-result').style.display = 'none';
}

/* 状态行：版本号走 odo 滚动（odoSet 内部签名对比，未变不动 DOM），其余文本变更检测写入 */
function renderSyncState(cfg) {
  odoSet($('sync-ver'), 'v' + (cfg.version || 0));
  let rest = cfg.last_upload_at
    ? ' · 上次上传 ' + fmtAgo(cfg.last_upload_at) + (cfg.last_device ? '（' + cfg.last_device + '）' : '')
    : ' · 尚未上传过存档';
  if (cfg.last_restore_at) rest += ' · 上次恢复 ' + fmtAgo(cfg.last_restore_at);
  setText('sync-state-rest', rest);
}

async function syncSave() {
  const pin = syncPin();
  if (pin && !/^\d{4}$/.test(pin)) { toast('PIN 须为 4 位数字或留空', 'err'); return; }
  const cfg = {
    target: syncTargetBackend(),
    webdav: { url: $('sync-wd-url').value.trim(), user: $('sync-wd-user').value.trim(), pass: $('sync-wd-pass').value },
    s3: {
      endpoint: $('sync-s3-endpoint').value.trim(), bucket: $('sync-s3-bucket').value.trim(),
      ak: $('sync-s3-ak').value.trim(), sk: $('sync-s3-sk').value,
      region: $('sync-s3-region').value.trim(), prefix: $('sync-s3-prefix').value.trim(),
    },
    // pin_set 仅 UI 提示位：本卡输满 4 位记 true；留空保留原值（PIN 本身不落盘；上传用过 PIN 后端也会置 true）
    pin_set: pin.length === 4 ? true : !!(SYNC_CFG && SYNC_CFG.pin_set),
  };
  if (cfg.target === 'webdav' && !cfg.webdav.url) { toast('请填写 WebDAV 地址', 'err'); return; }
  if (cfg.target === 's3' && (!cfg.s3.endpoint || !cfg.s3.bucket)) { toast('请填写 S3 Endpoint 与 Bucket', 'err'); return; }
  const btn = $('btn-sync-save');
  syncBusy(btn, true, '保存中…');
  try {
    await invoke('set_sync_config', { cfg });
    localStorage.setItem('ag_sync_target_ui', $('sync-target').value);
    toast('同步配置已保存', 'ok');
    await loadSyncConfig(); // 重拉刷新掩码与状态行
  } catch (e) { toast(friendlyError(e), 'err'); }
  syncBusy(btn, false);
}

/* relation → 状态行下方小字（检查远端 / 上传成功后渲染） */
function renderSyncCheck(st) {
  const el = $('sync-check-result');
  let s;
  switch (st.relation) {
    case 'newer': s = '远端 v' + st.remote_version + ' 更新（' + (st.remote_device || '未知设备') + ' · ' + fmtAgo(st.remote_at) + '）'; break;
    case 'same': s = '本地已是最新 v' + st.local_version; break;
    case 'older': s = '本地 v' + st.local_version + ' 比远端 v' + st.remote_version + ' 新'; break;
    case 'empty': s = '远端还没有存档'; break;
    case 'unconfigured': s = '请先保存通道配置'; break;
    case 'need-pin': s = '远端存档已加密，请输入 PIN'; break;
    default: s = st.relation;
  }
  el.textContent = s;
  el.style.display = '';
}

async function syncCheck() {
  const pin = syncPinValid(); if (pin === null) return;
  const btn = $('btn-sync-check');
  syncBusy(btn, true, '检查中…');
  try { renderSyncCheck(await invoke('sync_check', { pin })); }
  catch (e) { $('sync-check-result').style.display = 'none'; toast(friendlyError(e), 'err'); }
  syncBusy(btn, false);
}

async function syncUpload() {
  const pin = syncPinValid(); if (pin === null) return;
  const btn = $('btn-sync-upload');
  syncBusy(btn, true, '上传中…');
  try {
    const st = await invoke('sync_upload', { pin });
    toast('已上传 v' + st.local_version, 'ok');
    await loadSyncConfig(); // version 已 +1，状态行 odo 滚动更新
    renderSyncCheck(st);
  } catch (e) { toast(friendlyError(e), 'err'); }
  syncBusy(btn, false);
}

/* 拉取恢复：先 sync_check 再弹确认 modal；不可恢复的关系（无配置/无存档/缺 PIN）直接 toast 拦截 */
async function syncRestoreAsk() {
  const pin = syncPinValid(); if (pin === null) return;
  const btn = $('btn-sync-restore');
  syncBusy(btn, true, '检查中…');
  try {
    const st = await invoke('sync_check', { pin });
    if (st.relation === 'unconfigured') { toast('请先保存通道配置', 'err'); return; }
    if (st.relation === 'empty') { toast('远端还没有存档', 'err'); return; }
    if (st.relation === 'need-pin') { toast('远端存档已加密，请输入正确 PIN', 'err'); return; }
    openSyncRestoreModal({ kind: 'remote', st });
  } catch (e) { toast(friendlyError(e), 'err'); }
  finally { syncBusy(btn, false); }
}

/* 恢复确认弹窗：远端（版本对比 + older 黄色警告）与文件导入（来源文案改为文件路径）共用 */
function openSyncRestoreModal(req) {
  SYNC_RESTORE = req;
  const isRemote = req.kind === 'remote';
  setText('sync-restore-src', isRemote
    ? '来自 ' + ($('sync-target').value === 's3' ? 'S3' : 'WebDAV') + ' 远端存档'
    : '来自本地文件');
  setText('sync-restore-remote-k', isRemote ? '远端存档' : '存档文件');
  setText('sync-restore-remote', isRemote
    ? 'v' + req.st.remote_version + ' · ' + (req.st.remote_device || '未知设备') + ' · ' + fmtAgo(req.st.remote_at)
    : req.path);
  setText('sync-restore-local', 'v' + (isRemote ? req.st.local_version : (SYNC_CFG ? SYNC_CFG.version : 0)));
  $('sync-restore-warn').style.display = isRemote && req.st.relation === 'older' ? '' : 'none';
  $('sync-restore-err').textContent = '';
  syncBusy($('sync-restore-ok'), false); // 复开时还原（上次失败遗留 busy 态）
  $('sync-restore-modal').style.display = 'flex';
}

/* 确认恢复：成功后后端 500ms 自动重启应用，前端无需任何后续动作 */
async function syncRestoreDo() {
  if (!SYNC_RESTORE) return;
  const pin = syncPinValid(); if (pin === null) return;
  const btn = $('sync-restore-ok');
  syncBusy(btn, true, '正在恢复…');
  try {
    if (SYNC_RESTORE.kind === 'remote') await invoke('sync_restore', { pin });
    else await invoke('sync_import', { path: SYNC_RESTORE.path, pin });
  } catch (e) {
    syncBusy(btn, false);
    $('sync-restore-err').textContent = friendlyError(e);
  }
}

/* 文件通道导出：toast 显示完整路径；导出同样版本 +1，刷新状态行 */
async function syncExportFile() {
  const path = $('sync-file-export').value.trim();
  if (!path) { toast('请填写导出路径', 'err'); return; }
  const pin = syncPinValid(); if (pin === null) return;
  const btn = $('btn-sync-export');
  syncBusy(btn, true, '导出中…');
  try {
    await invoke('sync_export', { path, pin });
    toast('已导出到 ' + path, 'ok');
    await loadSyncConfig();
  } catch (e) { toast(friendlyError(e), 'err'); }
  syncBusy(btn, false);
}

/* 文件通道导入：同恢复确认流程（来源文案为文件路径） */
function syncImportAsk() {
  const path = $('sync-file-import').value.trim();
  if (!path) { toast('请填写导入路径', 'err'); return; }
  if (syncPinValid() === null) return;
  openSyncRestoreModal({ kind: 'file', path });
}
