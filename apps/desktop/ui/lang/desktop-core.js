// desktop-core.js — dictionary shard for main-window core / logs view / startup sequence (app-core / app-logs / app.js).
// Load order: agi18n.js → aglang.js → this file (index.html loads via <script src>, before app-core.js).
// Reuses common.* / term.* from aglang.js (common.connected/save/edit, term.kernel/rule/fanout/logs/events, etc.);
// core.st-* keys carry over the legacy I18N table (the T(k) compat bridge in app-core.js resolves 'core.'+k; app-views etc. follow).
AgI18n.register({
  // ---- core.* endpoint/proxy states (carried over from legacy I18N table; st-connected reuses common.connected) ----
  'core.st-connecting': { zh: '连接中', en: 'Connecting' },
  'core.st-reconnecting': { zh: '重连中', en: 'Reconnecting' },
  'core.st-disconnected': { zh: '已断开', en: 'Disconnected' },
  'core.st-unreachable': { zh: '不可达', en: 'Unreachable' },
  'core.st-degraded': { zh: '部分网络不可达', en: 'Some networks unreachable' },
  'core.banner-degraded': { zh: '端点 {name} 网络不可达，正在自动重连…', en: 'Endpoint {name} unreachable, reconnecting…' },
  'core.banner-down': { zh: '端点 {name} 已离线，其网段当前不可达', en: 'Endpoint {name} is offline; its networks are unreachable' },
  'core.proxy-running': { zh: '代理运行中', en: 'Proxy running' },
  'core.proxy-stopped': { zh: '代理未启动', en: 'Proxy stopped' },
  'core.reconnecting-nodes': { zh: '正在自动重连 {n} 个已保存的扇入…', en: 'Reconnecting {n} saved fan-ins…' },
  'core.connected-toast': { zh: '已连接 {name}（下发规则 {n} 条）', en: 'Connected {name} ({n} rules)' },
  'core.proxy-on': { zh: '代理已启动', en: 'Proxy started' },
  'core.proxy-off': { zh: '代理已停止', en: 'Proxy stopped' },
  'core.btn-start-proxy': { zh: '启动代理', en: 'Start Proxy' },
  'core.btn-stop-proxy': { zh: '停止代理', en: 'Stop Proxy' },
  'core.err-need-url': { zh: '请粘贴接入链接', en: 'Please paste a connect URL' },
  'core.err-bad-url': { zh: '链接格式不正确，应以 agilenet://connect? 开头', en: 'Invalid URL: must start with agilenet://connect?' },
  'core.clip-ok': { zh: '已识别剪贴板中的接入链接', en: 'Connect URL detected in clipboard' },
  'core.clip-none': { zh: '剪贴板中没有接入链接', en: 'No connect URL in clipboard' },
  'core.clip-fail': { zh: '无法读取剪贴板', en: 'Cannot read clipboard' },
  'core.disconnected': { zh: '已断开', en: 'Disconnected' },
  'core.no-rules': { zh: '无生效规则', en: 'No active rules' },
  'core.no-creds': { zh: '尚未添加扇入', en: 'No fan-in saved' },
  // ---- core.* generic errors and hints (invoke bridge / friendlyError / dynamic island) ----
  'core.err-no-web': { zh: '该操作不支持 Web 远程调用', en: 'This operation is unavailable via Web remote' },
  'core.err-auth-expired': { zh: '未登录或会话已过期', en: 'Not logged in or session expired' },
  'core.err-request-failed': { zh: '请求失败 (code {code})', en: 'Request failed (code {code})' },
  'core.island-detail': { zh: '以下端点当前不可达，其网段流量不会进入隧道：', en: 'These endpoints are unreachable; their traffic bypasses the tunnel:' },
  'core.err-login': { zh: '账号或密码错误，请核对接入信息', en: 'Incorrect account or password; check your access info' },
  'core.err-not-client': { zh: '该账号不是客户端账号，请向管理员确认', en: 'Not a client account; confirm with your administrator' },
  'core.err-cert': { zh: '证书校验失败：请检查证书固定配置，或仅在受信网络开启 insecure', en: 'Certificate verification failed: check cert pinning, or enable insecure only on trusted networks' },
  'core.err-timeout': { zh: '连接超时：端点不可达或网络受限', en: 'Connection timed out: endpoint unreachable or network restricted' },
  'core.err-refused': { zh: '无法连接端点：地址/端口错误或端点未启动', en: 'Cannot connect to endpoint: wrong address/port, or endpoint not running' },
  'core.err-dns': { zh: '域名解析失败：请检查端点地址', en: 'DNS resolution failed: check the endpoint address' },
  'core.err-disabled': { zh: '账号已被禁用，请联系管理员', en: 'Account disabled; contact your administrator' },
  // ---- core.* relative time (fmtAgo) ----
  'core.ago-never': { zh: '未刷新', en: 'Not refreshed' },
  'core.ago-min': { zh: '{n} 分钟前', en: '{n} min ago' },
  'core.ago-hour': { zh: '{n} 小时前', en: '{n} hr ago' },
  'core.ago-day': { zh: '{n} 天前', en: '{n}d ago' },
  'core.ago-month': { zh: '{n} 个月前', en: '{n}mo ago' },

  // ---- logs.* logs view (four tabs: connections/logs/hits/events; latter two reuse term.logs/term.events) ----
  'logs.tab.conn': { zh: '连接', en: 'Connections' },
  'logs.tab.hits': { zh: '命中', en: 'Hits' },
  // empty states
  'logs.empty.conn': { zh: '内核未运行或暂无连接', en: 'Kernel not running or no connections' },
  'logs.empty.hits': { zh: '内核未运行或暂无命中记录', en: 'Kernel not running or no rule hits' },
  'logs.empty.ev': { zh: '暂无事件', en: 'No events' },
  'logs.empty.evDesc': { zh: '本机操作与系统事件会记录在这里', en: 'Local operations and system events are recorded here' },
  // event pills (kernel/rule/fan-out reuse term.kernel/term.rule/term.fanout; install/uninstall reuse app.install/app.uninstall)
  'logs.ev.role': { zh: '开关', en: 'Toggle' },
  'logs.ev.sysproxy': { zh: '系统代理', en: 'System Proxy' },
  'logs.ev.script': { zh: '脚本', en: 'Script' },
  'logs.ev.doctor': { zh: '诊断', en: 'Doctor' },
  // connection detail expanded rows (active/closed kept 2-char symmetric in zh; rule reuses term.rule)
  'logs.topo.local': { zh: '本机', en: 'Local' },
  'logs.conn.process': { zh: '进程', en: 'Process' },
  'logs.conn.started': { zh: '开始', en: 'Started' },
  'logs.conn.down': { zh: '累计 ↓', en: 'Total ↓' },
  'logs.conn.up': { zh: '累计 ↑', en: 'Total ↑' },
  'logs.conn.final': { zh: '未命中（最终出口）', en: 'No rule hit (final exit)' },
  'logs.conn.live': { zh: '活跃', en: 'Active' },
  'logs.conn.closed': { zh: '关闭', en: 'Closed' },
  // actions and feedback (context-menu entries are menu items, English Title Case)
  'logs.cleared': { zh: '日志已清空', en: 'Logs cleared' },
  'logs.hitsCleared': { zh: '命中记录已清空', en: 'Rule hits cleared' },
  'logs.ctx.kill': { zh: '强制打断', en: 'Force Close' },
  'logs.killed': { zh: '连接已打断', en: 'Connection closed' },
  'logs.ctx.direct': { zh: '直连该域名', en: 'Direct This Host' },
  'logs.ctx.sub': { zh: '走订阅该域名', en: 'Proxy This Host' },
  'logs.rule.direct': { zh: '已添加直连规则：{host}', en: 'Direct rule added: {host}' },
  'logs.rule.sub': { zh: '已添加经订阅规则：{host}', en: 'Subscription rule added: {host}' },

  // ---- app.* startup sequence / login / uninstall ----
  'app.loginFailed': { zh: '登录失败', en: 'Login failed' },
  'app.loginUnreachable': { zh: '无法连接管理服务', en: 'Cannot reach the management service' },
  'app.install': { zh: '安装', en: 'Install' },
  'app.uninstall': { zh: '卸载', en: 'Uninstall' },
  'app.uninstalling': { zh: '正在卸载…', en: 'Uninstalling…' },
  'app.err.fillAll': { zh: '请填写完整信息', en: 'Please fill in all fields' },
});
