// aglang.js — AgileNet bilingual dictionary, single source for desktop GUI and admin UI.
// Loaded after agi18n.js; registers all entries via AgI18n.register().
// Wiki site uses the agi18n.js runtime with its own small inline dict instead.
//
// Writing conventions (both languages enforced on every entry):
// - zh: official tone, minimal length, symmetric at the same level
//   (menu items of one group share the same character count, e.g. the Home/Nodes/Rules/Logs/Settings items = 2 chars each).
//   Use established product terms (see the term.* entries below).
// - en: terminology first, faithful and concise; menus use Title Case, messages use sentence case.
//   Symmetry is nice-to-have but not forced.
// - Key namespaces: common.* (shared actions/states), desktop.*, admin.*, plus domain prefixes
//   (menu./settings./logs./hero./sub./tray./float./doctor./conn./sync./tun./sysproxy.).
// - Message templates use {name} placeholders (see AgI18n.t).
//
// Terminology glossary: the canonical zh <-> en mapping lives in the term.* entries below
// (Endpoint / Fan-out / Fan-in / Node / Rule / Group / Account / Token / Relay / Tunnel /
//  Proxy / Subscription / Kernel / Doctor / Logs / Events / Control Plane / System Proxy / Lock).
// Keep both languages consistent with it everywhere.
AgI18n.register({
  // ---- common actions (2-char zh symmetry) ----
  'common.save': { zh: '保存', en: 'Save' },
  'common.cancel': { zh: '取消', en: 'Cancel' },
  'common.confirm': { zh: '确认', en: 'Confirm' },
  'common.delete': { zh: '删除', en: 'Delete' },
  'common.edit': { zh: '编辑', en: 'Edit' },
  'common.add': { zh: '新增', en: 'Add' },
  'common.search': { zh: '搜索', en: 'Search' },
  'common.refresh': { zh: '刷新', en: 'Refresh' },
  'common.copy': { zh: '复制', en: 'Copy' },
  'common.enable': { zh: '启用', en: 'Enable' },
  'common.disable': { zh: '禁用', en: 'Disable' },
  'common.close': { zh: '关闭', en: 'Close' },
  'common.back': { zh: '返回', en: 'Back' },
  'common.export': { zh: '导出', en: 'Export' },
  'common.import': { zh: '导入', en: 'Import' },
  'common.reset': { zh: '重置', en: 'Reset' },
  'common.apply': { zh: '应用', en: 'Apply' },
  'common.retry': { zh: '重试', en: 'Retry' },
  'common.view': { zh: '查看', en: 'View' },
  'common.clear': { zh: '清空', en: 'Clear' },
  // ---- common states (2-char zh symmetry) ----
  'common.loading': { zh: '加载中', en: 'Loading' },
  'common.empty': { zh: '暂无数据', en: 'No data' },
  'common.success': { zh: '成功', en: 'Success' },
  'common.failed': { zh: '失败', en: 'Failed' },
  'common.running': { zh: '运行中', en: 'Running' },
  'common.stopped': { zh: '已停止', en: 'Stopped' },
  'common.enabled': { zh: '已启用', en: 'Enabled' },
  'common.disabled': { zh: '已禁用', en: 'Disabled' },
  'common.connected': { zh: '已连接', en: 'Connected' },
  'common.disconnected': { zh: '未连接', en: 'Disconnected' },
  'common.all': { zh: '全部', en: 'All' },
  'common.none': { zh: '无', en: 'None' },
  'common.yes': { zh: '是', en: 'Yes' },
  'common.no': { zh: '否', en: 'No' },
  'common.status': { zh: '状态', en: 'Status' },
  'common.action': { zh: '操作', en: 'Actions' },
  'common.remark': { zh: '备注', en: 'Remark' },
  'common.createdAt': { zh: '创建时间', en: 'Created' },
  'common.updatedAt': { zh: '更新时间', en: 'Updated' },
  'common.never': { zh: '从未', en: 'Never' },
  // ---- shared domain terms ----
  'term.endpoint': { zh: '端点', en: 'Endpoint' },
  'term.fanout': { zh: '扇出', en: 'Fan-out' },
  'term.fanin': { zh: '扇入', en: 'Fan-in' },
  'term.node': { zh: '节点', en: 'Node' },
  'term.rule': { zh: '规则', en: 'Rule' },
  'term.group': { zh: '权限组', en: 'Group' },
  'term.account': { zh: '账号', en: 'Account' },
  'term.token': { zh: '令牌', en: 'Token' },
  'term.relay': { zh: '中继', en: 'Relay' },
  'term.tunnel': { zh: '隧道', en: 'Tunnel' },
  'term.proxy': { zh: '代理', en: 'Proxy' },
  'term.subscription': { zh: '订阅', en: 'Subscription' },
  'term.kernel': { zh: '内核', en: 'Kernel' },
  'term.logs': { zh: '日志', en: 'Logs' },
  'term.events': { zh: '事件', en: 'Events' },
  // ---- language names (for switchers) ----
  'lang.zh': { zh: '简体中文', en: '简体中文' },
  'lang.en': { zh: 'English', en: 'English' },
});
