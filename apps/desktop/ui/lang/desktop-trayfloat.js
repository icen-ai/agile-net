// desktop-trayfloat.js — dictionary shard for the tray popup and the three float-ball windows (tray / float / float-menu / float-bubble).
// Load order: agi18n.js → aglang.js → this file (each popup HTML loads via <script src>, before its existing scripts).
// Reuses common.* / term.* from aglang.js (e.g. common.running/stopped, term.rule); this shard only adds page-specific entries.
AgI18n.register({
  // ---- tray.html / tray.js (tray popup) ----
  'tray.winTitle': { zh: 'AgileNet 托盘', en: 'AgileNet Tray' },
  'tray.down': { zh: '下行', en: 'Down' },
  'tray.up': { zh: '上行', en: 'Up' },
  'tray.proxyOff': { zh: '本地代理未启动', en: 'Local proxy not running' },
  'tray.proxyAddr': { zh: '本地代理 {addr}', en: 'Local proxy {addr}' },
  'tray.startProxy': { zh: '启动代理', en: 'Start Proxy' },
  'tray.stopProxy': { zh: '停止代理', en: 'Stop Proxy' },
  'tray.tunLockTip': { zh: 'TUN 模式下出站固定为规则', en: 'Outbound is fixed to Rule under TUN' },
  'tray.outMode': { zh: '出站模式', en: 'Outbound' },
  'tray.proxyMode': { zh: '代理模式', en: 'Proxy Mode' },
  // outbound three-segment: rule reuses term.rule; global/direct shared by tray and float-ball menu
  'tray.outGlobal': { zh: '全局', en: 'Global' },
  'tray.outDirect': { zh: '直连', en: 'Direct' },
  'tray.groups': { zh: '代理组', en: 'Proxy Groups' },
  'tray.kernelOff': { zh: '订阅内核未运行', en: 'Kernel not running' },
  'tray.noGroups': { zh: '无可用代理组', en: 'No proxy groups' },
  'tray.conns': { zh: '连接', en: 'Connections' },
  'tray.activeCount': { zh: '活跃 {n}', en: '{n} active' },
  'tray.noConns': { zh: '暂无活跃连接', en: 'No active connections' },
  'tray.showMain': { zh: '主面板', en: 'Main Panel' },
  'tray.quit': { zh: '退出', en: 'Quit' },
  'tray.noenv': { zh: '此页面需在 AgileNet 桌面端窗口中打开', en: 'Open this page in the AgileNet desktop app' },

  // ---- float.html / float.js (float ball) ----
  // winTitle doubles as the ball's aria-label
  'float.winTitle': { zh: 'AgileNet 悬浮球', en: 'AgileNet Floating Ball' },
  'float.noenv': { zh: '需在 AgileNet 桌面端中使用', en: 'Requires the AgileNet desktop app' },

  // ---- float-menu.html / float-menu.js (float-ball menu) ----
  'float.menuTitle': { zh: 'AgileNet 悬浮球菜单', en: 'AgileNet Ball Menu' },
  'float.openMain': { zh: '打开主窗口', en: 'Open Main Window' },
  'float.sysStart': { zh: '启动系统代理', en: 'Start System Proxy' },
  'float.sysStop': { zh: '停止系统代理', en: 'Stop System Proxy' },
  'float.subStart': { zh: '启动订阅代理', en: 'Start Subscription Proxy' },
  'float.subStop': { zh: '停止订阅代理', en: 'Stop Subscription Proxy' },
  // proxy mode three-segment (2-char symmetric in zh)
  'float.modeSystem': { zh: '系统', en: 'System' },
  'float.modeLocal': { zh: '本地', en: 'Local' },
  'float.modeTun': { zh: '虚拟', en: 'TUN' },
  'float.modeTip': { zh: '系统=接管系统代理 · 本地=仅 127.0.0.1 代理 · 虚拟=TUN 虚拟网卡', en: 'System: take over system proxy · Local: 127.0.0.1 only · TUN: virtual NIC' },
  'float.outTip': { zh: '出站模式：规则=按规则分流 · 全局=全部走节点 · 直连=全部直连', en: 'Outbound — Rule: route by rules · Global: all via node · Direct: all direct' },
  'float.needAdmin': { zh: '需管理员重启', en: 'Requires admin restart' },
  'float.switchFailed': { zh: '切换失败', en: 'Switch failed' },
  'float.hideBall': { zh: '隐藏悬浮球', en: 'Hide Floating Ball' },
  'float.quit': { zh: '退出 AgileNet', en: 'Quit AgileNet' },

  // ---- float-bubble.html / float-bubble.js (float-ball bubble) ----
  'float.bubbleTitle': { zh: 'AgileNet 悬浮球气泡', en: 'AgileNet Ball Notification' },
});
