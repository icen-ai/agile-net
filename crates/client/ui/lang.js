'use strict';
/* Client console dictionary shard (keys specific to the /client SPA; common.* / term.* /
   import.* come from the shared aglang.js base layer). zh: official tone, minimal length;
   en: Title Case for labels, sentence case for messages. */
AgI18n.register({
  'cl.title': { zh: 'AgileNet 客户端', en: 'AgileNet Client' },
  'cl.role': { zh: '客户端', en: 'Client' },
  'cl.theme': { zh: '切换主题', en: 'Toggle theme' },

  'cl.adminMenu': { zh: '管理端', en: 'Admin' },
  'cl.adminLocal': { zh: '本机', en: 'This Machine' },
  'cl.adminIssuer': { zh: '签发端', en: 'Issuer' },
  'cl.adminUpstream': { zh: '上游', en: 'Upstream' },
  'cl.adminEmpty': { zh: '暂无可管理端点', en: 'No manageable endpoints' },

  'cl.nodes': { zh: '节点', en: 'Nodes' },
  'cl.nodesEmpty': { zh: '暂无节点，导入链接接入', en: 'No nodes yet — import a link to connect' },
  'cl.importLink': { zh: '导入链接', en: 'Import Link' },
  'cl.disconnect': { zh: '断开', en: 'Disconnect' },
  'cl.connecting': { zh: '连接中', en: 'Connecting' },
  'cl.reconnecting': { zh: '重连中', en: 'Reconnecting' },
  'cl.manage': { zh: '可管理', en: 'Manageable' },

  'cl.proxy': { zh: '本地代理', en: 'Local Proxy' },
  'cl.start': { zh: '启动', en: 'Start' },
  'cl.stop': { zh: '停止', en: 'Stop' },

  'cl.creds': { zh: '凭据', en: 'Credentials' },
  'cl.split': { zh: '分流', en: 'Split' },
  'cl.exportTitle': { zh: '导出链接', en: 'Export Link' },
  'cl.exportWarn': { zh: '链接含明文令牌，注意保密', en: 'The link contains the token plaintext. Keep it secret.' },
  'cl.exportConfirm': { zh: '导出含明文令牌的接入链接？', en: 'Export the connect link with the token plaintext?' },
  'cl.delCred': { zh: '删除该凭据？', en: 'Delete this credential?' },
  'cl.copied': { zh: '已复制', en: 'Copied' },
});
