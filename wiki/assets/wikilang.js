// wikilang.js — AgileNet docs site mini-dictionary (zh-CN / en-US).
// Loaded after agi18n.js, before app.js; single AgI18n.register() call.
// Nav-item bilingual text is not here: nav.json inlines {zh, en} structures, resolved by app.js per AgI18n.lang.
// zh: official/terse; en: Title Case for labels, sentence case for messages.
AgI18n.register({
  // ---- language names (for switcher) ----
  'lang.zh': { zh: '简体中文', en: '简体中文' },
  'lang.en': { zh: 'English', en: 'English' },
  // ---- topbar ----
  'ui.siteTitle': { zh: 'AgileNet 文档', en: 'AgileNet Docs' },
  'ui.brandTag': { zh: '文档', en: 'Docs' },
  'ui.menu': { zh: '目录', en: 'Menu' },
  'ui.theme': { zh: '切换主题', en: 'Toggle Theme' },
  'ui.lang': { zh: '切换语言', en: 'Switch Language' },
  'ui.searchBtn': { zh: '搜索文档', en: 'Search Docs' },
  'ui.searchPh': { zh: '搜索文档内容…', en: 'Search documentation…' },
  // ---- sidebar / footer ----
  'ui.releases': { zh: '下载发布版', en: 'Downloads' },
  'ui.footerTag': { zh: 'AgileNet — 双产物网络穿透与代理链路由系统', en: 'AgileNet — dual-binary network tunneling and proxy-chain routing' },
  'ui.footerHosted': { zh: '文档与软件同源，托管于', en: 'Docs ship with the software, hosted on' },
  // ---- content ----
  'ui.tocTitle': { zh: '本页内容', en: 'On This Page' },
  'ui.copy': { zh: '复制', en: 'Copy' },
  'ui.copied': { zh: '已复制', en: 'Copied' },
  'ui.pageNotFound': { zh: '页面不存在', en: 'Page Not Found' },
  'ui.noDocForPath': { zh: '路径 {path} 没有对应文档。', en: 'No document found for path {path}.' },
  'ui.backHome': { zh: '返回首页', en: 'Back to Home' },
  // ---- search ----
  'ui.searchEmpty': { zh: '输入关键字开始搜索', en: 'Type keywords to search' },
  'ui.searchNoHit': { zh: '没有找到「{q}」相关内容', en: 'No results for "{q}"' },
});
