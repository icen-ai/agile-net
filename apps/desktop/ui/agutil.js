'use strict';
/* AgileNet 共享基础工具（agutil，AGENTS.md §6 组件沉淀）：
   桌面端 <script src="agutil.js"> 引入；管理端经 crates/node/src/ui/mod.rs 内嵌服务于 /ui/agutil.js
   （同 agchart.js / icons.js 机制）。仅收录两端语义完全一致的工具——
   有差异的（如 fmtBytes 输出格式、toast 通知通道）各端保留本地实现，严禁为合并而改行为。
   依赖：ahelp 的问号图标走共享图标表 AgIcon（icons.js 须先加载）。 */
(function () {

const $ = (id) => document.getElementById(id);

/* HTML 转义：动态内容进 innerHTML/属性前必须过 esc */
function esc(s) {
  return String(s ?? '').replace(/[&<>"'`]/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','`':'&#96;'
  }[c]));
}

/* 行内帮助（共享组件 .ahelp，样式在 components.css）：问号图标 + 纯 CSS hover 说明卡 */
function ahelp(text) {
  return '<span class="ahelp">' + AgIcon('badge-question-mark', 13) + '<span class="ahelp-tip">' + esc(text) + '</span></span>';
}

window.$ = $;
window.esc = esc;
window.ahelp = ahelp;
})();
