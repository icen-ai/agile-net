'use strict';
/* AgileNet shared base utilities (agutil, AGENTS.md §6 shared component layer):
   desktop loads via <script src="agutil.js">; admin UI serves it embedded via crates/node/src/ui/mod.rs at /ui/agutil.js
   (same mechanism as agchart.js / icons.js). Only utilities with identical semantics on both ends —
   divergent ones (e.g. fmtBytes output format, toast channel) keep local per-end implementations; never change behavior to force a merge.
   Dependency: ahelp's question-mark icon uses the shared icon table AgIcon (icons.js must load first). */
(function () {

const $ = (id) => document.getElementById(id);

/* HTML escape: dynamic content must pass through esc before entering innerHTML/attributes */
function esc(s) {
  return String(s ?? '').replace(/[&<>"'`]/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','`':'&#96;'
  }[c]));
}

/* Inline help (shared component .ahelp, styles in components.css): question-mark icon + pure CSS hover tip card */
function ahelp(text) {
  return '<span class="ahelp">' + AgIcon('badge-question-mark', 13) + '<span class="ahelp-tip">' + esc(text) + '</span></span>';
}

window.$ = $;
window.esc = esc;
window.ahelp = ahelp;
})();
