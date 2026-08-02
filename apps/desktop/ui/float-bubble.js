'use strict';
/* 悬浮球气泡（float-bubble 窗）：后端创建窗口并 emit ag-bubble-text(payload=string)，
   本页更新文本并重置 4s 计时；到点加淡出 class（opacity/translateX 300ms）后自行 close()。
   动态文本一律 textContent 写入（等价 esc，杜绝注入）。 */
/* 主题须首行执行防闪烁（本脚本在 head 同步加载，先于首次绘制） */
document.documentElement.dataset.theme = localStorage.getItem('ag_theme') || 'light';

const TAURI = window.__TAURI__;
const invoke = TAURI && TAURI.core ? TAURI.core.invoke : null;
const $ = (id) => document.getElementById(id);

let hideT = 0;   // 4s 到点计时
let closeT = 0;  // 淡出动画结束后关窗计时

function showText(text) {
  const card = $('bb-card');
  card.textContent = text;
  card.hidden = false;
  clearTimeout(hideT);
  clearTimeout(closeT);
  card.classList.remove('out');
  card.classList.add('show');
  hideT = setTimeout(() => {
    card.classList.add('out');
    closeT = setTimeout(() => {
      try { TAURI.window.getCurrentWindow().close(); } catch (e) {}
    }, 320); // 略大于 300ms 淡出时长
  }, 4000);
}

/* ---------------- 启动 ---------------- */
window.addEventListener('DOMContentLoaded', () => {
  if (!invoke) {
    $('bb-noenv').hidden = false;
    return;
  }
  if (TAURI.event && TAURI.event.listen) {
    TAURI.event.listen('ag-theme', e => { document.documentElement.dataset.theme = e.payload; }).catch(() => {});
    TAURI.event.listen('ag-bubble-text', e => {
      const t = String(e.payload ?? '');
      if (t) showText(t); // 空文本不刷新计时，避免空气泡顶掉在显内容
    }).catch(() => {});
  }
});
