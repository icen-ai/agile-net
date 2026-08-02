'use strict';
/* 悬浮球：72×72 全透明窗口常驻（恒等尺寸，前端不做任何 setSize/setPosition 扩容）。
   - 球内实时网速（↓ 主显 / ↑ 次显，2s 轮询 sub_traffic；无流量显示 logo 点）
   - 左键拖拽（>4px 阈值 → startDragging；dragging 态缩放 .94 + 阴影加深；松手边缘吸附）
   - 单击播 Q 弹动画（260ms 定时器与双击区分；动画无害，双击不抑制）/ 双击开主窗口
   - 右键 invoke float_open_menu()（后端在球旁创建/显示 float-menu 窗）
   渲染纪律：签名对比，数据不变不动 DOM；窗口不可见暂停轮询。 */
/* 主题须首行执行防闪烁（本脚本在 head 同步加载，先于首次绘制） */
document.documentElement.dataset.theme = localStorage.getItem('ag_theme') || 'light';

const TAURI = window.__TAURI__;
const invoke = TAURI && TAURI.core ? TAURI.core.invoke : null;
const $ = (id) => document.getElementById(id);

let speedSig = '';         // 网速签名
let dragging = false;
let clickTimer = 0;

function win() { return TAURI.window.getCurrentWindow(); }
function inv(cmd, args) { return invoke(cmd, args).catch(() => null); }

/* ---------------- 轮询（2s）：实时网速 ---------------- */
function fmtShort(b) {
  b = +b || 0;
  if (b >= 1048576) return (b / 1048576).toFixed(1) + 'M';
  if (b >= 1024) return b >= 102400 ? Math.round(b / 1024) + 'K' : (b / 1024).toFixed(1) + 'K';
  return String(Math.round(b));
}

async function tick() {
  let sig = 'x'; // 默认：无数据 → logo 点
  try {
    const tr = await invoke('sub_traffic');
    if (tr) {
      const d = +tr.down_rate || 0, u = +tr.up_rate || 0;
      sig = (d || u) ? d + '/' + u : 'idle';
      if (sig !== speedSig) {
        speedSig = sig;
        if (sig === 'idle') {
          $('ball-speed').hidden = true;
          $('ball-idle').hidden = false;
        } else {
          $('ball-idle').hidden = true;
          $('ball-speed').hidden = false;
          $('sp-down').textContent = fmtShort(d);
          $('sp-up').textContent = fmtShort(u);
        }
      }
      return;
    }
  } catch (e) { /* 命令失败按无数据处理 */ }
  if (sig !== speedSig) {
    speedSig = sig;
    $('ball-speed').hidden = true;
    $('ball-idle').hidden = false;
  }
}

let pollT = 0;
function startLoops() { if (!pollT && invoke) { tick(); pollT = setInterval(tick, 2000); } }
function stopLoops() { clearInterval(pollT); pollT = 0; }

/* ---------------- 单击 Q 弹 ---------------- */
function boing() {
  const ball = $('ball');
  if (ball.classList.contains('boing')) return; // 连击不叠加
  ball.classList.add('boing');
}

/* ---------------- 拖拽 / 单击 / 双击 / 右键 ---------------- */
let moveTimer = 0;

function endDrag() {
  if (!dragging) return;
  dragging = false;
  $('ball').classList.remove('dragging');
  snapEdge();
}

/* 边缘吸附：贴近屏幕左右边缘 24px 内则吸附（无权限静默跳过；位置微调不属扩容） */
async function snapEdge() {
  if (!TAURI || !TAURI.window) return;
  try {
    const w = win();
    const [pos, size, sf] = await Promise.all([w.outerPosition(), w.outerSize(), w.scaleFactor()]);
    const lx = pos.x / sf, bw = size.width / sf, sw = window.screen.width;
    let tx = null;
    if (lx <= 24) tx = 0;
    else if (lx + bw >= sw - 24) tx = Math.max(0, sw - bw);
    if (tx === null) return;
    await w.setPosition(new TAURI.window.PhysicalPosition(Math.round(tx * sf), pos.y));
  } catch (e) {}
}

function bindBall() {
  const ball = $('ball');

  ball.addEventListener('animationend', (e) => {
    if (e.animationName === 'fl-boing') ball.classList.remove('boing');
  });

  ball.addEventListener('mousedown', (e) => {
    if (e.button !== 0) return;
    const sx = e.clientX, sy = e.clientY;
    let moved = false;
    const onMove = (ev) => {
      if (moved) return;
      if (Math.hypot(ev.clientX - sx, ev.clientY - sy) > 4) {
        moved = true;
        dragging = true;
        ball.classList.add('dragging');
        try { win().startDragging(); } catch (err) { endDrag(); }
        window.removeEventListener('mousemove', onMove);
      }
    };
    const onUp = () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
      if (moved) endDrag();
      else tap();
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
  });

  // 原生拖拽期间 webview 收不到 mouseup：用窗口移动事件 180ms 静默判定拖拽结束
  if (TAURI && TAURI.window) {
    try {
      win().listen('tauri://move', () => {
        if (!dragging) return;
        clearTimeout(moveTimer);
        moveTimer = setTimeout(endDrag, 180);
      }).catch(() => {});
    } catch (e) {}
  }

  // 单击（260ms 与双击区分）：仅播 Q 弹动画；双击：直接开主窗口
  function tap() {
    if (clickTimer) {
      clearTimeout(clickTimer);
      clickTimer = 0;
      inv('tray_show_main');
      return;
    }
    clickTimer = setTimeout(() => { clickTimer = 0; boing(); }, 260);
  }

  // 右键：后端在球旁定位创建/显示 float-menu 窗（toggle 语义）
  document.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    inv('float_open_menu');
  });
}

/* ---------------- 启动 ---------------- */
window.addEventListener('DOMContentLoaded', () => {
  if (!invoke) {
    $('fl-noenv').hidden = false;
    return;
  }
  $('fl-root').hidden = false;
  if (TAURI.event && TAURI.event.listen) {
    TAURI.event.listen('ag-theme', e => { document.documentElement.dataset.theme = e.payload; }).catch(() => {});
  }
  document.addEventListener('visibilitychange', () => { document.hidden ? stopLoops() : startLoops(); });
  bindBall();
  startLoops();
});
