'use strict';
/* 悬浮球：72×72 全透明窗口常驻。
   - 球内实时网速（↓ 主显 / ↑ 次显，2s 轮询 sub_traffic；无流量显示 logo 点）
   - 左键拖拽（>4px 阈值 → startDragging；dragging 态缩放 .94 + 阴影加深；松手边缘吸附）
   - 单击显隐快捷菜单（250ms 定时器与双击区分）/ 双击开主面板 / 右键同一菜单
   - 气泡通知：ag-float-notify → 球左侧滑入，4s 淡出，最多堆叠 3 条
   渲染纪律：签名对比，数据不变不动 DOM；窗口不可见暂停轮询。 */
/* 主题须首行执行防闪烁（本脚本在 head 同步加载，先于首次绘制） */
document.documentElement.dataset.theme = localStorage.getItem('ag_theme') || 'light';

const TAURI = window.__TAURI__;
const invoke = TAURI && TAURI.core ? TAURI.core.invoke : null;
const $ = (id) => document.getElementById(id);

const PROXY_PORT = 57890;
const MENU_TOP = 132;    // 菜单展开时窗口需向上扩容的 CSS px（菜单高 ~124 + 间隙）
const BUBBLE_LEFT = 212; // 有气泡时窗口需向左扩容的 CSS px（气泡 max-width 200 + 间隙）

let running = false;       // 本地代理运行状态（菜单项文案）
let speedSig = '';         // 网速签名
let menuOpen = false;
let dragging = false;
let clickTimer = 0;

function win() { return TAURI.window.getCurrentWindow(); }
function inv(cmd, args) { return invoke(cmd, args).catch(() => null); }

/* ---------------- 窗口扩容管理（菜单/气泡需要超出 72×72 的空间） ----------------
   记录基准（无扩容时的 pos/size），目标 = 基准 + 扩容偏移。
   任一窗口 API 无权限即静默失败：菜单/气泡退化为在 72px 窗口内被裁剪，功能本身可用。 */
const expand = { left: 0, top: 0, base: null, chain: Promise.resolve() };

async function rebase() {
  if (!TAURI || !TAURI.window) return;
  try {
    const w = win();
    const [pos, size, sf] = await Promise.all([w.outerPosition(), w.outerSize(), w.scaleFactor()]);
    const dL = Math.round(expand.left * sf), dT = Math.round(expand.top * sf);
    expand.base = { x: pos.x + dL, y: pos.y + dT, w: size.width - dL, h: size.height - dT, sf };
  } catch (e) { /* 无 outer-position/outer-size 权限：保持 null，扩容整体停用 */ }
}

async function applyExpand() {
  if (!TAURI || !TAURI.window || !expand.base) return;
  const b = expand.base;
  const dL = Math.round(expand.left * b.sf), dT = Math.round(expand.top * b.sf);
  const w = win();
  const P = TAURI.window;
  try {
    await w.setSize(new P.PhysicalSize(b.w + dL, b.h + dT));
    try {
      await w.setPosition(new P.PhysicalPosition(b.x - dL, b.y - dT));
    } catch (e) {
      // 位置回写失败则把尺寸退回，避免球体视觉漂移
      try { await w.setSize(new P.PhysicalSize(b.w, b.h)); } catch (e2) {}
    }
  } catch (e) { /* 无 set-size 权限：忽略 */ }
}

function setExpand() {
  expand.chain = expand.chain.then(applyExpand);
}
function growLeft(px) { if (expand.left !== px) { expand.left = px; setExpand(); } }
function growTop(px) { if (expand.top !== px) { expand.top = px; setExpand(); } }

/* ---------------- 菜单 ---------------- */
function showMenu(show) {
  if (menuOpen === show) return;
  menuOpen = show;
  $('menu').hidden = !show;
  growTop(show ? MENU_TOP : 0);
}

/* ---------------- 轮询（2s）：网速 + 代理状态 ---------------- */
function fmtShort(b) {
  b = +b || 0;
  if (b >= 1048576) return (b / 1048576).toFixed(1) + 'M';
  if (b >= 1024) return b >= 102400 ? Math.round(b / 1024) + 'K' : (b / 1024).toFixed(1) + 'K';
  return String(Math.round(b));
}

async function tick() {
  const [tr, pr] = await Promise.allSettled([invoke('sub_traffic'), invoke('proxy_status')]);
  if (pr.status === 'fulfilled' && pr.value) {
    const r = !!pr.value.running;
    if (r !== running) { running = r; $('fl-toggle-label').textContent = r ? '停止代理' : '启动代理'; }
  }
  let sig = 'x'; // 默认：无数据 → logo 点
  if (tr.status === 'fulfilled' && tr.value) {
    const d = +tr.value.down_rate || 0, u = +tr.value.up_rate || 0;
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
  if (sig !== speedSig) {
    speedSig = sig;
    $('ball-speed').hidden = true;
    $('ball-idle').hidden = false;
  }
}

let pollT = 0;
function startLoops() { if (!pollT && invoke) { tick(); pollT = setInterval(tick, 2000); } }
function stopLoops() { clearInterval(pollT); pollT = 0; }

/* ---------------- 气泡通知 ---------------- */
function pushBubble(text) {
  const box = $('bubbles');
  while (box.children.length >= 3) box.firstChild.remove();
  const el = document.createElement('div');
  el.className = 'bubble';
  el.textContent = String(text ?? '');
  box.appendChild(el);
  growLeft(BUBBLE_LEFT);
  setTimeout(() => {
    el.classList.add('out');
    setTimeout(() => { el.remove(); if (!box.children.length) growLeft(0); }, 350);
  }, 4000);
}

/* ---------------- 拖拽 / 单击 / 双击 / 右键 ---------------- */
let moveTimer = 0;

function endDrag() {
  if (!dragging) return;
  dragging = false;
  $('ball').classList.remove('dragging');
  snapEdge().then(rebase);
}

/* 边缘吸附：贴近屏幕左右边缘 24px 内则吸附（无权限静默跳过） */
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
        showMenu(false);
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

  // 单击（250ms 与双击区分）：显隐菜单；双击：打开主面板
  function tap() {
    if (clickTimer) {
      clearTimeout(clickTimer);
      clickTimer = 0;
      showMenu(false);
      inv('tray_show_main');
      return;
    }
    clickTimer = setTimeout(() => { clickTimer = 0; showMenu(!menuOpen); }, 250);
  }

  document.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    showMenu(true);
  });

  // 点击菜单/球体之外收起菜单
  document.addEventListener('mousedown', (e) => {
    if (menuOpen && !e.target.closest('#menu') && !e.target.closest('#ball')) showMenu(false);
  });
  window.addEventListener('blur', () => showMenu(false));

  // 菜单动作（事件委托）
  $('menu').addEventListener('click', async (e) => {
    const it = e.target.closest('.ctx-item');
    if (!it) return;
    const act = it.dataset.act;
    showMenu(false);
    if (act === 'show') inv('tray_show_main');
    else if (act === 'quit') inv('tray_quit');
    else if (act === 'toggle') {
      const st = await inv('proxy_status');
      if (st && st.running) await inv('stop_proxy');
      else await inv('start_proxy', { port: PROXY_PORT });
      tick();
    }
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
    TAURI.event.listen('ag-float-notify', e => pushBubble(e.payload)).catch(() => {});
  }
  document.addEventListener('visibilitychange', () => { document.hidden ? stopLoops() : startLoops(); });
  bindBall();
  rebase();
  startLoops();
});
