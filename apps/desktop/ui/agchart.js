/* AgileNet 共享图表组件（agchart）—— 零依赖原生 SVG/JS，首个共享 JS 组件（AGENTS.md §6）
   桌面端 <script src="agchart.js"> 引入；管理端经 crates/node/src/ui/mod.rs 内嵌服务于 /ui/agchart.js。
   颜色一律吃 tokens.css 的 var(--*)，严禁硬编码色值、主题无蓝。
   序列色（var(--*) 字符串）经 getComputedStyle 解析为实色再写 SVG 呈现属性（呈现属性内
   var() 引擎兼容性不一；网格/文字色走 components.css 的 CSS 类），主题切换后下一次绘制自然生效。

   两版本（API 留扩展位）：
   - AgChart.sparkline(el, series, opts)  省略版：仅趋势折线 + 渐变面积，无轴无字
   - AgChart.line(el, cfg)                完整版：XY 轴刻度网格 / 多序列 / hover 十字 + 每点浮层
     cfg = { x: [标签], series: [{name?, color?, values}], fmtX?, fmtY?, legend?, empty? }
     series 也允许直接传数值数组 [v,...]（单序列匿名）

   行为约定：
   - 重复调用同元素 = 幂等更新；数据签名（x + 序列名/色/值）不变不重绘
   - 数据更新 rAF 数值插值过渡（~400ms ease-out；等长点列直接插值，不等长按索引对齐截断、
     新增点自基线生长）；prefers-reduced-motion 时跳过动画
   - hover 十字/浮层跟随只动 transform，不重排
   - ResizeObserver 跟随容器尺寸（重排直接落目标值，不重演数据动画）
   返回实例 { update, destroy }；元素被移除后一切活动自动停止。 */
(function () {
'use strict';

var SVG_NS = 'http://www.w3.org/2000/svg';
/* 默认序列色板：主序列 --accent（近黑），次序列 --dim2（灰），其后语义色（主题无蓝） */
var PALETTE = ['var(--accent)', 'var(--dim2)', 'var(--ok)', 'var(--warn)', 'var(--danger)'];
var DURATION = 400;
var uidSeq = 0;

function mk(tag, attrs, parent) {
  var n = document.createElementNS(SVG_NS, tag);
  if (attrs) for (var k in attrs) n.setAttribute(k, attrs[k]);
  if (parent) parent.appendChild(n);
  return n;
}

/* series 规格化：允许 [v,...] 或 [{values, name?, color?},...] */
function normSeries(series) {
  if (!Array.isArray(series)) return [];
  if (!series.length) return [];
  if (typeof series[0] !== 'object' || series[0] === null) {
    return [{ name: '', values: series.map(function (v) { return +v || 0; }), color: '' }];
  }
  return series.map(function (s) {
    return {
      name: s.name || '',
      values: (s.values || []).map(function (v) { return +v || 0; }),
      color: s.color || '',
    };
  });
}

function sigOf(x, series) {
  return JSON.stringify([x || [], series.map(function (s) { return [s.name, s.color, s.values]; })]);
}

function easeOutCubic(t) { return 1 - Math.pow(1 - t, 3); }

/* Y 轴上限取整（1/2/2.5/5×10^n 步长，约 count 级刻度） */
function niceMax(max, count) {
  if (!(max > 0)) return 1;
  var rough = max / count;
  var mag = Math.pow(10, Math.floor(Math.log10(rough)));
  var m = rough / mag;
  var step = (m <= 1 ? 1 : m <= 2 ? 2 : m <= 2.5 ? 2.5 : m <= 5 ? 5 : 10) * mag;
  return step * Math.ceil(max / step);
}

function defaultFmt(v) {
  v = +v || 0;
  var abs = Math.abs(v);
  if (abs >= 1e9) return (v / 1e9).toFixed(1) + 'G';
  if (abs >= 1e6) return (v / 1e6).toFixed(1) + 'M';
  if (abs >= 1e3) return (v / 1e3).toFixed(1) + 'K';
  return String(Math.round(v * 100) / 100);
}

function num(v) { return Math.round(v * 100) / 100; }

/* var(--*) 解析为实色（写 SVG 呈现属性用；主题切换后下一次绘制自然生效） */
function resolveColor(c) {
  var m = /^var\(\s*(--[\w-]+)\s*(?:,[^)]*)?\)$/.exec(c);
  if (m && typeof getComputedStyle === 'function') {
    var v = getComputedStyle(document.documentElement).getPropertyValue(m[1]);
    if (v) return v.trim();
  }
  return c;
}

/* Catmull-Rom 平滑转三次贝塞尔；控制点钳制在值域内，避免 0 基线以下/上限以上过冲 */
function smoothPath(pts, yLo, yHi) {
  if (pts.length === 1) return 'M ' + num(pts[0][0]) + ' ' + num(pts[0][1]);
  var d = 'M ' + num(pts[0][0]) + ' ' + num(pts[0][1]);
  function clampY(y) { return Math.min(yLo, Math.max(yHi, y)); }
  for (var i = 0; i < pts.length - 1; i++) {
    var p0 = pts[i - 1] || pts[i], p1 = pts[i], p2 = pts[i + 1], p3 = pts[i + 2] || p2;
    var c1x = p1[0] + (p2[0] - p0[0]) / 6, c1y = clampY(p1[1] + (p2[1] - p0[1]) / 6);
    var c2x = p2[0] - (p3[0] - p1[0]) / 6, c2y = clampY(p2[1] - (p3[1] - p1[1]) / 6);
    d += ' C ' + num(c1x) + ' ' + num(c1y) + ' ' + num(c2x) + ' ' + num(c2y) + ' ' + num(p2[0]) + ' ' + num(p2[1]);
  }
  return d;
}

function Chart(el, kind) {
  this.el = el;
  this.kind = kind;
  this.id = ++uidSeq;
  this.cur = [];          // 当前展示序列（动画中间态）
  this.data = null;       // 目标数据
  this.sig = '';
  this.raf = 0;
  this.hover = -1;
  this.w = 0; this.h = 0;
  this.n = 0; this.ymax = 1;
  this.dots = [];
  this.gradColors = [];
  this.rcolors = [];      // 解析后的序列实色（_resolveColors 维护）
  this.tipKey = '';
  this._build();
  var self = this;
  this._ro = new ResizeObserver(function () { self._onResize(); });
  this._ro.observe(el);
}

Chart.prototype._build = function () {
  var self = this;
  this.el.classList.add('agchart');
  if (this.kind === 'line') {
    this.el.classList.add('agchart-line');
    this.legendEl = document.createElement('div');
    this.legendEl.className = 'agchart-legend';
    this.el.appendChild(this.legendEl);
    this.plot = document.createElement('div');
    this.plot.className = 'agchart-plot';
    this.el.appendChild(this.plot);
  } else {
    this.el.classList.add('agchart-spark');
    this.plot = this.el;
  }
  this.svg = mk('svg', { 'class': 'agchart-svg' }, this.plot);
  if (this.kind === 'line') {
    this.defs = mk('defs', null, this.svg);
    this.gGrid = mk('g', null, this.svg);
    this.gSeries = mk('g', null, this.svg);
    this.gCross = mk('g', { visibility: 'hidden' }, this.svg);
    this.crossLine = mk('line', { 'class': 'agc-cross', y1: 0, y2: 0 }, this.gCross);
    this.tip = document.createElement('div');
    this.tip.className = 'agchart-tip';
    this.tip.style.display = 'none';
    this.plot.appendChild(this.tip);
    this._onMove = function (e) { self._onPointer(e); };
    this._onLeave = function () { self.hover = -1; self._drawHover(); };
    this.plot.addEventListener('pointermove', this._onMove);
    this.plot.addEventListener('pointerleave', this._onLeave);
  } else {
    this.defs = mk('defs', null, this.svg);
    this.gSeries = mk('g', null, this.svg);
  }
};

/* ================= 布局 ================= */
Chart.prototype._layout = function () {
  var w = this.plot.clientWidth, h = this.plot.clientHeight;
  if (w < 10 || h < 10 || !this.data) return false;
  this.w = w; this.h = h;
  if (this.kind === 'line') {
    this.padL = 64; this.padR = 14; this.padT = 10; this.padB = 22;
  } else {
    this.padL = 2; this.padR = 2; this.padT = 4; this.padB = 2;
  }
  var maxV = 0, n = this.kind === 'line' ? this.data.x.length : 0;
  this.data.series.forEach(function (s) {
    if (s.values.length > n) n = s.values.length;
    s.values.forEach(function (v) { if (v > maxV) maxV = v; });
  });
  this.n = n;
  /* 完整版取漂亮刻度；sparkline 顶部留 15% 余量不贴边 */
  this.ymax = this.kind === 'line' ? niceMax(maxV, 4) : (maxV > 0 ? maxV * 1.15 : 1);
  return true;
};
Chart.prototype._x = function (i) {
  var iw = this.w - this.padL - this.padR;
  return this.padL + (this.n <= 1 ? iw / 2 : i * iw / (this.n - 1));
};
Chart.prototype._y = function (v) {
  var ih = this.h - this.padT - this.padB;
  return this.padT + ih - (Math.max(0, v) / this.ymax) * ih;
};

/* ================= 数据入口（签名变更检测） ================= */
Chart.prototype._setData = function (cfg) {
  var series = normSeries(cfg.series);
  var sig = sigOf(cfg.x, series);
  if (sig === this.sig) return;
  this.sig = sig;
  this.data = {
    x: cfg.x || [],
    series: series,
    fmtX: cfg.fmtX || null,
    fmtY: cfg.fmtY || null,
    empty: cfg.empty || '暂无数据',
    legend: cfg.legend !== false,
  };
  this._resolveColors();
  /* 对齐：旧值按索引截断，新增点自基线 0 生长 */
  var cur = this.cur;
  var from = series.map(function (s, i) {
    var old = cur[i] ? cur[i].values : [];
    return s.values.map(function (v, j) { return j < old.length ? old[j] : 0; });
  });
  if (!this._layout()) { this._setCur(series); return; }
  this._drawAxes();
  this._drawLegend();
  this._animate(from);
};

Chart.prototype._setCur = function (series) {
  this.cur = series.map(function (s) { return { name: s.name, color: s.color, values: s.values.slice() }; });
};
Chart.prototype._curVals = function () {
  return this.cur.map(function (s) { return s.values; });
};

/* ================= 动画（rAF 数值插值） ================= */
Chart.prototype._animate = function (from) {
  var self = this;
  cancelAnimationFrame(this.raf);
  var reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduced) {
    this._setCur(this.data.series);
    this._drawSeries(this._curVals());
    this._drawHover();
    return;
  }
  var start = -1;
  function frame(ts) {
    if (!self.el.isConnected) return;
    if (start < 0) start = ts;
    var t = Math.min(1, (ts - start) / DURATION);
    var e = easeOutCubic(t);
    self.cur = self.data.series.map(function (s, i) {
      return {
        name: s.name, color: s.color,
        values: s.values.map(function (v, j) {
          var f = from[i] && j < from[i].length ? from[i][j] : 0;
          return f + (v - f) * e;
        }),
      };
    });
    self._drawSeries(self._curVals());
    if (self.hover >= 0) self._drawHover();
    if (t < 1) self.raf = requestAnimationFrame(frame);
  }
  this.raf = requestAnimationFrame(frame);
};

/* ================= 绘制 ================= */
/* 序列实色解析：var(--*) → getComputedStyle 实色（_setData/_onResize 时刷新，签名机制不变） */
Chart.prototype._resolveColors = function () {
  this.rcolors = this.data.series.map(function (s, i) {
    return resolveColor(s.color || PALETTE[i % PALETTE.length]);
  });
};

Chart.prototype._seriesColor = function (i) {
  return this.rcolors[i] || PALETTE[i % PALETTE.length];
};

Chart.prototype._drawAxes = function () {
  if (this.kind !== 'line') return;
  var g = this.gGrid;
  while (g.firstChild) g.removeChild(g.firstChild);
  var fmtY = this.data.fmtY || defaultFmt;
  if (!this.n) {
    var t = mk('text', {
      'class': 'agc-empty', x: this.w / 2, y: this.h / 2, 'text-anchor': 'middle',
    }, g);
    t.textContent = this.data.empty;
    return;
  }
  var levels = 4;
  for (var i = 0; i <= levels; i++) {
    var v = this.ymax * i / levels;
    var y = this._y(v);
    mk('line', { 'class': 'agc-grid', x1: this.padL, y1: y, x2: this.w - this.padR, y2: y }, g);
    var lbl = mk('text', { 'class': 'agc-lbl', x: this.padL - 8, y: y + 4, 'text-anchor': 'end' }, g);
    lbl.textContent = fmtY(v);
  }
  var iw = this.w - this.padL - this.padR;
  var maxLbl = Math.max(2, Math.floor(iw / 72));
  var step = Math.max(1, Math.ceil(this.n / maxLbl));
  for (var j = 0; j < this.n; j += step) {
    var raw = this.data.x[j];
    var xt = mk('text', { 'class': 'agc-lbl', x: this._x(j), y: this.h - 6, 'text-anchor': 'middle' }, g);
    xt.textContent = this.data.fmtX ? this.data.fmtX(raw, j) : String(raw == null ? '' : raw);
  }
};

Chart.prototype._drawLegend = function () {
  if (this.kind !== 'line') return;
  var el = this.legendEl;
  el.textContent = '';
  var named = this.data.series.filter(function (s) { return s.name; });
  if (!this.data.legend || named.length < 1) { el.style.display = 'none'; return; }
  el.style.display = '';
  var fmtY = this.data.fmtY || defaultFmt;
  this.data.series.forEach(function (s, i) {
    if (!s.name) return;
    var item = document.createElement('span');
    item.className = 'agchart-legend-item';
    var chip = document.createElement('span');
    chip.className = 'c';
    chip.style.background = s.color || PALETTE[i % PALETTE.length];
    item.appendChild(chip);
    var total = s.values.reduce(function (a, b) { return a + b; }, 0);
    item.appendChild(document.createTextNode(s.name + ' ' + fmtY(total)));
    el.appendChild(item);
  });
};

Chart.prototype._drawSeries = function (values2d) {
  var g = this.gSeries;
  while (g.firstChild) g.removeChild(g.firstChild);
  var yBase = this._y(0), yTop = this._y(this.ymax);
  for (var i = 0; i < this.data.series.length; i++) {
    var vals = values2d[i] || [];
    if (!vals.length) continue;
    var color = this._seriesColor(i);
    var pts = [];
    for (var j = 0; j < vals.length; j++) pts.push([this._x(j), this._y(vals[j])]);
    if (pts.length === 1) {
      mk('circle', { cx: pts[0][0], cy: pts[0][1], r: 3, fill: color }, g);
      continue;
    }
    var d = smoothPath(pts, yBase, yTop);
    if (this.kind !== 'line') {
      /* 渐变面积：序列色 22% → 全透明（stop-opacity 不依赖 color-mix） */
      var gid = 'agc-grad-' + this.id + '-' + i;
      if (this.gradColors[i] !== color) {
        this.gradColors[i] = color;
        var old = this.defs.querySelector('#' + gid);
        if (old) old.remove();
        var grad = mk('linearGradient', { id: gid, x1: 0, y1: 0, x2: 0, y2: 1 }, this.defs);
        mk('stop', { offset: '0%', 'stop-color': color, 'stop-opacity': 0.22 }, grad);
        mk('stop', { offset: '100%', 'stop-color': color, 'stop-opacity': 0 }, grad);
      }
      var area = d + ' L ' + num(pts[pts.length - 1][0]) + ' ' + num(yBase) + ' L ' + num(pts[0][0]) + ' ' + num(yBase) + ' Z';
      mk('path', { d: area, fill: 'url(#' + gid + ')', stroke: 'none' }, g);
    }
    mk('path', {
      d: d, fill: 'none', stroke: color,
      'stroke-width': this.kind === 'line' ? 2 : 1.8,
      'stroke-linecap': 'round', 'stroke-linejoin': 'round',
    }, g);
  }
};

/* ================= hover（十字 + 浮层，transform 跟随不重排） ================= */
Chart.prototype._onPointer = function (e) {
  if (!this.n) return;
  var rect = this.plot.getBoundingClientRect();
  var px = e.clientX - rect.left;
  var iw = this.w - this.padL - this.padR;
  var i = this.n <= 1 ? 0 : Math.round((px - this.padL) * (this.n - 1) / iw);
  i = Math.max(0, Math.min(this.n - 1, i));
  if (i !== this.hover) { this.hover = i; this.tipKey = ''; }
  this._drawHover();
};

Chart.prototype._drawHover = function () {
  if (this.kind !== 'line') return;
  var i = this.hover;
  if (i < 0 || !this.n || !this.data) {
    this.gCross.setAttribute('visibility', 'hidden');
    this.tip.style.display = 'none';
    return;
  }
  var x = this._x(i);
  this.gCross.setAttribute('visibility', 'visible');
  this.gCross.setAttribute('transform', 'translate(' + num(x) + ' 0)');
  this.crossLine.setAttribute('y1', this.padT);
  this.crossLine.setAttribute('y2', this.h - this.padB);
  /* 每序列一个取值点（随动画值落位） */
  var cur = this._curVals();
  while (this.dots.length < this.data.series.length) {
    this.dots.push(mk('circle', { 'class': 'agc-dot', r: 3.5 }, this.gCross));
  }
  for (var s = 0; s < this.dots.length; s++) {
    var dot = this.dots[s];
    if (s >= this.data.series.length || !cur[s] || cur[s][i] == null) { dot.setAttribute('visibility', 'hidden'); continue; }
    dot.setAttribute('visibility', 'visible');
    dot.setAttribute('cx', 0);
    dot.setAttribute('cy', this._y(cur[s][i]));
    dot.setAttribute('stroke', this._seriesColor(s));
  }
  /* 浮层内容仅悬停点或数据变化时重建，跟随只改 transform */
  var key = this.sig + '|' + i;
  if (this.tipKey !== key) {
    this.tipKey = key;
    this.tip.textContent = '';
    var title = document.createElement('div');
    title.className = 't';
    var raw = this.data.x[i];
    title.textContent = raw == null ? '' : String(raw);
    this.tip.appendChild(title);
    var fmtY = this.data.fmtY || defaultFmt;
    for (var k = 0; k < this.data.series.length; k++) {
      var sv = this.data.series[k];
      if (!sv.values.length) continue;
      var row = document.createElement('div');
      row.className = 'r';
      var chip = document.createElement('span');
      chip.className = 'c';
      chip.style.background = this._seriesColor(k);
      row.appendChild(chip);
      var nm = document.createElement('span');
      nm.className = 'n';
      nm.textContent = sv.name || '值';
      row.appendChild(nm);
      var vv = document.createElement('span');
      vv.className = 'v';
      vv.textContent = fmtY(sv.values[i] != null ? sv.values[i] : 0);
      row.appendChild(vv);
      this.tip.appendChild(row);
    }
  }
  this.tip.style.display = '';
  var flip = x > this.w * 0.62;
  var tx = flip ? x - 10 : x + 10;
  var ty = Math.max(4, this.padT + 2);
  this.tip.style.transform = 'translate(' + num(tx) + 'px,' + num(ty) + 'px)' + (flip ? ' translateX(-100%)' : '');
};

/* ================= 尺寸跟随 ================= */
Chart.prototype._onResize = function () {
  if (!this.data || !this.el.isConnected) return;
  if (!this._layout()) return;
  cancelAnimationFrame(this.raf);
  this._setCur(this.data.series);
  this._resolveColors();
  this._drawAxes();
  this._drawSeries(this._curVals());
  this._drawHover();
};

Chart.prototype.update = function (cfg) { this._setData(cfg); };

Chart.prototype.destroy = function () {
  cancelAnimationFrame(this.raf);
  if (this._ro) this._ro.disconnect();
  if (this.kind === 'line') {
    this.plot.removeEventListener('pointermove', this._onMove);
    this.plot.removeEventListener('pointerleave', this._onLeave);
  }
  this.el.textContent = '';
  this.el.classList.remove('agchart', 'agchart-line', 'agchart-spark');
  if (this.el.__agchart === this) this.el.__agchart = null;
};

function mount(el, kind, cfg) {
  if (!el) return null;
  var inst = el.__agchart;
  if (inst && inst.kind !== kind) { inst.destroy(); inst = null; }
  if (!inst) { inst = new Chart(el, kind); el.__agchart = inst; }
  inst._setData(cfg);
  return inst;
}

window.AgChart = {
  sparkline: function (el, series, opts) {
    opts = opts || {};
    return mount(el, 'spark', { series: series, empty: opts.empty });
  },
  line: function (el, cfg) {
    return mount(el, 'line', cfg || {});
  },
};
})();
