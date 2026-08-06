# UI 设计（与实现一致）

AgileNet 有三套用户界面：节点 Web 管理后台、节点 TUI 终端、客户端桌面/Android 应用。
视觉语言全面对齐 Cindy 桌面端：中性灰底 + 浅色卡片 + 反相深色主按钮，单色为主、状态色点缀。

## 0. 设计规范（全部前端共用）

### 设计 Token（浅色为默认主题）

| Token | 浅色 | 深色 | 用途 |
| --- | --- | --- | --- |
| `--bg` | `#EDEDED` | `#2A2828` | 页面背景 |
| `--bg2` | `#F4F4F4` | `#2F2D2D` | 次级表面 |
| `--panel` | `#F8F8F8` | `#312F2F` | 卡片 |
| `--panel2` | `#FFFFFF` | `#3A3838` | 浮层 / 输入框 / 弹窗 |
| `--border` / `--border2` | `#DCDFE3` / `#C9CDD3` | `#434343` / `#504F4F` | 边框 |
| `--text` / `--text-strong` | `#3C3F43` / `#2E3237` | `#D4D4D4` / `#EEEEEE` | 正文 / 强调 |
| `--dim` / `--dim2` | `#686B72` / `#8C8E94` | `#9A9DA3` / `#6F6F6F` | 次级 / 三级文字 |
| `--accent` / `--accent2` / `--accent-fg` | `#3C3F43` / `#2E3237` / `#FCFCFC` | `#EEEEEE` / `#E2E2E2` / `#252222` | 反相主按钮、侧栏选中胶囊、**全部激活态**（选中节点/订阅卡/段控，非选中用梯度灰） |
| `--link` / `--ring` | `#2E3237` / `#2E3237` | `#EEEEEE` / `#EEEEEE` | 链接（带下划线）/ 聚焦环——主题无蓝，激活与焦点一律近黑（深主题近白） |
| `--ok` / `--warn` / `--danger` | `#61C555` / `#F6BE50` / `#ED6A5F` | `#5FCF65` / `#F8CE52` / `#F96057` | 语义基准色 = **macOS 红绿灯**（仅填充/圆点/进度条/开关等图形场景） |
| `--ok-text` / `--warn-text` / `--danger-text` | `#3E8E2E` / `#9A7414` / `#CE3F34` | 同基准色 | 语义文本色：基准色直接作文字对比度不足，浅主题用加深变体（深主题亮色可直接作文本） |
| `--shadow-1` / `--shadow-2` / `--shadow-3` | 双层柔和投影（alpha .045/.08~.12/.06~.14） | 同层级加深（alpha .24~.28/.36~.40/.40~.48） | 阴影层级：1 卡片（hover 微抬升并升至 2 级）/ 2 弹层·菜单·浮层 / 3 模态；深色以 `--glass-border` 发光补偿 |
| `--glass-bg` / `--glass-border` | `rgba(252,252,252,.78)` / `rgba(0,0,0,.08)` | `rgba(56,54,54,.78)` / `rgba(255,255,255,.10)` | 玻璃拟态（须配合 backdrop-filter blur；ctx-menu/float-menu 浮层） |
| `--info` / `--info-text` / `--info-bg` | `#5484BC` / `#3E6A9E` / `rgba(84,132,188,.14)` | `#7EA6D8` / 同 / `rgba(126,166,216,.14)` | info 语义（日志级别用；主题无蓝，取低饱和钢蓝） |
| `--tbl-head-bg` / `--tbl-row-hover` / `--tbl-row-alt` | `#F1F1F1` / `rgba(0,0,0,.03)` / `rgba(0,0,0,.015)` | `#383636` / `rgba(255,255,255,.04)` / `rgba(255,255,255,.02)` | 表格：粘性表头底 / 行 hover / 极淡斑马纹 |
| `--log-debug` / `--log-info` / `--log-warn` / `--log-error` | `#686B72` / `#3E6A9E` / `#9A7414` / `#CE3F34` | `#9A9DA3` / `#7EA6D8` / `#F8CE52` / `#F96057` | 日志级别文本色（logv 行字 + 左侧色条，深浅两套均保对比度） |
| `--accent-grad` | `linear-gradient(180deg,#45484D,#2E3237)` | `linear-gradient(180deg,#F5F5F5,#DFDFDF)` | 主操作渐变（克制：仅侧栏激活胶囊等大激活面，小件仍用纯色 `--accent`） |
| `--mask` | `rgba(0,0,0,.46)` | `rgba(0,0,0,.58)` | 模态遮罩（配 backdrop-filter blur(8px)） |
| `--toggle-knob` | `#FFFFFF` | 同 | 开关/勾选框旋钮（深浅恒白） |
| `--dur-fast` / `--dur-slow` | `120ms` / `320ms` | 同 | 动效时长梯度（中档 `--dur` 180ms 保留于 style.css；reduced-motion 全局关闭） |
| `--chart-grid` / `--chart-up` / `--chart-down` | `rgba(0,0,0,.09)` / `#61C555` / `#5484BC` | `rgba(255,255,255,.10)` / `#74CE8A` / `#8FB6DE` | 图表：网格线 / 速率双色（上行绿·下行钢蓝；深色降饱和提亮变体，agchart 序列可传 `var(--chart-up)` 等） |
| `--lat-good` / `--lat-mid` / `--lat-bad`（+ `--lat-*-bg`） | `#3E8E2E` / `#9A7414` / `#CE3F34` | `#5FCF65` / `#F8CE52` / `#F96057` | 延迟三档语义文字色（与 ok/warn/danger 文字色同值，独立命名保语义；`-bg` 变体为 `.lat` 胶囊底，同 `--ok/warn/danger-bg` 值） |
| `--power-ring` / `--power-glow` | `rgba(60,63,67,.35)` / `rgba(60,63,67,.28)` | `rgba(238,238,238,.40)` / `rgba(238,238,238,.22)` | power-btn 运行态：呼吸环色 + 外发光光晕 |
| `--skel-bg` / `--skel-shine` | `rgba(0,0,0,.06)` / `rgba(255,255,255,.65)` | `rgba(255,255,255,.07)` / `rgba(255,255,255,.14)` | 骨架屏 `.skel` 底色 + 扫光色 |
| `--beta-grad` | Beta 徽章/实验卡渐变（badge-beta / beta-card 描边） |
| `--glass-hi` | `rgba(255,255,255,.5)` | `rgba(255,255,255,.06)` | Liquid Glass 静态顶部高光（`inset 0 1px 0`：nav-item.active / ctx-menu / modal） |
| `--card-hi` | `rgba(255,255,255,.65)` | `rgba(255,255,255,.05)` | 机加工卡片顶部高光（v2：`.card`/`.dcard`/`.stat` 的 `inset 0 1px 0`） |
| `--input-bg` / `--input-border` | `#ECEDEF` / `#C9CDD3` | `rgba(255,255,255,.07)` / `#504F4F` | 硬边控件（v2：input/textarea/select/agsel-btn）：下沉灰填充 + 2px 底缘；聚焦 = 填充加深 + 近黑底缘 |
| `--btn-hi` | `rgba(255,255,255,.14)` | `rgba(255,255,255,.10)` | 实体按键顶高光（v2：填充型按钮 inset 高光；透明/ghost 变体豁免或降级） |
| `--well-inset` | `inset 0 1px 3px rgba(16,24,40,.07)` | `inset 0 1px 3px rgba(0,0,0,.30)` | well 数据凹槽内阴影 |
| `--mast-*` 组 | 固定深色（两主题同值）：`--mast-bg`/`--mast-border`/`--mast-hi`/`--mast-text`/`--mast-dim`/`--mast-dim2`/`--mast-faint`/`--mast-div`/`--mast-btn-*`/`--mast-on-*` | 同左 | 深色仪器主卡（首页 hero 总电闸面板，深浅主题均为固定深色） |

- 圆角：卡片 10px（`--radius`），按钮 8px，输入框 6px（硬边底缘 4px），徽标与胶囊 999px，上下文菜单 10px（菜单项 6px）
- 阴影：三级层级 token —— `--shadow-1` 卡片（hover translateY(-1px) 微抬升并升至 `--shadow-2`）、`--shadow-2` 弹层/菜单/浮层、`--shadow-3` 模态；深色同层级加深，玻璃拟态浮层另以 `--glass-border` 发光补偿。`--shadow` 为管理端 crates/node/ui 存量引用的兼容别名（值 = `--shadow-3`），新代码勿用。v2 起三级不透明度约翻倍（卡片读作「装在机架上的面板」而非漂浮纸片）
- **内容区质感 v2（两端一致，以后层级联覆盖落在各自 style.css 末尾）**：①机加工卡——卡面 `--panel2` + `--border2` 描边 + `--card-hi` 顶高光 + 加倍阴影；②铭牌头带——`.card > h3:first-child` / `.dc-head` / `.modal > h3:first-child` 负边距头带（`--bg2` 底 + 底线 + 12px 字距丝印，零标记改动）；③硬边控件——input/textarea/select/agsel-btn 下沉灰填充 + 2px 底缘，聚焦底缘近黑；④未开启降饱和——首页角色卡 `.dcard.off`（syncDashOff 驱动：头带开关关 → 整卡退灰去影、卡身压 45%，开关本身保持全亮作开启入口），hero 主卡停止态数据区压 30%；⑤深色仪器主卡——首页 hero 固定深色 `--mast-*` 面板（两主题同深色），状态墙横排分隔线 + 等宽大数字，总电闸运行态反相白键 + 白色呼吸环
- 侧栏选中项为反相胶囊（`--accent-grad` 微渐变 + `--shadow-1`；浅主题深底浅字，深主题浅底深字），hover 用 `--hover`
- 默认主题为浅色；深/浅切换持久化于 localStorage（`ag_theme`）

### 图标规范

- 统一使用 Lucide 风格内联 SVG（24x24 viewBox、`stroke="currentColor"`、stroke-width 2、圆角端点）。
- Web 后台：`crates/node/src/ui/mod.rs` 内 `ICONS` 表 + `ic(name, size)`；静态 HTML 用 `<i data-ic="name" data-sz="n">` 占位，启动时 `hydrateIcons()` 替换。
- 桌面/Android：`apps/desktop/ui/icons.js` 暴露 `AgIcon(name, size)`，同样支持 `data-ic` 占位水合。
- 两个图标表均只收录实际用到的图标（无构建链下等价于 tree-shaking，未引用的图标不进入产物）。新增图标时把对应 Lucide 图标的 SVG 内部节点追加进表即可。
- 严禁使用文字表情符号（Emoji）充当图标；状态标识一律用 `.dot` / `.badge` / `.rdot` 等 CSS 元素。

### 共享组件层（components.css）

- `apps/desktop/ui/components.css` 是两端共用组件样式的唯一来源（桌面 `<link>`，管理端经 `/ui/components.css` 内嵌服务，机制同 tokens.css）；端特有覆盖留在各自 style.css。
- 当前收录 **ag-select 统一自定义下拉**：原生 select 保留为数据/逻辑载体（视觉隐藏），`agSelectEnhance(root)` 幂等增强、`agSelectRefresh(sel)` 程序化变更后刷新；类名 `.agsel` / `.agsel-btn` / `.agsel-label` / `.agsel-pop` / `.agsel-opt`（修饰类 `.open` / `.sel` / `.agsel-sm`），弹出层 fixed 挂 body、只吃 var(--*)。
- 当前收录 **ag-tabs 横向页签条**：页内分区切换（质感泛化自段控 `.group-tab`），结构 `.agtabs` > `.agtabs-pill` > `button.agtab[data-agtab]`（`.active` 反相胶囊），可选右侧工具位 `.agtabs-tools`（搜索/按钮右对齐）；两端 app.js 各自 `agTabsBind(bar, onSwitch)` 驱动——面板 = 与页签条同容器直属 `[data-agpanel]`，纯显隐切换不重渲染。应用：管理端扇入页（监听|连接|令牌 + 跨页签联动搜索）、客户端扇出页（监听|连接）。
- 当前收录 **agchart 图表**（首个共享 JS 组件）：`apps/desktop/ui/agchart.js` 零依赖原生 SVG/JS，桌面端 `<script src>` 引入、管理端经 `/ui/agchart.js` 内嵌服务（机制同 components.css）。两版本：`AgChart.sparkline(el, series, opts)` 省略版（趋势折线 + 渐变面积，无轴无字）与 `AgChart.line(el, {x, series, fmtX?, fmtY?, legend?, empty?})` 完整版（XY 轴刻度网格 / 多序列 / hover 十字 + 每点浮层）；颜色只吃 var(--*)（序列色字符串经 getComputedStyle 解析为实色再写 SVG 呈现属性，主题切换后下一次绘制自然生效；网格线走 `--chart-grid` token，默认色板 `--accent`/`--dim2`/语义色，速率序列建议传 `var(--chart-up)`/`var(--chart-down)`），数据签名不变不重绘，数据更新 rAF 数值插值过渡（~400ms ease-out，新增点自基线生长），hover 跟随只动 transform。样式类 `.agchart*` 在 components.css（图例 `.agchart-legend`、浮层 `.agchart-tip`、网格 `.agc-grid`、空态 `.agc-empty`）。应用：管理端概览 24h 流量趋势（完整版）+ 扇入/扇出/中继三张流量卡（sparkline）。
- 当前收录 **ahelp 行内帮助**：解释性小字的归宿（替代常驻 hint 长文）。结构 `.ahelp`（badge-question-mark 13px 图标，dim 色）> `.ahelp-tip`（纯 CSS hover 上浮说明卡，panel2/border/阴影质感，max-width 240px 正常换行，z-index 高于卡片低于 agsel-pop）；不吃 JS。两端 app.js 各有 `ahelp(text)` 内联 helper，静态 HTML 手写同构 span（图标用 `data-ic="badge-question-mark"` 占位水合）。应用：管理端扇入令牌卡头、客户端远程卡/扇出监听/订阅内核卡头。
- 当前收录 **agedit 行内编辑**：「值 [修改] ↔ 输入框 [保存]」统一模式（Enter 保存 / Esc 取消，validate 报错 toast 不写入）。JS 驱动：宿主元素（任意容器）调 `bindInlineEdit(el, {get, set, validate?, editValue?})`（两端各自 app.js），返回 `{refresh()}` 供轮询同步显示值（编辑中不打扰，显示值变更检测不重排 DOM）；样式 `.agedit*` 在 components.css（inline-flex 宿主 + `.agedit-val` 截断 + `.agedit-input` 紧凑输入框）。应用：客户端首页代理卡监听行（编辑端口，变更即重启代理生效）、远程卡监听地址。
- 当前收录 **ctx-menu / float-menu 上下文菜单**：macOS 风格右键菜单（10px 圆角 + `--glass-bg` 毛玻璃 backdrop-filter blur(18px) + `--glass-border` 边缘发光 + `--shadow-2`，z-index 600 高于 agsel-pop(500)）。结构 `.ctx-menu`（fixed 浮层，JS 写 left/top；transform-origin 默认左上，可按弹出方位覆盖）> `.ctx-item`（危险项加 `.danger`，分隔线 `.ctx-sep`）；菜单内缩 5px 间距、item 6px 圆角 hover，出现动画 ctx-in = scale(.96)+fade 120ms。`.float-menu` 为悬浮球场景的语义别名，同一选择器分组、结构与样式完全复用，不重复实现。
- 当前收录 **tbl 实时数据表格**：`.tbl`（table-layout: fixed 保对齐与省略号，列宽在 th 上设 `style="width:…"`，不设均分；border-collapse: separate + spacing 0 使粘性表头底线随表头吸附不脱落）——th 粘性 + `--tbl-head-bg`，行高 34px、全表 tabular-nums、单元格 nowrap 省略号，tbody 行 hover `--tbl-row-hover`、偶数行极淡斑马纹 `--tbl-row-alt`（hover 覆盖）；修饰类 `.tbl-dense` 行高 28px。
- 当前收录 **logv 日志流**：`.logv`（`--bg2` 底 + 1px border + 10px 圆角，等宽 12px/1.6，可选中复制）> `.logv-line`（行 hover 微亮 `--tbl-row-hover`），级别修饰 `.lv-debug/.lv-info/.lv-warn/.lv-error` = 左 3px 色条（border-left 恒占 3px，无级别行等宽对齐）+ 整行字着色（`--log-*`）；关键字命中包 `<mark class="logv-hl">`（`--accent-bg` 圆角 2px，`color: inherit` 压 UA mark 样式）。
- 当前收录 **pill 状态胶囊**：badge 的共享泛化沉淀，新代码一律用 pill。`.pill` + 修饰 `.pill-ok/.pill-warn/.pill-danger/.pill-dim`（语义 bg/text token；dim 档 `--accent-bg` + `--dim`）。
- 当前收录 **side-foot 侧栏底部区**：桌面外壳侧栏 flex 列内 `margin-top:auto` 沉底，border-top 细分隔 + 纵向堆叠；`.side-foot-rate` 网速行（tabular-nums），上下行箭头 = `.up`/`.down` 的 ::before 注入 unicode ↑↓ 并着色（ok-text/info-text，不引图标字体）；折叠态（body.collapsed）只留速率（纵向紧凑排布），≤720px 窄屏整体 display:none。
- 当前收录 **odo 数字滚动**（odometer 实用级，CSS 结构与动效、JS 由端内实现）：`.odo`（inline-flex + tabular-nums + line-height 1）> `.odo-digit`（1ch × 1em，overflow hidden）> `.odo-strip`（0-9 竖排，每格 1em）；JS 按值写 `transform: translateY(-N em)`，300ms `--ease` 过渡；非数字位直接放文本节点。
- 当前收录 **skel 骨架屏**：`.skel`（`--skel-bg` 底 + linear-gradient 扫光位移动画 1.4s）+ 修饰 `.skel-text`（h1em）/`.skel-card`（h80px）；prefers-reduced-motion 与 `html.no-blur` 下停扫光留静态块。
- 当前收录 **empty-state 空态三件套**：`.empty-state`（flex 垂直居中，padding 40px 20px）> `.ic`（36px，dim2）+ `.empty-t`（14px dim）+ `.empty-d`（12px dim2，max-width 320px）+ 可选主按钮（自动居中）。
- 当前收录 **power-btn 中控台大开关**：88px 圆形（2px `--border2` 边，hover 1.03 / active .97）；运行态 `.on` = `--accent-grad` 底 + `--accent-fg` 反相 32px 电源图标 + `--power-glow` 外发光 + 呼吸环（box-shadow 扩散 2s，`--power-ring`，reduced-motion 停）。
- 当前收录 **lat 延迟徽标**：`.lat` 等宽 12px 胶囊（min-width 54px tabular-nums）+ 修饰 `.lat-good`/`.lat-mid`/`.lat-bad`（`--lat-*` + `--lat-*-bg`）/`.lat-na`（超时灰）。
- 当前收录 **ev-list 事件中心列表**：`.ev-row`（行高 34px）> `.ev-time`（dim2 等宽）+ 类型 `.pill` + `.ev-detail`（flex:1 省略号）。
- 当前收录 **bnav 底部导航**：仅 ≤720px 显示（桌面 `display:none`），fixed 底栏毛玻璃（`--glass-bg` + blur 双写 + 顶部 1px `--glass-border`，`padding-bottom: env(safe-area-inset-bottom)`）；`.bnav-item` 图标 20px + 10px 文字，active = accent 色 + 顶部 2px 指示条；与 style.css 同断点媒体查询联动（隐藏侧栏 + `.content` 底部留白 64px），JS 无需干预。
- 当前收录 **well 数据凹槽**：卡内关键技术数据的嵌入式凹槽（mono 地址/指纹/端口）。结构 `.well`（`--input-bg` 底 + `--border` 边 + `--well-inset` 内阴影，flex 行）> `.k`（11px 字距丝印标签）+ `.grow`（省略号主值）；内容区质感 v2 配套件。
- **玻璃降级机制**：含 backdrop-filter 组件一律 `-webkit-` 前缀双写，并备 `html.no-blur` 规则——backdrop-filter:none + 背景改实色 `--panel2` 托底；覆盖点：ctx-menu / float-menu / bnav（components.css）、modal-mask（style.css，仅关 blur，`--mask` 本身实色半透明托底）；`html.no-blur` 同时停 `.skel` 扫光。
- odo/skel/empty-state/power-btn/lat/ev-list/bnav 与既有 ctx-menu/float-menu/tbl/logv/pill/side-foot 色值全部走 token 自动适配深色，并内置 prefers-reduced-motion 降级（关闭动画与过渡）。

## 1. 节点 Web 管理后台（crates/node/src/ui）

单文件嵌入式 SPA（原生 JS，无构建链），浅色中性风，左侧边栏导航。

### 视图结构

```
├── 登录页（不预填凭据，错误统一提示）
└── 主界面（侧边栏 + 内容区）
    ├── 概览       — 状态卡片 / 扇入·扇出·中继途径流量卡（AgChart sparkline）/
    │                24h 流量趋势图（AgChart 完整版）/ WebSocket 实时事件流
    ├── 客户端账号 — 搜索/组过滤/状态过滤/分页；新建(组选择→sk-密码+connect_url+二维码)
    │                重置密码 / 启停 / 删除
    ├── 权限组     — 列表(规则数/账号数)；详情 / 绑定规则(勾选) / 编辑 / 删除(占用时强制)
    ├── 路由规则   — 类型过滤/搜索；新建(类型校验提示) / 编辑 / 批量导入(JSON/NDJSON) / 删除
    ├── Relay 令牌 — 生成(psk_ 一次性展示) / 吊销
    ├── 审计日志   — 动作过滤 / 分页
    └── 节点设置   — 节点名编辑 / 服务信息 / 最近系统日志
```

### 前端安全约定

- 所有动态内容经 `esc()` 转义后渲染（杜绝存储型 XSS），CSP/XFO/nosniff 响应头
- access_token 过期自动以 refresh_token 续期（单次重试），401 兜底回登录页
- 密码/令牌明文只在模态框展示一次，提供复制按钮与 SVG 二维码（10 分钟缓存）
- 危险操作（删除/吊销/强制）均有确认弹窗；批量结果显示 toast
- 深色/浅色主题切换（侧边栏底部按钮，localStorage 持久化）

## 2. 节点 TUI（crates/node/src/tui）

ratatui 终端控制台（`agile-net-node tui` 或 `anet tui`），直连本地数据库，无需 API 在线。

```
页签：概览 | 规则 | 权限组 | 账号 | 令牌 | 审计
按键：Tab/←→ 切换 · ↑↓ 选择 · r 刷新 · e 启停账号 · n 生成令牌 · d 删除(y 确认) · q 退出
```

## 3. 客户端桌面/Android（apps/desktop）

Tauri 2 + 原生 HTML/JS，一体化应用外壳（无边框窗口 + 自定义标题栏 + 左侧功能分区导航）：

```
├── 标题栏：拖拽区（Logo + 应用名）+ 灵动岛 + 窗口控制（最小化/最大化/关闭到托盘）
├── 灵动岛：标题栏中央，常态显示代理/网络状态；通知瞬时弹出自动收回；
│           部分网络不可达时变黄，点击展开具体异常节点清单（动效伸缩）
├── 侧栏导航：连接 / 节点 / 路由 / 设置（≤720px 窄屏隐藏侧栏，改由共享 .bnav 底部导航接管，Android 复用）
├── 连接   — Hero 空状态引导 / 快速接入（agilenet:// 含 fp 证书指纹自动固定）
│            本地代理启停 / 手动添加（折叠）/ 已保存节点管理
├── 节点   — 实时状态徽标（绿=已连接 / 黄脉冲=连接中·重连中 / 灰=不可达），
│            离线整卡降饱和虚线框；断开
├── 路由   — 合并视图，每条规则带状态点与启停开关（暂停立即生效、本地记忆，
│            暂停不占冲突位次，允许其他节点同名规则接管 → 自由组合）
└── 设置   — 开机自启 / 自动代理 / 自动重连 / 语言(zh·en) / 主题(浅·深) / 关于
```

**已保存节点管理**：状态徽标区分（已连接/连接中/重连中/未连接），主操作按状态切换
（连接 ⇄ 断开），支持删除（二次确认）与导出为 `agilenet://connect?...` 接入链接
（复制到剪贴板，含明文密码需提示谨慎分享）。

**列表搜索**：节点/已保存节点/路由列表均为「常驻收起 + 搜索图标展开」式客户端筛选
（名称/地址/状态、账号/地址、类型/匹配值/节点）。

**仪表盘摘要大数字 `.dstat`**（style.css 预留样式，结构由后续迭代落地）：`.dstat` > `.dstat-l`（上行 11px dim 标签）+ `.dstat-v`（28px 等宽大数字，可替换 `.dc-val`/`.dc-sub` 组合）。

**前端硬约束**：

- Tauri CSP 为 `script-src 'self'`：**严禁内联事件属性**（onclick 等），全部事件在
  app.js 中绑定或用事件委托（data-act/data-key），否则静默失效
- 轮询渲染必须做变更检测（签名对比），不变更不重写 DOM，避免频闪与动画重放
- 状态可视化约定：绿=健康，黄=过渡态（连接中/重连中/部分不可达），灰=不可用

支持 zh/en 双语与浅/深主题（localStorage 持久化）。

Android 复用同一前端（Tauri 2 Mobile，响应式布局），构建见 apps/README.md。
