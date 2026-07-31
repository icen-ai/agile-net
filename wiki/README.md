# AgileNet 文档站（wiki）

AgileNet 官方文档站源码，部署于 Cloudflare Pages：<https://anet.icen.ai>

## 结构

```
wiki/
├── index.html          # 文档站外壳（顶栏 + 侧栏大纲 + 正文 + 右侧 TOC + 搜索）
├── assets/
│   ├── style.css       # Cindy 设计 token（浅色默认 + 深色切换）
│   ├── app.js          # hash 路由 + Markdown 渲染 + 大纲 + 全文搜索 + 主题
│   ├── icons.js        # Lucide 内联 SVG（仅收录用到的图标，严禁文字表情）
│   └── marked.min.js   # marked v15（MIT，本地内嵌无 CDN 依赖）
├── content/
│   ├── nav.json        # 大纲结构（分组 / 页面 / 图标）
│   └── **/*.md         # 文档页（GFM；<path> 对应 #/<path> 路由）
└── _headers            # Cloudflare Pages 安全响应头与缓存策略
```

无构建链：原生 JS + 本地内嵌 marked，直接静态托管即可。

## 写作约定

- 新页面：在 `content/` 下建 `<dir>/<page>.md`，并在 `nav.json` 登记（标题、路径、图标）
- 图标：只用 `icons.js` 已收录的 Lucide 名；新增图标按 Lucide SVG 内部节点追加
- 严禁文字表情充当图标；代码块、表格、引用块样式已内置
- 外链自动新窗口打开；代码块自动带复制按钮

## 本地预览

```bash
python -m http.server 8080 -d wiki   # 打开 http://127.0.0.1:8080
```

## 部署

```bash
wrangler pages deploy wiki --project-name anet
```

自定义域 `anet.icen.ai` 已在 Pages 项目绑定（首次绑定后持续生效）。
