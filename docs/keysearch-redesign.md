# pinchtab → key 搜索引擎 改造方案

> 版本：v0.1 草案（2026-08-21）
> 目标：把 pinchtab 从「通用 AI Agent 浏览器控制面」改造成「专用 key 搜索引擎」。

## 1. 背景与目标

pinchtab（fork 自 `pinchtab/pinchtab`）是 Go 编写的浏览器控制面：standalone HTTP server + headless Chrome（CDP）+ 多实例 bridge。改造目标是新增一个「key 搜索」能力：导航到合规公网站点，抓取渲染后 HTML / JS 资源 / 网络响应，检测泄露的 API key，命中后定位并截图、脱敏回流。

相比 gitleaks / truffleHog 等静态扫描引擎，本方案的差异化在于：用真实浏览器加载，能拿到 SPA 运行时注入、API 响应、动态加载 chunk 里的 key——这些是静态扫描的盲区。

## 2. 现有代码关键链路（已读源码）

| 能力 | 入口 / 实现 |
| --- | --- |
| 抓取 | `POST /scrape` → `internal/handlers/scrape.go:47 HandleScrape` → `internal/scrape/run.go:194 Run` → `renderPageHTML`（`handlers/scrape.go:147`） |
| 导航 | `internal/bridge/bridge.go:401 Navigate` → `cdpops/navigation.go:53 NavigatePageWithRedirectLimit` |
| 等待渲染 | `internal/bridge/observe/lifecycle.go:51 WaitForQuietWindow` |
| 取渲染后 HTML | `internal/bridge/evaluate.go:10 Evaluate("document.documentElement.outerHTML")` |
| 网络响应 | `internal/bridge/observe/network.go:36 NetworkMonitor.StartCapture`（CDP）；`internal/handlers/network.go` 提供 `/network`、`/network/export`(HAR)；需 `RetainNetworkBodies` 才有响应体 |
| 截图 | `internal/handlers/screenshot.go:67 HandleScreenshot` → `bridge/screenshot.go:171 CaptureScreenshot`；全页 `WithCaptureBeyondViewport`，元素 `ScreenshotClipForNode:212`，坐标 `Clip` |
| 访问控制 | 默认仅本地：`internal/config/config_utils.go:14 defaultLocalAllowedDomains=["127.0.0.1","localhost","::1"]`；IDPI 默认严格；拦截点 `handlers/navigation.go:213`、`scrape.go:63` |
| 调度 | `internal/scheduler/scheduler.go:90` 进程内异步队列，**无 Kafka**，多机需换外部 MQ |

## 3. 改造方案（最小侵入）

**新增 `internal/keydetect` 包 + 新端点 `POST /keysearch`**，复用现有渲染/网络/截图能力，不改 `scrape`/`browserops` 核心。

### 3.1 检测流程

```
POST /keysearch  { url, provider_hints?, ... }
  1. 导航：CreateTab → Navigate → WaitForQuietWindow
  2. 抓取：
     a. 渲染后 HTML：Evaluate("document.documentElement.outerHTML")
     b. JS 资源：NetworkMonitor 捕获的脚本响应体
     c. 网络响应：XHR / fetch 响应体（API 可能直接返回 key）
  3. 检测（internal/keydetect）：
     a. 正则规则：各提供商 key 格式（sk- / Bearer / ak- / 方舟 / 智谱 等）
     b. 熵检测：高熵长串（base64 / hex）
     c. 上下文归类：结合环境变量名、API base URL、模型名 → 提供商/模型
     d. 去噪：排除版本号、哈希、库常量等误报
  4. 命中 → 定位：key 在 HTML/响应中的文本偏移 或 DOM 元素
  5. 截图：ScreenshotClipForNode（元素）或 Clip（坐标）
  6. 脱敏回流：末 8 位 + HMAC-SHA256 指纹 + 资产/供应商/模型 + 截图
```

### 3.2 keydetect 包设计

```
internal/keydetect/
  ├── detector.go   # 主流程：输入文本 → 输出命中列表（含位置偏移）
  ├── rules.go      # 提供商 key 正则规则（可扩展）
  ├── entropy.go    # 香农熵检测（高熵字符串）
  ├── classify.go   # 上下文归类：提供商 / 模型归属
  └── result.go     # 命中结果结构（provider / model / offset / snippet）
```

### 3.3 改动文件清单

**新增**
- `internal/keydetect/`（detector.go / rules.go / entropy.go / classify.go / result.go）
- `internal/handlers/keysearch.go`（keysearch handler）

**修改**
- `internal/routes/routes.go`：注册 `POST /keysearch`
- `internal/config/`：放开公网站点白名单（`security.allowedDomains` 支持指定域名）

**复用（不改）**
- `renderPageHTML`（渲染 HTML）
- `observe.NetworkMonitor`（JS / 网络响应）
- `bridge.CaptureScreenshot`（命中截图）
- `bridge.Navigate` + `WaitForQuietWindow`

## 4. 关键改造点

### 4.1 网络响应体（难点）

现状 `scrape` 不抓响应体，需要 keysearch 自己启用 `RetainNetworkBodies` 并过滤 JS/XHR/fetch 类型，避免内存爆掉（需限制单响应体大小、总量，沿用现有「最小采集」原则）。

### 4.2 访问白名单放开

默认仅本地。改造需：
- 配置层支持 `security.allowedDomains` 显式列白名单（不默认全开）
- 保留 `netguard` SSRF 校验（防私网/内网访问），这是公益合规底线，不能放开
- 只对「公开、目标明确」的域名放行

### 4.3 检测规则来源

- 复用 SecretWatcher 现有 11 家提供商上下文规则（DeepSeek / 百炼 / 方舟 / 智谱 / Kimi / 文心 / 混元 / MiniMax / 百川 / 零一 / 硅基流动）
- 新增熵检测做兜底，配合上下文降噪

## 5. 后续衔接（Kafka 多机）

`internal/scheduler` 是进程内队列，多机化时：
1. 把 keysearch 任务投递到 Kafka topic
2. 各 Worker 上的 pinchtab 作为 consumer 消费任务
3. 结果（脱敏 + 截图）回流 Kafka 或直写数据库

## 6. 里程碑拆分

| 里程碑 | 内容 | 验收 |
| --- | --- | --- |
| M1 | 打通 `/keysearch` 最小闭环 | 输入 URL，返回渲染后 HTML + 网络响应中命中的 key 列表 |
| M2 | 检测引擎 | 规则 + 熵 + 归类，误报可控 |
| M3 | 命中截图 | 对 key 位置截图并回传 |
| M4 | 脱敏回流 | 末 8 位 + HMAC 指纹，对接 SecretWatcher 数据库 |
| M5 | 白名单合规 | 仅放行授权域名，保留 SSRF 防护 |

## 7. 待确认

- 检测规则是否复用 SecretWatcher 现有 11 家，还是重写
- `/keysearch` 是独立端点，还是复用 `/scrape` 加参数
- 响应体保留策略的内存上限
