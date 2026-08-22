# WebLens · 网页数据采集与检测底座

> **WebLens（网页透镜）** —— 基于 [pinchtab](https://github.com/pinchtab/pinchtab)（Apache 2.0）二次开发。
> 在其浏览器控制面之上，扩展为「Web 数据采集 + 泄露检测」的通用底座。

---

## 这是什么

一个**可大规模并行、超低成本、能过反爬的 Web 数据采集与检测底座**。

底层是浏览器自动化控制面（HTTP API + CDP 多实例编排 + 安全边界），之上是可插拔的分析引擎。**换掉分析逻辑，底座不变，就得到不同的产品。**

```
┌─────────────────────────────────────────────┐
│  产品层（换分析逻辑）                          │
│  密钥泄露监测 · 网页数据提取 · AI 数据采集 · BaaS │
├─────────────────────────────────────────────┤
│  能力层                                      │
│  超低成本 · 高并发 · 过反爬 · 安全边界          │
├─────────────────────────────────────────────┤
│  底座（本仓库）                               │
│  浏览器控制面 + Lightpanda 轻量引擎 + 检测引擎   │
└─────────────────────────────────────────────┘
```

## 能力底座

| 组件 | 说明 |
|---|---|
| **浏览器控制面** | 导航 / 渲染 / 截图 / 网络抓取 / 多实例编排 / SSRF 与 IDPI 安全边界（继承自 pinchtab） |
| **Lightpanda 轻量引擎** | 52MB/实例、毫秒启动、CDP 兼容，比 Chrome 省 9~16 倍内存，1G 节点可跑 10+ 并发 |
| **keydetect 检测引擎** | 规则匹配 + 上下文门控熵检测 + 脱敏 + provider 归类（二开新增） |

## 二开新增的能力

### keydetect — 密钥检测引擎（`internal/keydetect`）

纯标准库、独立可测的检测器：

- **规则匹配**：OpenAI `sk-` / Anthropic `sk-ant-` / AWS `AKIA` / Google `AIza` / GitHub `ghp_` / Slack `xox` / NVIDIA `nvapi-` / 通用 `Bearer`
- **上下文门控熵检测**：只在 `api_key` / `token` / `secret` 等敏感字段值上做熵检测，排除变量名、静态资源路径、RSC base64 数据等误报源
- **脱敏输出**：完整 key 不落任何地方，只保留前缀 + 末四位 + SHA256 指纹
- **provider 归类**：结合上下文（如 `api.deepseek.com`）自动纠正 provider，不再误标
- **占位符排除**：打码占位值（`nvapi-xxx...`）不再误报

实测效果：对某 Next.js 应用全站抓取，命中从 **27 个（26 误报）收敛到 1 个精准命中**（信噪比 1:26 → 1:0）。

### `/keysearch` 端点（`internal/handlers/keysearch.go`）

一条端点完成「导航 → 渲染 DOM → 抓 API/JS 响应体 → 检测 → 脱敏返回」闭环：

- 覆盖运行时密钥：SPA 运行时注入、API 响应体、动态 chunk —— 这些是 gitleaks / truffleHog 等静态扫描器**看不到**的盲区
- 命中来源标注（`html` / `network`），内存上限适配 1G 节点（24 body × 256KB × 总 8MB）

### `cmd/keydemo` — 独立 CLI

读文件或 STDIN，输出检测结果 JSON，可用于快速验证与交叉编译部署：

```bash
go run ./cmd/keydemo ./api_bodies.txt
```

### 数据提取 —— 快慢双路径（`cmd/fetch` / `cmd/lpfetch`）

输入 URL，输出结构化正文 Markdown：

- **快路径 `cmd/fetch`**：静态站走 seaportal HTTP 提取，毫秒级、零浏览器
- **慢路径 `cmd/lpfetch`**：动态站走 Lightpanda 真实渲染再提取，秒级

```bash
fetch <url> [outfile.md]                    # 快路径
lpfetch -lp 127.0.0.1:9222 <url> [out.md]   # 慢路径（Lightpanda 渲染）
```

驱动 Lightpanda 的 Go 客户端在 `internal/lightpanda`（处理了 `browserContextId` 字段、sessionId 附加、默认 UA 覆盖三个 CDP 差异）。

### 监控巡检（`cmd/monitor`）

一个网页监控页面：输入网址 + 频率，定时抓取并检测网页变化，红绿 diff 直观展示。

- **静态 / 动态双模式**：静态站走 seaportal 快路径，动态站走 Lightpanda 真实渲染（能监控 SPA、反爬站等传统云监控看不见的站点）
- **关键词模式**：设置关键词后，只在关键词出现/消失时才算变化，适配行情站、reddit 等高频变化页面
- **通俗摘要**：每次变化首行一句话总结（「新增 2 行、删除 1 行」「关键词「特价」出现了」）+ 红绿 diff 细节
- 自托管，数据在自己服务器，可私有化

```bash
go build ./cmd/monitor && ./monitor    # 默认监听 8080
# 监控内网站点加：MONITOR_ALLOW_PRIVATE=1 ./monitor
# 动态站渲染的 Lightpanda 地址：LIGHTPANDA_ADDR=127.0.0.1:9222
```

## 产品矩阵（同一个底座，换分析逻辑）

| 方向 | 说明 | 状态 |
|---|---|---|
| **密钥泄露监测** | 全网测绘目标组件的 API key 泄露，负责任披露 | ✅ 已跑通（206 资产 3.6 分钟扫完，命中 15 key） |
| **网页数据提取** | URL → 正文 / 结构化数据，Scraping as a Service | ✅ 已跑通（快慢双路径，wikipedia 507KB 实测） |
| **监控巡检** | 网页变化监测，静态/动态双模式 + 关键词，红绿 diff | ✅ 已跑通（102 部署，reddit/binance 实测） |
| **AI 数据采集** | 舆情 / 竞品 / 价格监测，为模型喂数据 | 📋 规划 |
| **浏览器即服务** | 封装为通用浏览器 API 供 AI Agent 调用 | 📋 规划 |

## 实测性能（1G 内存服务器）

| 指标 | 数据 |
|---|---|
| Lightpanda 单实例内存 | ~52MB（vs Chrome 200~400MB） |
| 并行扫描吞吐 | 6 路并行 1.05 秒/资产 |
| 全量扫描 | 206 资产 3.6 分钟 |
| 检测信噪比 | 1:26 → 1:0（降噪后） |

## 快速开始

```bash
# 编译
go build -o pinchtab ./cmd/pinchtab

# 启动控制面（默认 headless，仅监听 127.0.0.1）
./pinchtab server --browser chrome

# 密钥检测：读文件
go run ./cmd/keydemo ./some_page_or_response.txt

# 密钥检测：通过 /keysearch 抓取在线页面
curl -X POST http://127.0.0.1:9867/keysearch \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'

# 数据提取：快路径（静态站）
go run ./cmd/fetch "https://example.com" out.md

# 数据提取：慢路径（动态站，Lightpanda 渲染）
go run ./cmd/lpfetch -lp 127.0.0.1:9222 "https://example.com" out.md

# 监控巡检：网页变化监控（页面 + API，默认 8080）
go build ./cmd/monitor && ./monitor
```

> 提示：`/scrape` 等浏览器端点在当前 `simple` 调度策略下需要先有可用 instance；
> 本机沙箱环境若 Chrome 起不稳，可改用纯 HTTP 提取（seaportal）或部署到服务器配合 Lightpanda。

## 安全与合规

- **脱敏优先**：检测结果只含打码 key 与指纹，完整凭据不落盘、不入库
- **公益原则**：发现的真实凭据**不使用、不验证**，走负责任披露
- **SSRF 边界**：保留上游的私网访问校验与 IDPI 域名白名单，放开到公网前请确认授权范围
- 本仓库为二开项目，仅用于**授权目标**的安全评估与数据采集

## 致谢与许可

**WebLens** 基于 [pinchtab](https://github.com/pinchtab/pinchtab) 二次开发，沿用其 **Apache 2.0** 许可。浏览器控制面、多实例编排、安全边界等核心能力来自上游；keydetect 检测引擎、keysearch 端点、Lightpanda 驱动、fetch/lpfetch 数据提取、monitor 监控巡检均为本仓库新增。
