<div align="center">

# Grok Register + Live Panel

Based on [AaronL725/grok-register](https://github.com/AaronL725/grok-register) (MIT).

批量注册 Grok 账号（Camoufox）+ Web 监控面板  
任务编排 / 代理池 / 邮箱服务 / 域名轮换 / 账号补录 / BFS 检测 / **Token 鉴权**

[介绍页](https://lij768423-svg.github.io/grok-register-panel/) · [Discussions](https://github.com/lij768423-svg/grok-register-panel/discussions)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg)
![Stars](https://img.shields.io/github/stars/lij768423-svg/grok-register-panel?style=flat)
[![Site](https://img.shields.io/badge/site-github.io-111111.svg)](https://lij768423-svg.github.io/grok-register-panel/)

</div>

---

> **声明：** 仅供自动化流程研究、自有环境联调与个人学习。请遵守 xAI / 邮箱 / 代理服务商条款与当地法律，勿用于未授权批量滥用。

## 功能一览

| 能力 | 说明 |
|------|------|
| 注册全链路 | 邮箱 OTP → 资料页 → Turnstile → SSO → Device / OAuth → 写入 CPA / Grok2API |
| 多邮箱后端 | Cloudflare Worker 邮、DuckMail、YYDS、MailNest、CloudMail、MoeMail、Inbucket 自建；面板内切换、保存和连通性测试 |
| 反检测浏览器 | [Camoufox](https://camoufox.com/)（Gecko 层指纹） |
| 出口预检 | 启动前解析出口 IP / ASN，命中黑名单直接换口 |
| 风控早停 | `botFlagSource=1` + `policy=deny` 时跳过后续 OAuth，避免无效重试 |
| **BFS 检测** | 解码 access_token / SSO JWT，检查是否含 `bfs` claim（与 botFlag 独立）；注册后自动标记，面板可批量扫描 CPA |
| **SSO 风控面板** | 用现有 SSO 读 grok.com 的 `botFlagSource` / `policy=deny`，不换 token；可粘贴或扫描库存，面板只导出不含凭据的脱敏状态名单 |
| 编排器 | 多轮 batch、风控满 N 暂停、ASN 自动扩黑；规则写入 JSON 状态，不修改源码 |
| **Live 面板** | 启停、并发、再跑 N、黑名单、时段成功率、本批代理流量、账号补录、SSO 风控和 BFS 扫描；操作 API 需 `MONITOR_TOKEN` |
| 外部代理池 | 面板单条/批量导入、去重、探活、启停、删除；记录出口 IP、ASN、延迟和冷却状态 |
| 邮箱域名池 | 自有域名/子域名导入、provider 绑定、连续拒绝阈值、自动拉黑、活跃数限制和手动重置 |
| 失败恢复 | 待处理 SSO / accounts 文本补录 CPA，跳过已有账号，成功后自动出队 |
| 安全静态缓存 | 面板任务默认复用 JS / CSS / 字体 / 图片等 GET 静态资源；不缓存文档、接口、WebSocket 或 Turnstile |
| 批次流量计量 | 在现有 HTTP 代理前增加仅监听本机的临时计量层，展示本批上行、下行与总量，不保存代理地址或凭据 |
| 安全存储 | 代理、账号、SSO、日志、auth 与运行状态默认使用 owner-only 权限 |

## 界面预览

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/dashboard-dark.png">
  <img alt="Grok Register 注册控制台" src="docs/screenshots/dashboard-light.png">
</picture>

控制台集中展示任务参数、批次进度、时段成功率、账号补录、BFS 扫描和黑名单状态。

<details>
<summary><strong>代理池：批量导入、探活、冷却和出口质量</strong></summary>
<br>
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/proxy-pool-dark.png">
  <img alt="Grok Register 外部代理池" src="docs/screenshots/proxy-pool-light.png">
</picture>
</details>

<details>
<summary><strong>邮箱服务：六种 provider 与高级域名轮换</strong></summary>
<br>
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/email-service-dark.png">
  <img alt="Grok Register 邮箱服务与域名轮换" src="docs/screenshots/email-service-light.png">
</picture>
</details>

以上图片使用脱敏示例数据，并会跟随 GitHub 的深浅主题自动切换。

## 架构示意

```text
┌─────────────────┐     HTTP proxy      ┌──────────────────┐
│  Camoufox 注册机 │ ──────────────────► │ 本地代理 mixed 口 │
│  (多 worker)     │   127.0.0.1:79xx    │ (可选链式 dialer) │
└────────┬────────┘                     └────────┬─────────┘
         │                                        │
         │ SSO / Device Flow                      ▼
         ▼                                 住宅出口 / 其它出口
   cpa_auth/ · grok2api_auth/
         │
         ▼
┌─────────────────┐
│ webui/monitor   │  读 log/register_results.jsonl · CPA 目录
│ :8787 Live 面板 │  启停 run_until_100 / run_batch_headless
│ + Bearer token  │  浏览器填「访问令牌」→ localStorage
└─────────────────┘
```

说明：**注册机本身只配置一层 HTTP 代理 URL**。若需要「先节点再家宽」等链式出口，在代理客户端（如 mihomo `dialer-proxy`）配置，对注册机透明。

## 快速开始

### 环境

- Python 3.10+
- 能访问注册页、临时邮箱 API、`auth.x.ai` 的网络

| 平台 | 支持状态 | 批处理启动方式 |
|------|----------|----------------|
| Linux | 正式支持 | 有显示会话时直启；无显示时面板自动调用 `xvfb-run` |
| macOS | 正式支持 | 直接使用本机显示会话，不依赖 Xvfb |
| Windows | 已本机验证，CI 覆盖 Node/Xvfb 解析 | 不依赖 Xvfb；面板直启 `.venv\Scripts\python.exe`。默认 `GROK_HEADLESS=1`（有头模式设 `GROK_HEADED=1`） |

Linux 容器必须保留 procfs（通常为默认的 `/proc` 挂载），面板依赖它读取并安全停止
当前项目的任务进程。

### 安装

```bash
git clone https://github.com/lij768423-svg/grok-register-panel.git
cd grok-register-panel

python3 -m venv .venv
source .venv/bin/activate          # Linux / macOS
# Windows PowerShell: .venv\Scripts\Activate.ps1

pip install -r requirements.txt
python -m camoufox fetch           # 必须：下载浏览器引擎（约数百 MB）

cp config.example.json config.json
# 编辑 config.json：邮箱、proxy、cpa_auth_dir 等
```

Windows 也可以一条命令完成安装，然后用本机代理 URL（http / socks5）跑批，不必 SSH 到 Linux：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1
# 编辑 config.json，或在面板导入代理池
powershell -ExecutionPolicy Bypass -File scripts\run_windows_batch.ps1 -Count 1 -Workers 1
powershell -ExecutionPolicy Bypass -File scripts\run_windows_panel.ps1
```

Windows 不要把 `PLAYWRIGHT_NODEJS_PATH` 指到 `scripts/playwright-node`（那是 bash 包装）。运行时会解析 `node.exe` 或 Playwright 自带 Node，并用带引号的 `NODE_OPTIONS --require` 注入 EPIPE 保护。代理请写 **Windows 本机可达** 的 URL（例如 `socks5://user:pass@gate.example:1000`），不要沿用 Linux 上的 `127.0.0.1:82xx` mixed 口。

> `pip install` 只装 Python 依赖；**不执行 `camoufox fetch` 无法启动浏览器**。

### 配置（`config.json`）

| 字段 | 说明 |
|------|------|
| `email_provider` | `cloudflare` / `duckmail` / `yyds` / `mailnest` / `cloudmail` / `moemail` / `outlook_rt` / `cf_outlook` / `inbucket` |
| `outlook_rt_inventory` | Outlook MSA 库存路径（jsonl：`email`+`refresh_token`；或 `email----rt`） |
| `outlook_rt_used_path` | 已用邮箱记录（可选；默认 `库存路径.used`） |
| `outlook_rt_client_id` | 可选 Client ID；默认 Microsoft Authentication Broker 公共客户端 |
| `cf_outlook_api_base` | `cf-outlook-email` 站点根 URL，例如 `https://mail.example.com` |
| `cf_outlook_api_key` | 对外 API Key；仅通过 `X-API-Key` 请求头发送 |
| `cf_outlook_inventory` | 可选本地邮箱库存路径；留空时调用 `/api/external/accounts/random` 随机获取 `active` 邮箱 |
| `cf_outlook_used_path` | 已用邮箱记录路径（可选；默认 `库存路径.used`） |
| `defaultDomains` | 临时邮域名（如二级 CF 域） |
| `cloudflare_*` / `duckmail_*` 等 | 对应邮箱 API |
| `cloudflare_randomize_subdomain` | 默认 `true`；为管理域名生成随机子域，要求泛域收信；不支持时设为 `false` |
| `moemail_api_base` | MoeMail 站点根 URL，例如 `https://mail.example.com` |
| `moemail_api_key` | MoeMail OpenAPI 的 `X-API-Key` |
| `moemail_domain` | 可选固定域名；留空时自动读取 `/api/config` 的可用域名 |
| `moemail_expiry_ms` | `3600000` / `86400000` / `604800000` / `0`，分别为 1 小时、1 天、7 天、永久 |
| `inbucket_api_base` | Inbucket 自建实例根 URL，例如 `http://127.0.0.1:9000`（可用 `INBUCKET_API_BASE` 环境变量） |
| `inbucket_domain` | Inbucket 收信根域名，可逗号分隔多个轮换，例如 `mail.example.com, box.example.net` |
| `inbucket_random_levels` | 随机子域级数：`0` 关闭 / `1` / `2` / `1-2` / `1-3`（在区间内随机取级数）；启用需泛解析收信（`*.根域名` 的 MX 指向实例） |
| `proxy` | 默认 HTTP 代理，如 `http://127.0.0.1:7890` |
| `proxies.txt` | 可选的旧版多行代理文件；未配置面板代理池时继续兼容 |
| `register_workers` | 并发浏览器数（建议先 2～3） |
| `register_count` | 单次目标数量 |
| `cpa_auto_add` | 是否 SSO→OAuth 并写入 auth |
| `cpa_auth_dir` | 本地 CPA 目录（`xai-*.json`） |
| `grok2api_auth_dir` | Grok2API 风格 auth 目录 |
| `cpa_remote_url` / `cpa_management_key` | 远程 CPA Management API（可选） |
| `grok2api_remote_url` | Grok2API 服务根地址，例如 `https://g2a.example.test`；自动上传到 `/api/admin/v1/accounts/import`（可选） |
| `grok2api_username` / `grok2api_password` | 管理员账号密码。调用 `/api/admin/v1/auth/login` 获取约 15 分钟的 access JWT，并在失效时自动刷新/重登（推荐） |
| `grok2api_management_key` | 可选的短期 admin JWT。有用户名/密码时不再使用；不要把浏览器里复制的过期 token 填在这里 |

### 环境变量

| 变量 | 默认 | 说明 |
|------|------|------|
| `MONITOR_TOKEN` | （空） | **必设**：面板写接口鉴权；未设时 start/stop/control 一律 401 |
| `MONITOR_HOST` | `127.0.0.1` | 面板绑定地址；**绑定失败不会回退到 `0.0.0.0`** |
| `MONITOR_PORT` | `8787` | 面板端口 |
| `PANEL_INCLUDE_TAIL` | `0` | `1` 时状态接口附带原始日志尾部（可能含敏感信息，默认关） |
| `CPA_AUTH_DIR` | `./cpa_auth` | 编排器 / 面板统计 CPA 数量 |
| `BATCH_LOG` | 自动发现最新 `log/batch*.log` | 面板跟踪的日志 |
| `BLACKLIST_STATE_FILE` | `./log/blacklist_state.json` | 运行时 ASN 黑名单状态 |
| `GROK_BATCH_IDLE_TIMEOUT` | `360` | batch 子进程连续无输出多少秒后自动重建（最小 60 秒） |
| `GROK_BATCH_MAX_RESTARTS` | `2` | 单批发生驱动崩溃或卡死时最多自动恢复次数 |
| `GROK_BROWSER_START_ATTEMPTS` | `2` | 同一代理的 Camoufox 启动尝试次数，范围 1-4 |
| `GROK_PROXY_BOOT_ROTATIONS` | `3` | 浏览器启动失败后最多更换的代理数，范围 0-10 |
| `GROK_SLOT_RETRIES` | `1` | 单账号槽位软失败时的重试次数，范围 0-3 |
| `GROK_ORCH_MAX_CONSECUTIVE_FAILURES` | `2` | 连续异常批次达到该值时停止编排，范围 1-10 |
| `GROK_PYTHON_BIN` | 项目 `.venv` 或当前解释器 | 可选：显式指定面板启动任务所用的 Python，支持项目外共享虚拟环境 |
| `GROK_USE_XVFB` | `auto` | `auto`：仅 Linux 无显示时启用；`1`：Linux 强制启用；`0`：直接启动 |
| `GROK_COMPAT_PROCESS_ROOTS` | （空） | 可选：用系统路径分隔符列出旧 release 绝对目录；新面板会精确识别其在途任务，避免切版后重复启动 |
| `PROXY_POOL_STATE_FILE` | `./log/proxy_pool.json` | 外部代理池凭据、健康与冷却状态，文件权限 `0600` |
| `PROXY_NETWORK_COOLDOWN_SECONDS` | `90` | 运行时网络异常的短冷却秒数 |
| `PROXY_RISK_COOLDOWN_SECONDS` | `1800` | 注册风控后的长冷却秒数 |
| `EMAIL_PROVIDER_CONFIG_FILE` | `./config.json` | 面板邮箱服务配置文件；保存时保持 `0600` |
| `EMAIL_DOMAIN_POOL_STATE_FILE` | `./log/email_domain_pool.json` | 邮箱域名池状态与规则，文件权限 `0600` |
| `GROK_STATIC_ASSET_CACHE` | 面板任务为 `1`，CLI 为空 | 面板启动链默认启用；命令行直启可设为 `1`，显式设 `0` 可关闭 |
| `GROK_STATIC_CACHE_DIR` | `./log/static-asset-cache` | 静态缓存目录，文件权限 `0700` |
| `GROK_STATIC_CACHE_MAX_MB` | `1024` | 静态缓存上限（MB），最低 `32` |

生成 token 示例：

```bash
# Linux / macOS
python3 -c "import secrets; print(secrets.token_urlsafe(24))"
```

### 跑起来

**A. Web 面板（推荐）**

```bash
export MONITOR_TOKEN='你的长随机串'   # 必设，否则点启动会 401
export MONITOR_HOST=127.0.0.1         # 仅本机；局域网请改成具体网卡 IP
export MONITOR_PORT=8787
export CPA_AUTH_DIR=./cpa_auth
# 可选：需要页面里看原始日志尾时
# export PANEL_INCLUDE_TAIL=1

python webui/monitor.py
# 浏览器打开 http://127.0.0.1:8787/
```

从面板或编排器启动批处理时会自动选择运行方式：Linux 无 `DISPLAY` /
`WAYLAND_DISPLAY` 时使用 Xvfb，Linux 有显示以及 macOS/Windows 均直接启动。

1. 页面顶部 **控制** 区找到 **面板 Token** 输入框  
2. 填入与 `MONITOR_TOKEN` **相同**的字符串（自动写入 `localStorage`）  
3. 设模式 / workers / batch 数量 / 再跑 N / 风控满 N → **启动**
4. 需要多出口时打开顶部 **代理池**，导入代理并等待检测完成
5. 打开顶部 **邮箱服务**，选择 provider、填写对应参数，保存后执行一次连接测试
6. 需要多个自有收信域名轮换时，再展开 **域名轮换 · 高级设置** 导入域名并保存规则

### 静态资源缓存与批次流量

从 Live 面板启动的单批和持续编排默认启用静态缓存。直接从命令行启动时，需要在标准命令上增加环境变量：

```bash
GROK_STATIC_ASSET_CACHE=1 \
GROK_STATIC_CACHE_DIR="$PWD/log/static-asset-cache" \
  xvfb-run -a python -u run_batch_headless.py 1 1
```

也可直接使用兼容入口 `run_batch_headless_static_cache.py` 或 `run_until_100_static_cache.py`。

缓存只处理 GET 静态资源；文档、XHR/fetch、WebSocket、Turnstile 和账号相关请求始终直连。

每个批次还会自动生成 `log/batch_traffic.json`。注册浏览器使用 HTTP/HTTPS
代理时，项目会在原代理前启动独立的 `127.0.0.1` 计量转发器，面板据此展示
真实上行、下行与总字节数。批次结束后还会把聚合结果写入 owner-only 的
`log/batch_traffic_history.json`（最多 500 批），用于展示每批平均流量和每个成功号
平均流量。成功号均值会包含失败尝试产生的流量，表示实际成功账号成本。计量文件
不保存代理 URL、用户名、密码或请求内容；SOCKS 代理会保持原链路并标记为未计量。

也可在控制台手动写入：

```js
localStorage.setItem('MONITOR_TOKEN', '你的长随机串')
location.reload()
```

若未填 token 点启动，会看到：

```text
unauthorized: set MONITOR_TOKEN and pass Authorization: Bearer <token>
```

这是预期行为，不是注册链路崩溃。

**B. 命令行单批**

```bash
# Linux 无头
xvfb-run -a python -u run_batch_headless.py 20 3
#                        数量↑        并发↑

# Linux 有显示 / macOS / Windows
python -u run_batch_headless.py 20 3
```

单批由独立监督进程运行。Playwright/Camoufox 驱动崩溃，或连续超过
`GROK_BATCH_IDLE_TIMEOUT` 没有输出时，监督进程会结束故障子进程并按原子进度文件
继续剩余数量；已经写入的账号、SSO 和 CPA 文件不会回滚。

**C. 编排器**

```bash
# 由面板写入 log/monitor_control.json（workers / add_count / risk_pause …）
python -u run_until_100.py
```

**D. GUI**

```bash
python grok_register_ttk.py
```

## Live 面板说明

### 控制

| 控件 | 作用 |
|------|------|
| **面板 Token** | 与环境变量 `MONITOR_TOKEN` 一致；启停/保存/重置黑名单必填 |
| 模式 Orch | 跑 `run_until_100.py` 多轮直到目标 CPA |
| 模式 单批 | 只跑一轮 `run_batch_headless` |
| workers | 并发浏览器 |
| batch 数量 | 单批账号数上限相关 |
| **再跑 N 个** | 从**当前** CPA 再注册 N 个（目标已满时点启动不会秒退） |
| 风控满 N 暂停 | 本轮注册风控达到 N 后停 batch 并分析 ASN |

### 鉴权约定

| 接口 | 鉴权 |
|------|------|
| `GET /` · `GET /api/health` | 可匿名；不返回运行数据 |
| `GET /api/status` · `/api/stats` · `/api/control` · `/api/blacklist` · `/api/recovery` · `/api/proxies` · `/api/email-domains` | 配置了 Token 后必须鉴权 |
| `POST /api/start` · `/api/stop` · `/api/control` · `/api/blacklist/reset` · `/api/recovery/*` · `/api/proxies/*` · `/api/email-domains/*` | 必须 `Authorization: Bearer <MONITOR_TOKEN>` |
| `PATCH /api/proxies/{id}` · `DELETE /api/proxies/{id}` · `PATCH/DELETE /api/email-domains/{id}` | 必须 `Authorization: Bearer <MONITOR_TOKEN>` |

前端 `api()` 会从 Token 输入框 / `localStorage.MONITOR_TOKEN` / `window.MONITOR_TOKEN` 自动带头。

### 外部代理池

- 支持单条或批量粘贴 `http://user:pass@host:port`、`host:port:user:pass`，也兼容 HTTPS / SOCKS URL
- 导入时规范化并去重，随后后台并发探活；GET 接口轮询检测进度
- API 和 UI 只返回脱敏端点及 `has_auth`，不会返回代理账号或密码
- worker 只选择“健康 + 启用”的条目，并在每个新账号创建浏览器前热加载一次
- 一个账号从注册、SSO 到 OAuth 始终固定同一代理，不会中途更换出口
- 网络异常进入短冷却，注册风控进入长冷却；邮箱域名、验证码或邮箱 API 错误不处罚代理
- 面板池已有条目但没有健康代理时任务会明确停止，不会绕过状态回退到旧文件
- `proxies.txt` 可从界面导入；只有面板池完全未配置时，worker 才直接兼容旧文件 / `config.proxy`

代理池不抓取、不分发公共代理，只管理操作者自己提供的外部代理。

### 邮箱服务与高级域名轮换

- 顶部“邮箱服务”统一配置 `cloudflare`、`duckmail`、`yyds`、`mailnest`、`cloudmail`、`moemail`、`outlook_rt`、`cf_outlook`、`inbucket`
- `outlook_rt` 从本地 jsonl 库存取号（非购买），用 MSA `refresh_token` 刷 Graph 收 xAI 验证码
- `cf_outlook` 默认通过 `/api/external/accounts/random` 随机获取 `active` 邮箱，再通过 `/api/external/emails` 查询 xAI 验证码；`cf_outlook_inventory` 可选，填写后才使用本地固定邮箱库存；API Key 使用 `X-API-Key` 请求头，不通过 URL 传输
- `inbucket` 使用自建 [Inbucket](https://github.com/inbucket/inbucket) 实例：填实例地址和收信根域名即可，邮箱即建即用，无需注册 API；根域名可配多个轮换，并可按 `inbucket_random_levels` 叠加随机多级子域（需泛解析收信）
- 切换服务商时只显示该服务实际支持的字段；保存后新的注册任务读取 `config.json`
- 已保存的 API Key、JWT 和密码不会通过接口或页面回显；密钥输入留空会保留原值，必须点“清除”并保存才会删除
- “测试当前提供商”使用表单中的未保存内容做连通性检查，不会改写 `config.json`；`outlook_rt` 刷新成功时会原子保存上游轮换后的 RT，避免库存保留已失效凭据，但不会标记邮箱已用
- `config.json` 以原子方式更新并保持 `0600`，现有无关配置项不会被覆盖

域名轮换位于邮箱服务页的高级设置中：

- 支持导入根域名或已有子域名，并绑定 `cloudflare`、`cloudmail`、`moemail`、`yyds` provider
- 每个 provider 可设置最大活跃域名数；超出部分待命，活跃域名停用或拉黑后自动补位
- xAI 明确拒绝邮箱域名时累计连续失败，达到阈值后自动拉黑；成功提交邮箱后清零连续失败
- 邮箱 API、验证码超时和普通网络异常不会处罚域名，避免把基础设施故障误判成域名质量问题
- 通过“启用”“重置”“删除”管理条目；对应 provider 的面板池配置后，域名池耗尽不会回退旧配置
- `duckmail` 与 `mailnest` 的域名由上游服务分配，不能在面板中伪造自定义域名池

域名池只保存域名和运行统计，不保存邮箱账号密码或 provider 密钥。

### 时段成功率

基于 `log/register_results.jsonl`（纯 JSON Lines，无横幅污染）：

```text
成功率 = ok / (ok + fail + risk) × 100%
窗口：近 1 小时 / 3 小时 / 12 小时
```

### 黑名单

- 下号前解析出口 ASN，命中则换 sticky / 代理口  
- 编排器在风控累计到阈值后，对「几乎只有失败」的 ASN 扩黑  
- 自动扩展写入 `log/blacklist_state.json`，不会改写或执行 Python 源码
- 面板可 **刷新列表**；**重置** 为写操作，同样需要 Token  

### 账号补录

- **补录待处理**：读取 `accounts/sso_pending.txt`，跳过 CPA 已存在邮箱，成功一条立即原子出队
- **扫描全部账号**：扫描 `accounts/*.txt` 并对缺失 CPA 的记录执行转换，不删除原账号文件
- 补录运行在独立子进程，面板可查看数量、上次结果和停止任务
- 命令行等价入口：

```bash
python sso_to_auth_json.py \
  --sso accounts/sso_pending.txt \
  --from-config config.json \
  --consume-success \
  --report-json log/recovery_report.json
```

### SSO 风控检测（botFlag / policy）

用现有 SSO 访问 grok.com，读取 `botFlagSource` / `policy=deny`，**不换 token、不入库**。判定与注册门禁一致：`botFlagSource` 为 1/2，或任意 `policy=deny`。

| 能力 | 说明 |
|------|------|
| 面板 | 顶部「SSO 风控」：粘贴列表，或扫描待处理 / 全部账号 / 已隔离名单 |
| 导出 | 面板下载的标记/干净名单均为脱敏 JSONL，不含 SSO；本机受保护的 `log/sso_clean.txt` 保留原始行，仅供操作者在主机上继续传给 `--sso`，不会通过 API 返回 |
| CLI | `python scripts/check_sso_state.py --sso list.txt --from-config config.json` |

```bash
python sso_to_auth_json.py --check-sso-state sso_list.txt --from-config config.json \
  --sso-state-export log/sso_flagged.jsonl \
  --sso-state-clean-export log/sso_clean.txt \
  --report-json log/sso_state_report.json
```

### BFS 检测（JWT claim）

xAI 部分 access_token 的 payload 会带 **`bfs` 字段**（常见值 `2`）。**只要 key 存在即视为标记**，与 grok.com 的 `botFlagSource` / `policy=deny` 不是同一信号。

| 能力 | 说明 |
|------|------|
| 注册后自动检测 | SSO→OAuth 换 token 后解码 JWT；命中写入 `accounts/sso_bfs_flagged.txt`，CPA 记录带 `bfs` / `bfs_value` |
| 面板 | 「BFS 检测」卡片：扫描 `cpa_auth` / `grok2api_auth`，导出 `log/bfs_flagged.jsonl` |
| CLI | `python scripts/check_bfs.py` 或 `python sso_to_auth_json.py --check-bfs-dir cpa_auth` |

`config.json` 可选：

| 字段 | 默认 | 含义 |
|------|------|------|
| `bfs_check` | `true` | 换 token 后检测 |
| `bfs_skip_cpa` | `false` | 命中 bfs 时跳过 CPA/Grok2API 写入 |
| `bfs_disable_cpa` | `false` | 命中仍写入，但 `disabled: true` |

无法解码的 token 会显示为 `unknown`，不会伪造为 clean；启用 `bfs_skip_cpa` 时，面板注册路径的 unknown 账号不会写入 CPA/Grok2API，而是进入待重转队列。CLI 则跳过本次写入并在报告中记为失败。

```bash
# 扫描本地 CPA 目录
python scripts/check_bfs.py --dir cpa_auth --export log/bfs_flagged.jsonl

# 单 token 诊断（不回显原文）
python scripts/check_bfs.py --token 'eyJ...'
```

## 工程实践备忘（非教程承诺）

以下为社区常见踩坑方向，**环境差异大，仅供参考**：

1. 邮箱：二级域名临时邮往往比批发一级域 / 大盘 Outlook·Google 更省事  
2. 出口：质量与冷却窗口影响大；同一出口短时间打太满容易抬失败率  
3. 风控字段：服务端 deny 后宜尽早结束 OAuth 路径  
4. JWT `bfs`：与 botFlag 分开统计；入库前可用面板/CLI 批量扫 CPA  
5. 并发建议从 2～3 起跳，过高易空页、Turnstile 卡住、代理打满  
6. 「资料填写失败」有时是资料页人机未过，不一定是姓名密码写不进  
7. 链式代理在客户端配，不在注册机 Python 里写死  

## 目录结构

```text
.
├── grok_register_ttk.py       # GUI + CLI 主程序
├── register_flow.py           # 注册页流程 / Turnstile
├── browser_session.py         # 会话、出口探测、ASN 黑名单
├── sso_to_auth_json.py        # SSO → OAuth / 写 CPA（auth 文件 0600）
├── camoufox_adapter.py
├── connectivity.py
├── batch_supervisor.py        # 批处理监督、卡死恢复与原子进度
├── run_batch_headless.py      # 无头批量（包根 Path 后 chdir）
├── run_until_100.py           # 编排器
├── webui/
│   ├── monitor.py             # Live 面板 HTTP 服务
│   ├── security_utils.py      # redact / token 校验
│   ├── blacklist_store.py     # 锁保护的 JSON 黑名单状态
│   ├── proxy_store.py         # 外部代理池、探活、冷却与脱敏视图
│   ├── email_provider_store.py # 邮箱 provider 配置、测试与密钥保护
│   ├── email_domain_store.py  # 邮箱域名池、拒绝阈值与轮换状态
│   ├── process_utils.py       # 当前项目实例的进程发现 / 停止
│   ├── recovery_ops.py        # SSO / accounts 异步补录
│   ├── bfs_ops.py             # JWT bfs 扫描 / 面板接口
│   └── blacklist_ops.py       # 面板黑名单接口
├── email_providers/
├── tests/                     # 结构 / 脱敏 / bfs / chdir 冒烟
├── scripts/
│   ├── check_bfs.py           # 批量 bfs 扫描
│   └── …                      # xvfb 等辅助
├── config.example.json
├── proxies.example.txt
├── requirements.txt
├── AGENTS.md                  # AI 编码代理的仓库工作指南
├── DEPLOYMENT.md
├── LICENSE · NOTICE
└── README.md
```

## 自检

参与开发或让 AI 修改仓库前，先阅读 [AGENTS.md](AGENTS.md)。部署细节见
[DEPLOYMENT.md](DEPLOYMENT.md)，发布验收见 [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)。

```bash
# 无需 pytest；运行全部发布检查
PYTHON_BIN=.venv/bin/python scripts/run_tests.sh
```

部署前还应执行：

```bash
.venv/bin/python -m pip check
.venv/bin/python scripts/harden_runtime_permissions.py .
```

## 常见问题

**Q: 点启动报 `unauthorized: set MONITOR_TOKEN...`？**  
A: 服务端已启用写接口鉴权。启动 monitor 时 `export MONITOR_TOKEN=...`，浏览器 **面板 Token** 填同一串（或 `localStorage.setItem`）。硬刷新后再点启动。

**Q: 日志尾部显示 `raw log tail disabled`？**  
A: 默认关闭防泄密。需要时 `export PANEL_INCLUDE_TAIL=1` 后重启 `monitor.py`。

**Q: 点启动立刻结束？**  
A: CPA 已达旧目标。面板填大 **再跑 N 个** 再启动；编排器用 `add_count` 抬目标。

**Q: 全是「无法解析出口 IP」？**  
A: 打开顶部“代理池”查看异常和冷却原因，重新检测后只启用健康条目。旧版单代理仍可用 `curl -x http://127.0.0.1:端口 https://httpbin.org/ip` 单独探活。

**Q: 提示“面板代理池没有健康且启用的代理”？**
A: 导入项尚未检测、已停用、检测失败或仍在冷却。先在代理池页面执行“检测全部”；面板池已配置时不会回退复用旧文件中的坏代理。

**Q: 邮箱域名被自动拉黑，或域名池没有可用项？**
A: 只有 xAI 明确拒绝邮箱域名才会累计。打开“邮箱服务”并展开“域名轮换 · 高级设置”查看连续拒绝次数，确认 provider 与域名绑定正确；可手动重置或启用其它待命域名。邮箱 API、验证码超时不会触发域名拉黑。

**Q: 邮箱 API 401？**  
A: 打开“邮箱服务”检查对应 provider 的 Key / JWT / `auth_mode`，保存后点“测试当前提供商”。页面不会回显已保存密钥，输入框留空表示保留原值。

**Q: `Address already in use` / 面板打不开？**  
A: 8787 被其它进程占用（例如同机其它服务）。换 `MONITOR_PORT`，或先释放端口。绑定失败**不会**自动改绑 `0.0.0.0`。

**Q: 启动任务报 `[Errno 2] No such file or directory: '/proc'`？**
A: 旧版面板直接读取 Linux `/proc`，macOS 上必然失败；更新后面板改用 `psutil`。若新版仍在 Linux 容器中提示无法读取进程列表，说明容器没有挂载 procfs，请恢复默认 `/proc` 挂载后重启面板。不要用“忽略进程检测”绕过，否则可能重复启动任务。

**Q: Windows？**  
A: 已本机验证，CI 覆盖 Node/Xvfb 解析。不依赖 Xvfb；用 `scripts\setup_windows.ps1` 安装，`scripts\run_windows_batch.ps1` 跑批。默认 `GROK_HEADLESS=1`。代理必须是本机可达的 HTTP/SOCKS URL，不要沿用 Linux 上的 `127.0.0.1:82xx` mixed 口。详见 `WINDOWS.md`。

**Q: 面板和真实进程不一致？**  
A: 看 `log/orch100-stdout.log` 与最新 `log/batch-*.log`；欢迎提 issue / PR。

**Q: accounts 文本或待处理 SSO 怎么补录 CPA？**
A: 在控制台使用“账号补录”。待处理模式成功后自动出队；扫描全部账号模式会保留原始文本，并跳过本地 CPA 已存在邮箱。

## 安全

- **必须**设置 `MONITOR_TOKEN`；不要把 token 提交进仓库或贴进公开 issue  
- **不要提交** `config.json`、`accounts/`、`cpa_auth/`、`proxies.txt`、`log/proxy_pool.json`、`log/email_domain_pool.json`、真实 stickies、`log/monitor.token`
- `.gitignore` 已忽略上述路径  
- 运行数据、日志、PID、代理和账号文件使用 0600，父目录使用 0700
- API 响应带 CSP、禁止 iframe、安全类型与 Referrer Policy；请求体上限 64 KiB
- 停止任务只匹配当前项目根目录，不按全系统模糊命令行误杀
- 开源前自查：`grep -R api_key --include='*.json' .`（勿提交真实配置）  
- 面板默认**不**回传原始日志尾；生产环境固定 `PANEL_INCLUDE_TAIL=0`

## 更新记录（摘录）

| 提交方向 | 内容 |
|----------|------|
| 面板鉴权 | `MONITOR_TOKEN` + Bearer；UI 内 Token 输入；CORS 不开放 `*` |
| 绑定安全 | 失败不回退 `0.0.0.0`；默认 `PANEL_INCLUDE_TAIL=0` |
| 脱敏 | `webui/security_utils.py`；JSONL / 日志去凭据 |
| 路径 | `run_batch_headless` / blacklist 使用包相对 ROOT，无硬编码机器路径 |
| 稳定性 | `from __future__` 置顶；`Path` 先于 `chdir`；workers DOM id 拆分 |
| 结果流 | `register_results.jsonl` 仅 JSON 行 |

## Star History

<a href="https://github.com/lij768423-svg/grok-register-panel/stargazers">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/star-history-dark.svg">
    <img alt="Grok Register Panel GitHub Star 增长趋势" src="docs/star-history-light.svg">
  </picture>
</a>

图表根据 GitHub Stargazer 时间戳生成，由 GitHub Actions 每日更新，不依赖第三方绘图接口。

## 相关项目

- [grok2api-egress-enhancements](https://github.com/lij768423-svg/grok2api-egress-enhancements) — grok2api 出口增强补丁：固定代理快速恢复 + 出口质量守护（被动 Token/s 熔断、硬阈值隔离、最低健康节点、管理面板）

## 友情链接

- [介绍页](https://lij768423-svg.github.io/grok-register-panel/) — 一页看面板、安装和声明
- [Discussions](https://github.com/lij768423-svg/grok-register-panel/discussions) — 版本公告、踩坑和想法
- [LINUX DO](https://linux.do) — 新的理想型社区

## License

[MIT](LICENSE) — 见 [NOTICE](NOTICE) 对 AaronL725/grok-register 的归属说明。面板内嵌 Geist 字体使用 [SIL OFL 1.1](LICENSES/OFL-1.1-Geist.txt)。

## 致谢

- [Camoufox](https://camoufox.com/)
- [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) 等下游生态
- 上游 [AaronL725/grok-register](https://github.com/AaronL725/grok-register)
- 社区里分享风控字段与工程经验的各位

---

Star 鼓励一下 → https://github.com/lij768423-svg/grok-register-panel
