<div align="center">

# Grok Register + Live Panel

Based on [AaronL725/grok-register](https://github.com/AaronL725/grok-register) (MIT).

批量注册 Grok 账号（Camoufox）+ Web 监控面板  
启停 / 并发 / ASN 黑名单 / 1h·3h·12h 成功率 / **Token 鉴权**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg)
![Stars](https://img.shields.io/github/stars/lij768423-svg/grok-register-panel?style=flat)

**仓库：** https://github.com/lij768423-svg/grok-register-panel

</div>

---

> **声明：** 仅供自动化流程研究、自有环境联调与个人学习。请遵守 xAI / 邮箱 / 代理服务商条款与当地法律，勿用于未授权批量滥用。

## 功能一览

| 能力 | 说明 |
|------|------|
| 注册全链路 | 邮箱 OTP → 资料页 → Turnstile → SSO → Device / OAuth → 写入 CPA / Grok2API |
| 多邮箱后端 | Cloudflare Worker 邮、DuckMail、YYDS、MailNest、CloudMail、**MoeMail** 等 |
| 反检测浏览器 | [Camoufox](https://camoufox.com/)（Gecko 层指纹） |
| 出口预检 | 启动前解析出口 IP / ASN，命中黑名单直接换口 |
| 风控早停 | `botFlagSource=1` + `policy=deny` 时跳过后续 OAuth，避免无效重试 |
| 编排器 | 多轮 batch、风控满 N 暂停、ASN 自动扩黑 |
| **Live 面板** | 启停、并发、再跑 N、黑名单、时段成功率；**写操作需 MONITOR_TOKEN** |
| 日志脱敏 | 代理 `user:pass@` 与邮箱在 JSONL / 控制台脱敏；auth 文件 0600 |

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
│ + Bearer token  │  浏览器填「面板 Token」→ localStorage
└─────────────────┘
```

说明：**注册机本身只配置一层 HTTP 代理 URL**。若需要「先节点再家宽」等链式出口，在代理客户端（如 mihomo `dialer-proxy`）配置，对注册机透明。

## 快速开始

### 环境

- Python 3.10+
- Linux 无头建议带 Xvfb；macOS 可本机 GUI/有头
- 能访问注册页、临时邮箱 API、`auth.x.ai` 的网络

### 安装

```bash
git clone https://github.com/lij768423-svg/grok-register-panel.git
cd grok-register-panel

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -r requirements.txt
python -m camoufox fetch           # 必须：下载浏览器引擎（约数百 MB）

cp config.example.json config.json
# 编辑 config.json：邮箱、proxy、cpa_auth_dir 等
```

> `pip install` 只装 Python 依赖；**不执行 `camoufox fetch` 无法启动浏览器**。

### 配置（`config.json`）

| 字段 | 说明 |
|------|------|
| `email_provider` | `cloudflare` / `duckmail` / `yyds` / `mailnest` / `cloudmail` / `moemail` |
| `defaultDomains` | 临时邮域名（CF / CloudMail / MoeMail 可选回落） |
| `cloudflare_*` / `duckmail_*` / `moemail_*` 等 | 对应邮箱 API |
| `moemail_api_base` | MoeMail 站点根（可写 `https://host` 或 `https://host/api`，代码会规范化） |
| `moemail_api_key` | MoeMail `X-API-Key` |
| `moemail_domain` | 可选固定域名；空则用 `defaultDomains` 或 `/api/config` 的 `emailDomains` |
| `moemail_expiry_ms` | 邮箱有效期毫秒：`3600000`=1h / `86400000`=1d / `0`=永久 |
| `proxy` | 默认 HTTP 代理，如 `http://127.0.0.1:7890` |
| `proxies.txt` | 可选；多行代理，多 worker 轮换端口 |
| `register_workers` | 并发浏览器数（建议先 2～3） |
| `register_count` | 单次目标数量 |
| `cpa_auto_add` | 是否 SSO→OAuth 并写入 auth |
| `cpa_auth_dir` | 本地 CPA 目录（`xai-*.json`） |
| `grok2api_auth_dir` | Grok2API 风格 auth 目录 |
| `cpa_remote_url` / `cpa_management_key` | 远程 CPA Management API（可选） |

### 环境变量

入口脚本会通过根目录 [`__init__.py`](__init__.py) **自动加载** 项目根目录的 `.env`（不覆盖已 `export` 的变量）。`.env` 已在 `.gitignore`。

```bash
cp .env.example .env
# 编辑 .env 填写 MONITOR_TOKEN 等
```

| 变量 | 默认 | 说明 |
|------|------|------|
| `MONITOR_TOKEN` | （空） | **必设**：面板写接口鉴权；未设时 start/stop/control 一律 401 |
| `MONITOR_HOST` | `127.0.0.1` | 面板绑定地址；**绑定失败不会回退到 `0.0.0.0`** |
| `MONITOR_PORT` | `8787` | 面板端口 |
| `PANEL_INCLUDE_TAIL` | `0` | `1` 时状态接口附带原始日志尾部（可能含敏感信息，默认关） |
| `CPA_AUTH_DIR` | `./cpa_auth` | 编排器 / 面板统计 CPA 数量 |
| `BATCH_LOG` | 自动发现最新 `log/batch*.log` | 面板跟踪的日志 |

生成 token 示例：

```bash
# Linux / macOS
python3 -c "import secrets; print(secrets.token_urlsafe(24))"
```

### 跑起来

**A. Web 面板（推荐）**

```bash
cp .env.example .env
# 编辑 .env：MONITOR_TOKEN=你的长随机串 等
# 也可继续用 export（优先级高于 .env）

python webui/monitor.py
# 浏览器打开 http://127.0.0.1:8787/
```

1. 页面顶部 **控制** 区找到 **面板 Token** 输入框  
2. 填入与 `MONITOR_TOKEN` **相同**的字符串（自动写入 `localStorage`）  
3. 设模式 / workers / batch 数量 / 再跑 N / 风控满 N → **启动**

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

**B. 命令行单批（无头 Linux）**

```bash
xvfb-run -a python -u run_batch_headless.py 20 3
#                        数量↑        并发↑
```

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
| `GET /` · `GET /api/health` · `GET /api/status` 等读接口 | 默认可匿名（便于看进度） |
| `POST /api/start` · `/api/stop` · `/api/control` · `/api/blacklist/reset` | 必须 `Authorization: Bearer <MONITOR_TOKEN>` |

前端 `api()` 会从 Token 输入框 / `localStorage.MONITOR_TOKEN` / `window.MONITOR_TOKEN` 自动带头。

### 时段成功率

基于 `log/register_results.jsonl`（纯 JSON Lines，无横幅污染）：

```text
成功率 = ok / (ok + fail + risk) × 100%
窗口：近 1 小时 / 3 小时 / 12 小时
```

### 黑名单

- 下号前解析出口 ASN，命中则换 sticky / 代理口  
- 编排器在风控累计到阈值后，对「几乎只有失败」的 ASN 扩黑  
- 面板可 **刷新列表**；**重置** 为写操作，同样需要 Token  

## 工程实践备忘（非教程承诺）

以下为社区常见踩坑方向，**环境差异大，仅供参考**：

1. 邮箱：二级域名临时邮往往比批发一级域 / 大盘 Outlook·Google 更省事  
2. 出口：质量与冷却窗口影响大；同一出口短时间打太满容易抬失败率  
3. 风控字段：服务端 deny 后宜尽早结束 OAuth 路径  
4. 并发建议从 2～3 起跳，过高易空页、Turnstile 卡住、代理打满  
5. 「资料填写失败」有时是资料页人机未过，不一定是姓名密码写不进  
6. 链式代理在客户端配，不在注册机 Python 里写死  

## 目录结构

```text
.
├── __init__.py                # 根包：自动 load 根目录 .env
├── .env.example               # 环境变量模板（复制为 .env）
├── grok_register_ttk.py       # GUI + CLI 主程序
├── register_flow.py           # 注册页流程 / Turnstile
├── browser_session.py         # 会话、出口探测、ASN 黑名单
├── sso_to_auth_json.py        # SSO → OAuth / 写 CPA（auth 文件 0600）
├── camoufox_adapter.py
├── connectivity.py
├── run_batch_headless.py      # 无头批量（包根 Path 后 chdir）
├── run_until_100.py           # 编排器
├── webui/
│   ├── monitor.py             # Live 面板 HTTP 服务
│   ├── security_utils.py      # redact / token 校验
│   └── blacklist_ops.py       # 黑名单读写 / 重置（包相对路径）
├── email_providers/
├── tests/                     # 结构 / 脱敏 / chdir 冒烟
├── scripts/                   # xvfb 辅助脚本
├── config.example.json
├── proxies.example.txt
├── requirements.txt
├── DEPLOYMENT.md
├── LICENSE · NOTICE
└── README.md
```

## 自检

```bash
# 无需 pytest；直接跑
python3 tests/test_security_utils.py
python3 tests/test_panel_structure.py
python3 tests/test_no_live_hardcode.py
python3 tests/test_batch_chdir_import.py
```

## 常见问题

**Q: 点启动报 `unauthorized: set MONITOR_TOKEN...`？**  
A: 服务端已启用写接口鉴权。在根目录 `.env` 写 `MONITOR_TOKEN=...`（或 `export`），浏览器 **面板 Token** 填同一串（或 `localStorage.setItem`）。硬刷新后再点启动。

**Q: 日志尾部显示 `raw log tail disabled`？**  
A: 默认关闭防泄密。需要时 `export PANEL_INCLUDE_TAIL=1` 后重启 `monitor.py`。

**Q: 点启动立刻结束？**  
A: CPA 已达旧目标。面板填大 **再跑 N 个** 再启动；编排器用 `add_count` 抬目标。

**Q: 全是「无法解析出口 IP」？**  
A: 代理挂了 / 流量耗尽 / dialer 下游失败。先 `curl -x http://127.0.0.1:端口 https://httpbin.org/ip` 探活。

**Q: 邮箱 API 401？**  
A: 与代理无关，检查 `config.json` 里对应 provider 的 key / auth_mode。

**Q: `Address already in use` / 面板打不开？**  
A: 8787 被其它进程占用（例如同机其它服务）。换 `MONITOR_PORT`，或先释放端口。绑定失败**不会**自动改绑 `0.0.0.0`。

**Q: Windows？**  
A: 主要在 macOS 与无界面 Linux 验证；Windows 需自备显示/依赖，欢迎 PR。

**Q: 面板和真实进程不一致？**  
A: 看 `log/orch100-stdout.log` 与最新 `log/batch-*.log`；欢迎提 issue / PR。

## 安全

- **必须**设置 `MONITOR_TOKEN`（推荐写在根目录 `.env`）；不要把 token 提交进仓库或贴进公开 issue  
- **不要提交** `config.json`、`.env`、`accounts/`、`cpa_auth/`、`proxies.txt`、真实 stickies、`log/monitor.token`  
- `.gitignore` 已忽略上述路径（含 `.env`）  
- 代理凭据与邮箱在结果 JSONL / 控制台走 `redact_proxy` / `mask_email`  
- 新写 auth 文件权限 0600、父目录 0700（`sso_to_auth_json`）  
- 开源前自查：`grep -R api_key --include='*.json' .`（勿提交真实配置）  
- 面板默认**不**回传原始日志尾；仅本机调试可开 `PANEL_INCLUDE_TAIL=1`

## 更新记录（摘录）

| 提交方向 | 内容 |
|----------|------|
| 面板鉴权 | `MONITOR_TOKEN` + Bearer；UI 内 Token 输入；CORS 不开放 `*` |
| 绑定安全 | 失败不回退 `0.0.0.0`；默认 `PANEL_INCLUDE_TAIL=0` |
| 脱敏 | `webui/security_utils.py`；JSONL / 日志去凭据 |
| 路径 | `run_batch_headless` / blacklist 使用包相对 ROOT，无硬编码机器路径 |
| 稳定性 | `from __future__` 置顶；`Path` 先于 `chdir`；workers DOM id 拆分 |
| 结果流 | `register_results.jsonl` 仅 JSON 行 |

## License

[MIT](LICENSE) — 见 [NOTICE](NOTICE) 对 AaronL725/grok-register 的归属说明。

## 致谢

- [Camoufox](https://camoufox.com/)
- [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) 等下游生态
- 上游 [AaronL725/grok-register](https://github.com/AaronL725/grok-register)
- 社区里分享风控字段与工程经验的各位

---

Star 鼓励一下 → https://github.com/lij768423-svg/grok-register-panel
