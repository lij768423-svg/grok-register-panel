# 本机部署

以下步骤使用 Python 3.13 在仓库内创建 `.venv` 隔离环境。

## 环境要求

- Python 3.10+（推荐 3.13）
- [Camoufox](https://camoufox.com/) 反检测浏览器（本机自动下载，无需安装 Chrome）
- 可用的 [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)
- 能访问注册页、临时邮箱 API、`auth.x.ai` 的网络

## 安装

### 1. 创建虚拟环境并安装依赖

```powershell
uv python install 3.13
uv venv --python 3.13 .venv
uv pip install --python .venv\Scripts\python.exe -r requirements.txt
```

或使用标准 pip：

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### 2. 下载 Camoufox 浏览器引擎

依赖安装完成后，必须下载 Camoufox 浏览器引擎（约 300MB，首次安装时下载）：

```powershell
# Windows
camoufox fetch

# macOS / Linux
python3 -m camoufox fetch
```

> 注意：`pip install camoufox[geoip]` 只安装了 Python 库，浏览器引擎需要额外执行 `camoufox fetch` 下载。
> `[geoip]` 额外依赖会下载 MaxMind GeoLite2 数据库，用于根据代理 IP 自动匹配时区、语言和经纬度，强烈推荐安装。

### 3. 验证安装

```powershell
camoufox version
```

输出应显示 Python 包版本、浏览器版本和安装状态（`Installed: Yes`）。

### 4. 配置

```powershell
cp config.example.json config.json
```

编辑 `config.json`，至少填写可用的临时邮箱配置：

- Cloudflare：`cloudflare_api_base`、`defaultDomains`，必要时填写认证配置
- DuckMail：将 `email_provider` 改为 `duckmail` 并填写 `duckmail_api_key`
- YYDS：将 `email_provider` 改为 `yyds` 并填写 `yyds_api_key` 或 `yyds_jwt`
- MoeMail：将 `email_provider` 改为 `moemail`，填写 `moemail_api_base`（站点根 URL）与 `moemail_api_key`；可选 `moemail_domain` / `moemail_expiry_ms`（兼容旧字段 `moemail_api_url`）

如需自动写入 CLIProxyAPI，再配置 `cpa_auto_add` 及本地 auth 目录或远程 Management API 参数。

## 启动

- 图形界面：双击 ``python grok_register_ttk.py` (GUI)`
- 命令行：双击 ``python run_batch_headless.py <n> <workers>``，输入 `start` 后开始任务

## Camoufox 常用命令

```powershell
camoufox fetch          # 下载/更新浏览器引擎
camoufox version        # 查看版本和安装状态
camoufox list           # 列出已安装版本
camoufox remove         # 卸载浏览器引擎
camoufox path           # 查看安装路径
```

## 故障排查

**`BrowserType.launch_persistent_context() got an unexpected keyword argument`**

Camoufox 版本过旧，升级到最新版：

```powershell
pip install -U camoufox[geoip]
camoufox fetch
```

**`official/stable is not installed`**

浏览器引擎未下载，执行 `camoufox fetch`。

**旧格式安装兼容**

如果 `camoufox fetch` 安装的是旧格式（无 `.0.5_FLAG` 文件），程序会自动检测 `executable_path` 绕过版本检查，无需额外操作。确保 `config.json` 中 `active_version` 设为 `"."`。

## Panel token (required for start/stop)

```bash
export MONITOR_TOKEN="$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")"
export MONITOR_HOST=127.0.0.1
export MONITOR_PORT=8787
# optional: export PANEL_INCLUDE_TAIL=1
python webui/monitor.py
```

In the browser, paste the same token into **面板 Token** (saved to localStorage).
Without it, POST /api/start returns 401.
