# -*- coding: utf-8 -*-
"""启动前连通性检查：代理 / 邮箱 API / CPA。"""
from __future__ import annotations

import socket
import time
from typing import Callable, List, Tuple
from urllib.parse import urlparse

from email_providers import cloudflare as cloudflare_provider
from webui.security_utils import redact_log_line

CheckResult = Tuple[str, bool, str]  # name, ok, detail
XAI_SIGNUP_CHECK_NAME = "xAI注册页"
XAI_SIGNUP_URL = "https://accounts.x.ai/sign-up?redirect=grok-com"


class XaiSignupPrecheckFailed(RuntimeError):
    """The registration page was not reachable through the selected proxy."""


def _tcp_open(host: str, port: int, timeout: float = 2.0) -> bool:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def check_proxy(proxy_url: str, http_get: Callable) -> CheckResult:
    proxy_url = (proxy_url or "").strip()
    if not proxy_url:
        return "代理", True, "未配置（直连）"
    try:
        u = urlparse(proxy_url)
        host = u.hostname or "127.0.0.1"
        port = u.port or (443 if u.scheme == "https" else 80)
        if not _tcp_open(host, port):
            return "代理", False, f"无法连接 {host}:{port}"
        # 轻量探测
        try:
            http_get(
                "https://www.cloudflare.com/cdn-cgi/trace",
                timeout=8,
                proxies={"http": proxy_url, "https": proxy_url},
            )
        except Exception as exc:
            # TCP 通但出站失败也提示
            return "代理", False, f"TCP 通，出站探测失败: {redact_log_line(str(exc))}"
        return "代理", True, f"{host}:{port} 可用"
    except Exception as exc:
        return "代理", False, redact_log_line(str(exc))


def check_xai_signup(proxy_url: str, http_get: Callable) -> CheckResult:
    """按注册浏览器同一出口检查 accounts.x.ai，CF 拦截时禁止继续建号。"""
    proxy_url = str(proxy_url or "").strip()
    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else {}
    try:
        resp = http_get(
            XAI_SIGNUP_URL,
            headers={
                "Accept": "text/html,application/xhtml+xml",
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/138.0.0.0 Safari/537.36"
                ),
            },
            timeout=15,
            allow_redirects=True,
            proxies=proxies,
            # curl_cffi 默认指纹容易被 accounts.x.ai 的 Cloudflare 判为非浏览器。
            # 预检必须使用与 OAuth 请求相同的 Chrome 指纹，否则会把可访问页面误判为 403。
            impersonate="chrome",
            _allow_direct_fallback=False,
        )
        status = int(getattr(resp, "status_code", 0) or 0)
        text = str(getattr(resp, "text", "") or "").lower()
        headers = {
            str(k).lower(): str(v).lower()
            for k, v in dict(getattr(resp, "headers", {}) or {}).items()
        }
        body_challenge = (
            "just a moment" in text[:2000]
            or "checking your browser" in text[:2000]
            or "__cf_chl" in text
            or "cf-error" in text
        )
        # Cloudflare 可能给正常页面也加 server: cloudflare，不能仅凭该头阻断。
        cf_challenge = body_challenge or (
            status in (403, 429, 503) and "cloudflare" in headers.get("server", "")
        )
        if status in (403, 429, 503) and cf_challenge:
            return (
                XAI_SIGNUP_CHECK_NAME,
                False,
                f"Cloudflare 拦截 HTTP {status}；请更换当前 proxy 后重试",
            )
        if cf_challenge:
            return XAI_SIGNUP_CHECK_NAME, False, "仍停留在 Cloudflare 挑战页"
        if status >= 400 or status <= 0:
            return XAI_SIGNUP_CHECK_NAME, False, f"HTTP {status or 'unknown'}"
        return XAI_SIGNUP_CHECK_NAME, True, f"可达 HTTP {status}"
    except Exception as exc:
        return XAI_SIGNUP_CHECK_NAME, False, redact_log_line(str(exc))


def has_blocking_xai_failure(results: List[CheckResult]) -> bool:
    return any(name == XAI_SIGNUP_CHECK_NAME and not ok for name, ok, _ in results)


def require_xai_signup(results: List[CheckResult]) -> None:
    if has_blocking_xai_failure(results):
        raise XaiSignupPrecheckFailed("xAI registration page precheck failed")


def check_email_api(provider: str, config: dict, http_get: Callable, http_post: Callable) -> CheckResult:
    provider = (provider or "").strip().lower()
    try:
        if provider == "cloudflare":
            base = str(config.get("cloudflare_api_base", "") or "").rstrip("/")
            if not base:
                return "邮箱API", False, "未配置 cloudflare_api_base"
            api_key = str(config.get("cloudflare_api_key", "") or "")
            auth_mode = str(config.get("cloudflare_auth_mode", "none") or "none")
            custom_auth = str(config.get("cloudflare_custom_auth", "") or "")
            accounts_path = str(
                config.get("cloudflare_path_accounts", "/api/new_address")
                or "/api/new_address"
            )
            if not accounts_path.startswith("/"):
                accounts_path = "/" + accounts_path

            admin_create = cloudflare_provider.is_admin_create_path(accounts_path)
            direct_create = not admin_create
            admin_header_create = admin_create and auth_mode.lower() == "x-admin-auth"

            if direct_create or admin_header_create:
                # 直建端点不使用管理密钥；/admin/new_address 则使用
                # x-admin-auth，而 domains 通常要邮箱 JWT。两者都不能用 domains
                # 做无副作用鉴权预检；POST 建号会产生数据，因此只做 TCP。
                parsed = urlparse(base)
                host = parsed.hostname
                if host:
                    port = parsed.port or (443 if parsed.scheme == "https" else 80)
                    if not _tcp_open(host, port):
                        return "邮箱API", False, f"Cloudflare 服务不可达: {host}:{port}"
                mode_label = "管理员建号" if admin_header_create else "直建"
                return (
                    "邮箱API",
                    True,
                    f"Cloudflare {mode_label}模式可用（建号端点 {accounts_path}）",
                )

            # 其他鉴权模式：检查 domains 鉴权是否正确。
            path = str(config.get("cloudflare_path_domains", "/api/domains") or "/api/domains")
            if not path.startswith("/"):
                path = "/" + path
            url = f"{base}{path}"
            headers = cloudflare_provider.build_headers(api_key, auth_mode, custom_auth)
            params = cloudflare_provider.apply_auth_params({}, api_key, auth_mode)
            resp = http_get(url, headers=headers, params=params, timeout=10)
            if resp.status_code >= 400:
                return "邮箱API", False, f"Cloudflare 鉴权失败 HTTP {resp.status_code}（auth_mode={auth_mode}）"
            return "邮箱API", True, f"Cloudflare 可达 HTTP {resp.status_code}（auth_mode={auth_mode}）"

        if provider == "duckmail":
            base = str(config.get("duckmail_api_base", "") or "https://api.duckmail.sbs").rstrip("/")
            resp = http_get(f"{base}/domains", headers={"Accept": "application/json"}, timeout=12)
            if resp.status_code >= 400:
                return "邮箱API", False, f"DuckMail/Mail.tm HTTP {resp.status_code}"
            return "邮箱API", True, f"DuckMail/Mail.tm 可达 HTTP {resp.status_code}"

        if provider == "yyds":
            key = str(config.get("yyds_api_key", "") or "")
            jwt = str(config.get("yyds_jwt", "") or "")
            if not key and not jwt:
                return "邮箱API", False, "YYDS 需配置 API Key 或 JWT"
            headers = {}
            if jwt:
                headers["Authorization"] = f"Bearer {jwt}"
            elif key:
                headers["X-API-Key"] = key
            resp = http_get("https://maliapi.215.im/v1/domains", headers=headers, timeout=12)
            ok = resp.status_code < 400
            return "邮箱API", ok, f"YYDS HTTP {resp.status_code}"

        if provider == "mailnest":
            key = str(config.get("mailnest_api_key", "") or "").strip()
            if not key:
                return "邮箱API", False, "MailNest 需配置 API Key"
            # 不实际买号，只检查鉴权头能否打到站点
            resp = http_get(
                "https://mailnest.top/",
                headers={"Authorization": f"Bearer {key}"},
                timeout=12,
            )
            return "邮箱API", resp.status_code < 400, f"MailNest 站点 HTTP {resp.status_code}"

        if provider == "cloudmail":
            url = str(config.get("cloudmail_url", "") or "").rstrip("/")
            if not url:
                return "邮箱API", False, "未配置 cloudmail_url"
            resp = http_get(url, timeout=10)
            return "邮箱API", resp.status_code < 400, f"CloudMail HTTP {resp.status_code}"

        if provider == "moemail":
            from email_providers import moemail as moemail_provider

            base = moemail_provider.normalize_base(
                str(
                    config.get("moemail_api_base")
                    or config.get("moemail_api_url")
                    or ""
                )
            )
            key = str(config.get("moemail_api_key") or "").strip()
            if not base:
                return "邮箱API", False, "未配置 moemail_api_base"
            if not key:
                return "邮箱API", False, "未配置 moemail_api_key"
            resp = http_get(
                f"{base}/api/config",
                headers={"Accept": "application/json", "X-API-Key": key},
                timeout=12,
                proxies={},
            )
            if resp.status_code in (401, 403):
                return "邮箱API", False, f"MoeMail API Key 无效 HTTP {resp.status_code}"
            if resp.status_code >= 400:
                return "邮箱API", False, f"MoeMail HTTP {resp.status_code}"
            data = resp.json()
            domains = ""
            if isinstance(data, dict):
                domains = str(data.get("emailDomains") or data.get("email_domains") or "")
            detail = f"MoeMail 可达 HTTP {resp.status_code}"
            if domains:
                detail += f"；域名 {domains[:80]}"
            return "邮箱API", True, detail

        if provider == "inbucket":
            from email_providers import inbucket as inbucket_provider

            base = inbucket_provider.normalize_base(
                str(config.get("inbucket_api_base") or "")
            )
            domains = inbucket_provider.parse_domains(config.get("inbucket_domain"))
            if not base:
                return "邮箱API", False, "未配置 inbucket_api_base"
            if not domains:
                return "邮箱API", False, "未配置 inbucket_domain"
            # GET 邮箱列表无副作用：不存在即返回空数组
            resp = http_get(
                f"{base}/api/v1/mailbox/probe",
                headers={"Accept": "application/json"},
                timeout=12,
                proxies={},
            )
            if resp.status_code in (401, 403):
                return "邮箱API", False, f"Inbucket 拒绝访问 HTTP {resp.status_code}"
            if resp.status_code == 404:
                return "邮箱API", False, "Inbucket API 404：请检查实例地址与 base path"
            if resp.status_code >= 400:
                return "邮箱API", False, f"Inbucket HTTP {resp.status_code}"
            return "邮箱API", True, f"Inbucket 可达 HTTP {resp.status_code}（域名 {','.join(domains)[:80]}）"

        if provider == "icloud":
            from email_providers import icloud as icloud_provider

            base = icloud_provider.normalize_base(
                str(config.get("icloud_hme_api_base") or "")
            )
            password = str(config.get("icloud_hme_admin_password") or "")
            if not base:
                return "邮箱API", False, "未配置 icloud_hme_api_base"
            if len(password) < 8:
                return "邮箱API", False, "未配置 icloud_hme_admin_password（至少 8 字符）"
            resp = http_post(
                f"{base}/api/auth/login",
                json={"password": password},
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                timeout=12,
                proxies={},
            )
            status = int(getattr(resp, "status_code", 0) or 0)
            if status == 401:
                return "邮箱API", False, "iCloud HME 管理员密码错误"
            if status == 429:
                return "邮箱API", False, "iCloud HME 登录过于频繁"
            if status >= 400:
                return "邮箱API", False, f"iCloud HME HTTP {status}"
            return "邮箱API", True, f"iCloud HME 可达 HTTP {status}"

        if provider == "outlook_rt":
            from email_providers import outlook_rt as outlook_rt_provider

            inv = str(config.get("outlook_rt_inventory") or "").strip()
            if not inv:
                return "邮箱API", False, "未配置 outlook_rt_inventory"
            used = str(config.get("outlook_rt_used_path") or "").strip()
            client_id = str(config.get("outlook_rt_client_id") or "").strip()
            detail = outlook_rt_provider.probe_inventory(
                http_post,
                inv,
                used_path=used,
                default_client_id=client_id,
            )
            ok = "refresh OK" in detail or "available=" in detail
            if "available=0" in detail and "refresh OK" not in detail:
                ok = False
            if "refresh 失败" in detail:
                ok = False
            return "邮箱API", ok, detail[:300]

        if provider == "cf_outlook":
            from email_providers import cf_outlook as cf_outlook_provider

            base = cf_outlook_provider.normalize_base(
                str(config.get("cf_outlook_api_base") or "")
            )
            key = str(config.get("cf_outlook_api_key") or "").strip()
            inventory = str(config.get("cf_outlook_inventory") or "").strip()
            if not base:
                return "邮箱API", False, "未配置 cf_outlook_api_base"
            if not key:
                return "邮箱API", False, "未配置 cf_outlook_api_key"
            if not inventory:
                detail = cf_outlook_provider.probe_api(http_get, base, key)
                return "邮箱API", True, detail
            candidate = cf_outlook_provider.first_available_email(
                inventory,
                str(config.get("cf_outlook_used_path") or ""),
            )
            if not candidate:
                return "邮箱API", False, "cf_outlook 邮箱库存已耗尽"
            detail = cf_outlook_provider.probe_api(http_get, base, key, candidate)
            return "邮箱API", True, detail

        return "邮箱API", True, f"提供商 {provider} 跳过深度探测"
    except Exception as exc:
        return "邮箱API", False, redact_log_line(str(exc))


def check_cpa(config: dict, http_get: Callable, http_post: Callable) -> CheckResult:
    if not config.get("cpa_auto_add"):
        return "CPA", True, "未开启 SSO→auth（跳过）"
    auth_dir = str(config.get("cpa_auth_dir", "") or "").strip()
    remote = str(config.get("cpa_remote_url", "") or "").strip()
    key = str(config.get("cpa_management_key", "") or "").strip()
    g2a_dir = str(config.get("grok2api_auth_dir", "") or "").strip()
    g2a_remote = str(config.get("grok2api_remote_url", "") or "").strip()
    g2a_username = str(config.get("grok2api_username", "") or "").strip()
    g2a_password = str(config.get("grok2api_password", "") or "")

    # 相对路径基于项目根目录解析（与 grok_register_ttk.py 的 APP_DIR 一致）
    import os as _os
    _app_dir = _os.path.dirname(_os.path.abspath(__file__))
    if auth_dir and not _os.path.isabs(auth_dir):
        auth_dir = _os.path.join(_app_dir, auth_dir)
    if g2a_dir and not _os.path.isabs(g2a_dir):
        g2a_dir = _os.path.join(_app_dir, g2a_dir)

    if not auth_dir and not remote and not g2a_dir and not g2a_remote:
        return "CPA", False, "已开启但未配置 CPA/Grok2API 本地或远程目标"
    parts = []
    import os
    if auth_dir:
        if os.path.isdir(auth_dir):
            parts.append("CPA本地目录OK")
        else:
            # 自动创建目录
            try:
                os.makedirs(auth_dir, exist_ok=True)
                parts.append("CPA本地目录已创建")
            except Exception as exc:
                return "CPA", False, f"CPA auth 目录不存在且无法创建: {auth_dir} ({exc})"
    if g2a_dir:
        if os.path.isdir(g2a_dir):
            parts.append("Grok2API目录OK")
        else:
            try:
                os.makedirs(g2a_dir, exist_ok=True)
                parts.append("Grok2API目录已创建")
            except Exception as exc:
                return "CPA", False, f"Grok2API 目录不存在且无法创建: {g2a_dir} ({exc})"
    if g2a_remote:
        if not (g2a_username and g2a_password):
            return "CPA", False, "已配 Grok2API 远程地址但缺少登录账号密码"
        try:
            u = urlparse(g2a_remote)
            host = u.hostname or "127.0.0.1"
            port = u.port or (443 if u.scheme == "https" else 80)
            if not _tcp_open(host, port):
                return "CPA", False, f"Grok2API 远程不可达 {host}:{port}"
            g2a_root = g2a_remote.rstrip("/")
            for suffix in (
                "/api/admin/v1/accounts/import",
                "/api/admin/v1",
                "/admin",
            ):
                if g2a_root.endswith(suffix):
                    g2a_root = g2a_root[: -len(suffix)].rstrip("/")
                    break
            login_resp = http_post(
                f"{g2a_root}/api/admin/v1/auth/login",
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                json={"username": g2a_username, "password": g2a_password},
                timeout=8,
                proxies={"http": "", "https": "", "all": ""},
            )
            if login_resp.status_code in (401, 403):
                return "CPA", False, f"Grok2API 登录账号或密码无效 HTTP {login_resp.status_code}"
            if login_resp.status_code >= 400:
                return "CPA", False, f"Grok2API 登录失败 HTTP {login_resp.status_code}"
            try:
                login_payload = login_resp.json()
                access_token = login_payload["data"]["tokens"]["accessToken"]
            except (AttributeError, KeyError, TypeError, ValueError):
                return "CPA", False, "Grok2API 登录响应缺少 accessToken"
            if not str(access_token or "").strip():
                return "CPA", False, "Grok2API 登录响应缺少 accessToken"
            parts.append("Grok2API登录OK")
            parts.append("Grok2API远程TCP可达")
        except Exception as exc:
            return "CPA", False, f"Grok2API 远程探测失败: {redact_log_line(str(exc))}"
    if remote:
        if not key:
            return "CPA", False, "已配远程地址但缺少管理密钥"
        try:
            u = urlparse(remote)
            host = u.hostname or "127.0.0.1"
            port = u.port or (443 if u.scheme == "https" else 80)
            if not _tcp_open(host, port):
                return "CPA", False, f"远程不可达 {host}:{port}"
            base = remote.rstrip("/")
            # 管理 API 列表
            resp = http_get(
                f"{base}/v0/management/auth-files",
                headers={"Authorization": f"Bearer {key}"},
                timeout=8,
                proxies={},  # CPA 一般本机
                impersonate="chrome",
            )
            if resp.status_code in (401, 403):
                return "CPA", False, f"管理密钥无效 HTTP {resp.status_code}"
            if resp.status_code >= 500:
                return "CPA", False, f"CPA 服务异常 HTTP {resp.status_code}"
            parts.append(f"远程OK HTTP {resp.status_code}")
        except Exception as exc:
            return "CPA", False, f"远程探测失败: {redact_log_line(str(exc))}"
    return "CPA", True, "；".join(parts) if parts else "OK"


def run_connectivity_checks(config: dict, http_get: Callable, http_post: Callable) -> List[CheckResult]:
    results = []
    proxy = str(config.get("proxy", "") or "")
    results.append(check_proxy(proxy, http_get))
    results.append(check_xai_signup(proxy, http_get))
    results.append(
        check_email_api(
            str(config.get("email_provider", "") or ""),
            config,
            http_get,
            http_post,
        )
    )
    results.append(check_cpa(config, http_get, http_post))
    return results


def format_check_results(results: List[CheckResult]) -> str:
    lines = []
    for name, ok, detail in results:
        mark = "OK" if ok else "FAIL"
        lines.append(f"[{mark}] {name}: {detail}")
    return "\n".join(lines)
