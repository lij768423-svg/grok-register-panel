#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Grok 注册机 - TTK GUI 版本
整合 openai_register.py, batch_open_nsfw.py（原 DrissionPage 已替换为 Camoufox）
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import datetime
import time
import os
from pathlib import Path
import sys
import signal
import gc
import queue
import secrets
import struct
import random
import re
import string
import json
import base64

os.environ.setdefault("TK_SILENCE_DEPRECATION", "1")

from playwright._impl._errors import TargetClosedError as PageDisconnectedError
from curl_cffi import requests
import requests as _std_requests

# SSO → CLIProxyAPI(CPA) 扁平格式转换（复用 sso_to_auth_json 的授权码流程 + 写入器）
import sso_to_auth_json as _s2cpa
from email_providers import cloudflare as cloudflare_provider
from email_providers import cloudmail as cloudmail_provider
from email_providers import duckmail as duckmail_provider
from email_providers import mailnest as mailnest_provider
from email_providers import moemail as moemail_provider
from email_providers import yyds as yyds_provider
from email_providers.common import extract_verification_code as _extract_code
from email_providers.common import generate_username as _generate_username
from email_providers.common import pick_list_payload as _pick_list

import browser_session as _bs
import register_flow as _rf
import connectivity as _conn
from batch_supervisor import mark_slot_completed
from batch_traffic import mark_successful_account
from retry_policy import proxy_boot_rotations, slot_retries
from secure_files import (
    append_private_text,
    atomic_write_json,
    atomic_write_text,
    create_private_text,
    ensure_private_dir,
    exclusive_file_lock,
)
from webui.proxy_store import (
    mark_proxy_used as _mark_managed_proxy_used,
    record_proxy_result as _record_managed_proxy_result,
    worker_proxy_snapshot as _managed_worker_proxy_snapshot,
)
from webui.email_domain_store import (
    PROVIDER_LABELS as _EMAIL_DOMAIN_PROVIDER_LABELS,
    SUPPORTED_PROVIDERS as _MANAGED_EMAIL_DOMAIN_PROVIDERS,
    record_domain_result as _record_managed_email_domain_result,
    select_domain as _select_managed_email_domain,
)
from webui.security_utils import redact_log_line as redact_sensitive_log_line
from browser_session import (

    browser,
    page,
    active_browser as _active_browser,
    active_page as _active_page,
    set_browser_session as _set_browser_session,
    start_browser,
    stop_browser,
    restart_browser,
    cleanup_runtime_memory,
    refresh_active_page,
    extract_cf_clearance_and_ua,
    create_browser_options,
    get_start_fail_streak,
    cleanup_stale_profiles as _cleanup_stale_profiles,
    get_exit_ip,
    get_bound_proxy,
    clear_exit_context,
)
from register_flow import (
    SIGNUP_URL,
    authorize_device_in_browser,
    click_email_signup_button,
    open_signup_page,
    has_profile_form,
    detect_email_domain_rejection,
    raise_if_email_domain_rejected,
    fill_email_and_submit,
    fill_code_and_submit,
    getTurnstileToken,
    build_profile,
    fill_profile_and_submit,
    wait_for_sso_cookie,
)



APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(APP_DIR, "config.json")
# 注册产物目录（账号 / 邮箱凭证 / 待重转 SSO），避免堆在项目根目录
ACCOUNTS_DIR = os.path.join(APP_DIR, "accounts")
MEMORY_CLEANUP_INTERVAL = 5

_session_log_path = None
_session_log_lock = threading.Lock()


def ensure_accounts_dir():
    """确保 accounts/ 存在，返回目录绝对路径。"""
    ensure_private_dir(ACCOUNTS_DIR)
    return ACCOUNTS_DIR


def new_accounts_output_path(now=None):
    """本批次账号输出路径：accounts/accounts_YYYYMMDD_HHMMSS.txt

    仅作为批次汇总文件（兼容旧逻辑）；每个账号还会单独保存到 accounts/{email}.txt。
    """
    ensure_accounts_dir()
    ts = (now or datetime.datetime.now()).strftime("%Y%m%d_%H%M%S")
    return os.path.join(ACCOUNTS_DIR, f"accounts_{ts}.txt")


def account_file_for_email(email):
    """单个账号的独立输出路径：accounts/{email}.txt"""
    ensure_accounts_dir()
    safe_email = str(email or "").strip().replace("/", "_").replace("\\", "_")
    return os.path.join(ACCOUNTS_DIR, f"{safe_email}.txt")


def accounts_side_file(name):
    """accounts/ 下的附属文件路径（mail_credentials / sso_pending 等）。"""
    ensure_accounts_dir()
    return os.path.join(ACCOUNTS_DIR, name)


def initialize_session_log(log_dir=None, now=None):
    """为本次程序启动创建一个独立的 UTF-8 日志文件。"""
    global _session_log_path
    with _session_log_lock:
        if _session_log_path:
            return _session_log_path

        target_dir = log_dir or os.path.join(APP_DIR, "log")
        ensure_private_dir(target_dir)
        timestamp = (now or datetime.datetime.now()).strftime("%Y%m%d_%H%M%S")
        suffix = 1
        while True:
            suffix_text = "" if suffix == 1 else f"_{suffix}"
            path = os.path.join(target_dir, f"app_{timestamp}{suffix_text}.log")
            try:
                create_private_text(path)
            except FileExistsError:
                suffix += 1
                continue
            _session_log_path = path
            return path


def append_session_log(line):
    path = _session_log_path
    if not path:
        return
    try:
        with _session_log_lock:
            append_private_text(path, f"{line}\n")
    except OSError:
        # 持久化日志失败不应中断正在进行的注册任务。
        pass

UI_BG = "#242424"
UI_PANEL_BG = "#2b2b2b"
UI_FG = "#f2f2f2"
UI_MUTED_FG = "#b8b8b8"
UI_ENTRY_BG = "#333333"
UI_BUTTON_BG = "#3a3a3a"
UI_ACTIVE_BG = "#4a6078"

DEFAULT_CONFIG = {
    "email_provider": "cloudflare",
    "duckmail_api_key": "",
    "duckmail_api_base": "https://api.duckmail.sbs",
    "defaultDomains": "",
    "cloudmail_url": "",
    "cloudmail_admin_email": "",
    "cloudmail_password": "",
    "cloudflare_api_base": "",
    "cloudflare_api_key": "",
    "cloudflare_auth_mode": "none",
    "cloudflare_custom_auth": "",
    "cloudflare_path_domains": "/api/domains",
    "cloudflare_path_accounts": "/api/new_address",
    "cloudflare_path_token": "/api/token",
    "cloudflare_path_messages": "/api/mails",
    "proxy": "http://127.0.0.1:7890",
    "enable_nsfw": True,
    "debug_mode": False,
    "close_browser_on_stop": False,
    "log_level": "info",
    "register_count": 1,
    "register_workers": 1,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    # CLIProxyAPI(CPA) 直出：注册拿到 SSO 后换 token，写入 CPA / Grok2API
    "cpa_auto_add": False,
    # Token 换取方式：device_protocol（协议 Device Flow，默认）/ device_browser（浏览器 Device Flow）/ auth_code
    "cpa_token_mode": "device_protocol",
    # CPA 本地 auth 目录（默认项目根目录下 cpa_auth/）
    "cpa_auth_dir": "cpa_auth",
    # 远程 CPA：通过 Management API POST /v0/management/auth-files 上传
    "cpa_remote_url": "",
    "cpa_management_key": "",
    # Grok2API / ~/.grok 风格 auth 目录（默认项目根目录下 grok2api_auth/）
    "grok2api_auth_dir": "grok2api_auth",
    "mailnest_api_key": "",
    "mailnest_project_code": "x-ai001",
    # YYDS：留空自动选已验证域名；填写则固定该域名
    "yyds_default_domain": "",
    # MoeMail：站点根 URL + X-API-Key；域名留空时从 /api/config 自动选择
    "moemail_api_base": "",
    "moemail_api_key": "",
    "moemail_domain": "",
    "moemail_expiry_ms": moemail_provider.DEFAULT_EXPIRY_MS,
    # 账号间注册间隔（秒），0=不等待。填一个整数=N秒固定等待，填区间"60-120"=随机等待
    "account_interval": "60-120",
}

config = DEFAULT_CONFIG.copy()
_cf_domain_index = 0


class RegistrationCancelled(Exception):
    pass


class AccountRetryNeeded(Exception):
    pass


class EmailDomainRejected(Exception):
    """xAI 拒绝当前邮箱域名（如公共临时域被拉黑）。"""

    def __init__(self, email="", message=""):
        self.email = email or ""
        self.message = message or "邮箱域名已被拒绝"
        domain = ""
        if "@" in self.email:
            domain = self.email.split("@", 1)[1]
        detail = self.message
        if domain and domain not in detail:
            detail = f"{detail}（域名: {domain}）"
        if self.email and self.email not in detail:
            detail = f"{detail} | 邮箱: {self.email}"
        super().__init__(detail)


class RegistrationRiskDenied(Exception):
    """账号已创建，但服务端将本次注册裁决为 OAuth 不可用。"""



FAIL_DOMAIN = "domain_rejected"
FAIL_RISK = "registration_risk"
FAIL_CODE = "code_timeout"
FAIL_BROWSER = "browser"
FAIL_CPA = "cpa"
FAIL_STUCK = "stuck_retry"
FAIL_SSO = "sso_timeout"
FAIL_TURNSTILE = "turnstile"
FAIL_PROFILE = "profile_fill"
FAIL_OTHER = "other"


def redact_proxy(url: str) -> str:
    """Strip credentials from proxy URL for logs/jsonl."""
    s = str(url or "").strip()
    if not s:
        return ""
    try:
        from urllib.parse import urlparse, urlunparse
        if "://" not in s:
            parts = s.split(":")
            if len(parts) >= 4:
                return f"{parts[0]}:{parts[1]}:***"
            return s
        p = urlparse(s)
        if p.username or p.password:
            host = p.hostname or ""
            netloc = f"{host}:{p.port}" if p.port else host
            return urlunparse((p.scheme, netloc, p.path, p.params, p.query, p.fragment))
        return s
    except Exception:
        import re as _re
        return _re.sub(r"://([^:/@]+):([^@/]+)@", r"://***:***@", s)


def mask_email(email: str) -> str:
    s = str(email or "").strip()
    if "@" not in s:
        return s
    local, _, domain = s.partition("@")
    if len(local) <= 2:
        return (local[:1] + "***@" + domain) if local else ("***@" + domain)
    return local[:2] + "***@" + domain


FAIL_LABELS = {
    FAIL_DOMAIN: "域名拒绝",
    FAIL_RISK: "注册风控",
    FAIL_CODE: "验证码超时",
    FAIL_BROWSER: "浏览器断开",
    FAIL_CPA: "CPA失败",
    FAIL_STUCK: "流程卡住",
    FAIL_SSO: "SSO超时",
    FAIL_TURNSTILE: "资料页Turnstile",
    FAIL_PROFILE: "资料填写",
    FAIL_OTHER: "其它",
}



_RESULT_LOG_LOCK = threading.Lock()
_RESULT_LOG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "log", "register_results.jsonl"
)


def record_register_result(
    status: str,
    email: str = "",
    *,
    kind: str = "",
    detail: str = "",
    worker: str = "",
    bot_flag=None,
    risk=None,
    bfs=None,
    bfs_value=None,
    log_callback=None,
) -> dict:
    """记录单次注册结果 + 出口 IP（控制台一行 + jsonl）。

    status: ok / fail / risk / sso_timeout / browser / other
    bfs: True/False/None — JWT claim 检测（与 botFlagSource 不同）
    """
    import json as _json
    from datetime import datetime, timezone

    exit_ip = ""
    proxy = ""
    try:
        exit_ip = get_exit_ip() or ""
    except Exception:
        pass
    try:
        proxy = get_bound_proxy() or ""
    except Exception:
        pass
    try:
        if status == "ok":
            _record_managed_proxy_result(proxy, "success")
        elif status == "risk" or kind == FAIL_RISK:
            _record_managed_proxy_result(proxy, "risk", detail)
        elif kind == FAIL_BROWSER:
            _record_managed_proxy_result(proxy, "network", detail)
    except Exception:
        pass
    # 从 proxy URL 抽端口
    port = ""
    try:
        if "://" in proxy:
            hostport = proxy.split("://", 1)[1]
            if ":" in hostport:
                port = hostport.rsplit(":", 1)[-1]
    except Exception:
        pass

    rec = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": status,
        "email": mask_email(email or ""),
        "kind": kind or "",
        "detail": redact_sensitive_log_line(detail or "")[:300],
        "worker": worker or "",
        "exit_ip": exit_ip,
        "proxy": redact_proxy(proxy),
        "port": port,
        "bot_flag": bot_flag,
        "risk": risk,
        "bfs": bfs,
        "bfs_value": bfs_value,
    }
    bfs_txt = "-"
    if bfs is True:
        bfs_txt = f"yes:{bfs_value}" if bfs_value is not None else "yes"
    elif bfs is False:
        bfs_txt = "clean"
    line = (
        f"[结果] status={status} ip={exit_ip or '?'} port={port or '?'} "
        f"email={mask_email(email) if email else '-'} kind={kind or '-'} bot={bot_flag if bot_flag is not None else '-'} "
        f"risk={risk if risk is not None else '-'} bfs={bfs_txt}"
    )
    if log_callback:
        try:
            log_callback(line)
        except Exception:
            pass
    try:
        ensure_private_dir(os.path.dirname(_RESULT_LOG_PATH))
        with _RESULT_LOG_LOCK:
            append_private_text(
                _RESULT_LOG_PATH,
                _json.dumps(rec, ensure_ascii=False) + "\n",
            )
    except Exception as exc:
        if log_callback:
            try:
                log_callback(f"[结果] 写入 jsonl 失败: {exc}")
            except Exception:
                pass
    return rec


def classify_failure(exc) -> str:
    if isinstance(exc, EmailDomainRejected):
        return FAIL_DOMAIN
    if isinstance(exc, RegistrationRiskDenied):
        return FAIL_RISK
    msg = str(exc or "")
    low = msg.lower()
    if isinstance(exc, AccountRetryNeeded) or "达到最大重试" in msg or "流程卡住" in msg:
        return FAIL_STUCK
    if "sso_timeout" in low or "未获取到 sso" in msg or "未获取到 sso cookie" in msg:
        return FAIL_SSO
    if (
        "资料页 Turnstile" in msg
        or "Turnstile 超时" in msg
        or "Turnstile 获取 token 失败" in msg
        or ("turnstile" in low and ("超时" in msg or "失败" in msg or "token" in low))
    ):
        return FAIL_TURNSTILE
    if (
        "资料页表单未就绪" in msg
        or "资料页无提交按钮" in msg
        or "资料页输入写入失败" in msg
        or "最终注册页资料填写失败" in msg
    ):
        return FAIL_PROFILE
    if "未收到验证码" in msg or "验证码阶段失败" in msg or ("验证码" in msg and "失败" in msg):
        return FAIL_CODE
    if (
        "浏览器" in msg
        or "page disconnected" in low
        or "与页面的连接已断开" in msg
        or "PageDisconnected" in msg
        or "disconnected" in low
    ):
        return FAIL_BROWSER
    if "[CPA]" in msg or ("CPA" in msg and ("失败" in msg or "跳过" in msg)):
        return FAIL_CPA
    return FAIL_OTHER


def empty_fail_stats():
    return {k: 0 for k in FAIL_LABELS}


def format_fail_stats(stats: dict) -> str:
    parts = [f"{FAIL_LABELS.get(k, k)}={stats.get(k, 0)}" for k in FAIL_LABELS if stats.get(k, 0)]
    if not parts:
        return "无分类失败"
    return " | ".join(parts)



def load_config():
    global config
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            config = {**DEFAULT_CONFIG, **loaded}
        except Exception:
            config = DEFAULT_CONFIG.copy()
    return config


def _sleep_cancelable(seconds, should_stop=None) -> None:
    """Sleep in short slices so stop flags can interrupt account gaps."""
    end = time.time() + max(0.0, float(seconds or 0))
    while time.time() < end:
        if callable(should_stop) and should_stop():
            return
        remaining = end - time.time()
        if remaining <= 0:
            break
        time.sleep(min(0.5, remaining))


def parse_account_interval() -> float:
    """解析 account_interval 配置，返回等待秒数。

    "0" / "" → 0（不等待）
    "30" → 30.0（固定 30 秒）
    "60-120" → 60~120 之间的随机值
    """
    raw = str(config.get("account_interval", "0") or "0").strip()
    if not raw or raw == "0":
        return 0.0
    if "-" in raw:
        parts = raw.split("-", 1)
        try:
            lo = max(int(parts[0].strip()), 0)
            hi = max(int(parts[1].strip()), lo)
            return float(random.randint(lo, hi))
        except (ValueError, IndexError):
            return 0.0
    try:
        return float(int(raw))
    except ValueError:
        return 0.0


def save_config():
    try:
        atomic_write_json(CONFIG_FILE, config)
    except Exception as e:
        print(f"保存配置失败: {e}")


def ensure_stable_python_runtime():
    if sys.version_info < (3, 14) or os.environ.get("DPE_REEXEC_DONE") == "1":
        return

    local_app_data = os.environ.get("LOCALAPPDATA", "")
    candidates = [
        os.path.join(local_app_data, "Programs", "Python", "Python312", "python.exe"),
        os.path.join(local_app_data, "Programs", "Python", "Python313", "python.exe"),
    ]

    current_python = os.path.normcase(os.path.abspath(sys.executable))
    for candidate in candidates:
        if not os.path.isfile(candidate):
            continue
        if os.path.normcase(os.path.abspath(candidate)) == current_python:
            return

        print(
            f"[*] 检测到 Python {sys.version.split()[0]}，自动切换到更稳定的解释器: {candidate}"
        )
        env = os.environ.copy()
        env["DPE_REEXEC_DONE"] = "1"
        os.execve(candidate, [candidate, os.path.abspath(__file__), *sys.argv[1:]], env)


def warn_runtime_compatibility():
    if sys.version_info >= (3, 14):
        print(
            "[提示] 当前 Python 为 3.14+；若出现 Mail.tm TLS 异常，建议改用 Python 3.12 或 3.13。"
        )


ensure_stable_python_runtime()
warn_runtime_compatibility()

load_config()

# turnstilePatch 是 Chrome 扩展，Camoufox 基于 Firefox 不兼容，已移除。
# Turnstile 交互改为纯 JS 注入方式（见 register_flow.getTurnstileToken）。
EXTENSION_PATH = ""


DUCKMAIL_API_BASE_DEFAULT = duckmail_provider.API_BASE_DEFAULT


# 每 worker 可绑定独立代理（Clash listener 端口），避免 8 并发挤同一 sticky
_proxy_tls = threading.local()
_proxy_pool: list = []
_proxy_pool_lock = threading.Lock()
_proxy_pool_source = "none"


def load_proxy_pool(path: str = "") -> list:
    """热加载健康面板代理；无可用项时兼容 proxies.txt / config.proxy。"""
    global _proxy_pool, _proxy_pool_source
    try:
        managed_snapshot = _managed_worker_proxy_snapshot()
    except Exception:
        managed_snapshot = {"configured": False, "urls": []}
    managed = list(managed_snapshot.get("urls") or [])
    if managed_snapshot.get("configured"):
        with _proxy_pool_lock:
            _proxy_pool = managed
            _proxy_pool_source = "managed" if managed else "managed-empty"
            return list(_proxy_pool)

    candidates = []
    if path:
        candidates.append(Path(path))
    candidates.append(Path(APP_DIR) / "proxies.txt")
    pool = []
    for fp in candidates:
        try:
            if not fp.is_file():
                continue
            for line in fp.read_text(encoding="utf-8").splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if s.startswith("http://") or s.startswith("socks5://") or s.startswith("socks5h://"):
                    pool.append(s)
            if pool:
                break
        except Exception:
            continue
    if not pool:
        single = str(config.get("proxy", "") or "").strip()
        if single:
            pool = [single]
    with _proxy_pool_lock:
        _proxy_pool = list(pool)
        _proxy_pool_source = "legacy" if pool else "none"
        return list(_proxy_pool)


def set_thread_proxy(proxy: str):
    _proxy_tls.proxy = str(proxy or "").strip()


def get_thread_proxy() -> str:
    return str(getattr(_proxy_tls, "proxy", "") or "").strip()


def pick_proxy_for_worker(worker_id: int, rotate_idx: int = 0) -> str:
    """账号边界热加载，全池轮换；当前浏览器会话内不再换代理。"""
    pool = load_proxy_pool()
    if not pool:
        if _proxy_pool_source == "managed-empty":
            raise RuntimeError("面板代理池没有健康且启用的代理，请先检测或等待冷却结束")
        return str(config.get("proxy", "") or "").strip()
    idx = (max(0, int(worker_id)) + max(0, int(rotate_idx))) % len(pool)
    selected = pool[idx]
    try:
        _mark_managed_proxy_used(selected)
    except Exception:
        pass
    return selected


def get_proxies():
    proxy = get_thread_proxy() or str(config.get("proxy", "") or "").strip()
    if proxy:
        return {"http": proxy, "https": proxy}
    return {}


def record_proxy_boot_failure(proxy: str, exc) -> None:
    """Apply runtime cooldown to managed proxies without touching legacy entries."""
    message = str(exc or "")
    outcome = "risk" if ("黑名单" in message or "policy=deny" in message) else "network"
    try:
        _record_managed_proxy_result(proxy, outcome, message)
    except Exception:
        pass


def _record_proxy_precheck_failure(proxy: str, checks) -> bool:
    for name, ok, detail in checks or []:
        if name != _conn.XAI_SIGNUP_CHECK_NAME or ok:
            continue
        record_proxy_boot_failure(
            proxy,
            RuntimeError(f"xAI registration-page precheck failed: {detail}"),
        )
        return True
    return False


_MAIL_DIRECT_PATH_MARKERS = (
    "/admin/new_address",
    "/api/mails",
    "/api/mail/",
    "/api/emails/",
)


def _url_needs_direct(url: str) -> bool:
    u = str(url or "").lower()
    configured_bases = (
        config.get("cloudflare_api_base"),
        config.get("cloudmail_url"),
        config.get("moemail_api_base"),
        config.get("duckmail_api_base"),
    )
    for value in configured_bases:
        base = str(value or "").strip().lower().rstrip("/")
        if base and (u == base or u.startswith(base + "/")):
            return True
    return any(marker in u for marker in _MAIL_DIRECT_PATH_MARKERS)


def _apply_mail_direct(url, request_kwargs: dict) -> dict:
    """邮箱 Worker API 强制直连，避免经住宅代理 TLS 失败。"""
    if _url_needs_direct(url):
        rk = dict(request_kwargs)
        rk["proxies"] = {}
        return rk
    return request_kwargs


def get_duckmail_api_base():
    return duckmail_provider.normalize_base(str(config.get("duckmail_api_base", "") or ""))


def get_duckmail_api_key():
    return config.get("duckmail_api_key", "")



def get_cloudflare_api_base():
    return str(config.get("cloudflare_api_base", "") or "").rstrip("/")


def get_cloudflare_api_key():
    return config.get("cloudflare_api_key", "")


def get_cloudflare_auth_mode():
    return str(config.get("cloudflare_auth_mode", "none") or "none").lower()


def get_cloudflare_custom_auth():
    """全局访问密码（cloudflare_temp_email 的 PASSWORDS）。"""
    return str(config.get("cloudflare_custom_auth", "") or "").strip()


def cloudflare_apply_custom_auth(headers):
    return cloudflare_provider.apply_custom_auth(headers, get_cloudflare_custom_auth())


def get_cloudflare_path(key, default_path):
    return cloudflare_provider.path_from_config(config, key, default_path)


def cloudflare_build_headers(content_type=False):
    return cloudflare_provider.build_headers(
        get_cloudflare_api_key(),
        get_cloudflare_auth_mode(),
        get_cloudflare_custom_auth(),
        content_type=content_type,
    )


def cloudflare_apply_auth_params(params=None):
    return cloudflare_provider.apply_auth_params(
        params, get_cloudflare_api_key(), get_cloudflare_auth_mode()
    )


def cloudflare_next_default_domain():
    global _cf_domain_index
    domains = [x.strip() for x in str(config.get("defaultDomains", "") or "").split(",") if x.strip()]
    domain, _cf_domain_index = cloudflare_provider.next_default_domain(domains, _cf_domain_index)
    return domain


def cloudflare_is_admin_create_path(path):
    return cloudflare_provider.is_admin_create_path(path)


def _pick_list_payload(data):
    return _pick_list(data)


def cloudflare_randomize_subdomain_enabled() -> bool:
    """主域易被风控时挂随机子域（需 CF Email Routing 对 *.apex catch-all）。

    配置 cloudflare_randomize_subdomain：true/false，默认 true。
    """
    raw = config.get("cloudflare_randomize_subdomain", True)
    if isinstance(raw, bool):
        return raw
    return str(raw or "1").strip().lower() not in {"0", "false", "no", "off", ""}


def cloudflare_create_temp_address(api_base, domain=""):
    selected_domain = str(domain or "").strip() or cloudflare_next_default_domain()
    return cloudflare_provider.create_temp_address(
        http_post,
        api_base,
        accounts_path=get_cloudflare_path("cloudflare_path_accounts", "/api/new_address"),
        domain=selected_domain,
        api_key=get_cloudflare_api_key(),
        auth_mode=get_cloudflare_auth_mode(),
        custom_auth=get_cloudflare_custom_auth(),
        name=generate_username(10),
        # 有管理域名时也默认随机子域，避免根域被批量风控
        randomize_subdomain=cloudflare_randomize_subdomain_enabled(),
    )


MAILNEST_API_BASE = mailnest_provider.API_BASE
MAILNEST_DEFAULT_PROJECT_CODE = mailnest_provider.DEFAULT_PROJECT_CODE


def get_mailnest_api_key():
    key = str(config.get("mailnest_api_key", "") or "").strip()
    if not key:
        raise Exception(f"请在配置文件中配置 mailnest_api_key | 注册网址：{MAILNEST_API_BASE}")
    return key


def get_mailnest_project_code():
    code = str(config.get("mailnest_project_code", "") or "").strip()
    return code or MAILNEST_DEFAULT_PROJECT_CODE


def mailnest_buy_email():
    return mailnest_provider.buy_email(http_post, get_mailnest_api_key(), get_mailnest_project_code())


def mailnest_receive_email(email):
    return mailnest_provider.receive_email(http_post, get_mailnest_api_key(), email)


def mailnest_get_code(email, timeout=180, poll_interval=3, log_callback=None, cancel_callback=None):
    return mailnest_provider.wait_for_code(
        http_post,
        get_mailnest_api_key(),
        email,
        timeout=timeout,
        poll_interval=poll_interval,
        raise_if_cancelled=raise_if_cancelled,
        sleep_with_cancel=sleep_with_cancel,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
    )


def get_user_agent():
    return config.get(
        "user_agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    )


def _normalize_sso_token(raw_token):
    token = str(raw_token or "").strip()
    if token.startswith("sso="):
        token = token[4:]
    return token


def _resolve_cpa_proxy():
    """CPA 换 token 用的代理：优先线程绑定 / config.proxy，其次环境变量，否则直连。"""
    proxy = get_thread_proxy() or str(config.get("proxy", "") or "").strip()
    if proxy:
        return proxy
    for key in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"):
        val = str(os.environ.get(key, "") or "").strip()
        if val:
            return val
    return ""


def _append_sso_pending(email: str, sso: str, log_callback=None):
    """CPA 失败时保留 SSO，便于事后 sso_to_auth_json 重转。"""
    try:
        path = accounts_side_file("sso_pending.txt")
        line = f"{email}----{sso}\n" if email else f"{sso}\n"
        with exclusive_file_lock(path + ".lock"):
            duplicate = False
            try:
                for existing in Path(path).read_text(encoding="utf-8").splitlines():
                    if existing.strip().split("----")[-1].removeprefix("sso=").strip() == sso:
                        duplicate = True
                        break
            except OSError:
                pass
            if not duplicate:
                append_private_text(path, line)
        if log_callback:
            action = "已存在" if duplicate else "已追加"
            log_callback(f"[CPA] 待重转 SSO {action} → {path}")
    except Exception as exc:
        if log_callback:
            log_callback(f"[CPA] 写入 sso_pending 失败: {exc}")


def _append_sso_risk_rejected(email: str, sso: str, details: str, log_callback=None):
    """保存注册风控拒绝的 SSO；该类账号不进入待重转队列。"""
    try:
        path = accounts_side_file("sso_risk_rejected.txt")
        safe_details = re.sub(r"[\r\n\t]+", " ", str(details or "")).strip()
        append_private_text(path, f"{email}----{sso}----{safe_details}\n")
        if log_callback:
            log_callback(f"[CPA] 已保存注册风控拒绝记录 → {path}")
    except Exception as exc:
        if log_callback:
            log_callback(f"[CPA] 保存注册风控拒绝记录失败: {exc}")


def _append_sso_bfs_flagged(email: str, sso: str, details: str, log_callback=None):
    """保存 JWT bfs 标记账号（access_token/sso 含 bfs claim）。"""
    try:
        path = accounts_side_file("sso_bfs_flagged.txt")
        safe_details = re.sub(r"[\r\n\t]+", " ", str(details or "")).strip()
        append_private_text(path, f"{email}----{sso}----{safe_details}\n")
        if log_callback:
            log_callback(f"[CPA] 已保存 bfs 标记记录 → {path}")
    except Exception as exc:
        if log_callback:
            log_callback(f"[CPA] 保存 bfs 标记记录失败: {exc}")


def _registration_risk_should_block(state: dict) -> tuple:
    """是否跳过 OAuth/入库。

    升级后额外拦住：
      - botFlagSource in (1, 2)（含 IP farm soft-flag / castle 等）
      - policy=deny 且 event 非 registration（如 $login）
    读不到风控字段时不硬拦，交给上层继续。
    """
    if not isinstance(state, dict):
        return False, ""
    details = str(state.get("bot_flag_details") or "").strip()
    bf = state.get("bot_flag_source")
    policy = str(state.get("policy") or "").strip().lower()
    event = str(state.get("event") or "").strip()

    # 1) 注册硬拒绝（原逻辑）
    if state.get("denied"):
        return True, details or "policy=deny,event=$registration"

    # 2) botFlagSource=1/2：含 soft-flag IP 农场、castle 等（原先放行）
    if bf in (1, 2):
        return True, details or ("botFlagSource=%s" % bf)

    # 3) policy=deny 其它 event（如 $login，原先放行）
    if policy == "deny":
        return True, details or ("policy=deny,event=%s" % (event or "unknown"))

    return False, ""


def ensure_sso_oauth_eligible(raw_token, email="", log_callback=None) -> dict:
    """检查新账号是否被注册风控拒绝；无法判定时继续原有 OAuth 路径。"""
    if not config.get("cpa_auto_add", False):
        return {}
    if not any(
        str(config.get(key, "") or "").strip()
        for key in ("cpa_auth_dir", "cpa_remote_url", "grok2api_auth_dir")
    ):
        return {}
    sso = _normalize_sso_token(raw_token)
    if not sso:
        raise RegistrationRiskDenied("注册风控检查失败: sso 为空")

    def _risk_log(message):
        if log_callback:
            log_callback(f"[CPA] {str(message).strip()}")

    _risk_log("检查新账号注册风控状态 ...")
    state = _s2cpa.inspect_sso_account_state(
        sso,
        proxy=_resolve_cpa_proxy(),
        log=_risk_log,
    )
    block, details = _registration_risk_should_block(state)
    if block:
        details = str(details or state.get("bot_flag_details") or "registration_risk")
        _append_sso_risk_rejected(email, sso, details, log_callback=log_callback)
        try:
            _bf = state.get("bot_flag_source")
            _rk = None
            _mrisk = re.search(r"risk=([\d.]+)", str(details))
            if _mrisk:
                try:
                    _rk = float(_mrisk.group(1))
                except Exception:
                    _rk = None
            record_register_result(
                "risk",
                email or "",
                kind=FAIL_RISK,
                detail=f"botFlagSource={_bf} {details}",
                bot_flag=_bf,
                risk=_rk,
                log_callback=log_callback,
            )
        except Exception:
            pass
        raise RegistrationRiskDenied(
            "注册风控拒绝，已跳过 OAuth: "
            f"botFlagSource={state.get('bot_flag_source')} {details}"
        )
    if not state.get("found"):
        _risk_log(f"未读取到注册风控字段，继续 OAuth: {state.get('error') or 'unknown'}")
    elif state.get("bot_flag_source") == 0:
        _risk_log("注册风控状态可用: botFlagSource=0")
    return state


def add_sso_to_cpa(raw_token, email="", log_callback=None) -> bool:
    """SSO → Device Flow（失败回退授权码）换 token → 写入 CPA / Grok2API。

    返回 True 表示入库成功（或未开启/无需转换）；False 表示转换失败（SSO 仍可能已写入 accounts）。
    """
    if not config.get("cpa_auto_add", False):
        if log_callback:
            log_callback("[*] 已关闭 SSO→auth，仅保存 SSO（不写 auth）")
        return True
    auth_dir = str(config.get("cpa_auth_dir", "") or "").strip()
    remote_url = str(config.get("cpa_remote_url", "") or "").strip()
    management_key = str(config.get("cpa_management_key", "") or "").strip()
    g2a_dir = str(config.get("grok2api_auth_dir", "") or "").strip()

    # 相对路径基于项目根目录解析，并自动创建目录
    if auth_dir and not os.path.isabs(auth_dir):
        auth_dir = os.path.join(APP_DIR, auth_dir)
    if g2a_dir and not os.path.isabs(g2a_dir):
        g2a_dir = os.path.join(APP_DIR, g2a_dir)

    if not auth_dir and not remote_url and not g2a_dir:
        if log_callback:
            log_callback(
                "[Debug] 已开启 SSO→auth 但未配置 cpa_auth_dir / cpa_remote_url / grok2api_auth_dir，跳过"
            )
        return True
    if remote_url and not management_key:
        if log_callback:
            log_callback("[Debug] 已配置 cpa_remote_url 但未配置 cpa_management_key，跳过远程上传")
        remote_url = ""
    if not auth_dir and not remote_url and not g2a_dir:
        return True
    sso = _normalize_sso_token(raw_token)
    if not sso:
        return False
    proxy = _resolve_cpa_proxy()

    def _cpa_log(message):
        if log_callback:
            log_callback(f"[CPA] {str(message).strip()}")

    try:
        token_mode = str(config.get("cpa_token_mode", "device_protocol") or "device_protocol").lower()
        if token_mode not in ("device_protocol", "device_browser", "auth_code"):
            token_mode = "device_protocol"
        _mode_labels = {
            "device_protocol": "协议 Device Flow",
            "device_browser": "浏览器 Device Flow",
            "auth_code": "Authorization Code",
        }
        _cpa_log(
            f"SSO → {_mode_labels.get(token_mode, token_mode)} 换 token "
            f"(proxy={redact_proxy(proxy)}) ..."
        )

        def _browser_approve(user_code, open_url):
            return authorize_device_in_browser(
                user_code,
                open_url,
                timeout=10,
                log_callback=log_callback,
                cancel_callback=None,
            )

        # device_browser 模式：需要活动浏览器来点「继续/允许」
        # device_protocol 模式：纯 HTTP 协议换 token，不依赖浏览器
        # auth_code 模式：走授权码流程
        use_browser = token_mode == "device_browser" and _active_page() is not None
        if token_mode == "device_browser" and not use_browser:
            _cpa_log("无活动浏览器，回退到协议 Device Flow")
            token_mode = "device_protocol"

        # sso_to_token 的 prefer 只区分 device / auth_code
        # browser_approve 是否传入决定走浏览器还是协议
        prefer = "auth_code" if token_mode == "auth_code" else "device"
        browser_cb = _browser_approve if use_browser else None

        token = _s2cpa.sso_to_token(
            sso,
            proxy=proxy,
            log=_cpa_log,
            prefer=prefer,
            allow_fallback=True,
            browser_approve=browser_cb,
        )
        if not token:
            _cpa_log("换 token 失败；SSO 已在 accounts 文件，稍后可重转")
            _append_sso_pending(email, sso, log_callback=log_callback)
            return False

        # JWT bfs 检测（与 botFlagSource 独立；key 存在即标记）
        bfs_check = config.get("bfs_check", True)
        if isinstance(bfs_check, str):
            bfs_check = bfs_check.strip().lower() not in ("0", "false", "no", "off")
        bfs_info = {"ok": False, "has_bfs": False, "bfs": None, "source": ""}
        if bfs_check:
            bfs_info = _s2cpa.inspect_token_bundle_bfs(
                access_token=str(token.get("access_token") or ""),
                sso=sso,
                id_token=str(token.get("id_token") or ""),
                refresh_token=str(token.get("refresh_token") or ""),
            )
            skip_cpa = config.get("bfs_skip_cpa", False)
            if isinstance(skip_cpa, str):
                skip_cpa = skip_cpa.strip().lower() in ("1", "true", "yes", "on")
            if not bfs_info.get("ok"):
                _cpa_log("JWT bfs 检测: unknown（无法解码 token）")
                if skip_cpa:
                    _append_sso_pending(email, sso, log_callback=log_callback)
                    _cpa_log("bfs_skip_cpa=true，未知状态不写入 CPA/Grok2API，已进入待重转队列")
                    return False
            elif bfs_info.get("has_bfs"):
                detail = (
                    f"bfs={bfs_info.get('bfs')!r} source={bfs_info.get('source') or '-'}"
                )
                _cpa_log(f"JWT bfs 标记: {detail}")
                _append_sso_bfs_flagged(email, sso, detail, log_callback=log_callback)
                if skip_cpa:
                    _cpa_log("bfs_skip_cpa=true，跳过 CPA/Grok2API 写入")
                    try:
                        record_register_result(
                            "ok",
                            email or "",
                            kind="bfs_flagged",
                            detail=detail,
                            bfs=True,
                            bfs_value=bfs_info.get("bfs"),
                            log_callback=log_callback,
                        )
                    except Exception:
                        pass
                    return False
            else:
                _cpa_log("JWT bfs 检测: clean")

        record = _s2cpa.token_to_cpa_record(
            token,
            email=email,
            sso=sso,
            bfs_info=bfs_info if bfs_check else None,
            check_bfs=bool(bfs_check),
        )
        ap = _s2cpa.decode_jwt_payload(record.get("access_token", ""))
        ref = ap.get("referrer")
        if ref:
            _cpa_log(f"access_token referrer={ref!r}")
        disable_bfs = config.get("bfs_disable_cpa", False)
        if isinstance(disable_bfs, str):
            disable_bfs = disable_bfs.strip().lower() in ("1", "true", "yes", "on")
        if disable_bfs and record.get("bfs") is True:
            record["disabled"] = True
            _cpa_log("bfs 账号已标记 disabled=true")
        wrote_ok = False
        if auth_dir:
            try:
                path = _s2cpa.write_cpa_auth(_s2cpa.Path(auth_dir), record)
                _cpa_log(f"已写入 CPA 本地 {path}")
                wrote_ok = True
            except Exception as local_exc:
                _cpa_log(f"CPA 本地写入失败: {local_exc}")
        if remote_url:
            try:
                name = _s2cpa.upload_cpa_auth_remote(remote_url, management_key, record, proxy=proxy)
                _cpa_log(f"已上传 CPA 远程 {remote_url.rstrip('/')}/.../{name}")
                wrote_ok = True
            except Exception as remote_exc:
                _cpa_log(f"CPA 远程上传失败: {remote_exc}")
        if g2a_dir:
            try:
                gpath = _s2cpa.write_grok2api_auth(_s2cpa.Path(g2a_dir), token, email=email)
                _cpa_log(f"已写入 Grok2API {gpath}")
                wrote_ok = True
            except Exception as g2a_exc:
                _cpa_log(f"Grok2API 写入失败: {g2a_exc}")
        if not wrote_ok:
            _cpa_log("token 已换出但 CPA/Grok2API 均未写入成功")
            _append_sso_pending(email, sso, log_callback=log_callback)
            return False
        # 成功写入后把 bfs 记入结果日志（ok 状态由上层注册成功路径再记一次时可能覆盖；此处补一条细节）
        if bfs_check and bfs_info.get("has_bfs"):
            try:
                record_register_result(
                    "ok",
                    email or "",
                    kind="bfs_flagged",
                    detail=f"bfs={bfs_info.get('bfs')!r} written",
                    bfs=True,
                    bfs_value=bfs_info.get("bfs"),
                    log_callback=log_callback,
                )
            except Exception:
                pass
        return True
    except Exception as exc:
        _cpa_log(f"直出失败: {redact_sensitive_log_line(str(exc))}")
        _append_sso_pending(email, sso, log_callback=log_callback)
        return False


# create_browser_options -> browser_session

def _build_request_kwargs(**kwargs):
    request_kwargs = dict(kwargs)
    proxies = request_kwargs.pop("proxies", None)
    if proxies is None:
        proxies = get_proxies()
    if proxies:
        request_kwargs["proxies"] = proxies
    request_kwargs.setdefault("timeout", 15)
    return request_kwargs


def http_get(url, **kwargs):
    allow_direct_fallback = bool(kwargs.pop("_allow_direct_fallback", True))
    if _url_needs_direct(url):
        rk = dict(kwargs)
        rk.pop("proxies", None)
        rk.setdefault("timeout", 20)
        clean = {k: v for k, v in rk.items() if k != "impersonate"}
        return _std_requests.get(url, proxies={}, **clean)
    try:
        rk = _build_request_kwargs(**kwargs)
        return requests.get(url, **rk)
    except Exception as exc:
        err = str(exc)
        if allow_direct_fallback and any(x in err for x in ("Could not connect", "TLS connect error", "OPENSSL_internal", "7890")):
            rk = dict(kwargs)
            rk.pop("proxies", None)
            rk.setdefault("timeout", 20)
            clean = {k: v for k, v in rk.items() if k != "impersonate"}
            return _std_requests.get(url, proxies={}, **clean)
        raise



def http_post(url, **kwargs):
    if _url_needs_direct(url):
        rk = dict(kwargs)
        rk.pop("proxies", None)
        rk.setdefault("timeout", 20)
        clean = {k: v for k, v in rk.items() if k != "impersonate"}
        return _std_requests.post(url, proxies={}, **clean)
    try:
        rk = _build_request_kwargs(**kwargs)
        if "_apply_mail_direct" in globals():
            rk = _apply_mail_direct(url, rk)
        return requests.post(url, **rk)
    except Exception as exc:
        err = str(exc)
        if any(x in err for x in ("Could not connect", "TLS connect error", "OPENSSL_internal", "7890")):
            rk = dict(kwargs)
            rk.pop("proxies", None)
            rk.setdefault("timeout", 20)
            clean = {k: v for k, v in rk.items() if k != "impersonate"}
            return _std_requests.post(url, proxies={}, **clean)
        raise



def http_delete(url, **kwargs):
    try:
        rk = _apply_mail_direct(url, _build_request_kwargs(**kwargs))
        return requests.delete(url, **rk)
    except Exception as exc:
        err = str(exc)
        if (
            "127.0.0.1 port 7890" in err
            or "Could not connect to server" in err
            or "TLS connect error" in err
            or "OPENSSL_internal" in err
        ):
            retry_kwargs = dict(kwargs)
            retry_kwargs["proxies"] = {}
            return requests.delete(url, **_build_request_kwargs(**retry_kwargs))
        raise



def raise_if_cancelled(cancel_callback=None):
    if cancel_callback and cancel_callback():
        raise RegistrationCancelled("用户停止注册")


def sleep_with_cancel(seconds, cancel_callback=None):
    deadline = time.time() + max(seconds, 0)
    while True:
        raise_if_cancelled(cancel_callback)
        remaining = deadline - time.time()
        if remaining <= 0:
            return
        time.sleep(min(0.2, remaining))


def get_domains(api_key=None):
    return duckmail_provider.get_domains(
        http_get,
        get_duckmail_api_base(),
        api_key=api_key or get_duckmail_api_key(),
    )


def create_account(address, password, api_key=None, expires_in=0):
    return duckmail_provider.create_account(
        http_post,
        get_duckmail_api_base(),
        address,
        password,
        api_key=api_key or get_duckmail_api_key(),
        expires_in=expires_in,
    )


def get_token(address, password):
    return duckmail_provider.get_token(
        http_post,
        get_duckmail_api_base(),
        address,
        password,
    )


def get_messages(token):
    return duckmail_provider.get_messages(
        http_get,
        get_duckmail_api_base(),
        token,
    )


def get_message_detail(token, message_id):
    return duckmail_provider.get_message_detail(
        http_get,
        get_duckmail_api_base(),
        token,
        message_id,
    )



def cloudflare_get_domains(api_base, api_key=None):
    return cloudflare_provider.get_domains(
        http_get,
        api_base,
        domains_path=get_cloudflare_path("cloudflare_path_domains", "/domains"),
        api_key=api_key or get_cloudflare_api_key(),
        auth_mode=get_cloudflare_auth_mode(),
        custom_auth=get_cloudflare_custom_auth(),
    )


def cloudflare_create_account(api_base, address, password, api_key=None, expires_in=0):
    return cloudflare_provider.create_account(
        http_post,
        api_base,
        address,
        password,
        accounts_path=get_cloudflare_path("cloudflare_path_accounts", "/accounts"),
        api_key=api_key or get_cloudflare_api_key(),
        auth_mode=get_cloudflare_auth_mode(),
        custom_auth=get_cloudflare_custom_auth(),
        expires_in=expires_in,
    )


def cloudflare_get_token(api_base, address, password, api_key=None):
    return cloudflare_provider.get_token(
        http_post,
        api_base,
        address,
        password,
        token_path=get_cloudflare_path("cloudflare_path_token", "/token"),
        api_key=api_key or get_cloudflare_api_key(),
        auth_mode=get_cloudflare_auth_mode(),
        custom_auth=get_cloudflare_custom_auth(),
    )


def cloudflare_get_messages(api_base, token):
    return cloudflare_provider.get_messages(
        http_get,
        api_base,
        token,
        messages_path=get_cloudflare_path("cloudflare_path_messages", "/messages"),
        api_key=get_cloudflare_api_key(),
        auth_mode=get_cloudflare_auth_mode(),
        custom_auth=get_cloudflare_custom_auth(),
    )


def cloudflare_get_message_detail(api_base, token, message_id):
    return cloudflare_provider.get_message_detail(
        http_get,
        api_base,
        token,
        message_id,
        messages_path=get_cloudflare_path("cloudflare_path_messages", "/messages"),
        api_key=get_cloudflare_api_key(),
        auth_mode=get_cloudflare_auth_mode(),
        custom_auth=get_cloudflare_custom_auth(),
    )


YYDS_API_BASE = yyds_provider.API_BASE


def get_yyds_api_key():
    return config.get("yyds_api_key", "")


def get_yyds_jwt():
    return config.get("yyds_jwt", "")


def get_yyds_default_domain():
    return str(config.get("yyds_default_domain", "") or "").strip()


def yyds_get_domains(api_key=None, jwt=None):
    return yyds_provider.get_domains(http_get, api_key=api_key or get_yyds_api_key(), jwt=jwt or get_yyds_jwt())


def yyds_create_account(local_part=None, domain=None, api_key=None, jwt=None):
    return yyds_provider.create_account(
        http_post,
        local_part=local_part or "",
        domain=domain or "",
        api_key=api_key or get_yyds_api_key(),
        jwt=jwt or get_yyds_jwt(),
    )


def yyds_get_token(address, api_key=None, jwt=None):
    return yyds_provider.get_token(http_post, address, api_key=api_key or get_yyds_api_key(), jwt=jwt or get_yyds_jwt())


def yyds_get_messages(address, token=None, api_key=None, jwt=None):
    return yyds_provider.get_messages(
        http_get,
        address,
        token=token or "",
        api_key=api_key or get_yyds_api_key(),
        jwt=jwt or get_yyds_jwt(),
    )


def yyds_get_message_detail(message_id, token=None, api_key=None, jwt=None):
    return yyds_provider.get_message_detail(
        http_get,
        message_id,
        token=token or "",
        api_key=api_key or get_yyds_api_key(),
        jwt=jwt or get_yyds_jwt(),
    )


def yyds_generate_username(length=10):
    return yyds_provider.generate_username(length)


def yyds_pick_domain(api_key=None, jwt=None):
    return yyds_provider.pick_domain(http_get, api_key=api_key or get_yyds_api_key(), jwt=jwt or get_yyds_jwt())


def yyds_get_email_and_token(api_key=None, jwt=None, domain=""):
    key = api_key or get_yyds_api_key()
    token = jwt or get_yyds_jwt()
    if not token and not key:
        raise Exception("YYDS API Key 或 JWT 未配置")
    domain = (
        str(domain or "").strip()
        or get_yyds_default_domain()
        or yyds_pick_domain(api_key=key, jwt=token)
    )
    username = yyds_generate_username(10)
    result = yyds_create_account(
        local_part=username, domain=domain, api_key=key, jwt=token
    )
    address = result.get("address") or f"{username}@{domain}"
    temp_token = result.get("token")
    if not temp_token:
        temp_token = yyds_get_token(address, api_key=key, jwt=token)
    if not temp_token:
        raise Exception("获取 YYDS token 失败")
    print(f"[*] 已创建 YYDS 邮箱: {address}")
    return address, temp_token


def yyds_get_oai_code(token, address, timeout=180, poll_interval=3, log_callback=None, jwt=None, cancel_callback=None):
    return yyds_provider.wait_for_code(
        http_get,
        token,
        address,
        timeout=timeout,
        poll_interval=poll_interval,
        jwt=jwt or get_yyds_jwt(),
        raise_if_cancelled=raise_if_cancelled,
        sleep_with_cancel=sleep_with_cancel,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
    )



def generate_username(length=10):
    return _generate_username(length)


def pick_domain(api_key=None):
    return duckmail_provider.pick_domain(get_domains(api_key=api_key))


def get_cloudmail_url():
    return str(os.environ.get("CLOUDMAIL_URL") or config.get("cloudmail_url", "") or "").strip().rstrip("/")


def get_cloudmail_admin_email():
    return str(os.environ.get("CLOUDMAIL_ADMIN_EMAIL") or config.get("cloudmail_admin_email", "") or "").strip()


def get_cloudmail_password():
    return str(os.environ.get("CLOUDMAIL_PASSWORD") or config.get("cloudmail_password", "") or "")


def cloudmail_get_email_and_token(domain=""):
    selected_domain = str(domain or "").strip()
    if selected_domain:
        domains = [selected_domain]
    else:
        raw_domains = str(config.get("defaultDomains", "") or "")
        domains = [
            item.strip()
            for item in re.split(r"[,，\s]+", raw_domains)
            if item.strip()
        ]
    return cloudmail_provider.create_mailbox(
        http_post,
        get_cloudmail_url(),
        get_cloudmail_admin_email(),
        get_cloudmail_password(),
        domains,
        username=generate_username(10),
    )


def get_moemail_api_base():
    raw = (
        os.environ.get("MOEMAIL_API_BASE")
        or os.environ.get("MOEMAIL_API_URL")
        or config.get("moemail_api_base")
        or config.get("moemail_api_url")
        or ""
    )
    return moemail_provider.normalize_base(str(raw))


def get_moemail_api_key():
    return str(
        os.environ.get("MOEMAIL_API_KEY")
        or config.get("moemail_api_key", "")
        or ""
    ).strip()


def get_moemail_domain():
    return str(config.get("moemail_domain", "") or "").strip().lstrip("@")


def get_moemail_expiry_ms():
    raw = config.get("moemail_expiry_ms", moemail_provider.DEFAULT_EXPIRY_MS)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return moemail_provider.DEFAULT_EXPIRY_MS
    allowed = {0, 3_600_000, 86_400_000, 604_800_000}
    return value if value in allowed else moemail_provider.DEFAULT_EXPIRY_MS


def moemail_get_email_and_token(domain=""):
    # MoeMail owns its domain list. Do not reuse defaultDomains from another provider.
    return moemail_provider.create_mailbox(
        http_get,
        http_post,
        get_moemail_api_base(),
        get_moemail_api_key(),
        domain=str(domain or "").strip() or get_moemail_domain(),
        expiry_time=get_moemail_expiry_ms(),
    )


def moemail_get_oai_code(
    email_id,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
    resend_callback=None,
):
    return moemail_provider.wait_for_code(
        http_get,
        get_moemail_api_base(),
        get_moemail_api_key(),
        email_id,
        email=email,
        timeout=timeout,
        poll_interval=poll_interval,
        http_delete=http_delete,
        raise_if_cancelled=raise_if_cancelled,
        sleep_with_cancel=sleep_with_cancel,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
        resend_callback=resend_callback,
    )


def cloudmail_get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
    resend_callback=None,
):
    del dev_token
    return cloudmail_provider.wait_for_code(
        http_post,
        http_delete,
        get_cloudmail_url(),
        get_cloudmail_admin_email(),
        get_cloudmail_password(),
        email,
        timeout=timeout,
        poll_interval=poll_interval,
        raise_if_cancelled=raise_if_cancelled,
        sleep_with_cancel=sleep_with_cancel,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
        resend_callback=resend_callback,
    )


def get_email_provider():
    return str(config.get("email_provider", "cloudflare") or "cloudflare").strip().lower()


def _managed_domain_for_provider(provider: str) -> str:
    if provider not in _MANAGED_EMAIL_DOMAIN_PROVIDERS:
        return ""
    selection = _select_managed_email_domain(provider)
    if not selection.get("configured"):
        return ""
    domain = str(selection.get("domain") or "").strip()
    if domain:
        return domain
    label = _EMAIL_DOMAIN_PROVIDER_LABELS.get(provider, provider)
    raise RuntimeError(
        f"邮箱域名池没有可用的 {label} 域名，请在面板启用或重置域名"
    )


def _record_email_domain_accepted(email: str) -> str:
    provider = get_email_provider()
    if provider not in _MANAGED_EMAIL_DOMAIN_PROVIDERS:
        return ""
    try:
        _record_managed_email_domain_result(provider, email, "accepted")
    except Exception:
        pass
    return ""


def _record_email_domain_rejected(email: str, message: str = "") -> str:
    provider = get_email_provider()
    if provider not in _MANAGED_EMAIL_DOMAIN_PROVIDERS:
        return ""
    try:
        result = _record_managed_email_domain_result(
            provider,
            email,
            "rejected",
            message,
        )
    except Exception:
        return ""
    if not result.get("matched"):
        return ""
    count = result.get("consecutive_rejections", 0)
    threshold = result.get("failure_threshold", 0)
    if result.get("newly_blocked"):
        return f"域名池已自动拉黑（连续拒绝 {count}/{threshold}）"
    return f"域名池拒绝计数 {count}/{threshold}"


def get_email_and_token(api_key=None):
    provider = get_email_provider()
    managed_domain = _managed_domain_for_provider(provider)
    if provider == "yyds":
        return yyds_get_email_and_token(
            api_key=api_key,
            jwt=get_yyds_jwt(),
            domain=managed_domain,
        )
    if provider == "cloudmail":
        return cloudmail_get_email_and_token(domain=managed_domain)
    if provider == "moemail":
        return moemail_get_email_and_token(domain=managed_domain)
    if provider == "cloudflare":
        api_base = get_cloudflare_api_base()
        if not api_base:
            raise Exception("Cloudflare API Base 未配置")
        try:
            # cloudflare_temp_email 专用模式
            return cloudflare_create_temp_address(api_base, domain=managed_domain)
        except Exception as primary_exc:
            try:
                return cloudflare_provider.create_mailbox_fallback(
                    http_get,
                    http_post,
                    api_base,
                    domains_path=get_cloudflare_path("cloudflare_path_domains", "/domains"),
                    accounts_path=get_cloudflare_path("cloudflare_path_accounts", "/accounts"),
                    token_path=get_cloudflare_path("cloudflare_path_token", "/token"),
                    api_key=api_key or get_cloudflare_api_key(),
                    auth_mode=get_cloudflare_auth_mode(),
                    custom_auth=get_cloudflare_custom_auth(),
                    domain=managed_domain,
                    randomize_subdomain=cloudflare_randomize_subdomain_enabled(),
                )
            except Exception as fallback_exc:
                primary_message = redact_sensitive_log_line(str(primary_exc))[:240]
                fallback_message = redact_sensitive_log_line(str(fallback_exc))[:240]
                raise Exception(
                    "Cloudflare 创建邮箱失败: "
                    f"{primary_message} | fallback: {fallback_message}"
                ) from primary_exc
    if provider == "mailnest":
        return mailnest_buy_email(), "_"
    return duckmail_provider.create_mailbox(
        http_get,
        http_post,
        get_duckmail_api_base(),
        api_key=api_key or get_duckmail_api_key(),
        expires_in=0,
    )


def get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
    resend_callback=None,
):
    provider = get_email_provider()
    if provider == "yyds":
        return yyds_get_oai_code(
            dev_token,
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            jwt=get_yyds_jwt(),
            cancel_callback=cancel_callback,
        )
    if provider == "cloudmail":
        return cloudmail_get_oai_code(
            dev_token,
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            cancel_callback=cancel_callback,
            resend_callback=resend_callback,
        )
    if provider == "moemail":
        return moemail_get_oai_code(
            dev_token,
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            cancel_callback=cancel_callback,
            resend_callback=resend_callback,
        )
    if provider == "cloudflare":
        return cloudflare_get_oai_code(
            dev_token,
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            cancel_callback=cancel_callback,
            resend_callback=resend_callback,
        )
    if provider == "mailnest":
        return mailnest_get_code(
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            log_callback=log_callback,
            cancel_callback=cancel_callback,
        )
    return duckmail_get_oai_code(
        dev_token,
        email,
        timeout=timeout,
        poll_interval=poll_interval,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
    )



def extract_verification_code(text, subject=""):
    return _extract_code(text, subject)


def duckmail_get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
):
    return duckmail_provider.wait_for_code(
        http_get,
        get_duckmail_api_base(),
        dev_token,
        email,
        timeout=timeout,
        poll_interval=poll_interval,
        extract_code=extract_verification_code,
        raise_if_cancelled=raise_if_cancelled,
        sleep_with_cancel=sleep_with_cancel,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
    )


def cloudflare_get_oai_code(
    dev_token,
    email,
    timeout=180,
    poll_interval=3,
    log_callback=None,
    cancel_callback=None,
    resend_callback=None,
):
    return cloudflare_provider.wait_for_code(
        http_get,
        get_cloudflare_api_base(),
        dev_token,
        email,
        messages_path=get_cloudflare_path("cloudflare_path_messages", "/messages"),
        api_key=get_cloudflare_api_key(),
        auth_mode=get_cloudflare_auth_mode(),
        custom_auth=get_cloudflare_custom_auth(),
        timeout=timeout,
        poll_interval=poll_interval,
        raise_if_cancelled=raise_if_cancelled,
        sleep_with_cancel=sleep_with_cancel,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
        resend_callback=resend_callback,
    )


def generate_random_birthdate():
    import datetime as dt

    today = dt.date.today()
    age = random.randint(20, 40)
    birth_year = today.year - age
    birth_month = random.randint(1, 12)
    birth_day = random.randint(1, 28)
    return f"{birth_year}-{birth_month:02d}-{birth_day:02d}T16:00:00.000Z"


def response_preview(res, limit=200):
    """安全预览 HTTP 响应体；gRPC/二进制内容不直接当文本打印。"""
    try:
        headers = {str(k).lower(): str(v).lower() for k, v in dict(getattr(res, "headers", {}) or {}).items()}
        content_type = headers.get("content-type", "")
        raw = getattr(res, "content", None)
        if raw is None:
            try:
                raw = (res.text or "").encode("utf-8", errors="replace")
            except Exception:
                raw = b""
        if not isinstance(raw, (bytes, bytearray)):
            raw = str(raw).encode("utf-8", errors="replace")
        raw = bytes(raw)

        # gRPC / protobuf 常见 content-type 或正文以不可打印字节为主
        is_binaryish = (
            "grpc" in content_type
            or "protobuf" in content_type
            or "octet-stream" in content_type
            or (raw[:1] in (b"\x00", b"\x01") and b"grpc-status" in raw)
        )
        if is_binaryish or (raw and sum(1 for b in raw[:64] if b < 9 or (13 < b < 32)) > 8):
            # 尽量抽出可读的 trailer 片段（如 grpc-status:0）
            readable = re.findall(rb"[ -~]{3,}", raw)
            text = " ".join(part.decode("ascii", errors="ignore") for part in readable)
            text = re.sub(r"\s+", " ", text).strip()
            if not text:
                text = f"<binary {len(raw)} bytes>"
            return text[:limit]

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
        text = re.sub(r"\s+", " ", text).strip()
        return text[:limit]
    except Exception:
        return ""


def is_cloudflare_block_response(res):
    try:
        headers = {str(k).lower(): str(v).lower() for k, v in dict(res.headers).items()}
        text = str(res.text or "").lower()
        server = headers.get("server", "")
        content_type = headers.get("content-type", "")
        return (
            res.status_code in (403, 429, 503)
            and (
                "cloudflare" in server
                or "cloudflare" in text
                or "cf-error" in text
                or "__cf_chl" in text
                or "text/html" in content_type
            )
        )
    except Exception:
        return False


def set_birth_date(session, log_callback=None):
    url = "https://grok.com/rest/auth/set-birth-date"
    new_headers = {
        "content-type": "application/json",
        "origin": "https://grok.com",
        "referer": "https://grok.com/",
    }
    payload = {"birthDate": generate_random_birthdate()}
    try:
        res = session.post(url, json=payload, headers=new_headers, timeout=15)
        body_preview = response_preview(res)
        if log_callback:
            log_callback(
                f"[Debug] set_birth_date status: {res.status_code}, body: {body_preview}"
            )
        if 200 <= res.status_code < 300:
            return True, "ok"
        # 生日一旦写过就不能改；算已完成，不能当失败中断后续 NSFW
        text = str(res.text or "")
        if res.status_code in (400, 409, 429) and (
            "birth-date-change-limit-reached" in text
            or "Birth date is locked" in text
            or "already set" in text.lower()
        ):
            return True, "already_set"
        if is_cloudflare_block_response(res):
            return (
                False,
                "set_birth_date 被 grok.com 的 Cloudflare 防护拦截，HTTP "
                f"{res.status_code}",
            )
        return False, f"set_birth_date HTTP {res.status_code}: {body_preview}"
    except Exception as e:
        if log_callback:
            log_callback(f"[set_birth_date] 异常: {e}")
        return False, f"set_birth_date 异常: {e}"


def set_tos_accepted(session, log_callback=None):
    url = "https://accounts.x.ai/auth_mgmt.AuthManagement/SetTosAcceptedVersion"
    payload = struct.pack("B", (2 << 3) | 0) + struct.pack("B", 1)
    data = b"\x00" + struct.pack(">I", len(payload)) + payload
    new_headers = {
        "content-type": "application/grpc-web+proto",
        "x-grpc-web": "1",
        "x-user-agent": "connect-es/2.1.1",
        "origin": "https://accounts.x.ai",
        "referer": "https://accounts.x.ai/accept-tos",
    }
    try:
        res = session.post(url, data=data, headers=new_headers, timeout=15)
        if log_callback:
            log_callback(f"[Debug] set_tos_accepted status: {res.status_code}")
        if 200 <= res.status_code < 300:
            return True, "ok"
        if is_cloudflare_block_response(res):
            return (
                False,
                "set_tos_accepted 被 accounts.x.ai 的 Cloudflare 防护拦截，HTTP "
                f"{res.status_code}",
            )
        return False, f"set_tos_accepted HTTP {res.status_code}: {response_preview(res)}"
    except Exception as e:
        if log_callback:
            log_callback(f"[set_tos_accepted] 异常: {e}")
        return False, f"set_tos_accepted 异常: {e}"


def encode_grpc_nsfw_settings():
    field1_content = bytes([0x10, 0x01])
    field1 = bytes([0x0A, len(field1_content)]) + field1_content
    nsfw_string = b"always_show_nsfw_content"
    field2_inner = bytes([0x0A, len(nsfw_string)]) + nsfw_string
    field2 = bytes([0x12, len(field2_inner)]) + field2_inner
    payload = field1 + field2
    return b"\x00" + struct.pack(">I", len(payload)) + payload


def update_nsfw_settings(session, log_callback=None):
    url = "https://grok.com/auth_mgmt.AuthManagement/UpdateUserFeatureControls"
    data = encode_grpc_nsfw_settings()
    new_headers = {
        "content-type": "application/grpc-web+proto",
        "x-grpc-web": "1",
        "origin": "https://grok.com",
        "referer": "https://grok.com/",
    }
    try:
        res = session.post(url, data=data, headers=new_headers, timeout=15)
        if log_callback:
            log_callback(
                f"[Debug] update_nsfw status: {res.status_code}, body: {response_preview(res)}"
            )
        if 200 <= res.status_code < 300:
            return True, "ok"
        if is_cloudflare_block_response(res):
            return (
                False,
                "update_nsfw_settings 被 grok.com 的 Cloudflare 防护拦截，HTTP "
                f"{res.status_code}",
            )
        return False, f"update_nsfw_settings HTTP {res.status_code}: {response_preview(res)}"
    except Exception as e:
        if log_callback:
            log_callback(f"[update_nsfw] 异常: {e}")
        return False, f"update_nsfw_settings 异常: {e}"


def enable_nsfw_via_browser(token="", log_callback=None):
    """在已登录的注册浏览器内调用 grok.com 接口，绕过外部 HTTP 的 CF 拦截。"""
    page_obj = _active_page()
    if page_obj is None:
        return False, "浏览器页面未就绪"

    birth = generate_random_birthdate()
    nsfw_bytes = encode_grpc_nsfw_settings()
    nsfw_b64 = base64.b64encode(nsfw_bytes).decode("ascii")

    try:
        if log_callback:
            log_callback("[*] 浏览器内开启 NSFW：打开 grok.com ...")
        # 确保 SSO cookie 在浏览器上下文中
        if token:
            try:
                page_obj.set.cookies(
                    [
                        {"name": "sso", "value": token, "domain": ".x.ai", "path": "/"},
                        {"name": "sso-rw", "value": token, "domain": ".x.ai", "path": "/"},
                        {"name": "sso", "value": token, "domain": ".grok.com", "path": "/"},
                        {"name": "sso-rw", "value": token, "domain": ".grok.com", "path": "/"},
                    ]
                )
            except Exception:
                try:
                    page_obj.run_js(
                        """
const token = arguments[0];
document.cookie = 'sso=' + token + '; path=/; domain=.grok.com';
document.cookie = 'sso-rw=' + token + '; path=/; domain=.grok.com';
                        """,
                        token,
                    )
                except Exception:
                    pass
        page_obj.get("https://grok.com/")
        try:
            page_obj.wait.doc_loaded()
        except Exception:
            pass
        # 等 CF 挑战结束，否则 fetch 也会拿到 Just a moment
        for i in range(25):
            try:
                title = str(page_obj.run_js("return document.title || '';") or "").lower()
                body = str(
                    page_obj.run_js(
                        "return (document.body && (document.body.innerText||'')) || '';"
                    )
                    or ""
                ).lower()
                if "just a moment" not in title and "just a moment" not in body[:200]:
                    if "checking your browser" not in body[:300]:
                        break
            except Exception:
                pass
            time.sleep(1.0)
        else:
            if log_callback:
                log_callback("[!] grok.com 仍停在 Cloudflare 挑战页，浏览器内 NSFW 可能失败")
        time.sleep(1.0)

        result = page_obj.run_js(
            r"""
const birthDate = arguments[0];
const nsfwB64 = arguments[1];
function b64ToBytes(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}
return (async () => {
  const out = { birthStatus: 0, birthBody: '', nsfwStatus: 0, nsfwBody: '', url: location.href };
  try {
    const birthRes = await fetch('https://grok.com/rest/auth/set-birth-date', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'content-type': 'application/json',
        'origin': 'https://grok.com',
        'referer': 'https://grok.com/',
      },
      body: JSON.stringify({ birthDate }),
    });
    out.birthStatus = birthRes.status;
    out.birthBody = (await birthRes.text()).slice(0, 240);
  } catch (e) {
    out.birthBody = String(e);
  }
  const birthOk = (out.birthStatus >= 200 && out.birthStatus < 300)
    || /birth-date-change-limit-reached|Birth date is locked|already set/i.test(out.birthBody || '');
  if (!birthOk && out.birthStatus !== 0) {
    return out;
  }
  try {
    const body = b64ToBytes(nsfwB64);
    const nsfwRes = await fetch('https://grok.com/auth_mgmt.AuthManagement/UpdateUserFeatureControls', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'content-type': 'application/grpc-web+proto',
        'x-grpc-web': '1',
        'origin': 'https://grok.com',
        'referer': 'https://grok.com/',
      },
      body,
    });
    out.nsfwStatus = nsfwRes.status;
    out.nsfwBody = (await nsfwRes.text()).slice(0, 240);
  } catch (e) {
    out.nsfwBody = String(e);
  }
  return out;
})();
            """,
            birth,
            nsfw_b64,
        )
        if not isinstance(result, dict):
            return False, f"浏览器 NSFW 返回异常: {result!r}"

        if log_callback:
            log_callback(
                f"[Debug] browser NSFW birth={result.get('birthStatus')} "
                f"nsfw={result.get('nsfwStatus')} body={str(result.get('birthBody') or '')[:120]}"
            )

        birth_status = int(result.get("birthStatus") or 0)
        birth_body = str(result.get("birthBody") or "")
        birth_ok = (200 <= birth_status < 300) or (
            birth_status in (400, 409, 429)
            and (
                "birth-date-change-limit-reached" in birth_body
                or "Birth date is locked" in birth_body
                or "already set" in birth_body.lower()
            )
        )
        if not birth_ok:
            if "just a moment" in birth_body.lower() or birth_status == 403:
                return False, f"浏览器内 set_birth_date 仍被 CF 拦截 HTTP {birth_status}"
            return False, f"浏览器内 set_birth_date HTTP {birth_status}: {birth_body[:160]}"

        nsfw_status = int(result.get("nsfwStatus") or 0)
        nsfw_body = str(result.get("nsfwBody") or "")
        if 200 <= nsfw_status < 300:
            return True, "成功开启 NSFW（浏览器内）"
        if "just a moment" in nsfw_body.lower() or nsfw_status == 403:
            return False, f"浏览器内 update_nsfw 被 CF 拦截 HTTP {nsfw_status}"
        return False, f"浏览器内 update_nsfw HTTP {nsfw_status}: {nsfw_body[:160]}"
    except Exception as exc:
        if log_callback:
            log_callback(
                f"[Debug] 浏览器内 NSFW 异常: {redact_sensitive_log_line(str(exc))}"
            )
        return False, f"浏览器内 NSFW 异常: {redact_sensitive_log_line(str(exc))}"


def enable_nsfw_for_token(token, cf_clearance="", user_agent="", log_callback=None):
    proxies = get_proxies()
    ua = user_agent or get_user_agent()
    if log_callback:
        log_callback(
            f"[Debug] NSFW 准备: cf_clearance={'有' if cf_clearance else '无'} | ua_len={len(ua)} | browser={'有' if _active_page() else '无'}"
        )

    # 有活动浏览器时直接走浏览器路径（HTTP 快速路径会被 accounts.x.ai Cloudflare 拦截）
    if _active_page() is not None:
        if log_callback:
            log_callback("[*] NSFW 通过浏览器执行...")
        return enable_nsfw_via_browser(token=token, log_callback=log_callback)

    # 无活动浏览器时尝试 HTTP 快速路径
    def _browser_fallback(reason):
        if _active_page() is None:
            return False, reason
        if log_callback:
            log_callback(f"[*] NSFW HTTP 快速路径未成功: {reason}，回退浏览器过盾...")
        ok, message = enable_nsfw_via_browser(token=token, log_callback=log_callback)
        if ok:
            return True, message
        return False, f"{reason}; browser fallback: {message}"

    try:
        if log_callback:
            log_callback("[*] NSFW 先尝试 HTTP 快速路径...")
        with requests.Session(impersonate="chrome120", proxies=proxies) as session:
            cookie_parts = [f"sso={token}", f"sso-rw={token}"]
            if cf_clearance:
                cookie_parts.append(f"cf_clearance={cf_clearance}")
            session.headers.update(
                {
                    "user-agent": ua,
                    "cookie": "; ".join(cookie_parts),
                    "accept": "application/json, text/plain, */*",
                    "accept-language": "en-US,en;q=0.9",
                }
            )
            ok, message = set_tos_accepted(session, log_callback)
            if not ok:
                return _browser_fallback(message)
            ok, message = set_birth_date(session, log_callback)
            if not ok:
                return _browser_fallback(message)
            ok, message = update_nsfw_settings(session, log_callback)
            if not ok:
                return _browser_fallback(message)
            return True, "成功开启 NSFW（HTTP 快速路径）"
    except Exception as e:
        return _browser_fallback(f"HTTP 快速路径异常: {e}")


# browser session state -> browser_session

def setup_light_theme(root):
    try:
        root.option_add("*Background", UI_BG)
        root.option_add("*Foreground", UI_FG)
        root.option_add("*selectBackground", UI_ACTIVE_BG)
        root.option_add("*selectForeground", UI_FG)
        root.option_add("*insertBackground", UI_FG)
        root.option_add("*Entry.Background", UI_ENTRY_BG)
        root.option_add("*Text.Background", UI_ENTRY_BG)
        root.option_add("*Menu.Background", UI_ENTRY_BG)
        root.option_add("*Menu.Foreground", UI_FG)
        style = ttk.Style(root)
        available = set(style.theme_names())
        if "clam" in available:
            style.theme_use("clam")
        elif "default" in available:
            style.theme_use("default")
        root.configure(bg=UI_BG)
        style.configure(".", background=UI_BG, foreground=UI_FG, fieldbackground=UI_ENTRY_BG)
        style.configure("TFrame", background=UI_BG)
        style.configure("TLabelframe", background=UI_BG, foreground=UI_FG)
        style.configure("TLabelframe.Label", background=UI_BG, foreground=UI_FG)
        style.configure("TLabel", background=UI_BG, foreground=UI_FG)
        style.configure("TCheckbutton", background=UI_BG, foreground=UI_FG)
        style.configure("TButton", background=UI_BUTTON_BG, foreground=UI_FG)
        style.configure("TEntry", fieldbackground=UI_ENTRY_BG, foreground=UI_FG)
        style.configure("TCombobox", fieldbackground=UI_ENTRY_BG, foreground=UI_FG)
        style.configure("TSpinbox", fieldbackground=UI_ENTRY_BG, foreground=UI_FG)
    except Exception:
        pass


def tk_label(parent, text="", **kwargs):
    return tk.Label(parent, text=text, bg=kwargs.pop("bg", UI_BG), fg=kwargs.pop("fg", UI_FG), **kwargs)


def tk_entry(parent, textvariable=None, width=30, **kwargs):
    return tk.Entry(
        parent,
        textvariable=textvariable,
        width=width,
        bg=UI_ENTRY_BG,
        fg=UI_FG,
        insertbackground=UI_FG,
        disabledbackground="#2f2f2f",
        disabledforeground=UI_MUTED_FG,
        highlightthickness=1,
        highlightbackground="#555555",
        relief=tk.SOLID,
        **kwargs,
    )


def tk_button(parent, text="", command=None, state=tk.NORMAL, **kwargs):
    return tk.Button(
        parent,
        text=text,
        command=command,
        state=state,
        bg=UI_BUTTON_BG,
        fg=UI_FG,
        activebackground=UI_ACTIVE_BG,
        activeforeground=UI_FG,
        disabledforeground="#777777",
        relief=tk.RAISED,
        padx=10,
        pady=3,
        **kwargs,
    )


def tk_checkbutton(parent, text="", variable=None, **kwargs):
    return tk.Checkbutton(
        parent,
        text=text,
        variable=variable,
        bg=UI_BG,
        fg=UI_FG,
        activebackground=UI_BG,
        activeforeground=UI_FG,
        selectcolor="#3d7be0",
        **kwargs,
    )


def tk_option_menu(parent, variable, values, width=12):
    menu = tk.OptionMenu(parent, variable, *values)
    menu.configure(
        width=width,
        bg=UI_ENTRY_BG,
        fg=UI_FG,
        activebackground=UI_ACTIVE_BG,
        activeforeground=UI_FG,
        highlightthickness=1,
        highlightbackground="#555555",
        relief=tk.SOLID,
    )
    menu["menu"].configure(bg=UI_ENTRY_BG, fg=UI_FG, activebackground=UI_ACTIVE_BG, activeforeground=UI_FG)
    return menu

def is_debug_mode():
    return bool(config.get("debug_mode", False))


def should_close_browser_after_run(user_stopped: bool) -> bool:
    """正常结束默认关浏览器；用户主动停止时由 close_browser_on_stop 控制。调试模式始终保留。"""
    if is_debug_mode():
        return False
    if user_stopped and not config.get("close_browser_on_stop", False):
        return False
    return True


def maybe_stop_browser(user_stopped: bool = False, log_callback=None):
    if should_close_browser_after_run(user_stopped):
        stop_browser()
        return
    if log_callback and user_stopped:
        log_callback("[*] 用户停止：已保留浏览器（勾选「停止时关闭浏览器」可改为关闭）")


def get_log_level() -> str:
    level = str(config.get("log_level", "info") or "info").strip().lower()
    return level if level in ("info", "debug") else "info"


def should_emit_log(message: str) -> bool:
    """info 级别过滤 [Debug] 行；debug 全开。"""
    if get_log_level() == "debug":
        return True
    text = str(message or "")
    if text.lstrip().startswith("[Debug]") or " [Debug] " in text:
        return False
    return True


def _wire_runtime_modules():
    """把主模块依赖注入到 browser_session / register_flow。"""
    _bs.configure(
        get_proxies=get_proxies,
        is_debug=is_debug_mode,
        extension_path=EXTENSION_PATH,
    )
    _rf.configure(
        get_email_and_token=get_email_and_token,
        get_oai_code=get_oai_code,
        on_email_accepted=_record_email_domain_accepted,
        on_email_domain_rejected=_record_email_domain_rejected,
        raise_if_cancelled=raise_if_cancelled,
        sleep_with_cancel=sleep_with_cancel,
        RegistrationCancelled=RegistrationCancelled,
        EmailDomainRejected=EmailDomainRejected,
        AccountRetryNeeded=AccountRetryNeeded,
    )

# register page flow -> register_flow

class GrokRegisterGUI:
    def __init__(self, root):
        self.root = root
        self._ui_thread_id = threading.get_ident()
        self.root.title("Grok 注册机")
        self.root.geometry("1120x900")
        self.root.minsize(960, 700)
        self.is_running = False
        self.batch_count = 0
        self.success_count = 0
        self.fail_count = 0
        self.results = []
        self.stop_requested = False
        self.ui_queue = queue.Queue()
        self.accounts_output_file = ""
        self.setup_ui()
        self.root.after(50, self._drain_ui_queue)

    def _queue_ui_call(self, callback, *args):
        if threading.get_ident() == self._ui_thread_id:
            return False
        self.ui_queue.put((callback, args))
        return True

    def _drain_ui_queue(self):
        while True:
            try:
                callback, args = self.ui_queue.get_nowait()
            except queue.Empty:
                break
            try:
                callback(*args)
            except (tk.TclError, RuntimeError):
                pass
        try:
            self.root.after(50, self._drain_ui_queue)
        except (tk.TclError, RuntimeError):
            pass

    def setup_ui(self):
        load_config()
        _wire_runtime_modules()
        main_frame = tk.Frame(self.root, bg=UI_BG, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(3, weight=1)

        config_frame = tk.LabelFrame(
            main_frame,
            text="配置",
            bg=UI_PANEL_BG,
            fg=UI_FG,
            padx=10,
            pady=10,
            relief=tk.GROOVE,
            borderwidth=1,
        )
        config_frame.grid(row=0, column=0, sticky=tk.EW, pady=(0, 8))
        config_frame.grid_columnconfigure(1, weight=1, minsize=260)
        config_frame.grid_columnconfigure(3, weight=1, minsize=260)

        def add_label(row, column, text):
            tk_label(config_frame, text=text, bg=UI_PANEL_BG).grid(
                row=row,
                column=column,
                sticky=tk.W,
                padx=(0, 6),
                pady=3,
            )

        def add_field(widget, row, column, columnspan=1, sticky=tk.EW):
            widget.grid(
                row=row,
                column=column,
                columnspan=columnspan,
                sticky=sticky,
                padx=(0, 14),
                pady=3,
            )

        # 公共配置
        add_label(0, 0, "邮箱服务商:")
        self.email_provider_var = tk.StringVar(value=config.get("email_provider", "cloudflare"))
        self.email_provider_combo = tk_option_menu(
            config_frame,
            self.email_provider_var,
            ["duckmail", "yyds", "cloudflare", "mailnest", "cloudmail", "moemail"],
            width=12,
        )
        add_field(self.email_provider_combo, 0, 1, sticky=tk.W)

        add_label(0, 2, "注册数量:")
        self.count_var = tk.StringVar(value=str(config.get("register_count", 1)))
        self.count_spinbox = tk.Spinbox(
            config_frame,
            from_=1,
            to=2500,
            width=8,
            textvariable=self.count_var,
            bg=UI_ENTRY_BG,
            fg=UI_FG,
            insertbackground=UI_FG,
            buttonbackground=UI_BUTTON_BG,
            disabledbackground="#2f2f2f",
            disabledforeground=UI_MUTED_FG,
            relief=tk.SOLID,
        )
        add_field(self.count_spinbox, 0, 3, sticky=tk.W)

        add_label(1, 0, "注册选项:")
        opt_frame = tk.Frame(config_frame, bg=UI_PANEL_BG)
        add_field(opt_frame, 1, 1, sticky=tk.W)
        self.nsfw_var = tk.BooleanVar(value=config.get("enable_nsfw", True))
        self.nsfw_check = tk_checkbutton(opt_frame, text="注册后开启 NSFW（可选）", variable=self.nsfw_var)
        self.nsfw_check.pack(side=tk.LEFT)
        self.debug_mode_var = tk.BooleanVar(value=bool(config.get("debug_mode", False)))
        self.debug_mode_check = tk_checkbutton(
            opt_frame, text="调试模式（可选）", variable=self.debug_mode_var
        )
        self.debug_mode_check.pack(side=tk.LEFT, padx=(12, 0))
        self.log_level_var = tk.StringVar(value=str(config.get("log_level", "info") or "info"))
        tk_label(opt_frame, text="日志:", bg=UI_PANEL_BG).pack(side=tk.LEFT, padx=(12, 2))
        self.log_level_combo = tk_option_menu(opt_frame, self.log_level_var, ["info", "debug"], width=6)
        self.log_level_combo.pack(side=tk.LEFT)

        add_label(1, 2, "代理（可选）:")
        self.proxy_var = tk.StringVar(value=config.get("proxy", ""))
        self.proxy_entry = tk_entry(config_frame, textvariable=self.proxy_var, width=34)
        add_field(self.proxy_entry, 1, 3)

        # 服务商专属配置（按选择显示）
        self.provider_frame = tk.LabelFrame(
            config_frame,
            text="邮箱服务商配置",
            bg=UI_PANEL_BG,
            fg=UI_FG,
            padx=8,
            pady=6,
            relief=tk.GROOVE,
            borderwidth=1,
        )
        self.provider_frame.grid(row=2, column=0, columnspan=4, sticky=tk.EW, pady=(6, 4))
        self.provider_frame.grid_columnconfigure(1, weight=1, minsize=240)
        self.provider_frame.grid_columnconfigure(3, weight=1, minsize=240)

        def p_label(row, column, text):
            w = tk_label(self.provider_frame, text=text, bg=UI_PANEL_BG)
            w.grid(row=row, column=column, sticky=tk.W, padx=(0, 6), pady=3)
            return w

        def p_field(widget, row, column, columnspan=1, sticky=tk.EW):
            widget.grid(
                row=row,
                column=column,
                columnspan=columnspan,
                sticky=sticky,
                padx=(0, 14),
                pady=3,
            )
            return widget

        # DuckMail / Mail.tm
        self.api_key_var = tk.StringVar(value=config.get("duckmail_api_key", ""))
        self.duckmail_api_base_var = tk.StringVar(
            value=str(config.get("duckmail_api_base", "") or DUCKMAIL_API_BASE_DEFAULT)
        )
        self._duckmail_widgets = [
            p_label(0, 0, "API Base（可选）:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.duckmail_api_base_var, width=52), 0, 1, columnspan=3),
            p_label(1, 0, "API Key（可选）:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.api_key_var, width=34), 1, 1),
            p_label(1, 2, "说明:"),
            p_field(
                tk_label(
                    self.provider_frame,
                    text="Mail.tm 填 https://api.mail.tm；公共域可不填 Key",
                    bg=UI_PANEL_BG,
                ),
                1,
                3,
                sticky=tk.W,
            ),
        ]

        # Cloudflare
        self.cloudflare_auth_mode_var = tk.StringVar(value=config.get("cloudflare_auth_mode", "none"))
        self.cloudflare_api_base_var = tk.StringVar(value=config.get("cloudflare_api_base", ""))
        self.cloudflare_api_key_var = tk.StringVar(value=config.get("cloudflare_api_key", ""))
        self.cloudflare_paths_var = tk.StringVar(
            value=",".join(
                [
                    config.get("cloudflare_path_domains", "/api/domains"),
                    config.get("cloudflare_path_accounts", "/api/new_address"),
                    config.get("cloudflare_path_token", "/api/token"),
                    config.get("cloudflare_path_messages", "/api/mails"),
                ]
            )
        )
        self.default_domains_var = tk.StringVar(value=str(config.get("defaultDomains", "")))
        self.cloudflare_custom_auth_var = tk.StringVar(value=str(config.get("cloudflare_custom_auth", "")))
        self._cloudflare_widgets = [
            p_label(0, 0, "API Base:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.cloudflare_api_base_var, width=52), 0, 1, columnspan=3),
            p_label(1, 0, "鉴权模式（可选）:"),
            p_field(
                tk_option_menu(
                    self.provider_frame,
                    self.cloudflare_auth_mode_var,
                    ["query-key", "bearer", "x-api-key", "x-admin-auth", "none"],
                    width=12,
                ),
                1,
                1,
                sticky=tk.W,
            ),
            p_label(1, 2, "API Key（可选）:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.cloudflare_api_key_var, width=34), 1, 3),
            p_label(2, 0, "收信域名（可选）:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.default_domains_var, width=34), 2, 1),
            p_label(2, 2, "全局密码（可选）:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.cloudflare_custom_auth_var, width=34), 2, 3),
            p_label(3, 0, "CF 路径（可选）:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.cloudflare_paths_var, width=52), 3, 1, columnspan=3),
        ]

        # YYDS
        self.yyds_api_key_var = tk.StringVar(value=str(config.get("yyds_api_key", "")))
        self.yyds_jwt_var = tk.StringVar(value=str(config.get("yyds_jwt", "")))
        self.yyds_default_domain_var = tk.StringVar(value=str(config.get("yyds_default_domain", "")))
        self._yyds_widgets = [
            p_label(0, 0, "API Key（可选）:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.yyds_api_key_var, width=34), 0, 1),
            p_label(0, 2, "JWT（可选）:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.yyds_jwt_var, width=34), 0, 3),
            p_label(1, 0, "固定收信域名（可选）:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.yyds_default_domain_var, width=34), 1, 1),
            p_label(1, 2, "说明:"),
            p_field(
                tk_label(self.provider_frame, text="Key/JWT 二选一；域名留空则自动选", bg=UI_PANEL_BG),
                1,
                3,
                sticky=tk.W,
            ),
        ]

        # MailNest
        self.mailnest_api_key_var = tk.StringVar(value=str(config.get("mailnest_api_key", "")))
        self.mailnest_project_code_var = tk.StringVar(
            value=str(config.get("mailnest_project_code", MAILNEST_DEFAULT_PROJECT_CODE) or MAILNEST_DEFAULT_PROJECT_CODE)
        )
        self._mailnest_widgets = [
            p_label(0, 0, "API Key:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.mailnest_api_key_var, width=34), 0, 1),
            p_label(0, 2, "项目代码（可选）:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.mailnest_project_code_var, width=34), 0, 3),
        ]

        # CloudMail
        self.cloudmail_url_var = tk.StringVar(value=str(config.get("cloudmail_url", "")))
        self.cloudmail_admin_email_var = tk.StringVar(value=str(config.get("cloudmail_admin_email", "")))
        self.cloudmail_password_var = tk.StringVar(value=str(config.get("cloudmail_password", "")))
        # CloudMail 也用 defaultDomains；与 CF 共用变量即可
        self._cloudmail_widgets = [
            p_label(0, 0, "站点 URL:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.cloudmail_url_var, width=52), 0, 1, columnspan=3),
            p_label(1, 0, "管理员邮箱:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.cloudmail_admin_email_var, width=34), 1, 1),
            p_label(1, 2, "管理员密码:"),
            p_field(
                tk_entry(self.provider_frame, textvariable=self.cloudmail_password_var, width=34, show="*"),
                1,
                3,
            ),
            p_label(2, 0, "收信域名:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.default_domains_var, width=34), 2, 1),
            p_label(2, 2, "说明:"),
            p_field(
                tk_label(self.provider_frame, text="多个域名用逗号分隔", bg=UI_PANEL_BG),
                2,
                3,
                sticky=tk.W,
            ),
        ]

        # MoeMail
        self.moemail_api_base_var = tk.StringVar(
            value=str(
                config.get("moemail_api_base")
                or config.get("moemail_api_url")
                or ""
            )
        )
        self.moemail_api_key_var = tk.StringVar(
            value=str(config.get("moemail_api_key", "") or "")
        )
        self.moemail_domain_var = tk.StringVar(
            value=str(config.get("moemail_domain", "") or "")
        )
        self.moemail_expiry_ms_var = tk.StringVar(
            value=str(
                config.get("moemail_expiry_ms", moemail_provider.DEFAULT_EXPIRY_MS)
            )
        )
        self._moemail_widgets = [
            p_label(0, 0, "站点 URL:"),
            p_field(
                tk_entry(self.provider_frame, textvariable=self.moemail_api_base_var, width=52),
                0,
                1,
                columnspan=3,
            ),
            p_label(1, 0, "API Key:"),
            p_field(
                tk_entry(self.provider_frame, textvariable=self.moemail_api_key_var, width=34, show="*"),
                1,
                1,
            ),
            p_label(1, 2, "固定域名（可选）:"),
            p_field(tk_entry(self.provider_frame, textvariable=self.moemail_domain_var, width=34), 1, 3),
            p_label(2, 0, "有效期:"),
            p_field(
                tk_option_menu(
                    self.provider_frame,
                    self.moemail_expiry_ms_var,
                    ["3600000", "86400000", "604800000", "0"],
                    width=12,
                ),
                2,
                1,
                sticky=tk.W,
            ),
            p_label(2, 2, "说明:"),
            p_field(
                tk_label(
                    self.provider_frame,
                    text="域名留空时自动读取 /api/config",
                    bg=UI_PANEL_BG,
                ),
                2,
                3,
                sticky=tk.W,
            ),
        ]

        self._provider_widget_groups = {
            "duckmail": self._duckmail_widgets,
            "cloudflare": self._cloudflare_widgets,
            "yyds": self._yyds_widgets,
            "mailnest": self._mailnest_widgets,
            "cloudmail": self._cloudmail_widgets,
            "moemail": self._moemail_widgets,
        }

        add_label(3, 0, "并发数（可选）:")
        self.workers_var = tk.StringVar(value=str(config.get("register_workers", 1)))
        self.workers_spinbox = tk.Spinbox(
            config_frame,
            from_=1,
            to=8,
            width=8,
            textvariable=self.workers_var,
            bg=UI_ENTRY_BG,
            fg=UI_FG,
            insertbackground=UI_FG,
            buttonbackground=UI_BUTTON_BG,
            disabledbackground="#2f2f2f",
            disabledforeground=UI_MUTED_FG,
            relief=tk.SOLID,
        )
        add_field(self.workers_spinbox, 3, 1, sticky=tk.W)

        add_label(3, 2, "账号间隔（秒）:")
        self.account_interval_var = tk.StringVar(
            value=str(config.get("account_interval", "60-120") or "60-120")
        )
        add_field(
            tk_entry(config_frame, textvariable=self.account_interval_var, width=20),
            3,
            3,
        )

        # SSO → CPA auth 可选
        self.cpa_frame = tk.LabelFrame(
            config_frame,
            text="SSO → CPA auth（可选）",
            bg=UI_PANEL_BG,
            fg=UI_FG,
            padx=8,
            pady=6,
            relief=tk.GROOVE,
            borderwidth=1,
        )
        self.cpa_frame.grid(row=4, column=0, columnspan=4, sticky=tk.EW, pady=(6, 2))
        self.cpa_frame.grid_columnconfigure(1, weight=1, minsize=240)
        self.cpa_frame.grid_columnconfigure(3, weight=1, minsize=240)

        self.cpa_auto_add_var = tk.BooleanVar(value=bool(config.get("cpa_auto_add", False)))
        tk_checkbutton(
            self.cpa_frame,
            text="开启后注册成功：SSO 换 token，写入 CPA / Grok2API（不勾选则只保存 SSO）",
            variable=self.cpa_auto_add_var,
        ).grid(row=0, column=0, columnspan=4, sticky=tk.W, pady=3)

        self._cpa_detail_widgets = []
        def c_label(row, col, text):
            w = tk_label(self.cpa_frame, text=text, bg=UI_PANEL_BG)
            w.grid(row=row, column=col, sticky=tk.W, padx=(0, 6), pady=3)
            self._cpa_detail_widgets.append(w)
            return w

        def c_field(widget, row, col, columnspan=1, sticky=tk.EW):
            widget.grid(row=row, column=col, columnspan=columnspan, sticky=sticky, padx=(0, 14), pady=3)
            self._cpa_detail_widgets.append(widget)
            return widget

        # Token 换取方式选择
        _cur_mode = str(config.get("cpa_token_mode", "device_protocol") or "device_protocol")
        _mode_display = {
            "device_protocol": "协议 Device Flow",
            "device_browser": "浏览器 Device Flow",
            "auth_code": "Authorization Code",
        }.get(_cur_mode, "协议 Device Flow")
        self.cpa_token_mode_var = tk.StringVar(value=_mode_display)
        c_label(1, 0, "Token 换取:")
        token_mode_menu = tk_option_menu(
            self.cpa_frame,
            self.cpa_token_mode_var,
            ["协议 Device Flow", "浏览器 Device Flow", "Authorization Code"],
            width=20,
        )
        c_field(token_mode_menu, 1, 1)
        c_label(1, 2, "（默认协议换 token；浏览器模式需活动浏览器）")

        self.cpa_auth_dir_var = tk.StringVar(value=str(config.get("cpa_auth_dir", "")))
        self.cpa_remote_url_var = tk.StringVar(value=str(config.get("cpa_remote_url", "")))
        self.cpa_management_key_var = tk.StringVar(value=str(config.get("cpa_management_key", "")))
        self.grok2api_auth_dir_var = tk.StringVar(value=str(config.get("grok2api_auth_dir", "")))
        c_label(2, 0, "CPA auth 目录:")
        c_field(tk_entry(self.cpa_frame, textvariable=self.cpa_auth_dir_var, width=52), 2, 1, columnspan=3)
        c_label(3, 0, "远程地址:")
        c_field(tk_entry(self.cpa_frame, textvariable=self.cpa_remote_url_var, width=34), 3, 1)
        c_label(3, 2, "管理密钥:")
        c_field(tk_entry(self.cpa_frame, textvariable=self.cpa_management_key_var, width=28), 3, 3)
        c_label(4, 0, "Grok2API 目录:")
        c_field(tk_entry(self.cpa_frame, textvariable=self.grok2api_auth_dir_var, width=52), 4, 1, columnspan=3)

        self.email_provider_var.trace_add("write", lambda *_: self._refresh_provider_fields())
        self.cpa_auto_add_var.trace_add("write", lambda *_: self._refresh_cpa_fields())
        self._refresh_provider_fields()
        self._refresh_cpa_fields()

        btn_frame = tk.Frame(main_frame, bg=UI_BG)
        btn_frame.grid(row=1, column=0, sticky=tk.EW, pady=(0, 6))
        self.start_btn = tk_button(btn_frame, text="开始注册", command=self.start_registration)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = tk_button(btn_frame, text="停止", command=self.stop_registration, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        self.close_browser_on_stop_var = tk.BooleanVar(
            value=bool(config.get("close_browser_on_stop", False))
        )
        self.close_browser_on_stop_check = tk_checkbutton(
            btn_frame,
            text="停止时关闭浏览器",
            variable=self.close_browser_on_stop_var,
        )
        self.close_browser_on_stop_check.pack(side=tk.LEFT, padx=(2, 8))
        self.check_btn = tk_button(btn_frame, text="连通性检查", command=self.run_connectivity_check)
        self.check_btn.pack(side=tk.LEFT, padx=5)
        self.clear_btn = tk_button(btn_frame, text="清空日志", command=self.clear_log)
        self.clear_btn.pack(side=tk.LEFT, padx=5)

        status_frame = tk.Frame(main_frame, bg=UI_BG)
        status_frame.grid(row=2, column=0, sticky=tk.EW, pady=(0, 6))
        self.status_var = tk.StringVar(value="就绪")
        tk_label(status_frame, text="状态: ").pack(side=tk.LEFT)
        self.status_label = tk.Label(status_frame, textvariable=self.status_var, bg=UI_BG, fg="green")
        self.status_label.pack(side=tk.LEFT)
        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_bar = ttk.Progressbar(
            status_frame, variable=self.progress_var, maximum=100, length=180, mode="determinate"
        )
        self.progress_bar.pack(side=tk.LEFT, padx=(16, 8))
        self.eta_var = tk.StringVar(value="进度 0/0 | ETA --")
        tk.Label(status_frame, textvariable=self.eta_var, bg=UI_BG, fg=UI_MUTED_FG).pack(side=tk.LEFT)
        self.stats_var = tk.StringVar(value="成功: 0 | 失败: 0")
        tk.Label(status_frame, textvariable=self.stats_var, bg=UI_BG, fg=UI_FG).pack(side=tk.RIGHT)
        log_frame = tk.LabelFrame(
            main_frame,
            text="日志",
            bg=UI_PANEL_BG,
            fg=UI_FG,
            padx=5,
            pady=5,
            relief=tk.GROOVE,
            borderwidth=1,
        )
        log_frame.grid(row=3, column=0, sticky=tk.NSEW)
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(0, weight=1)
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=18,
            width=60,
            bg="#111111",
            fg="#f5f5f5",
            insertbackground="#f5f5f5",
            selectbackground="#345a8a",
            selectforeground="#ffffff",
            relief=tk.SOLID,
            borderwidth=1,
            highlightthickness=1,
            highlightbackground="#555555",
        )
        self.log_text.grid(row=0, column=0, sticky=tk.NSEW)
        self.log("[*] GUI 已就绪，配置已加载")
        self.log(f"[*] 当前邮箱服务商: {self.email_provider_var.get()} | 注册数量: {self.count_var.get()}")

    def _refresh_provider_fields(self):
        """按当前邮箱服务商只显示相关配置项。"""
        provider = (self.email_provider_var.get() or "cloudflare").strip().lower()
        titles = {
            "duckmail": "DuckMail / Mail.tm 配置",
            "cloudflare": "Cloudflare 配置",
            "yyds": "YYDS 配置",
            "mailnest": "MailNest 配置",
            "cloudmail": "CloudMail 配置",
            "moemail": "MoeMail 配置",
        }
        self.provider_frame.configure(text=titles.get(provider, "邮箱服务商配置"))
        for widgets in self._provider_widget_groups.values():
            for widget in widgets:
                widget.grid_remove()
        for widget in self._provider_widget_groups.get(provider, self._cloudflare_widgets):
            # grid_remove 后无参 grid() 会恢复原行列
            widget.grid()

    def _refresh_cpa_fields(self):
        """未开启 SSO→auth 时隐藏 CPA 目录/远程配置。"""
        enabled = bool(self.cpa_auto_add_var.get())
        for widget in getattr(self, "_cpa_detail_widgets", []):
            if enabled:
                widget.grid()
            else:
                widget.grid_remove()

    def log(self, message):
        if not should_emit_log(message):
            return
        if self._queue_ui_call(self.log, message):
            return
        from runtime_platform import beijing_strftime

        timestamp = beijing_strftime("%H:%M:%S")
        line = f"[{timestamp}] {message}"
        append_session_log(line)
        print(line, flush=True)
        self.log_text.insert(tk.END, f"{line}\n")
        self.log_text.see(tk.END)

    def clear_log(self):
        self.log_text.delete(1.0, tk.END)

    def update_stats(self):
        if self._queue_ui_call(self.update_stats):
            return
        fail_detail = format_fail_stats(getattr(self, "fail_stats", {}) or {})
        if self.fail_count:
            self.stats_var.set(
                f"成功: {self.success_count} | 失败: {self.fail_count}（{fail_detail}）"
            )
        else:
            self.stats_var.set(f"成功: {self.success_count} | 失败: 0")
        self._update_progress()

    def _update_progress(self):
        total = max(int(getattr(self, "batch_count", 0) or 0), 1)
        done = int(self.success_count) + int(self.fail_count)
        pct = min(100.0, 100.0 * done / total)
        if hasattr(self, "progress_var"):
            self.progress_var.set(pct)
        # ETA
        started = getattr(self, "_batch_started_at", None)
        eta_text = "ETA --"
        if started and done > 0:
            elapsed = max(time.time() - started, 0.1)
            rate = done / elapsed
            remain = max(total - done, 0)
            if rate > 0:
                sec = int(remain / rate)
                if sec < 60:
                    eta_text = f"ETA {sec}s"
                else:
                    eta_text = f"ETA {sec // 60}m{sec % 60:02d}s"
        if hasattr(self, "eta_var"):
            self.eta_var.set(f"进度 {done}/{total} | {eta_text}")

    def run_connectivity_check(self):
        """一键测：代理 / 邮箱 API / CPA。"""
        # 先把当前 GUI 关键字段写回内存配置（不强制保存文件）
        try:
            config["email_provider"] = self.email_provider_var.get().strip() or "cloudflare"
            config["proxy"] = self.proxy_var.get().strip()
            config["duckmail_api_key"] = self.api_key_var.get().strip()
            config["duckmail_api_base"] = self.duckmail_api_base_var.get().strip()
            config["cloudflare_api_base"] = self.cloudflare_api_base_var.get().strip()
            config["cloudflare_api_key"] = self.cloudflare_api_key_var.get().strip()
            config["cloudflare_auth_mode"] = self.cloudflare_auth_mode_var.get().strip() or "none"
            config["defaultDomains"] = self.default_domains_var.get().strip()
            config["cloudflare_custom_auth"] = self.cloudflare_custom_auth_var.get().strip()
            config["yyds_api_key"] = self.yyds_api_key_var.get().strip()
            config["yyds_jwt"] = self.yyds_jwt_var.get().strip()
            config["mailnest_api_key"] = self.mailnest_api_key_var.get().strip()
            config["cloudmail_url"] = self.cloudmail_url_var.get().strip()
            config["cloudmail_admin_email"] = self.cloudmail_admin_email_var.get().strip()
            config["cloudmail_password"] = self.cloudmail_password_var.get()
            config["moemail_api_base"] = self.moemail_api_base_var.get().strip()
            config["moemail_api_key"] = self.moemail_api_key_var.get().strip()
            config["moemail_domain"] = self.moemail_domain_var.get().strip().lstrip("@")
            config["moemail_expiry_ms"] = int(
                self.moemail_expiry_ms_var.get().strip()
                or moemail_provider.DEFAULT_EXPIRY_MS
            )
            config["cpa_auto_add"] = bool(self.cpa_auto_add_var.get())
            _mode_text = str(self.cpa_token_mode_var.get()).strip()
            if "协议" in _mode_text:
                config["cpa_token_mode"] = "device_protocol"
            elif "浏览器" in _mode_text:
                config["cpa_token_mode"] = "device_browser"
            elif "auth" in _mode_text.lower() or "code" in _mode_text.lower():
                config["cpa_token_mode"] = "auth_code"
            else:
                config["cpa_token_mode"] = "device_protocol"
            config["cpa_auth_dir"] = self.cpa_auth_dir_var.get().strip()
            config["cpa_remote_url"] = self.cpa_remote_url_var.get().strip()
            config["cpa_management_key"] = self.cpa_management_key_var.get().strip()
            config["grok2api_auth_dir"] = self.grok2api_auth_dir_var.get().strip()
        except Exception:
            pass
        self.log("[*] 开始连通性检查...")
        self.check_btn.config(state=tk.DISABLED)

        def _job():
            try:
                results = _conn.run_connectivity_checks(config, http_get, http_post)
                text = _conn.format_check_results(results)
                all_ok = all(ok for _, ok, _ in results)
                self.ui_queue.put((self._on_check_done, (text, all_ok)))
            except Exception as exc:
                self.ui_queue.put(
                    (
                        self._on_check_done,
                        (f"检查异常: {redact_sensitive_log_line(str(exc))}", False),
                    )
                )

        threading.Thread(target=_job, daemon=True).start()

    def _on_check_done(self, text, all_ok):
        self.check_btn.config(state=tk.NORMAL)
        for line in str(text).splitlines():
            self.log(f"[检查] {line}")
        self.status_var.set("检查通过" if all_ok else "检查有失败项")
        self.status_label.config(foreground="green" if all_ok else "orange")

    def _record_failure(self, exc):
        kind = classify_failure(exc)
        lock = getattr(self, "_stats_lock", None)
        if lock:
            with lock:
                self.fail_count += 1
                if not hasattr(self, "fail_stats") or self.fail_stats is None:
                    self.fail_stats = empty_fail_stats()
                self.fail_stats[kind] = self.fail_stats.get(kind, 0) + 1
        else:
            self.fail_count += 1
            if not hasattr(self, "fail_stats") or self.fail_stats is None:
                self.fail_stats = empty_fail_stats()
            self.fail_stats[kind] = self.fail_stats.get(kind, 0) + 1
        return kind

    def _record_success(self):
        lock = getattr(self, "_stats_lock", None)
        if lock:
            with lock:
                self.success_count += 1
        else:
            self.success_count += 1

    def _set_running_ui(self, running):
        if self._queue_ui_call(self._set_running_ui, running):
            return
        self.is_running = running
        self.start_btn.config(state=tk.DISABLED if running else tk.NORMAL)
        self.stop_btn.config(state=tk.NORMAL if running else tk.DISABLED)
        self.status_var.set("运行中..." if running else "就绪")
        self.status_label.config(foreground="blue" if running else "green")

    def should_stop(self):
        return self.stop_requested or not self.is_running

    def start_registration(self):
        if self.is_running:
            self.log("[!] 当前已有任务在运行")
            return

        config["email_provider"] = self.email_provider_var.get().strip() or "cloudflare"
        config["enable_nsfw"] = bool(self.nsfw_var.get())
        config["debug_mode"] = bool(self.debug_mode_var.get())
        config["close_browser_on_stop"] = bool(self.close_browser_on_stop_var.get())
        config["log_level"] = (self.log_level_var.get().strip() or "info").lower()
        config["proxy"] = self.proxy_var.get().strip()
        config["duckmail_api_key"] = self.api_key_var.get().strip()
        config["duckmail_api_base"] = self.duckmail_api_base_var.get().strip() or DUCKMAIL_API_BASE_DEFAULT
        config["cloudflare_api_base"] = self.cloudflare_api_base_var.get().strip()
        config["cloudflare_api_key"] = self.cloudflare_api_key_var.get().strip()
        config["cloudflare_auth_mode"] = self.cloudflare_auth_mode_var.get().strip() or "none"
        config["defaultDomains"] = self.default_domains_var.get().strip()
        config["cloudflare_custom_auth"] = self.cloudflare_custom_auth_var.get().strip()
        config["yyds_api_key"] = self.yyds_api_key_var.get().strip()
        config["yyds_jwt"] = self.yyds_jwt_var.get().strip()
        config["mailnest_api_key"] = self.mailnest_api_key_var.get().strip()
        config["mailnest_project_code"] = (
            self.mailnest_project_code_var.get().strip() or MAILNEST_DEFAULT_PROJECT_CODE
        )
        config["yyds_default_domain"] = self.yyds_default_domain_var.get().strip()
        config["cloudmail_url"] = self.cloudmail_url_var.get().strip()
        config["cloudmail_admin_email"] = self.cloudmail_admin_email_var.get().strip()
        config["cloudmail_password"] = self.cloudmail_password_var.get()
        config["moemail_api_base"] = self.moemail_api_base_var.get().strip()
        config["moemail_api_key"] = self.moemail_api_key_var.get().strip()
        config["moemail_domain"] = self.moemail_domain_var.get().strip().lstrip("@")
        try:
            config["moemail_expiry_ms"] = int(
                self.moemail_expiry_ms_var.get().strip()
                or moemail_provider.DEFAULT_EXPIRY_MS
            )
        except ValueError:
            config["moemail_expiry_ms"] = moemail_provider.DEFAULT_EXPIRY_MS
        config["cpa_auto_add"] = bool(self.cpa_auto_add_var.get())
        _mode_text = str(self.cpa_token_mode_var.get()).strip()
        if "协议" in _mode_text:
            config["cpa_token_mode"] = "device_protocol"
        elif "浏览器" in _mode_text:
            config["cpa_token_mode"] = "device_browser"
        elif "auth" in _mode_text.lower() or "code" in _mode_text.lower():
            config["cpa_token_mode"] = "auth_code"
        else:
            config["cpa_token_mode"] = "device_protocol"
        config["cpa_auth_dir"] = self.cpa_auth_dir_var.get().strip()
        config["cpa_remote_url"] = self.cpa_remote_url_var.get().strip()
        config["cpa_management_key"] = self.cpa_management_key_var.get().strip()
        config["grok2api_auth_dir"] = self.grok2api_auth_dir_var.get().strip()
        raw_paths = [x.strip() for x in self.cloudflare_paths_var.get().split(",") if x.strip()]
        if len(raw_paths) >= 4:
            config["cloudflare_path_domains"] = raw_paths[0] if raw_paths[0].startswith("/") else ("/" + raw_paths[0])
            config["cloudflare_path_accounts"] = raw_paths[1] if raw_paths[1].startswith("/") else ("/" + raw_paths[1])
            config["cloudflare_path_token"] = raw_paths[2] if raw_paths[2].startswith("/") else ("/" + raw_paths[2])
            config["cloudflare_path_messages"] = raw_paths[3] if raw_paths[3].startswith("/") else ("/" + raw_paths[3])
        config["account_interval"] = self.account_interval_var.get().strip() or "0"
        save_config()
        if config["email_provider"] == "cloudflare" and not config["cloudflare_api_base"]:
            self.log("[!] Cloudflare 模式需要先填写 Cloudflare API Base")
            return
        if config["email_provider"] == "mailnest" and not config["mailnest_api_key"]:
            self.log("[!] MailNest 模式需要先填写 MailNest API Key")
            return
        if config["email_provider"] == "moemail":
            missing = []
            if not get_moemail_api_base():
                missing.append("MoeMail 站点 URL")
            if not get_moemail_api_key():
                missing.append("MoeMail API Key")
            if missing:
                self.log(f"[!] MoeMail 模式缺少配置: {', '.join(missing)}")
                return
        if config["email_provider"] == "cloudmail":
            missing = []
            if not get_cloudmail_url():
                missing.append("CloudMail URL")
            if not get_cloudmail_admin_email():
                missing.append("CloudMail 管理员邮箱")
            if not get_cloudmail_password():
                missing.append("CloudMail 管理员密码")
            if not config["defaultDomains"]:
                missing.append("默认收信域名")
            if missing:
                self.log(f"[!] CloudMail 模式缺少配置: {', '.join(missing)}")
                return
        if config.get("cpa_auto_add") and not config.get("cpa_auth_dir") and not config.get("cpa_remote_url") and not config.get("grok2api_auth_dir"):
            self.log("[!] 已开启 SSO→auth，但未配置 CPA auth 目录 / 远程地址 / Grok2API 目录")
            return
        try:
            count = int(self.count_var.get())
        except Exception:
            self.log("[!] 注册数量无效")
            return
        try:
            workers = int(self.workers_var.get())
        except Exception:
            workers = 1
        if config.get("debug_mode"):
            if count != 1 or workers != 1:
                self.log("[*] 调试模式：强制 数量=1、并发=1，结束后不关闭浏览器")
            count = 1
            workers = 1
            self.count_var.set("1")
            self.workers_var.set("1")
        workers = max(1, min(workers, 24, count))
        config["register_count"] = count
        config["register_workers"] = workers
        save_config()
        self.stop_requested = False
        self.success_count = 0
        self.fail_count = 0
        self.fail_stats = empty_fail_stats()
        self.results = []
        self.batch_count = count
        self._batch_started_at = time.time()
        self.progress_var.set(0)
        self.eta_var.set(f"进度 0/{count} | ETA --")
        self.update_stats()
        self._set_running_ui(True)
        self._stats_lock = threading.Lock()
        self._accounts_lock = threading.Lock()
        # 启动前快速连通性检查（失败仍可继续，只警告）
        try:
            checks = _conn.run_connectivity_checks(config, http_get, http_post)
            for name, ok, detail in checks:
                self.log(
                    f"[检查] [{'OK' if ok else 'FAIL'}] {name}: "
                    f"{redact_sensitive_log_line(detail)}"
                )
            if _conn.has_blocking_xai_failure(checks):
                self.log("[!] xAI 注册页被 Cloudflare 拦截，已停止建号；请更换当前 proxy 后重试")
                self._set_running_ui(False)
                return
            if not all(ok for _, ok, _ in checks):
                self.log("[!] 连通性检查存在失败项，仍继续注册（可先点「连通性检查」排查）")
        except Exception as exc:
            self.log(f"[!] 连通性检查异常: {redact_sensitive_log_line(str(exc))}")
        _interval_raw = str(config.get("account_interval", "0") or "0").strip()
        _interval_info = f" | 账号间隔: {_interval_raw}s" if _interval_raw and _interval_raw != "0" else ""
        self.log(
            f"[*] 配置已保存，开始执行。目标数量: {count} | 并发: {workers}{_interval_info}"
            + (" | 调试模式" if config.get("debug_mode") else "")
        )
        if int(self.workers_var.get() or 1) > count and not config.get("debug_mode"):
            self.log(f"[*] 并发已自动调整为 {workers}（不超过注册数量）")
        _mode_map = {"device_protocol": "协议 Device Flow", "device_browser": "浏览器 Device Flow", "auth_code": "Authorization Code"}
        _mode_label = _mode_map.get(str(config.get("cpa_token_mode", "device_protocol")), "协议 Device Flow")
        self.log(f"[*] SSO→auth: {'开' if config.get('cpa_auto_add') else '关（仅保存 SSO）'}" + (f"（{_mode_label}）" if config.get('cpa_auto_add') else ""))
        threading.Thread(
            target=self._run_registration_entry,
            args=(count, workers),
            daemon=True,
        ).start()

    def stop_registration(self):
        self.stop_requested = True
        # 即时写入，worker finally 能读到最新勾选状态
        config["close_browser_on_stop"] = bool(self.close_browser_on_stop_var.get())
        keep = not config.get("close_browser_on_stop", False)
        self.log("[!] 用户停止注册" + ("（将保留浏览器）" if keep else "（将关闭浏览器）"))

    def _run_registration_entry(self, count, workers):
        # 并发数不超过任务数，避免空 worker 白开浏览器
        workers = max(1, min(int(workers or 1), 24, int(count or 1)))
        # 启动前清理上次崩溃 / 强杀残留的临时 profile 目录
        try:
            _cleanup_stale_profiles(log_callback=self.log)
        except Exception:
            pass
        try:
            if workers <= 1:
                self.run_registration(count, worker_id=0, workers=1)
            else:
                base, rem = divmod(count, workers)
                chunks = [base + (1 if i < rem else 0) for i in range(workers)]
                # 去掉 0 任务分片，重新编号
                chunks = [n for n in chunks if n > 0]
                self.log(f"[*] 实际并发 worker={len(chunks)}，分片={chunks}")
                threads = []
                for wid, n in enumerate(chunks):
                    t = threading.Thread(
                        target=self.run_registration,
                        args=(n, wid, len(chunks)),
                        daemon=True,
                    )
                    t.start()
                    threads.append(t)
                    # 错开启动，降低同时拉起 Chrome 端口/用户目录冲突
                    time.sleep(2.0)
                for t in threads:
                    t.join()
        finally:
            # 协调线程自身无浏览器；各 worker 线程 finally 已各自 stop
            self._set_running_ui(False)
            self.log(
                f"[*] 任务结束。成功 {self.success_count} | 失败 {self.fail_count}"
                + (f" | {format_fail_stats(self.fail_stats)}" if self.fail_count else "")
            )

    def run_registration(self, count, worker_id=0, workers=1):
        prefix = f"[W{worker_id + 1}] " if workers > 1 else ""

        def wlog(message):
            text = str(message)
            if prefix and not text.startswith(prefix):
                self.log(prefix + text)
            else:
                self.log(text)

        try:
            try:
                start_browser(log_callback=wlog)
            except Exception as boot_exc:
                streak = get_start_fail_streak()
                wlog(
                    f"[-] 浏览器启动失败 (连续失败 {streak}): "
                    f"{redact_sensitive_log_line(str(boot_exc))}"
                )
                if workers > 1 and streak >= 3:
                    wlog("[!] 连续启动失败较多，建议降低并发后重试")
                for _ in range(max(int(count or 0), 0)):
                    self._record_failure(boot_exc)
                self.update_stats()
                return
            wlog("[*] 浏览器已启动")
            i = 0
            retry_count_for_slot = 0
            max_slot_retry = slot_retries()
            while i < count:
                if self.should_stop():
                    break
                wlog(f"--- 开始第 {i + 1}/{count} 个账号 ---")
                try:
                    email = ""
                    dev_token = ""
                    code = ""
                    mail_ok = False
                    max_mail_retry = 3
                    for mail_try in range(1, max_mail_retry + 1):
                        wlog(f"[*] 1. 打开注册页 (尝试 {mail_try}/{max_mail_retry})")
                        open_signup_page(
                            log_callback=wlog, cancel_callback=self.should_stop
                        )
                        wlog("[*] 2. 创建邮箱并提交")
                        email, dev_token = fill_email_and_submit(
                            log_callback=wlog, cancel_callback=self.should_stop
                        )
                        wlog(f"[*] 邮箱: {email}")
                        wlog(f"[Debug] 邮箱 token 已获取 (len={len(str(dev_token or ''))})")
                        try:
                            append_private_text(
                                accounts_side_file("mail_credentials.txt"),
                                f"{email}\t{dev_token}\n",
                            )
                        except Exception:
                            pass
                        wlog("[*] 3. 拉取验证码")
                        try:
                            code = fill_code_and_submit(
                                email,
                                dev_token,
                                log_callback=wlog,
                                cancel_callback=self.should_stop,
                            )
                            mail_ok = True
                            break
                        except Exception as mail_exc:
                            msg = str(mail_exc)
                            if ("未收到验证码" in msg or "验证码" in msg) and mail_try < max_mail_retry:
                                wlog(f"[!] 本邮箱未取到验证码，自动更换新邮箱重试: {msg}")
                                restart_browser(log_callback=wlog)
                                sleep_with_cancel(1, self.should_stop)
                                continue
                            raise

                    if not mail_ok:
                        raise Exception("验证码阶段失败，已达到最大重试次数")
                    wlog(f"[*] 验证码: {code}")
                    wlog("[*] 4. 填写资料")
                    profile = fill_profile_and_submit(
                        log_callback=wlog, cancel_callback=self.should_stop
                    )
                    wlog(f"[*] 资料已填: {profile.get('given_name')} {profile.get('family_name')}")
                    wlog("[*] 5. 等待 sso cookie")
                    sso = wait_for_sso_cookie(
                        log_callback=wlog,
                        cancel_callback=self.should_stop,
                        email=email,
                        password=profile.get("password", ""),
                    )
                    ensure_sso_oauth_eligible(sso, email=email, log_callback=wlog)
                    if config.get("enable_nsfw", True):
                        wlog("[*] 6. 开启 NSFW（失败不阻塞入库）")
                        try:
                            nsfw_ok, nsfw_msg = enable_nsfw_for_token(
                                sso, log_callback=wlog
                            )
                            if nsfw_ok:
                                wlog(f"[+] NSFW 开启成功: {nsfw_msg}")
                            else:
                                wlog(f"[!] NSFW 自动开启失败（账号仍可用，可网页手动开）: {nsfw_msg}")
                        except Exception as nsfw_exc:
                            wlog(f"[!] NSFW 步骤异常，已跳过: {nsfw_exc}")
                    try:
                        line = f"{email}----{profile.get('password','')}----{sso}\n"
                        # 以邮箱命名单独保存
                        email_file = account_file_for_email(email)
                        alock = getattr(self, "_accounts_lock", None)
                        if alock:
                            with alock:
                                atomic_write_text(email_file, line)
                        else:
                            atomic_write_text(email_file, line)
                    except Exception as file_exc:
                        wlog(f"[!] 保存账号文件失败，当前账号不计为成功: {file_exc}")
                        _append_sso_pending(email, sso, log_callback=wlog)
                        raise RuntimeError(f"保存账号文件失败: {file_exc}") from file_exc
                    lock = getattr(self, "_stats_lock", None)
                    if lock:
                        with lock:
                            self.results.append({"email": email, "sso": sso, "profile": profile})
                    else:
                        self.results.append({"email": email, "sso": sso, "profile": profile})
                    cpa_ok = add_sso_to_cpa(sso, email=email, log_callback=wlog)
                    self._record_success()
                    retry_count_for_slot = 0
                    i += 1
                    if cpa_ok:
                        wlog(f"[+] 注册成功: {email}")
                    else:
                        wlog(f"[+] 注册成功（SSO 已保存，CPA 入库失败）: {email}")
                    if (
                        self.success_count > 0
                        and self.success_count % MEMORY_CLEANUP_INTERVAL == 0
                        and i < count
                        and workers <= 1
                    ):
                        cleanup_runtime_memory(
                            log_callback=wlog,
                            reason=f"已成功 {self.success_count} 个账号，执行定期清理",
                        )
                except RegistrationCancelled:
                    wlog("[!] 注册被用户停止")
                    break
                except EmailDomainRejected as exc:
                    kind = self._record_failure(exc)
                    retry_count_for_slot = 0
                    i += 1
                    wlog(
                        f"[-] 邮箱域名被 xAI 拒绝 [{FAIL_LABELS.get(kind, kind)}]: "
                        f"{redact_sensitive_log_line(str(exc))}"
                    )
                    wlog("[!] 请更换邮箱提供商或域名（如 Cloudflare 自建域 / MailNest），公共临时域常被拉黑")
                except AccountRetryNeeded as exc:
                    retry_count_for_slot += 1
                    if retry_count_for_slot <= max_slot_retry:
                        wlog(
                            f"[!] 当前账号流程卡住，重试第 {retry_count_for_slot}/{max_slot_retry} 次: "
                            f"{redact_sensitive_log_line(str(exc))}"
                        )
                    else:
                        kind = self._record_failure(exc)
                        wlog(
                            f"[-] 当前账号已达到最大重试次数，跳过 [{FAIL_LABELS.get(kind, kind)}]: "
                            f"{redact_sensitive_log_line(str(exc))}"
                        )
                        retry_count_for_slot = 0
                        i += 1
                except Exception as exc:
                    kind = self._record_failure(exc)
                    retry_count_for_slot = 0
                    i += 1
                    wlog(
                        f"[-] 注册失败 [{FAIL_LABELS.get(kind, kind)}]: "
                        f"{redact_sensitive_log_line(str(exc))}"
                    )
                finally:
                    self.update_stats()
                if self.should_stop():
                    break
                # 每轮结束只关浏览器，不立刻再开。
                # 下一轮 open_signup_page 会按需启动并导航到官网，避免空浏览器残留。
                if i >= count:
                    continue
                # 账号间随机间隔
                wait_sec = parse_account_interval()
                if wait_sec > 0:
                    wlog(f"[*] 下一个账号前等待 {wait_sec:.0f} 秒...")
                    sleep_with_cancel(wait_sec, self.should_stop)
                try:
                    stop_browser()
                    time.sleep(0.5)
                except Exception as close_exc:
                    if self.should_stop():
                        break
                    wlog(f"[Debug] 轮次关闭浏览器失败: {close_exc}")
        except RegistrationCancelled:
            wlog("[!] 注册被用户停止")
        except Exception as exc:
            wlog(f"[!] 任务异常: {redact_sensitive_log_line(str(exc))}")
        finally:
            try:
                maybe_stop_browser(user_stopped=bool(self.stop_requested), log_callback=wlog)
            except BaseException:
                pass
            # 收尾 UI / 汇总只由 _run_registration_entry 负责，避免打印两次


class CliStopController:
    def __init__(self):
        self.stop_requested = False

    def should_stop(self):
        return self.stop_requested

    def stop(self):
        self.stop_requested = True


def cli_log(message):
    if not should_emit_log(message):
        return
    from runtime_platform import beijing_strftime

    timestamp = beijing_strftime("%H:%M:%S")
    line = f"[{timestamp}] {message}"
    append_session_log(line)
    print(line, flush=True)


def run_registration_cli(count):
    controller = CliStopController()

    # 一次 Ctrl+C 可靠置停：SIGINT 处理器直接设停止标志，不依赖异常在
    # curl_cffi C 回调里向上传播（那里 KeyboardInterrupt 会被吞掉，导致
    # 第一次 Ctrl+C 无效、循环继续跑下一个账号）。连按两次 Ctrl+C 时第二次
    # 恢复默认行为强制中断。
    _prev_sigint = signal.getsignal(signal.SIGINT)

    def _on_sigint(signum, frame):
        if controller.should_stop():
            # 第二次：恢复默认并重新抛出，强制中断
            signal.signal(signal.SIGINT, _prev_sigint)
            raise KeyboardInterrupt
        controller.stop()
        cli_log("[!] 收到 Ctrl+C，正在停止（再按一次强制中断）")

    signal.signal(signal.SIGINT, _on_sigint)
    success_count = 0
    fail_count = 0
    fail_stats = empty_fail_stats()
    retry_count_for_slot = 0
    max_slot_retry = slot_retries()
    max_proxy_boot_rotations = proxy_boot_rotations()
    accounts_output_file = ""  # 已改为按邮箱单独保存，不再使用批量文件
    workers = max(1, min(int(config.get("register_workers", 1) or 1), 24, int(count or 1)))
    pool = load_proxy_pool()
    cli_log(
        f"[*] 终端模式启动，目标数量: {count} | 并发: {workers} | "
        f"代理池: {len(pool)} ({_proxy_pool_source})"
    )
    _cli_interval_raw = str(config.get("account_interval", "0") or "0").strip()
    if _cli_interval_raw and _cli_interval_raw != "0":
        cli_log(f"[*] 账号间注册间隔: {_cli_interval_raw}s")
    _cli_mode_map = {"device_protocol": "协议 Device Flow", "device_browser": "浏览器 Device Flow", "auth_code": "Authorization Code"}
    _cli_mode_label = _cli_mode_map.get(str(config.get("cpa_token_mode", "device_protocol")), "协议 Device Flow")
    cli_log(f"[*] SSO→auth: {'开' if config.get('cpa_auto_add') else '关（仅保存 SSO）'}" + (f"（{_cli_mode_label}）" if config.get('cpa_auto_add') else ""))
    # 启动前清理上次崩溃 / 强杀残留的临时 profile 目录
    try:
        _cleanup_stale_profiles(log_callback=cli_log)
    except Exception:
        pass
    try:
        startup_config = dict(config)
        if pool:
            startup_config["proxy"] = pool[0]
        startup_checks = _conn.run_connectivity_checks(startup_config, http_get, http_post)
        for name, ok, detail in startup_checks:
            cli_log(
                f"[检查] [{'OK' if ok else 'FAIL'}] {name}: "
                f"{redact_sensitive_log_line(detail)}"
            )
        if _conn.has_blocking_xai_failure(startup_checks):
            _record_proxy_precheck_failure(
                str(startup_config.get("proxy") or ""),
                startup_checks,
            )
            cli_log("[!] xAI 注册页预检失败，已停止当前批次；请检查或更换当前 proxy 后重试")
            try:
                signal.signal(signal.SIGINT, _prev_sigint)
            except Exception:
                pass
            _conn.require_xai_signup(startup_checks)
    except _conn.XaiSignupPrecheckFailed:
        raise
    except Exception as exc:
        cli_log(
            f"[!] 启动连通性检查异常，已停止当前批次: "
            f"{redact_sensitive_log_line(str(exc))}"
        )
        try:
            signal.signal(signal.SIGINT, _prev_sigint)
        except Exception:
            pass
        raise _conn.XaiSignupPrecheckFailed(
            "xAI registration page precheck raised an exception"
        ) from exc

    def _cli_record_failure(exc):
        nonlocal fail_count
        kind = classify_failure(exc)
        fail_count += 1
        fail_stats[kind] = fail_stats.get(kind, 0) + 1
        return kind

    if workers > 1:
        # CLI 并发：多线程，每线程独立浏览器（thread-local）
        stats_lock = threading.Lock()
        accounts_lock = threading.Lock()
        base, rem = divmod(count, workers)
        chunks = [base + (1 if i < rem else 0) for i in range(workers)]
        threads = []
        shared = {"success": 0, "fail": 0, "fail_stats": empty_fail_stats()}

        def worker(n, wid):
            local_success = 0
            local_fail = 0
            local_fail_stats = empty_fail_stats()
            rotate_idx = 0
            try:
                try:
                    px = pick_proxy_for_worker(wid, rotate_idx)
                except Exception as proxy_exc:
                    local_fail = n
                    local_fail_stats[FAIL_BROWSER] = local_fail_stats.get(FAIL_BROWSER, 0) + n
                    cli_log(
                        f"[W{wid+1}] [-] 没有可用代理，停止该 worker: "
                        f"{redact_sensitive_log_line(str(proxy_exc))}"
                    )
                    return
                set_thread_proxy(px)
                cli_log(f"[W{wid+1}] [*] 绑定代理: {redact_proxy(px)}")
                try:
                    start_browser(log_callback=lambda m: cli_log(f"[W{wid+1}] {m}"))
                except Exception as boot_exc:
                    record_proxy_boot_failure(px, boot_exc)
                    # 黑名单/死代理：多换几条 sticky 再放弃
                    booted = False
                    last_boot = boot_exc
                    for _try in range(1, max_proxy_boot_rotations + 1):
                        msgb = str(last_boot)
                        if not (
                            "出口IP命中黑名单" in msgb
                            or "无法解析出口 IP" in msgb
                            or "代理不可用或过慢" in msgb
                            or "Failed to get IP" in msgb
                        ):
                            break
                        rotate_idx += 1
                        try:
                            px = pick_proxy_for_worker(wid, rotate_idx)
                            set_thread_proxy(px)
                            cli_log(
                                f"[W{wid+1}] [*] 跳过坏出口，换代理 #{rotate_idx}: "
                                f"{redact_proxy(px)} ({redact_sensitive_log_line(msgb[:80])})"
                            )
                            start_browser(log_callback=lambda m: cli_log(f"[W{wid+1}] {m}"))
                            booted = True
                            break
                        except Exception as boot2:
                            last_boot = boot2
                            record_proxy_boot_failure(px, boot2)
                            continue
                    if not booted:
                        local_fail = n
                        local_fail_stats[FAIL_BROWSER] = local_fail_stats.get(FAIL_BROWSER, 0) + n
                        mark_slot_completed(n)
                        cli_log(
                            f"[W{wid+1}] [-] 浏览器启动失败，{n} 个任务均记为失败: "
                            f"{redact_sensitive_log_line(str(last_boot))}"
                        )
                        record_register_result(
                            "fail",
                            kind=FAIL_BROWSER,
                            detail=str(last_boot)[:300],
                            worker=f"W{wid+1}",
                            log_callback=lambda m: cli_log(f"[W{wid+1}] {m}"),
                        )
                        return
                i = 0
                retry = 0
                worker_stop = False
                while i < n and not controller.should_stop() and not worker_stop:
                    email = ""
                    try:
                        open_signup_page(
                            log_callback=lambda m: cli_log(f"[W{wid+1}] {m}"),
                            cancel_callback=controller.should_stop,
                        )
                        email, dev_token = fill_email_and_submit(
                            log_callback=lambda m: cli_log(f"[W{wid+1}] {m}"),
                            cancel_callback=controller.should_stop,
                        )
                        code = fill_code_and_submit(
                            email,
                            dev_token,
                            log_callback=lambda m: cli_log(f"[W{wid+1}] {m}"),
                            cancel_callback=controller.should_stop,
                        )
                        profile = fill_profile_and_submit(
                            log_callback=lambda m: cli_log(f"[W{wid+1}] {m}"),
                            cancel_callback=controller.should_stop,
                        )
                        sso = wait_for_sso_cookie(
                            log_callback=lambda m: cli_log(f"[W{wid+1}] {m}"),
                            cancel_callback=controller.should_stop,
                            email=email,
                            password=profile.get("password", ""),
                        )
                        ensure_sso_oauth_eligible(
                            sso,
                            email=email,
                            log_callback=lambda m: cli_log(f"[W{wid+1}] {m}"),
                        )
                        if config.get("enable_nsfw", True):
                            enable_nsfw_for_token(
                                sso,
                                log_callback=lambda m: cli_log(f"[W{wid+1}] {m}"),
                            )
                        line = f"{email}----{profile.get('password','')}----{sso}\n"
                        try:
                            with accounts_lock:
                                # 以邮箱命名单独保存
                                email_file = account_file_for_email(email)
                                atomic_write_text(email_file, line)
                        except Exception as file_exc:
                            cli_log(
                                f"[W{wid+1}] [!] 保存账号文件失败，当前账号不计为成功: {file_exc}"
                            )
                            _append_sso_pending(
                                email,
                                sso,
                                log_callback=lambda m: cli_log(f"[W{wid+1}] {m}"),
                            )
                            raise RuntimeError(f"保存账号文件失败: {file_exc}") from file_exc
                        cpa_ok = add_sso_to_cpa(
                            sso, email=email, log_callback=lambda m: cli_log(f"[W{wid+1}] {m}")
                        )
                        local_success += 1
                        mark_successful_account()
                        i += 1
                        retry = 0
                        if cpa_ok:
                            cli_log(f"[W{wid+1}] [+] 注册成功: {email}")
                        else:
                            cli_log(f"[W{wid+1}] [+] 注册成功（SSO 已保存，CPA 入库失败）: {email}")
                        record_register_result(
                            "ok",
                            email,
                            kind="success",
                            detail="cpa_ok" if cpa_ok else "cpa_fail",
                            worker=f"W{wid+1}",
                            bot_flag=0,
                            log_callback=lambda m: cli_log(f"[W{wid+1}] {m}"),
                        )
                        mark_slot_completed()
                        # 每成功 2 个换 sticky，降低同 IP 密度（对齐 ~4 分钟窗口）
                        if local_success % 2 == 0:
                            rotate_idx += 1
                    except RegistrationCancelled:
                        break
                    except EmailDomainRejected as exc:
                        kind = classify_failure(exc)
                        local_fail_stats[kind] = local_fail_stats.get(kind, 0) + 1
                        local_fail += 1
                        i += 1
                        retry = 0
                        cli_log(
                            f"[W{wid+1}] [-] 域名拒绝: "
                            f"{redact_sensitive_log_line(str(exc))}"
                        )
                        record_register_result(
                            "fail",
                            email if email else "",
                            kind=kind,
                            detail=str(exc)[:300],
                            worker=f"W{wid+1}",
                            log_callback=lambda m: cli_log(f"[W{wid+1}] {m}"),
                        )
                        mark_slot_completed()
                    except AccountRetryNeeded as exc:
                        retry += 1
                        if retry > max_slot_retry:
                            kind = classify_failure(exc)
                            local_fail_stats[kind] = local_fail_stats.get(kind, 0) + 1
                            local_fail += 1
                            i += 1
                            retry = 0
                            cli_log(
                                f"[W{wid+1}] [-] 卡住跳过: "
                                f"{redact_sensitive_log_line(str(exc))}"
                            )
                            mark_slot_completed()
                    except Exception as exc:
                        msg = str(exc)
                        blank_ui = (
                            "inputs=none" in msg
                            or "未找到邮箱输入框" in msg
                            or "页面空白" in msg
                            or "打开注册页后页面空白" in msg
                        )
                        proxy_dead = (
                            "无法解析出口 IP" in msg
                            or "Failed to get IP address" in msg
                            or "代理不可用或过慢" in msg
                            or "出口IP命中黑名单" in msg
                            or "命中黑名单" in msg
                        )
                        if proxy_dead:
                            record_proxy_boot_failure(
                                get_bound_proxy() or get_thread_proxy(), exc
                            )
                        turnstile_stuck = (
                            "资料页 Turnstile" in msg
                            or "Turnstile 超时" in msg
                            or "Turnstile 获取 token 失败" in msg
                        )
                        profile_soft = (
                            "资料页表单未就绪" in msg
                            or "资料页无提交按钮" in msg
                        )
                        if (blank_ui or proxy_dead or turnstile_stuck or profile_soft) and retry < max_slot_retry:
                            retry += 1
                            why = (
                                "Turnstile卡住"
                                if turnstile_stuck
                                else ("资料页未就绪" if profile_soft else "空页/表单未就绪")
                            )
                            cli_log(
                                f"[W{wid+1}] [!] {why}，同槽位换口重试 {retry}/{max_slot_retry}: "
                                f"{redact_sensitive_log_line(str(exc))}"
                            )
                            rotate_idx += 1
                            continue
                        kind = classify_failure(exc)
                        local_fail_stats[kind] = local_fail_stats.get(kind, 0) + 1
                        local_fail += 1
                        i += 1
                        retry = 0
                        cli_log(
                            f"[W{wid+1}] [-] 失败 [{FAIL_LABELS.get(kind, kind)}]: "
                            f"{redact_sensitive_log_line(str(exc))}"
                        )
                        _bf = None
                        _rk = None
                        if kind == FAIL_RISK:
                            import re as _re_f
                            _m = _re_f.search(r"botFlagSource=(\d+)", str(exc))
                            if _m:
                                _bf = int(_m.group(1))
                            _m2 = _re_f.search(r"risk=([\d.]+)", str(exc))
                            if _m2:
                                try:
                                    _rk = float(_m2.group(1))
                                except Exception:
                                    _rk = None
                        # 风控已在 ensure_sso_oauth_eligible 里记过，避免重复
                        if kind != FAIL_RISK:
                            record_register_result(
                                "fail",
                                email or "",
                                kind=kind,
                                detail=str(exc)[:300],
                                worker=f"W{wid+1}",
                                bot_flag=_bf,
                                risk=_rk,
                                log_callback=lambda m: cli_log(f"[W{wid+1}] {m}"),
                            )
                        mark_slot_completed()
                        if kind == FAIL_RISK:
                            rotate_idx += 1
                            cli_log(f"[W{wid+1}] [*] 风控拒绝，切换 sticky #{rotate_idx}")
                        elif blank_ui or proxy_dead or turnstile_stuck or profile_soft or kind in (
                            FAIL_TURNSTILE,
                            FAIL_PROFILE,
                        ):
                            rotate_idx += 1
                        elif local_success > 0 and local_success % 2 == 0:
                            rotate_idx += 1
                    finally:
                        if i < n and not controller.should_stop():
                            try:
                                stop_browser()
                                # 冷却：避免热重启立刻撞 SPA 空壳
                                time.sleep(0.5)
                            except Exception:
                                pass
                            try:
                                px = pick_proxy_for_worker(wid, rotate_idx)
                                set_thread_proxy(px)
                                cli_log(f"[W{wid+1}] [*] 下号代理: {redact_proxy(px)}")
                                start_browser(log_callback=lambda m: cli_log(f"[W{wid+1}] {m}"))
                                time.sleep(0.5)
                            except Exception as boot_exc:
                                last_boot = boot_exc
                                record_proxy_boot_failure(px, boot_exc)
                                if "面板代理池没有健康且启用的代理" in str(boot_exc):
                                    remaining = max(n - i, 0)
                                    local_fail += remaining
                                    local_fail_stats[FAIL_BROWSER] = (
                                        local_fail_stats.get(FAIL_BROWSER, 0) + remaining
                                    )
                                    cli_log(
                                        f"[W{wid+1}] [-] 健康代理已耗尽，停止该 worker: "
                                        f"{redact_sensitive_log_line(str(boot_exc))}"
                                    )
                                    worker_stop = True
                                else:
                                    for _try in range(1, max_proxy_boot_rotations + 1):
                                        msgb = str(last_boot)
                                        if not (
                                            "出口IP命中黑名单" in msgb
                                            or "无法解析出口 IP" in msgb
                                            or "代理不可用或过慢" in msgb
                                        ):
                                            break
                                        rotate_idx += 1
                                        try:
                                            px = pick_proxy_for_worker(wid, rotate_idx)
                                            set_thread_proxy(px)
                                            cli_log(
                                                f"[W{wid+1}] [*] 下号跳过黑名单，换 #{rotate_idx}: "
                                                f"{redact_proxy(px)}"
                                            )
                                            start_browser(log_callback=lambda m: cli_log(f"[W{wid+1}] {m}"))
                                            time.sleep(0.5)
                                            last_boot = None
                                            break
                                        except Exception as boot2:
                                            last_boot = boot2
                                            record_proxy_boot_failure(px, boot2)
                                            if "面板代理池没有健康且启用的代理" in str(boot2):
                                                remaining = max(n - i, 0)
                                                local_fail += remaining
                                                local_fail_stats[FAIL_BROWSER] = (
                                                    local_fail_stats.get(FAIL_BROWSER, 0) + remaining
                                                )
                                                cli_log(
                                                    f"[W{wid+1}] [-] 健康代理已耗尽，停止该 worker: "
                                                    f"{redact_sensitive_log_line(str(boot2))}"
                                                )
                                                worker_stop = True
                                                break
                                    if last_boot is not None and not worker_stop:
                                        cli_log(
                                            f"[W{wid+1}] [-] 切换代理后启动失败: "
                                            f"{redact_sensitive_log_line(str(last_boot))}"
                                        )
            finally:
                try:
                    maybe_stop_browser(
                        user_stopped=bool(controller.should_stop()),
                        log_callback=lambda m: cli_log(f"[W{wid+1}] {m}"),
                    )
                except Exception:
                    pass
                with stats_lock:
                    shared["success"] += local_success
                    shared["fail"] += local_fail
                    for k, v in local_fail_stats.items():
                        shared["fail_stats"][k] = shared["fail_stats"].get(k, 0) + v

        for wid, n in enumerate(chunks):
            if n <= 0:
                continue
            t = threading.Thread(target=worker, args=(n, wid), daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        success_count = shared["success"]
        fail_count = shared["fail"]
        fail_stats = shared["fail_stats"]
        cli_log(
            f"[*] 任务结束。成功 {success_count} | 失败 {fail_count}"
            + (f" | {format_fail_stats(fail_stats)}" if fail_count else "")
        )
        try:
            signal.signal(signal.SIGINT, _prev_sigint)
        except Exception:
            pass
        return

    try:
        single_rotate_idx = 0
        last_boot = None
        boot_attempts = max(
            1,
            min(max_proxy_boot_rotations + 1, len(pool) or 1),
        )
        for _boot_try in range(boot_attempts):
            px = ""
            try:
                px = pick_proxy_for_worker(0, single_rotate_idx)
                set_thread_proxy(px)
                cli_log(f"[*] 绑定代理: {redact_proxy(px) or '直连'}")
                start_browser(log_callback=cli_log)
                last_boot = None
                break
            except Exception as boot_exc:
                last_boot = boot_exc
                record_proxy_boot_failure(px, boot_exc)
                single_rotate_idx += 1
        if last_boot is not None:
            fail_count += count
            fail_stats[FAIL_BROWSER] = fail_stats.get(FAIL_BROWSER, 0) + count
            mark_slot_completed(count)
            cli_log(
                f"[-] 浏览器启动失败，{count} 个任务均记为失败: "
                f"{redact_sensitive_log_line(str(last_boot))}"
            )
            record_register_result(
                "fail",
                kind=FAIL_BROWSER,
                detail=str(last_boot),
                worker="W1",
                log_callback=cli_log,
            )
            return
        cli_log("[*] 浏览器已启动")
        i = 0
        while i < count:
            if controller.should_stop():
                break
            cli_log(f"--- 开始第 {i + 1}/{count} 个账号 ---")
            try:
                email = ""
                dev_token = ""
                code = ""
                mail_ok = False
                max_mail_retry = 3
                for mail_try in range(1, max_mail_retry + 1):
                    cli_log(f"[*] 1. 打开注册页 (尝试 {mail_try}/{max_mail_retry})")
                    open_signup_page(
                        log_callback=cli_log, cancel_callback=controller.should_stop
                    )
                    cli_log("[*] 2. 创建邮箱并提交")
                    email, dev_token = fill_email_and_submit(
                        log_callback=cli_log, cancel_callback=controller.should_stop
                    )
                    cli_log(f"[*] 邮箱: {email}")
                    cli_log(f"[Debug] 邮箱 token 已获取 (len={len(str(dev_token or ''))})")
                    try:
                        append_private_text(
                            accounts_side_file("mail_credentials.txt"),
                            f"{email}\t{dev_token}\n",
                        )
                    except Exception:
                        pass
                    cli_log("[*] 3. 拉取验证码")
                    try:
                        code = fill_code_and_submit(
                            email,
                            dev_token,
                            log_callback=cli_log,
                            cancel_callback=controller.should_stop,
                        )
                        mail_ok = True
                        break
                    except Exception as mail_exc:
                        msg = str(mail_exc)
                        if ("未收到验证码" in msg or "验证码" in msg) and mail_try < max_mail_retry:
                            cli_log(f"[!] 本邮箱未取到验证码，自动更换新邮箱重试: {msg}")
                            restart_browser(log_callback=cli_log)
                            sleep_with_cancel(1, controller.should_stop)
                            continue
                        raise

                if not mail_ok:
                    raise Exception("验证码阶段失败，已达到最大重试次数")
                cli_log(f"[*] 验证码: {code}")
                cli_log("[*] 4. 填写资料")
                profile = fill_profile_and_submit(
                    log_callback=cli_log, cancel_callback=controller.should_stop
                )
                cli_log(f"[*] 资料已填: {profile.get('given_name')} {profile.get('family_name')}")
                cli_log("[*] 5. 等待 sso cookie")
                sso = wait_for_sso_cookie(
                    log_callback=cli_log,
                    cancel_callback=controller.should_stop,
                    email=email,
                    password=profile.get("password", ""),
                )
                ensure_sso_oauth_eligible(sso, email=email, log_callback=cli_log)
                if config.get("enable_nsfw", True):
                    cli_log("[*] 6. 开启 NSFW")
                    nsfw_ok, nsfw_msg = enable_nsfw_for_token(
                        sso, log_callback=cli_log
                    )
                    if nsfw_ok:
                        cli_log(f"[+] NSFW 开启成功: {nsfw_msg}")
                    else:
                        cli_log(f"[!] NSFW 未开启，继续保存账号: {nsfw_msg}")
                try:
                    line = f"{email}----{profile.get('password','')}----{sso}\n"
                    # 以邮箱命名单独保存
                    email_file = account_file_for_email(email)
                    atomic_write_text(email_file, line)
                except Exception as file_exc:
                    cli_log(f"[!] 保存账号文件失败，当前账号不计为成功: {file_exc}")
                    _append_sso_pending(email, sso, log_callback=cli_log)
                    raise RuntimeError(f"保存账号文件失败: {file_exc}") from file_exc
                cpa_ok = add_sso_to_cpa(sso, email=email, log_callback=cli_log)
                success_count += 1
                mark_successful_account()
                retry_count_for_slot = 0
                i += 1
                if cpa_ok:
                    cli_log(f"[+] 注册成功: {email}")
                else:
                    cli_log(f"[+] 注册成功（SSO 已保存，CPA 入库失败）: {email}")
                record_register_result(
                    "ok",
                    email,
                    kind="success",
                    detail="cpa_ok" if cpa_ok else "cpa_fail",
                    worker="W1",
                    bot_flag=0,
                    log_callback=cli_log,
                )
                if success_count % 2 == 0:
                    single_rotate_idx += 1
                cli_log(f"[*] 当前统计: 成功 {success_count} | 失败 {fail_count}")
                mark_slot_completed()
                if success_count > 0 and success_count % MEMORY_CLEANUP_INTERVAL == 0 and i < count:
                    cleanup_runtime_memory(
                        log_callback=cli_log,
                        reason=f"已成功 {success_count} 个账号，执行定期清理",
                    )
            except RegistrationCancelled:
                cli_log("[!] 注册被停止")
                break
            except EmailDomainRejected as exc:
                kind = _cli_record_failure(exc)
                retry_count_for_slot = 0
                i += 1
                cli_log(
                    f"[-] 邮箱域名被 xAI 拒绝 [{FAIL_LABELS.get(kind, kind)}]: "
                    f"{redact_sensitive_log_line(str(exc))}"
                )
                record_register_result(
                    "fail",
                    email or "",
                    kind=kind,
                    detail=str(exc),
                    worker="W1",
                    log_callback=cli_log,
                )
                cli_log("[!] 请更换邮箱提供商或域名（如 Cloudflare 自建域 / MailNest），公共临时域常被拉黑")
                mark_slot_completed()
            except AccountRetryNeeded as exc:
                retry_count_for_slot += 1
                if retry_count_for_slot <= max_slot_retry:
                    cli_log(
                        f"[!] 当前账号流程卡住，重试第 {retry_count_for_slot}/{max_slot_retry} 次: "
                        f"{redact_sensitive_log_line(str(exc))}"
                    )
                else:
                    kind = _cli_record_failure(exc)
                    retry_count_for_slot = 0
                    i += 1
                    cli_log(
                        f"[-] 当前账号已达到最大重试次数，跳过 [{FAIL_LABELS.get(kind, kind)}]: "
                        f"{redact_sensitive_log_line(str(exc))}"
                    )
                    record_register_result(
                        "fail",
                        email or "",
                        kind=kind,
                        detail=str(exc),
                        worker="W1",
                        log_callback=cli_log,
                    )
                    mark_slot_completed()
            except Exception as exc:
                kind = _cli_record_failure(exc)
                retry_count_for_slot = 0
                i += 1
                message = str(exc)
                proxy_dead = any(
                    marker in message
                    for marker in (
                        "无法解析出口 IP",
                        "Failed to get IP address",
                        "代理不可用或过慢",
                        "出口IP命中黑名单",
                        "命中黑名单",
                    )
                )
                if proxy_dead:
                    record_proxy_boot_failure(
                        get_bound_proxy() or get_thread_proxy(), exc
                    )
                if kind == FAIL_RISK or proxy_dead or kind in (FAIL_TURNSTILE, FAIL_PROFILE):
                    single_rotate_idx += 1
                cli_log(
                    f"[-] 注册失败 [{FAIL_LABELS.get(kind, kind)}]: "
                    f"{redact_sensitive_log_line(message)}"
                )
                if kind != FAIL_RISK:
                    record_register_result(
                        "fail",
                        email or "",
                        kind=kind,
                        detail=message,
                        worker="W1",
                        log_callback=cli_log,
                    )
                mark_slot_completed()
            if controller.should_stop():
                break
            # 每轮结束只关浏览器，不立刻再开。
            # 下一轮 open_signup_page 会按需启动并导航到官网，避免空浏览器残留。
            if i >= count:
                continue
            # 账号间随机间隔
            wait_sec = parse_account_interval()
            if wait_sec > 0:
                cli_log(f"[*] 下一个账号前等待 {wait_sec:.0f} 秒...")
                _sleep_cancelable(wait_sec, controller.should_stop)
            try:
                stop_browser()
                time.sleep(0.5)
            except KeyboardInterrupt:
                controller.stop()
                cli_log("[!] 收到 Ctrl+C，正在停止（再按一次强制中断）")
                break
            except RegistrationCancelled:
                break
            except Exception as close_exc:
                if controller.should_stop():
                    break
                cli_log(f"[Debug] 轮次关闭浏览器失败: {close_exc}")
            try:
                px = pick_proxy_for_worker(0, single_rotate_idx)
                set_thread_proxy(px)
                cli_log(f"[*] 下号代理: {redact_proxy(px) or '直连'}")
            except Exception as proxy_exc:
                cli_log(
                    f"[-] 下号没有可用代理: "
                    f"{redact_sensitive_log_line(str(proxy_exc))}"
                )
                remaining = max(count - i, 0)
                fail_count += remaining
                fail_stats[FAIL_BROWSER] = fail_stats.get(FAIL_BROWSER, 0) + remaining
                break
    except KeyboardInterrupt:
        controller.stop()
        cli_log("[!] 收到 Ctrl+C，正在停止并清理")
    except RegistrationCancelled:
        cli_log("[!] 注册被停止")
    except Exception as exc:
        cli_log(f"[!] 任务异常: {redact_sensitive_log_line(str(exc))}")
    finally:
        try:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
        except Exception:
            pass
        try:
            user_stopped = bool(controller.should_stop())
            if user_stopped and not should_close_browser_after_run(True):
                maybe_stop_browser(user_stopped=True, log_callback=cli_log)
            else:
                cleanup_runtime_memory(log_callback=cli_log, reason="任务结束")
        except BaseException:
            pass
        try:
            cli_log(
                f"[*] 任务结束。成功 {success_count} | 失败 {fail_count}"
                + (f" | {format_fail_stats(fail_stats)}" if fail_count else "")
            )
        except BaseException:
            pass
        try:
            signal.signal(signal.SIGINT, _prev_sigint)
        except Exception:
            pass


def main_cli():
    load_config()
    _wire_runtime_modules()
    count = int(config.get("register_count", 1) or 1)
    if config.get("debug_mode"):
        count = 1
        config["register_workers"] = 1
        cli_log("[*] 调试模式：强制单账号，结束后不关闭浏览器")
    cli_log("[*] CLI 已加载配置")
    cli_log(f"[*] 当前邮箱服务商: {config.get('email_provider', 'duckmail')} | 注册数量: {count}")
    cli_log("[*] 输入 start 后开始；按 Ctrl+C 可强制停止")
    try:
        command = input("> ").strip().lower()
    except KeyboardInterrupt:
        cli_log("[!] 已取消")
        return
    if command != "start":
        cli_log("[!] 未输入 start，已退出")
        return
    try:
        run_registration_cli(count)
    except KeyboardInterrupt:
        # 清理阶段仍可能漏出，保证 CLI 干净退出
        cli_log("[!] 已停止")


def main():
    try:
        initialize_session_log()
    except OSError as exc:
        print(f"[日志] 无法创建日志文件: {exc}", flush=True)
    load_config()
    _wire_runtime_modules()
    if len(sys.argv) > 1 and sys.argv[1].strip().lower() in ("start", "cli", "--cli"):
        main_cli()
        return
    root = tk.Tk()
    setup_light_theme(root)
    app = GrokRegisterGUI(root)
    root.mainloop()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
