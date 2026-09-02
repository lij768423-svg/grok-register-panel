"""Secure config management and non-destructive checks for email providers."""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from secure_files import atomic_write_json, exclusive_file_lock
from webui.email_domain_store import EmailDomainValidationError, normalize_domain
from webui.security_utils import redact_log_line


ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = Path(
    os.environ.get("EMAIL_PROVIDER_CONFIG_FILE", str(ROOT / "config.json"))
)
LOCK_PATH = CONFIG_PATH.with_suffix(CONFIG_PATH.suffix + ".lock")

PROVIDER_LABELS = {
    "cloudflare": "Cloudflare",
    "duckmail": "DuckMail / Mail.tm",
    "yyds": "YYDS",
    "mailnest": "MailNest",
    "cloudmail": "CloudMail",
    "moemail": "MoeMail",
    "outlook_rt": "Outlook RT 库存",
    "cf_outlook": "cf-outlook 邮箱 API",
    "inbucket": "Inbucket",
    "icloud": "iCloud HME",
}
SUPPORTED_PROVIDERS = tuple(PROVIDER_LABELS)

FIELD_DEFINITIONS = {
    "duckmail_api_base": {
        "label": "API Base",
        "type": "url",
        "default": "https://api.duckmail.sbs",
        "placeholder": "https://api.duckmail.sbs",
    },
    "duckmail_api_key": {
        "label": "API Key",
        "type": "password",
        "secret": True,
        "placeholder": "公共域可留空",
    },
    "cloudflare_api_base": {
        "label": "API Base",
        "type": "url",
        "placeholder": "https://temp-mail.example.com",
    },
    "cloudflare_api_key": {
        "label": "API Key",
        "type": "password",
        "secret": True,
    },
    "cloudflare_auth_mode": {
        "label": "鉴权模式",
        "type": "select",
        "default": "none",
        "options": ["none", "query-key", "bearer", "x-api-key", "x-admin-auth"],
    },
    "cloudflare_custom_auth": {
        "label": "全局密码",
        "type": "password",
        "secret": True,
    },
    "cloudflare_randomize_subdomain": {
        "label": "随机子域",
        "type": "select",
        "default": "true",
        "options": [
            {"value": "true", "label": "启用（需泛域收信）"},
            {"value": "false", "label": "关闭（固定域名）"},
        ],
    },
    "defaultDomains": {
        "label": "收信域名",
        "type": "text",
        "placeholder": "mail.example.com, inbox.example.net",
    },
    "cloudflare_path_domains": {
        "label": "域名接口",
        "type": "path",
        "default": "/api/domains",
    },
    "cloudflare_path_accounts": {
        "label": "建号接口",
        "type": "path",
        "default": "/api/new_address",
    },
    "cloudflare_path_token": {
        "label": "令牌接口",
        "type": "path",
        "default": "/api/token",
    },
    "cloudflare_path_messages": {
        "label": "收信接口",
        "type": "path",
        "default": "/api/mails",
    },
    "yyds_api_key": {
        "label": "API Key",
        "type": "password",
        "secret": True,
        "placeholder": "与 JWT 二选一",
    },
    "yyds_jwt": {
        "label": "JWT",
        "type": "password",
        "secret": True,
        "placeholder": "与 API Key 二选一",
    },
    "yyds_default_domain": {
        "label": "固定收信域名",
        "type": "domain",
        "placeholder": "留空自动选择",
    },
    "mailnest_api_key": {
        "label": "API Key",
        "type": "password",
        "secret": True,
    },
    "mailnest_project_code": {
        "label": "项目代码",
        "type": "text",
        "default": "x-ai001",
    },
    "cloudmail_url": {
        "label": "站点 URL",
        "type": "url",
        "placeholder": "https://mail.example.com",
    },
    "cloudmail_admin_email": {
        "label": "管理员邮箱",
        "type": "email",
    },
    "cloudmail_password": {
        "label": "管理员密码",
        "type": "password",
        "secret": True,
    },
    "moemail_api_base": {
        "label": "站点 URL",
        "type": "url",
        "placeholder": "https://mail.example.com",
    },
    "moemail_api_key": {
        "label": "API Key",
        "type": "password",
        "secret": True,
    },
    "moemail_domain": {
        "label": "固定收信域名",
        "type": "domain",
        "placeholder": "留空自动选择",
    },
    "moemail_expiry_ms": {
        "label": "邮箱有效期",
        "type": "select",
        "default": 3600000,
        "options": [
            {"value": 3600000, "label": "1 小时"},
            {"value": 86400000, "label": "1 天"},
            {"value": 604800000, "label": "7 天"},
            {"value": 0, "label": "永久"},
        ],
    },
    "outlook_rt_inventory": {
        "label": "库存文件路径",
        "type": "text",
        "placeholder": "/path/to/outlook_latest_50_with_rt.jsonl",
    },
    "outlook_rt_used_path": {
        "label": "已用记录路径（可选）",
        "type": "text",
        "placeholder": "默认 inventory.used",
    },
    "outlook_rt_client_id": {
        "label": "Client ID（可选）",
        "type": "text",
        "default": "9e5f94bc-e8a4-4e73-b8be-63364c29d753",
        "placeholder": "默认 Microsoft Authentication Broker",
    },
    "cf_outlook_api_base": {
        "label": "站点 URL",
        "type": "url",
        "placeholder": "https://mail.example.com",
    },
    "cf_outlook_api_key": {
        "label": "API Key",
        "type": "password",
        "secret": True,
    },
    "cf_outlook_inventory": {
        "label": "邮箱库存路径（可选）",
        "type": "text",
        "placeholder": "留空时通过 API 随机取 active 邮箱",
    },
    "cf_outlook_used_path": {
        "label": "已用记录路径（可选）",
        "type": "text",
        "placeholder": "默认 inventory.used",
    },
    "inbucket_api_base": {
        "label": "实例地址",
        "type": "url",
        "placeholder": "http://127.0.0.1:9000",
    },
    "inbucket_domain": {
        "label": "收信根域名（可多个）",
        "type": "text",
        "placeholder": "mail.example.com, box.example.net",
    },
    "inbucket_random_levels": {
        "label": "随机子域级数",
        "type": "select",
        "default": "0",
        "options": [
            {"value": "0", "label": "关闭（使用根域名）"},
            {"value": "1", "label": "随机 1 级子域"},
            {"value": "2", "label": "随机 2 级子域"},
            {"value": "1-2", "label": "随机 1-2 级子域"},
            {"value": "1-3", "label": "随机 1-3 级子域"},
        ],
    },
    "icloud_hme_api_base": {
        "label": "icloud-hme 地址",
        "type": "url",
        "default": "http://127.0.0.1:8081",
        "placeholder": "http://127.0.0.1:8081",
    },
    "icloud_hme_admin_password": {
        "label": "管理员密码",
        "type": "password",
        "secret": True,
        "placeholder": "与 ICLOUD_HME_ADMIN_PASSWORD 相同",
    },
    "icloud_hme_account_id": {
        "label": "账号 ID（可选）",
        "type": "text",
        "placeholder": "留空自动选择可用 iCloud 账号",
    },
}

PROVIDER_FIELDS = {
    "cloudflare": (
        "cloudflare_api_base",
        "cloudflare_auth_mode",
        "cloudflare_api_key",
        "cloudflare_custom_auth",
        "cloudflare_randomize_subdomain",
        "defaultDomains",
        "cloudflare_path_domains",
        "cloudflare_path_accounts",
        "cloudflare_path_token",
        "cloudflare_path_messages",
    ),
    "duckmail": ("duckmail_api_base", "duckmail_api_key"),
    "yyds": ("yyds_api_key", "yyds_jwt", "yyds_default_domain"),
    "mailnest": ("mailnest_api_key", "mailnest_project_code"),
    "cloudmail": (
        "cloudmail_url",
        "cloudmail_admin_email",
        "cloudmail_password",
        "defaultDomains",
    ),
    "moemail": (
        "moemail_api_base",
        "moemail_api_key",
        "moemail_domain",
        "moemail_expiry_ms",
    ),
    "outlook_rt": (
        "outlook_rt_inventory",
        "outlook_rt_used_path",
        "outlook_rt_client_id",
    ),
    "cf_outlook": (
        "cf_outlook_api_base",
        "cf_outlook_api_key",
        "cf_outlook_inventory",
        "cf_outlook_used_path",
    ),
    "inbucket": ("inbucket_api_base", "inbucket_domain", "inbucket_random_levels"),
    "icloud": (
        "icloud_hme_api_base",
        "icloud_hme_admin_password",
        "icloud_hme_account_id",
    ),
}

SECRET_FIELDS = {
    name for name, definition in FIELD_DEFINITIONS.items() if definition.get("secret")
}
DEFAULT_VALUES = {
    name: definition.get("default", "") for name, definition in FIELD_DEFINITIONS.items()
}
MAX_VALUE_LENGTH = 2048


class EmailProviderConfigError(ValueError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _provider(value: object) -> str:
    provider = str(value or "").strip().lower()
    if provider not in SUPPORTED_PROVIDERS:
        raise EmailProviderConfigError("不支持的邮箱服务商")
    return provider


def _read_unlocked() -> tuple[dict, str]:
    if not CONFIG_PATH.exists():
        return {}, ""
    try:
        import json

        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8") or "{}")
        if not isinstance(data, dict):
            raise ValueError("config.json 必须是 JSON 对象")
        return data, ""
    except Exception as exc:
        return {}, redact_log_line(str(exc))[:240]


def _string(value: object, *, strip: bool = True) -> str:
    text = str(value or "")
    if any(ord(char) < 32 and char not in "\t" for char in text):
        raise EmailProviderConfigError("配置值包含非法控制字符")
    text = text.strip() if strip else text
    if len(text) > MAX_VALUE_LENGTH:
        raise EmailProviderConfigError("配置值过长")
    return text


def _normalize_url(value: object) -> str:
    text = _string(value).rstrip("/")
    if not text:
        return ""
    parsed = urlparse(text)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise EmailProviderConfigError("地址必须是有效的 HTTP 或 HTTPS URL")
    if parsed.username or parsed.password:
        raise EmailProviderConfigError("地址中不能包含账号密码")
    return text


def _normalize_domains(value: object) -> str:
    text = _string(value)
    if not text:
        return ""
    domains = []
    seen = set()
    for part in re.split(r"[,，\s]+", text):
        if not part:
            continue
        try:
            domain = normalize_domain(part)
        except EmailDomainValidationError as exc:
            raise EmailProviderConfigError(str(exc)) from exc
        if domain not in seen:
            seen.add(domain)
            domains.append(domain)
    return ",".join(domains)


def _normalize_value(name: str, value: object):
    definition = FIELD_DEFINITIONS[name]
    field_type = definition.get("type")
    if field_type == "url":
        normalized = _normalize_url(value)
        return normalized or definition.get("default", "")
    if field_type == "domain":
        text = _string(value).lstrip("@")
        if not text:
            return ""
        try:
            return normalize_domain(text)
        except EmailDomainValidationError as exc:
            raise EmailProviderConfigError(str(exc)) from exc
    if name in {"defaultDomains", "inbucket_domain"}:
        return _normalize_domains(value)
    if field_type == "email":
        text = _string(value)
        if text and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", text):
            raise EmailProviderConfigError("管理员邮箱格式无效")
        return text
    if field_type == "path":
        text = _string(value) or str(definition.get("default") or "")
        if not text.startswith("/") or "://" in text or any(char.isspace() for char in text):
            raise EmailProviderConfigError(f"{definition['label']}必须是以 / 开头的接口路径")
        return text
    if field_type == "select":
        options = definition.get("options") or []
        allowed = {
            item.get("value") if isinstance(item, dict) else item for item in options
        }
        candidate = value
        if isinstance(definition.get("default"), int):
            try:
                candidate = int(value)
            except (TypeError, ValueError) as exc:
                raise EmailProviderConfigError(f"{definition['label']}无效") from exc
        else:
            candidate = _string(value) or definition.get("default", "")
        if candidate not in allowed:
            raise EmailProviderConfigError(f"{definition['label']}无效")
        return candidate
    if name == "mailnest_project_code":
        text = _string(value) or str(definition.get("default") or "")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", text):
            raise EmailProviderConfigError("项目代码格式无效")
        return text
    if name == "outlook_rt_client_id":
        text = _string(value) or str(definition.get("default") or "")
        if text and not re.fullmatch(r"[A-Za-z0-9._-]{8,80}", text):
            raise EmailProviderConfigError("Outlook Client ID 格式无效")
        return text
    if name in {"outlook_rt_inventory", "outlook_rt_used_path"}:
        text = _string(value)
        if text and any(ch in text for ch in "\n\r\0"):
            raise EmailProviderConfigError("库存路径无效")
        return text
    if name == "icloud_hme_account_id":
        text = _string(value)
        if text and not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", text):
            raise EmailProviderConfigError("iCloud 账号 ID 格式无效")
        return text
    if name in {"cf_outlook_inventory", "cf_outlook_used_path"}:
        text = _string(value)
        if text and any(ch in text for ch in "\n\r\0"):
            raise EmailProviderConfigError("邮箱库存路径无效")
        return text
    return _string(value, strip=name != "cloudmail_password")


def _field_payload(name: str) -> dict:
    definition = FIELD_DEFINITIONS[name]
    return {"name": name, **definition}


def _merged(raw: dict) -> dict:
    return {**DEFAULT_VALUES, **raw}


def _is_configured(provider: str, values: dict) -> bool:
    if provider == "cloudflare":
        return bool(values.get("cloudflare_api_base"))
    if provider == "duckmail":
        return bool(values.get("duckmail_api_base"))
    if provider == "yyds":
        return bool(values.get("yyds_api_key") or values.get("yyds_jwt"))
    if provider == "mailnest":
        return bool(values.get("mailnest_api_key"))
    if provider == "cloudmail":
        return all(
            values.get(key)
            for key in (
                "cloudmail_url",
                "cloudmail_admin_email",
                "cloudmail_password",
                "defaultDomains",
            )
        )
    if provider == "moemail":
        return bool(values.get("moemail_api_base") and values.get("moemail_api_key"))
    if provider == "outlook_rt":
        inventory = str(values.get("outlook_rt_inventory") or "").strip()
        return bool(inventory and Path(inventory).expanduser().is_file())
    if provider == "cf_outlook":
        inventory = str(values.get("cf_outlook_inventory") or "").strip()
        return bool(
            values.get("cf_outlook_api_base")
            and values.get("cf_outlook_api_key")
            and (not inventory or Path(inventory).expanduser().is_file())
        )
    if provider == "inbucket":
        return bool(values.get("inbucket_api_base") and values.get("inbucket_domain"))
    if provider == "icloud":
        password = str(values.get("icloud_hme_admin_password") or "")
        return bool(values.get("icloud_hme_api_base") and len(password) >= 8)
    return False


def _public_state(raw: dict, error: str = "") -> dict:
    values = _merged(raw)
    active = str(values.get("email_provider") or "cloudflare").strip().lower()
    if active not in SUPPORTED_PROVIDERS:
        active = "cloudflare"
    public_values = {
        name: "" if name in SECRET_FIELDS else values.get(name, definition.get("default", ""))
        for name, definition in FIELD_DEFINITIONS.items()
    }
    secret_configured = {name: bool(values.get(name)) for name in SECRET_FIELDS}
    providers = []
    for provider in SUPPORTED_PROVIDERS:
        providers.append(
            {
                "id": provider,
                "label": PROVIDER_LABELS[provider],
                "configured": _is_configured(provider, values),
                "fields": [_field_payload(name) for name in PROVIDER_FIELDS[provider]],
            }
        )
    try:
        mtime = CONFIG_PATH.stat().st_mtime
    except OSError:
        mtime = None
    return {
        "ok": not error,
        "error": error or None,
        "provider": active,
        "provider_label": PROVIDER_LABELS[active],
        "configured": _is_configured(active, values),
        "providers": providers,
        "values": public_values,
        "secret_configured": secret_configured,
        "config_exists": CONFIG_PATH.exists(),
        "mtime": mtime,
    }


def read_email_provider_config() -> dict:
    with exclusive_file_lock(LOCK_PATH):
        raw, error = _read_unlocked()
    return _public_state(raw, error)


def _candidate_config(
    raw: dict,
    provider: object,
    settings: object,
    clear_secrets: object = None,
) -> dict:
    normalized_provider = _provider(provider)
    if not isinstance(settings, dict):
        raise EmailProviderConfigError("settings 必须是 JSON 对象")
    allowed = set(PROVIDER_FIELDS[normalized_provider])
    unknown = sorted(set(settings) - allowed)
    if unknown:
        raise EmailProviderConfigError(f"包含不支持的配置字段: {unknown[0]}")
    if clear_secrets is None:
        clear = set()
    elif isinstance(clear_secrets, list):
        clear = {str(item or "").strip() for item in clear_secrets}
    else:
        raise EmailProviderConfigError("clear_secrets 必须是数组")
    if not clear <= (allowed & SECRET_FIELDS):
        raise EmailProviderConfigError("包含不支持的密钥清除字段")

    updated = dict(raw)
    updated["email_provider"] = normalized_provider
    for name, value in settings.items():
        if name in SECRET_FIELDS and not str(value or ""):
            continue
        updated[name] = _normalize_value(name, value)
    for name in clear:
        updated[name] = ""
    return updated


def save_email_provider_config(
    provider: object,
    settings: object,
    *,
    clear_secrets: object = None,
) -> dict:
    with exclusive_file_lock(LOCK_PATH):
        raw, error = _read_unlocked()
        if error:
            raise RuntimeError(f"config.json 无法读取: {error}")
        updated = _candidate_config(raw, provider, settings, clear_secrets)
        atomic_write_json(CONFIG_PATH, updated)
    result = _public_state(updated)
    result["saved_at"] = _utc_now()
    return result


def test_email_provider_config(
    provider: object,
    settings: object,
    *,
    clear_secrets: object = None,
    http_get=None,
    http_post=None,
) -> dict:
    with exclusive_file_lock(LOCK_PATH):
        raw, error = _read_unlocked()
    if error:
        raise RuntimeError(f"config.json 无法读取: {error}")
    candidate = _candidate_config(raw, provider, settings, clear_secrets)
    normalized_provider = _provider(provider)
    if http_get is None or http_post is None:
        import requests

        http_get = http_get or requests.get
        http_post = http_post or requests.post
    import connectivity

    _, ok, detail = connectivity.check_email_api(
        normalized_provider,
        candidate,
        http_get,
        http_post,
    )
    return {
        "ok": bool(ok),
        "provider": normalized_provider,
        "provider_label": PROVIDER_LABELS[normalized_provider],
        "detail": redact_log_line(str(detail))[:300],
        "checked_at": _utc_now(),
    }
