"""MoeMail 临时邮箱提供商。

API 参考：https://docs.moemail.app/api.html
鉴权头：X-API-Key
成功响应多为裸 JSON 对象（无 code/success 包装）；DELETE 返回 {"success": true}。
"""

from __future__ import annotations

import re
import threading
import time
from typing import Any, Callable, List, Optional, Tuple
from urllib.parse import urlparse

from email_providers.common import extract_verification_code, generate_username

HttpGet = Callable[..., Any]
HttpPost = Callable[..., Any]
HttpDelete = Callable[..., Any]

# 文档示例：3600000=1h, 86400000=1d, 604800000=7d, 0=永久
DEFAULT_EXPIRY_MS = 3_600_000

_account_ids: dict[str, str] = {}
_account_ids_lock = threading.Lock()
_domain_index = 0
_domain_cache: List[str] = []
_domain_cache_key: Optional[Tuple[str, str]] = None
_domain_lock = threading.Lock()


def reset_runtime_state() -> None:
    global _domain_index, _domain_cache, _domain_cache_key
    _domain_index = 0
    _domain_cache = []
    _domain_cache_key = None
    with _account_ids_lock:
        _account_ids.clear()


def normalize_base(base_url: str = "") -> str:
    """站点根 URL（不含路径尾斜杠）。配置可写 https://host 或 https://host/api。"""
    raw = str(base_url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    origin = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    path = (parsed.path or "").rstrip("/")
    # 允许用户误填 .../api 或 .../api/v1：统一剥到站点根，再拼 /api/...
    while path.endswith("/api") or path.endswith("/api/v1"):
        if path.endswith("/api/v1"):
            path = path[: -len("/api/v1")]
        else:
            path = path[: -len("/api")]
        path = path.rstrip("/")
    if path:
        return f"{origin}{path}"
    return origin


def _api(base: str, path: str) -> str:
    base = normalize_base(base)
    if not path.startswith("/"):
        path = "/" + path
    return f"{base}{path}"


def _headers(api_key: str, content_type: bool = False) -> dict:
    headers = {"Accept": "application/json", "X-API-Key": str(api_key or "").strip()}
    if content_type:
        headers["Content-Type"] = "application/json"
    return headers


def _parse_json(resp, action: str) -> Any:
    try:
        return resp.json()
    except Exception as exc:
        preview = str(getattr(resp, "text", "") or "")[:300]
        raise Exception(f"MoeMail {action} 返回非 JSON: {preview}") from exc


def _raise_http(resp, action: str) -> None:
    status = int(getattr(resp, "status_code", 0) or 0)
    if status < 400:
        return
    detail = ""
    try:
        data = resp.json()
        if isinstance(data, dict):
            detail = str(data.get("message") or data.get("error") or data)[:300]
        else:
            detail = str(data)[:300]
    except Exception:
        detail = str(getattr(resp, "text", "") or "")[:300]
    raise Exception(f"MoeMail {action} 失败 HTTP {status}: {detail or 'unknown'}")


def _unwrap_payload(data: Any) -> Any:
    """兼容裸对象 / {data: ...} / {code:200,data:...} / {success:true,data:...}。"""
    if not isinstance(data, dict):
        return data
    if "code" in data and data.get("code") not in (200, "200", 0, "0", None):
        msg = data.get("message") or data.get("error") or data
        raise Exception(f"MoeMail 业务失败: {msg}")
    if data.get("success") is False:
        msg = data.get("message") or data.get("error") or data
        raise Exception(f"MoeMail 业务失败: {msg}")
    if "data" in data and isinstance(data.get("data"), (dict, list)):
        # 若顶层已是业务字段（id/email/messages），优先顶层
        if any(k in data for k in ("id", "email", "address", "messages", "message", "emails")):
            return data
        return data.get("data")
    return data


def get_config(http_get: HttpGet, base_url: str, api_key: str) -> dict:
    """GET /api/config → defaultRole, emailDomains, adminContact, maxEmails。"""
    resp = http_get(
        _api(base_url, "/api/config"),
        headers=_headers(api_key),
        timeout=15,
    )
    _raise_http(resp, "获取配置")
    data = _unwrap_payload(_parse_json(resp, "获取配置"))
    return data if isinstance(data, dict) else {}


def list_domains(
    http_get: HttpGet,
    base_url: str,
    api_key: str,
    *,
    force_refresh: bool = False,
) -> List[str]:
    """从 /api/config 的 emailDomains（逗号分隔）解析可用域名。"""
    global _domain_cache, _domain_cache_key
    base = normalize_base(base_url)
    key = (base, str(api_key or "").strip())
    with _domain_lock:
        if (
            not force_refresh
            and _domain_cache
            and _domain_cache_key == key
        ):
            return list(_domain_cache)
    cfg = get_config(http_get, base, api_key)
    raw = str(cfg.get("emailDomains") or cfg.get("email_domains") or "")
    domains = [d.strip().lstrip("@") for d in re.split(r"[,，\s]+", raw) if d.strip()]
    with _domain_lock:
        _domain_cache = domains
        _domain_cache_key = key
    return list(domains)


def create_mailbox(
    http_get: HttpGet,
    http_post: HttpPost,
    base_url: str,
    api_key: str,
    *,
    domains: Optional[List[str]] = None,
    domain: str = "",
    name: str = "",
    expiry_time: int = DEFAULT_EXPIRY_MS,
) -> Tuple[str, str]:
    """POST /api/emails/generate → (address, email_id)。

    文档响应：{"id": "...", "email": "..."}
    """
    global _domain_index
    base = normalize_base(base_url)
    key = str(api_key or "").strip()
    if not base:
        raise Exception("MoeMail 站点 URL 未配置（moemail_api_base）")
    if not key:
        raise Exception("MoeMail API Key 未配置（moemail_api_key）")

    chosen = str(domain or "").strip().lstrip("@")
    if not chosen:
        cleaned = [d.strip().lstrip("@") for d in (domains or []) if str(d).strip()]
        if not cleaned:
            cleaned = list_domains(http_get, base, key)
        if not cleaned:
            raise Exception(
                "MoeMail 无可用域名：请在 defaultDomains / moemail_domain 配置，"
                "或确认 API Key 能读到 /api/config 的 emailDomains"
            )
        chosen = cleaned[_domain_index % len(cleaned)]
        _domain_index += 1

    payload = {
        "name": (name or generate_username(10)).strip(),
        "expiryTime": int(expiry_time) if expiry_time is not None else DEFAULT_EXPIRY_MS,
        "domain": chosen,
    }
    resp = http_post(
        _api(base, "/api/emails/generate"),
        json=payload,
        headers=_headers(key, content_type=True),
        timeout=30,
    )
    _raise_http(resp, "创建邮箱")
    data = _unwrap_payload(_parse_json(resp, "创建邮箱"))
    if not isinstance(data, dict):
        raise Exception(f"MoeMail 创建邮箱响应异常: {data!r}")

    email_id = str(data.get("id") or data.get("emailId") or "").strip()
    address = str(
        data.get("email")
        or data.get("address")
        or data.get("emailAddress")
        or ""
    ).strip()
    if not address and payload["name"] and chosen:
        address = f"{payload['name']}@{chosen}"
    if not address:
        raise Exception(f"MoeMail 返回邮箱地址为空: {data}")
    if not email_id:
        raise Exception(f"MoeMail 返回邮箱 id 为空: {data}")

    with _account_ids_lock:
        _account_ids[address.lower()] = email_id
    print(f"[MoeMail] 创建邮箱成功: {address} (id={email_id})")
    return address, email_id


def get_messages(
    http_get: HttpGet,
    base_url: str,
    email_id: str,
    api_key: str,
    cursor: Optional[str] = None,
) -> List[dict]:
    """GET /api/emails/{emailId} → messages[{id, from_address, subject, received_at}]。"""
    if not base_url or not api_key or not email_id:
        return []
    params = {}
    if cursor:
        params["cursor"] = cursor
    resp = http_get(
        _api(base_url, f"/api/emails/{email_id}"),
        params=params or None,
        headers=_headers(api_key),
        timeout=20,
    )
    _raise_http(resp, "获取邮件列表")
    data = _unwrap_payload(_parse_json(resp, "获取邮件列表"))
    if isinstance(data, list):
        return [m for m in data if isinstance(m, dict)]
    if isinstance(data, dict):
        messages = data.get("messages")
        if isinstance(messages, list):
            return [m for m in messages if isinstance(m, dict)]
    return []


def get_message_detail(
    http_get: HttpGet,
    base_url: str,
    email_id: str,
    message_id: str,
    api_key: str,
) -> dict:
    """GET /api/emails/{emailId}/{messageId} → message{id, content, html, ...}。"""
    resp = http_get(
        _api(base_url, f"/api/emails/{email_id}/{message_id}"),
        headers=_headers(api_key),
        timeout=20,
    )
    _raise_http(resp, "获取邮件详情")
    data = _unwrap_payload(_parse_json(resp, "获取邮件详情"))
    if not isinstance(data, dict):
        return {}
    # 文档：{"message": {...}}
    msg = data.get("message")
    if isinstance(msg, dict):
        return msg
    # 兼容直接返回正文对象
    if any(k in data for k in ("content", "html", "subject", "from_address")):
        return data
    return {}


def delete_mailbox(
    http_delete: HttpDelete,
    base_url: str,
    email_id: str,
    api_key: str,
) -> None:
    """DELETE /api/emails/{emailId}。"""
    if not base_url or not email_id or not api_key:
        return
    resp = http_delete(
        _api(base_url, f"/api/emails/{email_id}"),
        headers=_headers(api_key),
        timeout=15,
    )
    status = int(getattr(resp, "status_code", 0) or 0)
    if status >= 400 and status != 404:
        _raise_http(resp, "删除邮箱")


def cleanup_address(
    http_delete: Optional[HttpDelete],
    base_url: str,
    api_key: str,
    email: str,
    email_id: str = "",
) -> None:
    eid = str(email_id or "").strip()
    with _account_ids_lock:
        if not eid:
            eid = str(_account_ids.pop(str(email or "").lower(), "") or "")
        else:
            _account_ids.pop(str(email or "").lower(), None)
    if not eid or http_delete is None:
        return
    try:
        delete_mailbox(http_delete, base_url, eid, api_key)
        print(f"[MoeMail] 已删除临时邮箱: {email} (id={eid})")
    except Exception as exc:
        print(f"[MoeMail] 删除邮箱失败: {email} -> {exc}")


def _message_text(detail: dict, subject: str = "") -> Tuple[str, str]:
    parts: List[str] = []
    subj = str(subject or detail.get("subject") or "")
    for field in ("content", "text", "textContent", "text_content", "body", "snippet", "intro"):
        value = detail.get(field)
        if isinstance(value, str) and value.strip():
            parts.append(value)
    html_value = detail.get("html") or detail.get("htmlContent") or detail.get("html_content")
    if isinstance(html_value, str) and html_value.strip():
        parts.append(re.sub(r"<[^>]+>", " ", html_value))
    elif isinstance(html_value, list):
        parts.extend(
            re.sub(r"<[^>]+>", " ", item)
            for item in html_value
            if isinstance(item, str)
        )
    return subj, "\n".join(parts)


def wait_for_code(
    http_get: HttpGet,
    base_url: str,
    api_key: str,
    email_id: str,
    email: str = "",
    *,
    timeout: int = 180,
    poll_interval: int = 3,
    http_delete: Optional[HttpDelete] = None,
    cleanup: bool = True,
    raise_if_cancelled: Callable[[Optional[Callable[[], bool]]], None],
    sleep_with_cancel: Callable[[float, Optional[Callable[[], bool]]], None],
    log_callback: Optional[Callable[[str], None]] = None,
    cancel_callback: Optional[Callable[[], bool]] = None,
    resend_callback: Optional[Callable[[], None]] = None,
) -> str:
    """轮询邮件列表 + 详情，提取 xAI 验证码。"""
    base = normalize_base(base_url)
    key = str(api_key or "").strip()
    eid = str(email_id or "").strip()
    if not base:
        raise Exception("MoeMail 站点 URL 未配置")
    if not key:
        raise Exception("MoeMail API Key 未配置")
    if not eid:
        # 兼容：若 create 把 id 缓存在地址映射里
        with _account_ids_lock:
            eid = str(_account_ids.get(str(email or "").lower(), "") or "")
    if not eid:
        raise Exception("MoeMail email_id 为空，无法收信")

    deadline = time.time() + timeout
    seen_attempts: dict[str, int] = {}
    next_resend_at = time.time() + 35

    try:
        while time.time() < deadline:
            raise_if_cancelled(cancel_callback)
            if resend_callback and time.time() >= next_resend_at:
                try:
                    resend_callback()
                    if log_callback:
                        log_callback("[*] 已触发重新发送验证码")
                except Exception as exc:
                    if log_callback:
                        log_callback(f"[Debug] 触发重发验证码失败: {exc}")
                next_resend_at = time.time() + 35

            try:
                messages = get_messages(http_get, base, eid, key)
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] MoeMail 拉取邮件失败: {exc}")
                sleep_with_cancel(poll_interval, cancel_callback)
                continue

            if log_callback:
                log_callback(f"[Debug] MoeMail 本轮邮件数量: {len(messages)}")

            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                msg_id = str(msg.get("id") or msg.get("messageId") or "").strip()
                if not msg_id:
                    continue
                attempt = int(seen_attempts.get(msg_id, 0))
                if attempt >= 5:
                    continue
                seen_attempts[msg_id] = attempt + 1

                list_subject = str(msg.get("subject") or "")
                # 列表通常无正文，先拿 subject 试一次（xAI 主题常带码）
                code = extract_verification_code(list_subject, list_subject)
                if code:
                    if log_callback:
                        log_callback(f"[*] MoeMail 从主题提取到验证码: {code}")
                    return code

                try:
                    detail = get_message_detail(http_get, base, eid, msg_id, key)
                except Exception as exc:
                    if log_callback:
                        log_callback(f"[Debug] MoeMail 获取邮件详情失败: {exc}")
                    continue

                subject, combined = _message_text(detail, list_subject)
                if log_callback:
                    log_callback(f"[Debug] MoeMail 收到邮件: {subject or list_subject}")
                code = extract_verification_code(combined, subject or list_subject)
                if code:
                    if log_callback:
                        log_callback(f"[*] MoeMail 从邮件中提取到验证码: {code}")
                    return code
                if log_callback:
                    log_callback(
                        "[Debug] 邮件已解析但未提取到验证码 "
                        f"id={msg_id} attempt={seen_attempts[msg_id]}"
                    )

            sleep_with_cancel(poll_interval, cancel_callback)
        raise Exception(f"MoeMail 在 {timeout}s 内未收到验证码邮件")
    finally:
        if cleanup:
            cleanup_address(http_delete, base, key, email, email_id=eid)
