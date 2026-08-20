"""cf-outlook-email API provider.

The upstream service exposes existing Outlook mailboxes through
``GET /api/external/emails``.  Mailboxes are therefore taken from a local
email-only inventory rather than created through the API.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from email_providers.common import extract_verification_code
from secure_files import (
    append_private_text,
    create_private_text,
    ensure_private_dir,
    exclusive_file_lock,
)

API_PATH = "/api/external/emails"
DEFAULT_FOLDER = "all"
DEFAULT_TOP = 10
WAIT_HEARTBEAT_SECONDS = 15
CODE_KEYWORDS = (
    "x.ai",
    "xai",
    "grok",
    "verification",
    "verify",
    "code",
    "confirm",
    "security",
    "one-time",
    "验证码",
    "确认",
)

HttpGet = Callable[..., Any]
LogFn = Optional[Callable[[str], None]]
CancelFn = Optional[Callable[[], bool]]

_lock = threading.RLock()
_reserved: set[str] = set()
_sessions: Dict[str, Dict[str, str]] = {}


class ApiError(RuntimeError):
    """An upstream API failure with a status suitable for retry decisions."""

    def __init__(self, status: int, message: str = "request_failed") -> None:
        self.status = int(status or 0)
        super().__init__(message)


def normalize_base(base_url: str = "") -> str:
    """Normalize the service site URL while retaining an optional prefix."""
    raw = str(base_url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    origin = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    path = (parsed.path or "").rstrip("/")
    if path == "/api":
        path = ""
    return f"{origin}{path}" if path else origin


def api_url(base_url: str) -> str:
    base = normalize_base(base_url)
    return f"{base}{API_PATH}" if base else ""


def used_path_for(inventory_path: str, used_path: str = "") -> Path:
    custom = str(used_path or "").strip()
    if custom:
        return Path(custom).expanduser()
    path = Path(str(inventory_path or "")).expanduser()
    return path.with_suffix(path.suffix + ".used") if path.suffix else Path(str(path) + ".used")


def inventory_lock_path(inventory_path: str) -> Path:
    path = Path(str(inventory_path or "")).expanduser()
    return path.with_suffix(path.suffix + ".lock") if path.suffix else Path(str(path) + ".lock")


def _claim_dir(inventory_path: str) -> Path:
    return Path(str(Path(str(inventory_path or "")).expanduser()) + ".claims")


def _claim_path(inventory_path: str, email: str) -> Path:
    digest = hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()
    return _claim_dir(inventory_path) / f"{digest}.claim"


def _claim_is_active(path: Path, now: float) -> bool:
    if not path.is_file():
        return False
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        created_at = float(payload.get("created_at") or 0)
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        created_at = 0
    if created_at and now - created_at <= 3600:
        return True
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    return False


def _create_claim(inventory_path: str, email: str, token_key: str) -> bool:
    path = _claim_path(inventory_path, email)
    ensure_private_dir(path.parent)
    try:
        create_private_text(
            path,
            json.dumps(
                {"token_key": token_key, "created_at": time.time(), "pid": os.getpid()},
                ensure_ascii=True,
            )
            + "\n",
        )
        return True
    except FileExistsError:
        return False


def _release_claim(inventory_path: str, email: str, token_key: str = "") -> None:
    path = _claim_path(inventory_path, email)
    if not path.is_file():
        return
    if token_key:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if str(payload.get("token_key") or "") != token_key:
                return
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            return
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _parse_row(value: object) -> Optional[Dict[str, str]]:
    if not isinstance(value, dict):
        return None
    email = str(value.get("email") or value.get("mail") or value.get("address") or "").strip()
    if not email or not re.fullmatch(r"[^\s@]+@[^\s@]+", email):
        return None
    return {"email": email}


def load_inventory(inventory_path: str) -> List[Dict[str, str]]:
    path = Path(str(inventory_path or "")).expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"cf_outlook 库存文件不存在: {path}")
    accounts: List[Dict[str, str]] = []
    seen: set[str] = set()
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        item: Optional[Dict[str, str]] = None
        if line.startswith("{"):
            try:
                item = _parse_row(json.loads(line))
            except (TypeError, ValueError, json.JSONDecodeError):
                item = None
        else:
            email = line.split("----", 1)[0].strip()
            if re.fullmatch(r"[^\s@]+@[^\s@]+", email):
                item = {"email": email}
        if not item:
            continue
        key = item["email"].lower()
        if key not in seen:
            seen.add(key)
            accounts.append(item)
    if not accounts:
        raise RuntimeError(f"cf_outlook 库存无有效邮箱: {path}")
    return accounts


def _load_used(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    used = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        value = line.strip().split("----", 1)[0].strip().lower()
        if value:
            used.add(value)
    return used


def mark_used(email: str, inventory_path: str, used_path: str = "", *, reason: str = "") -> None:
    mailbox = str(email or "").strip()
    if not mailbox:
        return
    used_file = used_path_for(inventory_path, used_path)
    with _lock:
        with exclusive_file_lock(inventory_lock_path(inventory_path)):
            existing = _load_used(used_file)
            if mailbox.lower() not in existing:
                suffix = str(reason or "").replace("\n", " ").strip()[:120]
                append_private_text(used_file, f"{mailbox}{'----' + suffix if suffix else ''}\n")
            _release_claim(inventory_path, mailbox)
            _reserved.discard(mailbox.lower())


def inventory_stats(inventory_path: str, used_path: str = "") -> Dict[str, int]:
    with _lock:
        with exclusive_file_lock(inventory_lock_path(inventory_path)):
            accounts = load_inventory(inventory_path)
            used = _load_used(used_path_for(inventory_path, used_path))
            now = time.time()
            available = sum(
                1
                for item in accounts
                if item["email"].lower() not in used
                and item["email"].lower() not in _reserved
                and not _claim_is_active(_claim_path(inventory_path, item["email"]), now)
            )
    return {"total": len(accounts), "used": len(accounts) - available, "available": available}


def first_available_email(inventory_path: str, used_path: str = "") -> str:
    """Return one unconsumed mailbox for a read-only connectivity probe."""
    accounts = load_inventory(inventory_path)
    used = _load_used(used_path_for(inventory_path, used_path))
    return next(
        (item["email"] for item in accounts if item["email"].lower() not in used),
        "",
    )


def take_mailbox(inventory_path: str, *, used_path: str = "", max_attempts: int = 8) -> Tuple[str, str]:
    path = str(inventory_path or "").strip()
    if not path:
        raise RuntimeError("请配置 cf_outlook_inventory（每行一个邮箱或 JSONL email 字段）")
    for _ in range(max(1, int(max_attempts or 8))):
        token_key = "cf_outlook:" + secrets.token_urlsafe(12)
        with _lock:
            with exclusive_file_lock(inventory_lock_path(path)):
                used = _load_used(used_path_for(path, used_path))
                for item in load_inventory(path):
                    email = item["email"].strip()
                    key = email.lower()
                    if key in used or key in _reserved:
                        continue
                    if not _create_claim(path, email, token_key):
                        continue
                    _reserved.add(key)
                    _sessions[token_key] = {
                        "email": email,
                        "inventory_path": path,
                        "used_path": str(used_path or ""),
                    }
                    return email, token_key
        time.sleep(0.01)
    raise RuntimeError(f"cf_outlook 库存耗尽（已用/预留），文件: {Path(path).expanduser()}")


def release_reservation(token_key: str = "", email: str = "") -> None:
    with _lock:
        session = _sessions.pop(token_key, None) if token_key else None
        mailbox = str((session or {}).get("email") or email or "").strip()
        inventory = str((session or {}).get("inventory_path") or "")
        if mailbox and inventory:
            with exclusive_file_lock(inventory_lock_path(inventory)):
                _release_claim(inventory, mailbox, token_key)
        if mailbox:
            _reserved.discard(mailbox.lower())


def _safe_api_error(resp: Any) -> str:
    status = int(getattr(resp, "status_code", 0) or 0)
    try:
        data = resp.json()
    except Exception:
        data = {}
    error = data.get("error") if isinstance(data, dict) else {}
    code = error.get("code") if isinstance(error, dict) else ""
    return str(code or f"HTTP {status or 'unknown'}")[:80]


def _messages(http_get: HttpGet, base_url: str, api_key: str, email: str) -> List[dict]:
    key = str(api_key or "").strip()
    if not key:
        raise ApiError(401, "cf_outlook API Key 未配置")
    resp = http_get(
        api_url(base_url),
        headers={"Accept": "application/json", "X-API-Key": key},
        params={
            "email": email,
            "folder": DEFAULT_FOLDER,
            "top": str(DEFAULT_TOP),
            "includeBody": "1",
        },
        timeout=20,
        proxies={},
    )
    status = int(getattr(resp, "status_code", 0) or 0)
    if status >= 400:
        raise ApiError(status, _safe_api_error(resp))
    try:
        payload = resp.json()
    except Exception as exc:
        raise ApiError(502, "invalid_json") from exc
    if not isinstance(payload, dict) or payload.get("success") is False:
        error = payload.get("error") if isinstance(payload, dict) else {}
        code = error.get("code") if isinstance(error, dict) else "request_failed"
        raise ApiError(status if status >= 400 else 502, str(code or "request_failed")[:80])
    data = payload.get("data")
    items = data.get("items") if isinstance(data, dict) else []
    return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []


def _message_text(item: dict) -> Tuple[str, str]:
    subject = str(item.get("subject") or "")
    parts = [str(item.get("bodyPreview") or "")]
    body = item.get("body")
    if isinstance(body, dict):
        parts.append(str(body.get("content") or body.get("text") or ""))
    elif body:
        parts.append(str(body))
    return subject, "\n".join(value for value in parts if value)


def find_code_in_messages(messages: List[dict], *, seen: Optional[set] = None, after_ts: float = 0.0) -> Optional[str]:
    seen = seen if seen is not None else set()
    for item in messages:
        subject, body = _message_text(item)
        fingerprint = str(item.get("id") or f"{subject}|{body[:100]}")
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        received = str(item.get("receivedDateTime") or "")
        if after_ts and received:
            try:
                parsed = datetime.fromisoformat(received.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                if parsed.timestamp() + 300 < after_ts - 120:
                    continue
            except ValueError:
                pass
        haystack = f"{subject}\n{body}"
        code = extract_verification_code(haystack, subject)
        if not code:
            continue
        lowered = haystack.lower()
        if any(keyword in lowered for keyword in CODE_KEYWORDS) or "code" in subject.lower() or "验证" in subject:
            return code
    return None


def wait_for_code(
    http_get: HttpGet,
    base_url: str,
    api_key: str,
    token_key: str,
    email: str,
    *,
    timeout: int = 180,
    poll_interval: int = 4,
    raise_if_cancelled: Callable[[CancelFn], None],
    sleep_with_cancel: Callable[[float, CancelFn], None],
    log_callback: LogFn = None,
    cancel_callback: CancelFn = None,
) -> str:
    session = _sessions.get(token_key) or {}
    inventory = str(session.get("inventory_path") or "")
    used_path = str(session.get("used_path") or "")
    mailbox = str(session.get("email") or email or "").strip()
    try:
        if not normalize_base(base_url):
            raise RuntimeError("未配置 cf_outlook_api_base")
        if not mailbox:
            raise RuntimeError("cf_outlook 邮箱地址为空")
        deadline = time.time() + max(1, int(timeout or 180))
        after_ts = time.time() - 90
        seen: set = set()
        polls = 0
        last_heartbeat = 0.0
        while time.time() < deadline:
            raise_if_cancelled(cancel_callback)
            try:
                messages = _messages(http_get, base_url, api_key, mailbox)
            except ApiError as exc:
                if exc.status in (400, 401, 403, 404):
                    raise RuntimeError(f"cf_outlook API {exc.status}: {exc}") from exc
                if log_callback:
                    log_callback(f"[Debug] cf_outlook 拉取邮件失败: {exc}")
                sleep_with_cancel(min(max(1, int(poll_interval or 4)), 5), cancel_callback)
                continue
            code = find_code_in_messages(messages, seen=seen, after_ts=after_ts)
            if code:
                if inventory:
                    mark_used(mailbox, inventory, used_path, reason="code_ok")
                release_reservation(token_key, mailbox)
                if log_callback:
                    log_callback("[*] cf_outlook 已提取验证码并完成库存记账")
                return code
            polls += 1
            now = time.time()
            if log_callback and (polls == 1 or now - last_heartbeat >= WAIT_HEARTBEAT_SECONDS):
                last_heartbeat = now
                log_callback(f"[*] cf_outlook 等待验证码… 剩余 {max(0, int(deadline - now))}s 邮件 {len(messages)} 封")
            sleep_with_cancel(max(1, int(poll_interval or 4)), cancel_callback)
        if inventory:
            mark_used(mailbox, inventory, used_path, reason="code_timeout")
        raise RuntimeError(f"cf_outlook 在 {timeout}s 内未收到验证码邮件")
    except Exception:
        release_reservation(token_key, mailbox)
        raise


def probe_api(http_get: HttpGet, base_url: str, api_key: str, email: str) -> str:
    """Read one configured mailbox without changing inventory state."""
    items = _messages(http_get, base_url, api_key, email)
    return f"cf_outlook 可达；邮箱当前返回 {len(items)} 封邮件"
