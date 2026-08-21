"""Outlook MSA refresh_token 库存邮箱（jsonl / 文本）。

适配 Desktop 导出的仅含 email + refresh_token 的库存（M.C5… MSA RT），
无需密码、可不带 client_id（默认用 Microsoft Authentication Broker 公共客户端）。

支持格式：
1) JSONL 每行: {"email","refresh_token","client_id"?,"created_at"?}
2) 文本行: email----refresh_token
3) 四段: email----password----clientId----refresh_token

取号：从库存领取未使用账号（非购买临时邮）。
收信：OAuth refresh → Microsoft Graph /me/messages 轮询 xAI 验证码。
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from email_providers.common import extract_verification_code
from secure_files import (
    append_private_text,
    atomic_write_text,
    create_private_text,
    ensure_private_dir,
    exclusive_file_lock,
)

# Microsoft Authentication Broker — 实测可刷 M.C5… MSA RT 并读 Graph 邮件
DEFAULT_CLIENT_ID = "9e5f94bc-e8a4-4e73-b8be-63364c29d753"

# 备用公共客户端（无 client_id 时依次尝试）
FALLBACK_CLIENT_IDS = (
    DEFAULT_CLIENT_ID,
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Microsoft Office
    "27922004-5251-4030-b22d-91ecd9a37ea4",  # Outlook
    "000000004FD94165",  # Outlook mobile
    "aebc6443-996d-45c2-90f0-388ff96faa56",  # VS Code
)

TOKEN_ENDPOINTS: Tuple[Tuple[str, Dict[str, str]], ...] = (
    (
        "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
        {"scope": "https://graph.microsoft.com/.default offline_access"},
    ),
    (
        "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
        {
            "scope": (
                "https://graph.microsoft.com/Mail.Read "
                "offline_access openid profile"
            )
        },
    ),
    (
        "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        {"scope": "https://graph.microsoft.com/.default offline_access"},
    ),
    (
        "https://login.live.com/oauth20_token.srf",
        {"scope": "https://graph.microsoft.com/.default offline_access"},
    ),
    (
        "https://login.live.com/oauth20_token.srf",
        {},
    ),
)

GRAPH_MESSAGES_URL = "https://graph.microsoft.com/v1.0/me/messages"
GRAPH_JUNK_MESSAGES_URL = (
    "https://graph.microsoft.com/v1.0/me/mailFolders/junkemail/messages"
)
GRAPH_INBOX_FOLDER_URL = "https://graph.microsoft.com/v1.0/me/mailFolders/inbox"
ACCESS_TOKEN_SKEW_SECONDS = 90
WAIT_HEARTBEAT_SECONDS = 15
# Graph 连续空箱这么久就提前放弃，避免 180s 空耗；不记 used，库存可再领
EMPTY_INBOX_ABORT_SECONDS = 20
CODE_KEYWORDS = (
    "x.ai",
    "xai",
    "spacexai",
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
HttpPost = Callable[..., Any]
LogFn = Optional[Callable[[str], None]]
CancelFn = Optional[Callable[[], bool]]

_lock = threading.RLock()
_reserved: set[str] = set()
_token_map: Dict[str, Dict[str, Any]] = {}
_refresh_locks: Dict[str, threading.Lock] = {}
_refresh_locks_guard = threading.Lock()
_CODE_WAIT_LIMIT = max(
    1, int(os.environ.get("OUTLOOK_RT_CODE_WAIT_CONCURRENCY", "3") or 3)
)
_code_wait_sema = threading.Semaphore(_CODE_WAIT_LIMIT)

# refresh 连续失败多少次视为死号（秒退，避免空耗 180s）
MAX_REFRESH_FAILURES = 2
CLAIM_TTL_SECONDS = 60 * 60
# 死号/不可用 client 的典型错误片段
_DEAD_RT_MARKERS = (
    "client does not exist",
    "not enabled for consumers",
    "AADSTS700016",
    "AADSTS70000",
    "AADSTS50173",  # expired
    "AADSTS700082",  # expired due to inactivity
    "AADSTS700084",
    "invalid_grant",
    "interaction_required",
)


def normalize_inventory_path(path: str = "") -> str:
    return str(path or "").strip()


def used_path_for(inventory_path: str, used_path: str = "") -> Path:
    custom = str(used_path or "").strip()
    if custom:
        return Path(custom).expanduser()
    inv = Path(normalize_inventory_path(inventory_path)).expanduser()
    return inv.with_suffix(inv.suffix + ".used") if inv.suffix else Path(str(inv) + ".used")


def inventory_lock_path(inventory_path: str) -> Path:
    inv = Path(normalize_inventory_path(inventory_path)).expanduser()
    return inv.with_suffix(inv.suffix + ".lock") if inv.suffix else Path(str(inv) + ".lock")


def _is_dead_rt_error(err: Any) -> bool:
    text = str(err or "").lower()
    return any(marker.lower() in text for marker in _DEAD_RT_MARKERS)


def _safe_error(exc: Any) -> str:
    """Return an operational category without upstream response bodies."""
    text = str(exc or "")
    lowered = text.lower()
    for marker in _DEAD_RT_MARKERS:
        if marker.lower() in lowered:
            return marker
    for status in (400, 401, 403, 404, 408, 429, 500, 502, 503, 504):
        if str(status) in text:
            return f"HTTP {status}"
    name = type(exc).__name__ if exc is not None else "unknown_error"
    return name if name and name != "str" else "request_failed"


def _claim_dir(inventory_path: str) -> Path:
    inventory = Path(normalize_inventory_path(inventory_path)).expanduser()
    return Path(str(inventory) + ".claims")


def _claim_path(inventory_path: str, email: str) -> Path:
    digest = hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()
    return _claim_dir(inventory_path) / f"{digest}.claim"


def _claim_is_active(path: Path, now: float) -> bool:
    if not path.is_file():
        return False
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        created_at = float(payload.get("created_at") or 0)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        created_at = 0
    if created_at > 0 and now - created_at <= CLAIM_TTL_SECONDS:
        return True
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    return False


def _create_claim(inventory_path: str, email: str, token_key: str) -> bool:
    path = _claim_path(inventory_path, email)
    ensure_private_dir(path.parent)
    if _claim_is_active(path, time.time()):
        return False
    try:
        create_private_text(
            path,
            json.dumps(
                {"token_key": token_key, "created_at": time.time(), "pid": os.getpid()},
                ensure_ascii=True,
            ) + "\n",
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
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _parse_jsonl_row(obj: dict) -> Optional[Dict[str, str]]:
    email = str(obj.get("email") or obj.get("mail") or obj.get("address") or "").strip()
    rt = str(
        obj.get("refresh_token")
        or obj.get("refreshToken")
        or obj.get("rt")
        or ""
    ).strip()
    if not email or "@" not in email or not rt:
        return None
    client_id = str(
        obj.get("client_id") or obj.get("clientId") or obj.get("client") or ""
    ).strip()
    password = str(obj.get("password") or obj.get("pass") or "").strip()
    return {
        "email": email,
        "refresh_token": rt,
        "client_id": client_id,
        "password": password,
    }


def _parse_text_line(raw: str) -> Optional[Dict[str, str]]:
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    if "----" in line:
        parts = line.split("----")
        if len(parts) >= 4 and "@" in parts[0]:
            return {
                "email": parts[0].strip(),
                "password": parts[1].strip(),
                "client_id": parts[2].strip(),
                "refresh_token": "----".join(parts[3:]).strip(),
            }
        if len(parts) == 2 and "@" in parts[0]:
            return {
                "email": parts[0].strip(),
                "password": "",
                "client_id": "",
                "refresh_token": parts[1].strip(),
            }
        if len(parts) == 3 and "@" in parts[0]:
            # email----clientId----rt
            return {
                "email": parts[0].strip(),
                "password": "",
                "client_id": parts[1].strip(),
                "refresh_token": parts[2].strip(),
            }
    # email,refresh_token CSV
    if "," in line and "@" in line:
        left, _, right = line.partition(",")
        if "@" in left and right.strip():
            return {
                "email": left.strip(),
                "password": "",
                "client_id": "",
                "refresh_token": right.strip().strip('"'),
            }
    return None


def load_inventory(inventory_path: str) -> List[Dict[str, str]]:
    path = Path(normalize_inventory_path(inventory_path)).expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"Outlook RT 库存文件不存在: {path}")
    accounts: List[Dict[str, str]] = []
    seen: set[str] = set()
    text = path.read_text(encoding="utf-8-sig")
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        acc: Optional[Dict[str, str]] = None
        if line.startswith("{"):
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                acc = _parse_jsonl_row(obj)
        else:
            acc = _parse_text_line(line)
        if not acc:
            continue
        key = acc["email"].lower()
        if key in seen:
            continue
        seen.add(key)
        accounts.append(acc)
    if not accounts:
        raise RuntimeError(f"Outlook RT 库存无有效记录: {path}")
    return accounts


def _load_used(used_file: Path) -> set[str]:
    if not used_file.is_file():
        return set()
    out: set[str] = set()
    for line in used_file.read_text(encoding="utf-8").splitlines():
        item = line.strip().lower()
        if not item or item.startswith("#"):
            continue
        if "----" in item:
            item = item.split("----", 1)[0].strip()
        if item:
            out.add(item)
    return out


def mark_used(
    email: str,
    inventory_path: str,
    used_path: str = "",
    *,
    reason: str = "",
) -> None:
    """标记邮箱已用（成功取码 / 死 RT / 预检失败都可调用）。"""
    email_key = str(email or "").strip()
    if not email_key:
        return
    used_file = used_path_for(inventory_path, used_path)
    used_file.parent.mkdir(parents=True, exist_ok=True)
    line = email_key
    if reason:
        # 仅注释用途，_load_used 会取 @ 前的邮箱段
        safe = str(reason).replace("\n", " ").strip()[:120]
        line = f"{email_key}----{safe}"
    with _lock:
        with exclusive_file_lock(inventory_lock_path(inventory_path)):
            existing = _load_used(used_file)
            if email_key.lower() not in existing:
                append_private_text(used_file, line + "\n")
            _release_claim(inventory_path, email_key)
            _reserved.discard(email_key.lower())


def inventory_stats(inventory_path: str, used_path: str = "") -> Dict[str, int]:
    with _lock:
        with exclusive_file_lock(inventory_lock_path(inventory_path)):
            accounts = load_inventory(inventory_path)
            used = _load_used(used_path_for(inventory_path, used_path))
            now = time.time()
            total = len(accounts)
            available = sum(
                1
                for acc in accounts
                if acc["email"].lower() not in used
                and acc["email"].lower() not in _reserved
                and not _claim_is_active(_claim_path(inventory_path, acc["email"]), now)
            )
    return {"total": total, "used": total - available, "available": available}


def _refresh_lock(email: str) -> threading.Lock:
    key = email.lower()
    with _refresh_locks_guard:
        if key not in _refresh_locks:
            _refresh_locks[key] = threading.Lock()
        return _refresh_locks[key]


def _client_ids_for(account: Dict[str, str], default_client_id: str = "") -> List[str]:
    ordered: List[str] = []
    for cid in (
        str(account.get("client_id") or "").strip(),
        str(default_client_id or "").strip(),
        *FALLBACK_CLIENT_IDS,
    ):
        if cid and cid not in ordered:
            ordered.append(cid)
    return ordered or [DEFAULT_CLIENT_ID]


def _update_refresh_in_inventory(
    inventory_path: str,
    email_addr: str,
    new_refresh: str,
    *,
    client_id: str = "",
) -> None:
    if not new_refresh:
        return
    path = Path(normalize_inventory_path(inventory_path)).expanduser()
    if not path.is_file():
        return
    # 线程锁 + 文件锁，避免多 worker 并发写串行/覆盖
    with _lock:
        with exclusive_file_lock(inventory_lock_path(inventory_path)):
            lines = path.read_text(encoding="utf-8-sig").splitlines(True)
            out: List[str] = []
            changed = False
            email_l = email_addr.lower()
            for raw in lines:
                stripped = raw.strip()
                if not stripped or stripped.startswith("#"):
                    out.append(raw if raw.endswith("\n") else raw + "\n")
                    continue
                rewritten = None
                if stripped.startswith("{"):
                    try:
                        obj = json.loads(stripped)
                    except Exception:
                        obj = None
                    if isinstance(obj, dict):
                        em = str(obj.get("email") or obj.get("mail") or "").strip().lower()
                        if em == email_l:
                            if "refresh_token" in obj:
                                obj["refresh_token"] = new_refresh
                            elif "refreshToken" in obj:
                                obj["refreshToken"] = new_refresh
                            else:
                                obj["refresh_token"] = new_refresh
                            if client_id:
                                obj["client_id"] = client_id
                            rewritten = json.dumps(obj, ensure_ascii=False) + "\n"
                else:
                    acc = _parse_text_line(stripped)
                    if acc and acc["email"].lower() == email_l:
                        if acc.get("client_id") and acc.get("password") is not None and "----" in stripped:
                            parts = stripped.split("----")
                            if len(parts) >= 4:
                                cid = client_id or parts[2].strip()
                                rewritten = (
                                    f"{parts[0].strip()}----{parts[1].strip()}----"
                                    f"{cid}----{new_refresh}\n"
                                )
                            elif len(parts) == 2:
                                rewritten = f"{parts[0].strip()}----{new_refresh}\n"
                            elif len(parts) == 3:
                                cid = client_id or parts[1].strip()
                                rewritten = (
                                    f"{parts[0].strip()}----{cid}----{new_refresh}\n"
                                )
                        else:
                            rewritten = f"{acc['email']}----{new_refresh}\n"
                if rewritten is not None:
                    out.append(rewritten)
                    changed = True
                else:
                    out.append(raw if raw.endswith("\n") else raw + "\n")
            if changed:
                atomic_write_text(path, "".join(out), encoding="utf-8")


def refresh_access_token(
    http_post: HttpPost,
    account: Dict[str, str],
    *,
    inventory_path: str = "",
    default_client_id: str = "",
    persist_refresh: bool = True,
) -> str:
    email_addr = account["email"]
    with _refresh_lock(email_addr):
        cached = str(account.get("_access_token") or "")
        try:
            cached_exp = float(account.get("_access_expires") or 0)
        except Exception:
            cached_exp = 0.0
        if cached and time.time() < cached_exp:
            return cached
        refresh_token = account.get("refresh_token") or ""
        last_err: Any = None
        # 已绑定 client_id 时优先只试该 client，减少无效 client 噪音
        client_ids = _client_ids_for(account, default_client_id)
        # 默认只试前 2 个 client（账号自带 + DEFAULT），其余作兜底
        primary = client_ids[:2] or [DEFAULT_CLIENT_ID]
        fallback = client_ids[2:]
        # endpoints：优先 consumers + graph.default（实测可用）
        endpoints = list(TOKEN_ENDPOINTS[:2]) + list(TOKEN_ENDPOINTS[2:])

        def _try_clients(cids: List[str]) -> Optional[str]:
            nonlocal last_err, refresh_token
            for client_id in cids:
                for url, extra in endpoints:
                    try:
                        data = {
                            "client_id": client_id,
                            "refresh_token": refresh_token,
                            "grant_type": "refresh_token",
                            **extra,
                        }
                        resp = http_post(
                            url,
                            data=data,
                            headers={
                                "Content-Type": "application/x-www-form-urlencoded",
                                "Accept": "application/json",
                            },
                            timeout=30,
                        )
                        token_data: Dict[str, Any] = {}
                        try:
                            token_data = resp.json() if hasattr(resp, "json") else {}
                        except Exception:
                            try:
                                token_data = json.loads(getattr(resp, "text", "") or "{}")
                            except Exception:
                                token_data = {}
                        access = token_data.get("access_token")
                        if access:
                            account["client_id"] = client_id
                            new_rt = token_data.get("refresh_token") or refresh_token
                            if new_rt and new_rt != refresh_token:
                                account["refresh_token"] = new_rt
                                refresh_token = new_rt
                                if inventory_path and persist_refresh:
                                    _update_refresh_in_inventory(
                                        inventory_path,
                                        email_addr,
                                        new_rt,
                                        client_id=client_id,
                                    )
                            try:
                                ttl = int(token_data.get("expires_in") or 3600)
                            except Exception:
                                ttl = 3600
                            account["_access_token"] = str(access)
                            account["_access_expires"] = time.time() + max(
                                60, ttl - ACCESS_TOKEN_SKEW_SECONDS
                            )
                            return str(access)
                        error_code = str(token_data.get("error") or "").strip()
                        description = str(token_data.get("error_description") or "")
                        aadsts = next(
                            (
                                marker
                                for marker in _DEAD_RT_MARKERS
                                if marker.lower() in description.lower()
                            ),
                            "",
                        )
                        status = getattr(resp, "status_code", "?")
                        last_err = aadsts or error_code or f"HTTP {status}"
                        # 明确死号：不必继续扫 client
                        if _is_dead_rt_error(last_err) and any(
                            m in str(last_err).lower()
                            for m in (
                                "invalid_grant",
                                "aadsts50173",
                                "aadsts700082",
                                "aadsts700084",
                            )
                        ):
                            raise RuntimeError(
                                f"Outlook RT refresh 失败: {_safe_error(last_err)}"
                            )
                    except RuntimeError:
                        raise
                    except Exception as exc:
                        last_err = _safe_error(exc)
            return None

        access = _try_clients(primary)
        if access:
            return access
        # primary 全失败且像 client 配置问题，再试 fallback
        if fallback and not _is_dead_rt_error(last_err):
            access = _try_clients(fallback)
            if access:
                return access
        raise RuntimeError(f"Outlook RT refresh 失败: {_safe_error(last_err)}")


def take_mailbox(
    inventory_path: str,
    *,
    used_path: str = "",
    default_client_id: str = "",
    http_post: Optional[HttpPost] = None,
    http_get: Optional[HttpGet] = None,
    log_callback: LogFn = None,
    max_attempts: int = 8,
    skip_empty_inbox: bool = True,
    exclude_emails: Optional[set[str]] = None,
) -> Tuple[str, str]:
    """领取一个未使用的 Outlook 邮箱。

    若传入 http_post，会在取号后立刻 refresh 预检：
    - 成功：返回 (email, token_key)
    - 失败：mark_used 并换下一个，避免把死 RT 带进 180s 等码
    若同时传入 http_get 且 skip_empty_inbox，Inbox 为 0 的号直接跳过。

    返回 (email, token_key)。token_key 供 wait_for_code 使用。
    """
    path = normalize_inventory_path(inventory_path)
    if not path:
        raise Exception("请配置 outlook_rt_inventory（jsonl 或文本库存路径）")
    attempts = max(1, int(max_attempts or 8))
    excluded = {str(value or "").strip().lower() for value in (exclude_emails or set())}
    last_err = ""

    for _ in range(attempts):
        used_file = used_path_for(path, used_path)
        email = ""
        token_key = ""
        account: Dict[str, str] = {}
        with _lock:
            with exclusive_file_lock(inventory_lock_path(path)):
                accounts = load_inventory(path)
                used = _load_used(used_file)
                picked = None
                token_key = "outlook_rt:" + secrets.token_urlsafe(12)
                for acc in accounts:
                    cand = acc["email"].strip()
                    key = cand.lower()
                    if key in used or key in _reserved or key in excluded:
                        continue
                    if not _create_claim(path, cand, token_key):
                        continue
                    picked = acc
                    break
                if not picked:
                    break
                email = picked["email"].strip()
                key = email.lower()
                _reserved.add(key)
                account = dict(picked)
            if not account.get("client_id") and default_client_id:
                account["client_id"] = default_client_id
            _token_map[token_key] = {
                "account": account,
                "email": email,
                "inventory_path": path,
                "used_path": used_path,
                "default_client_id": default_client_id or DEFAULT_CLIENT_ID,
                "created_at": time.time(),
                "refresh_failures": 0,
            }

        # 无 http_post：保持旧行为（仅领取）
        if http_post is None:
            return email, token_key

        # refresh 预检
        try:
            access = refresh_access_token(
                http_post,
                account,
                inventory_path=path,
                default_client_id=default_client_id or DEFAULT_CLIENT_ID,
            )
        except Exception as exc:
            last_err = _safe_error(exc)
            if log_callback:
                log_callback(f"[!] Outlook RT 预检失败，弃用当前库存项: {last_err}")
            try:
                mark_used(
                    email,
                    path,
                    used_path,
                    reason=f"precheck_fail:{last_err}",
                )
            except Exception:
                pass
            release_reservation(token_key, email)
            continue

        if skip_empty_inbox and http_get is not None:
            try:
                inbox_n = inbox_total_count(http_get, access)
            except Exception as exc:
                last_err = _safe_error(exc)
                if log_callback:
                    log_callback(
                        f"[!] Outlook RT Inbox 预检失败，保留该号继续用: {last_err}"
                    )
                inbox_n = -1
            if inbox_n == 0:
                last_err = "empty_inbox"
                if log_callback:
                    log_callback("[*] Outlook RT Inbox=0，跳过空箱换号")
                try:
                    mark_used(
                        email,
                        path,
                        used_path,
                        reason="precheck_empty_inbox",
                    )
                except Exception:
                    pass
                release_reservation(token_key, email)
                continue

        if log_callback:
            extra = ""
            if skip_empty_inbox and http_get is not None:
                extra = f" inbox={inbox_n}"
            log_callback(f"[*] Outlook RT 预检 OK (at_len={len(access)}{extra})")
        return email, token_key

    used_file = used_path_for(path, used_path)
    hint = f"；最后预检错误: {last_err}" if last_err else ""
    raise Exception(
        f"Outlook RT 库存耗尽或预检均失败（已用/预留/死号），文件: {path}；"
        f"used={used_file}{hint}"
    )


def release_reservation(token_key: str = "", email: str = "") -> None:
    with _lock:
        if token_key and token_key in _token_map:
            info = _token_map.pop(token_key, None) or {}
            em = str(info.get("email") or email or "").strip().lower()
            inventory_path = str(info.get("inventory_path") or "")
            if em:
                if inventory_path:
                    with exclusive_file_lock(inventory_lock_path(inventory_path)):
                        _release_claim(inventory_path, em, token_key)
                _reserved.discard(em)
            return
        if email:
            _reserved.discard(email.strip().lower())
            for k, info in list(_token_map.items()):
                if str(info.get("email") or "").lower() == email.strip().lower():
                    _token_map.pop(k, None)
                    inventory_path = str(info.get("inventory_path") or "")
                    if inventory_path:
                        with exclusive_file_lock(inventory_lock_path(inventory_path)):
                            _release_claim(inventory_path, email, k)


def _resolve_session(
    token_key: str,
    email: str,
) -> Dict[str, Any]:
    info = _token_map.get(token_key or "")
    if info:
        return info
    # 允许仅凭 email 找回（同进程内）
    email_l = (email or "").strip().lower()
    if email_l:
        for info in _token_map.values():
            if str(info.get("email") or "").lower() == email_l:
                return info
    raise Exception("Outlook RT token_key 无效或会话已过期，请重新取号")


def inbox_total_count(http_get: HttpGet, access_token: str) -> int:
    """读取 Inbox totalItemCount；读不到则抛错。"""
    resp = http_get(
        GRAPH_INBOX_FOLDER_URL,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        },
        params={"$select": "id,displayName,totalItemCount,unreadItemCount"},
        timeout=20,
    )
    status = getattr(resp, "status_code", 0)
    if status >= 400:
        raise RuntimeError(f"Graph inbox folder HTTP {status}")
    try:
        data = resp.json() if hasattr(resp, "json") else {}
    except Exception as exc:
        raise RuntimeError("Graph inbox folder 响应无效") from exc
    if not isinstance(data, dict):
        raise RuntimeError("Graph inbox folder 响应无效")
    err = data.get("error")
    if isinstance(err, dict) and err.get("code"):
        raise RuntimeError(f"Graph inbox folder {err.get('code')}")
    try:
        return int(data.get("totalItemCount") or 0)
    except Exception as exc:
        raise RuntimeError("Graph inbox folder 无 totalItemCount") from exc


def _list_messages_url(
    http_get: HttpGet,
    access_token: str,
    url: str,
    *,
    top: int = 25,
) -> List[dict]:
    params = {
        "$top": str(max(5, min(50, int(top or 25)))),
        "$orderby": "receivedDateTime desc",
        "$select": "id,subject,receivedDateTime,from,bodyPreview,body",
    }
    resp = http_get(
        url,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        },
        params=params,
        timeout=40,
    )
    status = getattr(resp, "status_code", 0)
    if status >= 400:
        raise RuntimeError(f"Graph messages HTTP {status}")
    try:
        data = resp.json()
    except Exception as exc:
        raise RuntimeError("Graph messages 响应无效") from exc
    items = data.get("value") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


def list_messages(
    http_get: HttpGet,
    access_token: str,
    *,
    top: int = 25,
    include_junk: bool = True,
) -> List[dict]:
    inbox = _list_messages_url(http_get, access_token, GRAPH_MESSAGES_URL, top=top)
    if not include_junk:
        return inbox
    try:
        junk = _list_messages_url(
            http_get,
            access_token,
            GRAPH_JUNK_MESSAGES_URL,
            top=min(15, top),
        )
    except Exception:
        return inbox
    seen: set[str] = set()
    merged: List[dict] = []
    for item in inbox + junk:
        mid = str(item.get("id") or item.get("Id") or "")
        if mid:
            if mid in seen:
                continue
            seen.add(mid)
        merged.append(item)
    return merged


def _message_blob(item: dict) -> Tuple[str, str, str]:
    subject = str(item.get("subject") or item.get("Subject") or "")
    preview = str(item.get("bodyPreview") or item.get("BodyPreview") or "")
    body_obj = item.get("body") or item.get("Body") or {}
    if isinstance(body_obj, dict):
        body = str(body_obj.get("content") or body_obj.get("Content") or "")
    else:
        body = str(body_obj or "")
    return subject, preview, body


def find_code_in_messages(
    messages: List[dict],
    *,
    seen: Optional[set] = None,
    after_ts: float = 0.0,
) -> Optional[str]:
    seen = seen if seen is not None else set()
    for item in messages:
        mid = str(item.get("id") or item.get("Id") or "")
        subject, preview, body = _message_blob(item)
        fingerprint = mid or f"{subject}|{preview[:80]}"
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        received = str(
            item.get("receivedDateTime") or item.get("ReceivedDateTime") or ""
        )
        if after_ts > 0 and received:
            try:
                parsed = datetime.fromisoformat(received.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                ts = parsed.timestamp()
                # Graph 时间为 UTC；允许 5 分钟时钟偏差
                if ts + 300 < after_ts - 120:
                    continue
            except Exception:
                pass
        hay = f"{subject}\n{preview}\n{body}"
        low = hay.lower()
        code = extract_verification_code(hay, subject)
        if not code:
            continue
        if any(k in low for k in CODE_KEYWORDS) or "x.ai" in low or "xai" in low:
            return code
        # 主题像验证码邮件时也接受
        if "code" in subject.lower() or "验证" in subject:
            return code
    return None


def wait_for_code(
    http_get: HttpGet,
    http_post: HttpPost,
    token_key: str,
    email: str,
    *,
    timeout: int = 180,
    poll_interval: int = 4,
    raise_if_cancelled: Callable[[CancelFn], None],
    sleep_with_cancel: Callable[[float, CancelFn], None],
    log_callback: LogFn = None,
    cancel_callback: CancelFn = None,
    mark_on_success: bool = True,
    max_refresh_failures: int = MAX_REFRESH_FAILURES,
    empty_abort_seconds: int = EMPTY_INBOX_ABORT_SECONDS,
) -> str:
    if not _code_wait_sema.acquire(timeout=max(5, int(timeout or 20))):
        raise Exception("Outlook RT 等码并发已满，提前放弃")
    try:
        return _wait_for_code_unlocked(
            http_get,
            http_post,
            token_key,
            email,
            timeout=timeout,
            poll_interval=poll_interval,
            raise_if_cancelled=raise_if_cancelled,
            sleep_with_cancel=sleep_with_cancel,
            log_callback=log_callback,
            cancel_callback=cancel_callback,
            mark_on_success=mark_on_success,
            max_refresh_failures=max_refresh_failures,
            empty_abort_seconds=empty_abort_seconds,
        )
    finally:
        _code_wait_sema.release()


def _wait_for_code_unlocked(
    http_get: HttpGet,
    http_post: HttpPost,
    token_key: str,
    email: str,
    *,
    timeout: int = 180,
    poll_interval: int = 4,
    raise_if_cancelled: Callable[[CancelFn], None],
    sleep_with_cancel: Callable[[float, CancelFn], None],
    log_callback: LogFn = None,
    cancel_callback: CancelFn = None,
    mark_on_success: bool = True,
    max_refresh_failures: int = MAX_REFRESH_FAILURES,
    empty_abort_seconds: int = EMPTY_INBOX_ABORT_SECONDS,
) -> str:
    info = _resolve_session(token_key, email)
    account = info["account"]
    inventory_path = str(info.get("inventory_path") or "")
    used_path = str(info.get("used_path") or "")
    default_client_id = str(info.get("default_client_id") or DEFAULT_CLIENT_ID)
    mailbox = str(account.get("email") or email)
    after_ts = time.time() - 90
    deadline = time.time() + timeout
    seen: set = set()
    last_refresh_err = ""
    refresh_failures = int(info.get("refresh_failures") or 0)
    graph_transient_failure = False
    max_rf = max(1, int(max_refresh_failures or MAX_REFRESH_FAILURES))
    last_heartbeat = 0.0
    polls = 0
    empty_since: Optional[float] = None
    try:
        empty_limit = max(0, int(empty_abort_seconds))
    except Exception:
        empty_limit = EMPTY_INBOX_ABORT_SECONDS

    def _retire(reason: str) -> None:
        if not inventory_path:
            return
        try:
            mark_used(mailbox, inventory_path, used_path, reason=reason)
        except Exception as exc:
            if log_callback:
                log_callback(
                    f"[Debug] Outlook RT 标记已用失败: {_safe_error(exc)}"
                )
        release_reservation(token_key, mailbox)

    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        try:
            access = refresh_access_token(
                http_post,
                account,
                inventory_path=inventory_path,
                default_client_id=default_client_id,
            )
            last_refresh_err = ""
            refresh_failures = 0
            info["refresh_failures"] = 0
        except Exception as exc:
            last_refresh_err = _safe_error(exc)
            refresh_failures += 1
            info["refresh_failures"] = refresh_failures
            if log_callback:
                log_callback(
                    f"[Debug] Outlook RT token 刷新失败 "
                    f"({refresh_failures}/{max_rf}): {last_refresh_err}"
                )
            # 死号或连续失败：秒退，不再空耗 timeout
            if _is_dead_rt_error(exc) or refresh_failures >= max_rf:
                _retire(f"refresh_fail:{last_refresh_err[:80]}")
                raise Exception(
                    f"Outlook RT refresh 不可用，已弃用当前库存项: {last_refresh_err}"
                ) from exc
            sleep_with_cancel(min(poll_interval, 3), cancel_callback)
            continue
        try:
            messages = list_messages(http_get, access)
        except Exception as exc:
            graph_transient_failure = True
            safe_graph_error = _safe_error(exc)
            if log_callback:
                log_callback(f"[Debug] Outlook RT 拉取邮件失败: {safe_graph_error}")
            # Graph 401/403 也计一次 refresh 相关失败，避免死循环
            status = getattr(getattr(exc, "response", None), "status_code", None)
            err_s = safe_graph_error
            if "401" in err_s or "403" in err_s or status in (401, 403):
                account.pop("_access_token", None)
                account.pop("_access_expires", None)
                refresh_failures += 1
                info["refresh_failures"] = refresh_failures
                if refresh_failures >= max_rf:
                    _retire(f"graph_auth_fail:{err_s[:80]}")
                    raise Exception("Outlook RT Graph 鉴权失败，已弃用当前库存项") from exc
            sleep_with_cancel(poll_interval, cancel_callback)
            continue
        code = find_code_in_messages(messages, seen=seen, after_ts=after_ts)
        if code:
            if mark_on_success and inventory_path:
                try:
                    mark_used(mailbox, inventory_path, used_path, reason="code_ok")
                except Exception as exc:
                    if log_callback:
                        log_callback(
                            f"[!] Outlook RT 库存状态写入失败: {_safe_error(exc)}"
                        )
                    raise RuntimeError(
                        "Outlook RT 库存状态写入失败，当前项保持预留"
                    ) from exc
            if log_callback:
                log_callback("[*] Outlook RT 已提取验证码并完成库存记账")
            release_reservation(token_key, mailbox)
            return code
        polls += 1
        now = time.time()
        remaining = max(0, int(deadline - now))
        if messages:
            empty_since = None
        else:
            if empty_since is None:
                empty_since = now
            empty_for = now - empty_since
            if empty_limit and empty_for >= empty_limit:
                if inventory_path:
                    try:
                        mark_used(
                            mailbox,
                            inventory_path,
                            used_path,
                            reason="code_empty_abort",
                        )
                    except Exception as exc:
                        if log_callback:
                            log_callback(
                                f"[Debug] Outlook RT 标记已用失败: {_safe_error(exc)}"
                            )
                release_reservation(token_key, mailbox)
                if log_callback:
                    log_callback(
                        f"[*] Outlook RT 连续 {int(empty_for)}s 仍是 0 封信，记 used 后换号"
                    )
                raise Exception(
                    f"Outlook RT 连续 {int(empty_for)}s 收件箱为空（0 封信），提前放弃"
                )
        if log_callback and (
            polls == 1 or now - last_heartbeat >= WAIT_HEARTBEAT_SECONDS
        ):
            last_heartbeat = now
            extra = ""
            if empty_since is not None and empty_limit:
                extra = f" 空箱 {int(now - empty_since)}/{empty_limit}s"
            log_callback(
                f"[*] Outlook RT 等待验证码… 剩余 {remaining}s 邮件 {len(messages)} 封{extra}"
            )
        sleep_with_cancel(poll_interval, cancel_callback)

    hint = f"；最后刷新错误: {last_refresh_err}" if last_refresh_err else ""
    # 等满 timeout：
    # - 必须 release 预留，否则同进程换号会误判「库存耗尽」
    # - 若 refresh 一直正常（last_refresh_err 空），说明 xAI 侧可能已占用该邮箱，
    #   mark used 避免反复空等；若 refresh 曾失败则已在上面 retire
    if inventory_path and not last_refresh_err and not graph_transient_failure:
        try:
            mark_used(
                mailbox,
                inventory_path,
                used_path,
                reason="code_timeout_rt_ok",
            )
        except Exception as exc:
            if log_callback:
                log_callback(
                    f"[Debug] Outlook RT 标记已用失败: {_safe_error(exc)}"
                )
    release_reservation(token_key, mailbox)
    raise Exception(f"Outlook RT 在 {timeout}s 内未收到验证码邮件{hint}")


def probe_inventory(
    http_post: HttpPost,
    inventory_path: str,
    *,
    used_path: str = "",
    default_client_id: str = "",
) -> str:
    """连通性探测：统计库存 + 尝试刷新首个可用账号。"""
    stats = inventory_stats(inventory_path, used_path)
    if stats["available"] <= 0:
        return f"库存 total={stats['total']} available=0（请补充 jsonl 或清理 used）"
    email = ""
    token_key = ""
    try:
        email, token_key = take_mailbox(
            inventory_path,
            used_path=used_path,
            default_client_id=default_client_id,
        )
        sample = dict(_resolve_session(token_key, email)["account"])
        access = refresh_access_token(
            http_post,
            sample,
            inventory_path=inventory_path,
            default_client_id=default_client_id or DEFAULT_CLIENT_ID,
        )
        return (
            f"库存 total={stats['total']} available={stats['available']}；"
            f"样本 refresh OK (at_len={len(access)})"
        )
    except Exception as exc:
        return (
            f"库存 total={stats['total']} available={stats['available']}；"
            f"样本 refresh 失败: {_safe_error(exc)}"
        )
    finally:
        if token_key:
            release_reservation(token_key, email)
