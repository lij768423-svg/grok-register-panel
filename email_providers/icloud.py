"""iCloud Hide My Email 提供商。

对接本地 icloud-hme 的供应商接口：
  POST   /api/vendor/mailbox   分配别名
  GET    /api/vendor/messages  读取验证码
  DELETE /api/vendor/mailbox   删除别名

注册无论成功或失败，都会在 wait_for_code 结束或下一次分配前删除本次别名。
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any, Callable, List, Optional, Tuple
from urllib.parse import urlparse

from email_providers.common import extract_verification_code

HttpGet = Callable[..., Any]
HttpPost = Callable[..., Any]
HttpDelete = Callable[..., Any]

_pending = threading.local()


def reset_runtime_state() -> None:
    """测试用：清空当前线程持有的待删除别名。"""
    _pending.token = ""


def normalize_base(base_url: str = "") -> str:
    raw = str(base_url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


def encode_mailbox_token(mailbox: dict[str, str]) -> str:
    return json.dumps(
        {
            "account_id": str(mailbox.get("account_id") or ""),
            "anonymous_id": str(mailbox.get("anonymous_id") or ""),
            "email": str(mailbox.get("email") or ""),
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def decode_mailbox_token(token: str) -> dict[str, str]:
    raw = str(token or "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        "account_id": str(data.get("account_id") or ""),
        "anonymous_id": str(data.get("anonymous_id") or ""),
        "email": str(data.get("email") or ""),
    }


def _json_payload(resp) -> dict:
    try:
        data = resp.json()
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _json_data(resp) -> dict:
    payload = _json_payload(resp)
    data = payload.get("data")
    return data if isinstance(data, dict) else {}


def _raise_http(resp, action: str) -> None:
    status = int(getattr(resp, "status_code", 0) or 0)
    if 200 <= status < 300:
        return
    payload = _json_payload(resp)
    message = str(payload.get("message") or "")[:240]
    if not message:
        message = str(getattr(resp, "text", "") or "")[:240]
    raise Exception(f"iCloud HME {action}失败 HTTP {status}: {message or 'unknown'}")


def _session_cookie(resp) -> str:
    cookies = getattr(resp, "cookies", None)
    if cookies is None:
        return ""
    getter = getattr(cookies, "get", None)
    if callable(getter):
        value = getter("hme_session")
        if value:
            return str(value)
    if isinstance(cookies, dict):
        return str(cookies.get("hme_session") or "")
    return ""


class ICloudHMEClient:
    """icloud-hme 会话客户端：登录一次，后续请求带 Cookie 与 CSRF。"""

    def __init__(
        self,
        http_get: HttpGet,
        http_post: HttpPost,
        http_delete: Optional[HttpDelete],
        api_base: str,
        admin_password: str,
        account_id: str = "",
    ):
        self.http_get = http_get
        self.http_post = http_post
        self.http_delete = http_delete
        self.api_base = normalize_base(api_base)
        self.admin_password = str(admin_password or "")
        self.account_id = str(account_id or "").strip()
        self._csrf = ""
        self._cookie = ""
        self._lock = threading.Lock()

    def _url(self, path: str) -> str:
        return f"{self.api_base}{path}"

    def _headers(self, mutate: bool = False) -> dict[str, str]:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self._cookie:
            headers["Cookie"] = f"hme_session={self._cookie}"
        if mutate and self._csrf:
            headers["X-CSRF-Token"] = self._csrf
        return headers

    def login(self) -> None:
        if not self.api_base:
            raise Exception("iCloud HME 实例地址未配置（icloud_hme_api_base）")
        if len(self.admin_password) < 8:
            raise Exception("iCloud HME 管理员密码未配置或不足 8 字符")
        resp = self.http_post(
            self._url("/api/auth/login"),
            json={"password": self.admin_password},
            headers=self._headers(),
            timeout=20,
            proxies={},
        )
        if int(getattr(resp, "status_code", 0) or 0) != 200:
            _raise_http(resp, "登录")
        csrf = str(_json_data(resp).get("csrf_token") or "")
        cookie = _session_cookie(resp)
        if not csrf or not cookie:
            raise Exception("iCloud HME 登录成功但未返回会话")
        self._csrf = csrf
        self._cookie = cookie

    def ensure_login(self) -> None:
        if self._csrf and self._cookie:
            return
        self.login()

    def _call(self, method: str, path: str, *, mutate: bool, **kwargs):
        kwargs.setdefault("timeout", 30)
        kwargs["proxies"] = {}
        self.ensure_login()
        kwargs["headers"] = self._headers(mutate=mutate)
        if method == "GET":
            resp = self.http_get(self._url(path), **kwargs)
        elif method == "POST":
            resp = self.http_post(self._url(path), **kwargs)
        elif method == "DELETE":
            if self.http_delete is None:
                raise Exception("iCloud HME 缺少 DELETE 客户端")
            resp = self.http_delete(self._url(path), **kwargs)
        else:
            raise Exception(f"不支持的 HTTP 方法: {method}")
        if int(getattr(resp, "status_code", 0) or 0) == 401:
            self._csrf = ""
            self._cookie = ""
            self.login()
            kwargs["headers"] = self._headers(mutate=mutate)
            if method == "GET":
                resp = self.http_get(self._url(path), **kwargs)
            elif method == "POST":
                resp = self.http_post(self._url(path), **kwargs)
            else:
                resp = self.http_delete(self._url(path), **kwargs)
        return resp

    def allocate(self, label: str = "grok-register") -> dict[str, str]:
        with self._lock:
            body: dict[str, str] = {"label": label or "grok-register"}
            if self.account_id:
                body["account_id"] = self.account_id
            resp = self._call("POST", "/api/vendor/mailbox", mutate=True, json=body)
            _raise_http(resp, "分配别名")
            data = _json_data(resp)
            email = str(data.get("email") or "").strip()
            if not email:
                raise Exception("iCloud HME 分配别名未返回 email")
            return {
                "email": email,
                "anonymous_id": str(data.get("anonymous_id") or ""),
                "account_id": str(data.get("account_id") or self.account_id),
                "label": str(data.get("label") or label),
            }

    def list_messages(self, account_id: str, alias: str, limit: int = 20, days: int = 7) -> List[dict]:
        with self._lock:
            resp = self._call(
                "GET",
                "/api/vendor/messages",
                mutate=False,
                params={
                    "account_id": account_id,
                    "alias": alias,
                    "limit": str(limit),
                    "days": str(days),
                },
            )
            _raise_http(resp, "读取邮件")
            messages = _json_data(resp).get("messages")
            return [item for item in messages if isinstance(item, dict)] if isinstance(messages, list) else []

    def release(self, account_id: str, email: str = "", anonymous_id: str = "") -> None:
        with self._lock:
            body: dict[str, str] = {}
            if account_id:
                body["account_id"] = account_id
            if email:
                body["email"] = email
            if anonymous_id:
                body["anonymous_id"] = anonymous_id
            resp = self._call("DELETE", "/api/vendor/mailbox", mutate=True, json=body)
            status = int(getattr(resp, "status_code", 0) or 0)
            if status not in (200, 404):
                _raise_http(resp, "删除别名")


def _client(
    http_get: HttpGet,
    http_post: HttpPost,
    http_delete: Optional[HttpDelete],
    api_base: str,
    admin_password: str,
    account_id: str = "",
) -> ICloudHMEClient:
    return ICloudHMEClient(
        http_get,
        http_post,
        http_delete,
        api_base,
        admin_password,
        account_id=account_id,
    )


def remember_mailbox(token: str) -> None:
    _pending.token = token or ""


def pending_mailbox_token() -> str:
    return str(getattr(_pending, "token", "") or "")


def create_mailbox(
    http_get: HttpGet,
    http_post: HttpPost,
    http_delete: Optional[HttpDelete],
    api_base: str,
    admin_password: str,
    account_id: str = "",
    label: str = "grok-register",
    log_callback: Optional[Callable[[str], None]] = None,
) -> Tuple[str, str]:
    """分配一个 HME 别名，返回 (email, token)。"""
    release_pending(
        http_get,
        http_post,
        http_delete,
        api_base,
        admin_password,
        log_callback=log_callback,
    )
    mailbox = _client(
        http_get, http_post, http_delete, api_base, admin_password, account_id
    ).allocate(label=label)
    email = mailbox["email"]
    token = encode_mailbox_token(mailbox)
    remember_mailbox(token)
    if log_callback:
        log_callback(f"[*] 已创建 iCloud 隐藏邮箱: {email}")
    return email, token


def release_mailbox(
    http_get: HttpGet,
    http_post: HttpPost,
    http_delete: Optional[HttpDelete],
    api_base: str,
    admin_password: str,
    token: str,
    log_callback: Optional[Callable[[str], None]] = None,
) -> None:
    meta = decode_mailbox_token(token)
    email = meta.get("email") or ""
    if not email and not meta.get("anonymous_id"):
        return
    if pending_mailbox_token() == token:
        _pending.token = ""
    try:
        _client(http_get, http_post, http_delete, api_base, admin_password).release(
            account_id=meta.get("account_id") or "",
            email=email,
            anonymous_id=meta.get("anonymous_id") or "",
        )
        if log_callback and email:
            log_callback(f"[*] 已删除 iCloud 隐藏邮箱: {email}")
    except Exception as exc:
        if log_callback:
            log_callback(f"[!] 删除 iCloud 隐藏邮箱失败: {exc}")
        else:
            raise


def release_pending(
    http_get: HttpGet,
    http_post: HttpPost,
    http_delete: Optional[HttpDelete],
    api_base: str,
    admin_password: str,
    log_callback: Optional[Callable[[str], None]] = None,
) -> None:
    token = pending_mailbox_token()
    _pending.token = ""
    if token:
        release_mailbox(
            http_get,
            http_post,
            http_delete,
            api_base,
            admin_password,
            token,
            log_callback=log_callback,
        )


def wait_for_code(
    http_get: HttpGet,
    http_post: HttpPost,
    token: str,
    email: str,
    *,
    api_base: str,
    admin_password: str,
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
    """轮询别名收件箱，提取 xAI 验证码；结束后按需删除别名。"""
    meta = decode_mailbox_token(token)
    account_id = meta.get("account_id") or ""
    mailbox = str(email or meta.get("email") or "").strip()
    if not mailbox:
        raise Exception("iCloud HME 邮箱地址为空")
    if not account_id:
        raise Exception("iCloud HME token 缺少 account_id")

    client = _client(http_get, http_post, http_delete, api_base, admin_password, account_id)
    deadline = time.time() + timeout
    seen_ids: set[str] = set()
    next_resend_at = time.time() + 35
    last_wait_log = 0.0
    try:
        while time.time() < deadline:
            raise_if_cancelled(cancel_callback)
            now = time.time()
            if log_callback and now - last_wait_log >= 15:
                log_callback(f"[Debug] iCloud 等待验证码中，剩余 {max(0, int(deadline - now))}s")
                last_wait_log = now
            if resend_callback and now >= next_resend_at:
                try:
                    resend_callback()
                    if log_callback:
                        log_callback("[*] 已触发重新发送验证码")
                except Exception as exc:
                    if log_callback:
                        log_callback(f"[Debug] 触发重发验证码失败: {exc}")
                next_resend_at = now + 35
            try:
                messages = client.list_messages(account_id, mailbox)
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] iCloud 拉取邮件失败: {exc}")
                sleep_with_cancel(poll_interval, cancel_callback)
                continue
            if log_callback:
                log_callback(f"[Debug] iCloud 本轮邮件数量: {len(messages)}")
            for msg in messages:
                msg_id = str(msg.get("id") or msg.get("msgid") or "").strip()
                if msg_id:
                    if msg_id in seen_ids:
                        continue
                    seen_ids.add(msg_id)
                to_addr = str(msg.get("to") or "").lower()
                if mailbox and to_addr and mailbox.lower() not in to_addr:
                    continue
                subject = str(msg.get("subject") or "")
                combined = "\n".join(
                    part
                    for part in (
                        subject,
                        str(msg.get("preview") or ""),
                        str(msg.get("text") or ""),
                        str(msg.get("body") or ""),
                    )
                    if str(part).strip()
                )
                if log_callback and subject:
                    log_callback(f"[Debug] iCloud 收到邮件: {subject}")
                code = extract_verification_code(combined, subject)
                if code:
                    if log_callback:
                        log_callback(f"[*] iCloud 从邮件中提取到验证码: {code}")
                    return code
            sleep_with_cancel(poll_interval, cancel_callback)
        raise Exception(f"iCloud 在 {timeout}s 内未收到验证码邮件")
    finally:
        if cleanup:
            release_pending(
                http_get,
                http_post,
                http_delete,
                api_base,
                admin_password,
                log_callback=log_callback,
            )
