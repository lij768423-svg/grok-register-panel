"""Outlook/Hotmail 真实邮箱 provider。

账号池行格式: email----password----client_id----refresh_token
create_mailbox 加锁领取账号，先保存已用记录再更新待用池，并记录 IMAP 基线 UID；
wait_for_code 用 refresh_token 换 access token 后走 IMAP XOAUTH2 轮询基线之后的新 x.ai 邮件。
"""

from __future__ import annotations

import email as email_lib
import email.header
import imaplib
import sys
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Callable, Optional

import requests as _requests

from secure_files import atomic_write_text, exclusive_file_lock

MS_TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
IMAP_HOST = "imap-mail.outlook.com"
IMAP_PORT = 993
IMAP_SCOPE = "offline_access https://outlook.office.com/IMAP.AccessAsUser.All"
DEFAULT_ACCOUNTS_FILE = "keys/outlook_pending.txt"
DEFAULT_USED_FILE = "keys/outlook_used.txt"


def _parse_line(line: str):
    parts = line.strip().split("----")
    if len(parts) < 4:
        return None
    return parts[0], parts[1], parts[2], "----".join(parts[3:])


def _proxies_for(proxy: Optional[str]):
    if not proxy:
        return {}
    return {"http": proxy, "https": proxy}


def refresh_access_token(client_id: str, refresh_token: str, proxy: Optional[str] = None) -> str:
    data = {
        "client_id": client_id,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "scope": IMAP_SCOPE,
    }
    last_exc = None
    for px in (_proxies_for(proxy), {}):
        try:
            r = _requests.post(MS_TOKEN_URL, data=data, timeout=30, proxies=px)
            r.raise_for_status()
            token = r.json().get("access_token")
            if token:
                return token
        except Exception as exc:  # 代理失败时回退直连
            last_exc = exc
    raise Exception(f"Outlook token 刷新失败: {last_exc}")


def _imap_login(email_addr: str, access_token: str) -> imaplib.IMAP4_SSL:
    conn = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, timeout=30)
    auth = f"user={email_addr}\x01auth=Bearer {access_token}\x01\x01"
    try:
        conn.authenticate("XOAUTH2", lambda x: auth.encode())
    except Exception:
        try:
            conn.logout()
        except Exception:
            pass
        raise
    return conn


def _max_uid(email_addr: str, access_token: str) -> int:
    conn = _imap_login(email_addr, access_token)
    try:
        typ, _ = conn.select("INBOX", readonly=True)
        if typ != "OK":
            raise RuntimeError("Outlook 无法打开收件箱")
        typ, data = conn.uid("SEARCH", None, "ALL")
        if typ != "OK" or not data or data[0] is None:
            raise RuntimeError("Outlook 无法读取基线 UID")
        return max((int(uid) for uid in data[0].split()), default=0)
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def _is_target_message(msg) -> bool:
    from_addr = (msg.get("From") or "").lower()
    subject = (msg.get("Subject") or "").lower()
    return "x.ai" in from_addr or "confirmation code" in subject


def _decode_subject(msg) -> str:
    raw = msg.get("Subject")
    if not raw:
        return ""
    try:
        out = ""
        for chunk, enc in email_lib.header.decode_header(raw):
            out += chunk.decode(enc or "utf-8", errors="ignore") if isinstance(chunk, bytes) else chunk
        return out
    except Exception:
        return str(raw)


def _message_text(msg) -> tuple[str, str]:
    subject = _decode_subject(msg)
    try:
        body = msg.get_body(preferencelist=("plain", "html"))
        body_text = body.get_content() if body else ""
    except Exception:
        body_text = ""
    if not body_text:
        parts = []
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                try:
                    parts.append(part.get_payload(decode=True).decode(errors="ignore"))
                except Exception:
                    pass
        body_text = "\n".join(parts)
    return subject, body_text


def _fetch_new_messages(email_addr: str, access_token: str, baseline_uid: int):
    conn = _imap_login(email_addr, access_token)
    out = []
    try:
        conn.select("INBOX", readonly=True)
        typ, data = conn.uid("SEARCH", None, "UID", f"{baseline_uid + 1}:*")
        uids = data[0].split() if typ == "OK" and data and data[0] else []
        for uid in uids:
            # IMAP ranges are inclusive in either direction: N:* can return
            # the last old message when N exceeds the mailbox's highest UID.
            if int(uid) <= baseline_uid:
                continue
            typ, fetched = conn.uid("FETCH", uid, "(BODY.PEEK[])")
            if typ != "OK" or not fetched or not fetched[0]:
                continue
            raw = fetched[0][1] if isinstance(fetched[0], tuple) and len(fetched[0]) > 1 else None
            if not raw:
                continue
            msg = email_lib.message_from_bytes(raw)
            if not _is_target_message(msg):
                continue
            subject, body = _message_text(msg)
            out.append((int(uid), subject, body))
    finally:
        try:
            conn.logout()
        except Exception:
            pass
    return out


def _pool_paths(accounts_file: str, used_file: str) -> tuple[Path, Path]:
    pending = Path(accounts_file or DEFAULT_ACCOUNTS_FILE).expanduser().resolve()
    used = Path(used_file or DEFAULT_USED_FILE).expanduser().resolve()
    if pending == used:
        raise ValueError("Outlook 待用池和已用记录必须使用不同文件")
    return pending, used


def _read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _lines_text(lines: list[str]) -> str:
    return "\n".join(lines) + ("\n" if lines else "")


@contextmanager
def _pool_lock(pending: Path, used: Path):
    # Different pending pools may share one used ledger. Lock both files in a
    # stable order so their read/replace operations cannot overwrite each other.
    with ExitStack() as stack:
        for path in sorted({pending, used}):
            stack.enter_context(exclusive_file_lock(str(path) + ".lock"))
        yield


def create_mailbox(accounts_file: str, used_file: str, proxy: Optional[str] = None,
                   log_callback: Optional[Callable] = None) -> tuple[str, str]:
    """取下一个未用账号，返回 (email, token)。token = pw----client_id----refresh----baseline_uid。"""
    pending, used = _pool_paths(accounts_file, used_file)
    if not pending.is_file():
        raise Exception(f"Outlook 账号池文件不存在: {pending}")
    with _pool_lock(pending, used):
        lines = _read_lines(pending)
        used_lines = _read_lines(used)
        used_emails = {line.split("----", 1)[0].strip().lower() for line in used_lines}
        index = next((i for i, line in enumerate(lines)
                      if line.split("----", 1)[0].strip().lower() not in used_emails), None)
        if index is None:
            raise Exception("Outlook 账号池已耗尽")
        line = lines[index]
        parsed = _parse_line(line)
        if not parsed:
            raise Exception("Outlook 账号行格式错误（需要四个字段）")
        rest = lines[:index] + lines[index + 1:]
        # Persist the credential before removing it from pending. A partial
        # write/crash cannot lose the row, and the used ledger prevents reuse.
        atomic_write_text(used, _lines_text(used_lines + [line]))
        try:
            atomic_write_text(pending, _lines_text(rest))
        except BaseException:
            # A replace may have completed before an interruption/error was
            # reported. Only undo the used entry if pending still has the row.
            try:
                if line in _read_lines(pending):
                    atomic_write_text(used, _lines_text(used_lines))
            except Exception:
                pass  # Keep the durable used copy if rollback itself fails.
            raise

    email_addr, password, client_id, refresh_token = parsed
    try:
        token = refresh_access_token(client_id, refresh_token, proxy)
        baseline = _max_uid(email_addr, token)
    except Exception as exc:
        # Zero is only valid for a confirmed empty inbox. A failed probe must
        # not make every old OTP eligible for the next signup attempt.
        release(str(pending), str(used), email_addr, log_callback=log_callback)
        raise RuntimeError("Outlook 基线 UID 探测失败，未提交邮箱") from exc
    if log_callback:
        log_callback(f"Outlook 取号 {email_addr}（池剩 {len(rest)}，基线 UID={baseline}）")
    return email_addr, f"{password}----{client_id}----{refresh_token}----{baseline}"


def release(accounts_file: str, used_file: str, email_addr: str,
            log_callback: Optional[Callable] = None) -> bool:
    """失败未注册的邮箱回收到池尾（从 used 移回 pending 末尾，可重挑）。"""
    if not email_addr:
        return False
    try:
        pending, used = _pool_paths(accounts_file, used_file)
        with _pool_lock(pending, used):
            used_lines = _read_lines(used)
            target, kept = None, []
            for line in used_lines:
                if target is None and line.split("----", 1)[0].strip().lower() == email_addr.lower():
                    target = line
                else:
                    kept.append(line)
            if target is None:
                return False
            pending_lines = _read_lines(pending)
            if not any(line.split("----", 1)[0].strip().lower() == email_addr.lower() for line in pending_lines):
                pending_lines.append(target)
            atomic_write_text(pending, _lines_text(pending_lines))
            atomic_write_text(used, _lines_text(kept))
    except Exception as exc:
        if log_callback:
            log_callback(f"[!] Outlook 回收失败 {email_addr}: {exc}")
        return False
    if log_callback:
        log_callback(f"[*] Outlook 失败回收 {email_addr} 回池尾")
    else:
        message = f"[*] Outlook 失败回收 {email_addr} 回池尾"
        encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
        # The pool update already succeeded; a legacy Windows code page must
        # not turn its informational log into a failed registration attempt.
        print(message.encode(encoding, errors="backslashreplace").decode(encoding), flush=True)
    return True


def wait_for_code(dev_token: str, email_addr: str, timeout: int = 240, poll_interval: int = 5,
                  extract_code: Optional[Callable] = None, raise_if_cancelled=None,
                  sleep_with_cancel=None, log_callback: Optional[Callable] = None,
                  cancel_callback=None, proxy: Optional[str] = None,
                  resend_callback=None) -> str:
    parts = (dev_token or "").split("----")
    if len(parts) < 4:
        raise Exception("Outlook dev_token 格式错误")
    _, client_id, refresh_token, baseline_raw = parts[0], parts[1], parts[2], parts[3]
    try:
        baseline_uid = int(baseline_raw)
    except ValueError:
        baseline_uid = 0

    if sleep_with_cancel is None:
        import time as _time

        def sleep_with_cancel(sec, cb=None):
            _time.sleep(sec)
    if raise_if_cancelled is None:
        def raise_if_cancelled(cb=None):
            pass
    if extract_code is None:
        raise Exception("Outlook provider 需要 extract_code")

    deadline = None
    access_token = None
    token_age = 0.0
    import time as _time
    start = _time.time()
    seen_uids: set[int] = set()
    while True:
        raise_if_cancelled(cancel_callback)
        if access_token is None or token_age > 1500:
            access_token = refresh_access_token(client_id, refresh_token, proxy)
            token_age = 0.0
        try:
            messages = _fetch_new_messages(email_addr, access_token, baseline_uid)
            for uid, subject, body in messages:
                if uid in seen_uids:
                    continue
                seen_uids.add(uid)
                code = extract_code(body, subject)
                if code:
                    if log_callback:
                        log_callback(f"Outlook 验证码到达 UID={uid} subject={subject[:60]!r}")
                    return code
                if log_callback:
                    log_callback(f"Outlook 新邮件无验证码 UID={uid} subject={subject[:60]!r}")
        except Exception as exc:
            access_token = None  # 下轮重新登录
            if log_callback:
                log_callback(f"Outlook IMAP 轮询异常（重试）: {str(exc)[:100]}")
        elapsed = _time.time() - start
        if elapsed >= timeout:
            raise Exception(f"在 {timeout}s 内未收到验证码邮件")
        sleep_with_cancel(min(poll_interval, max(1.0, timeout - elapsed)), cancel_callback)
        token_age += poll_interval
