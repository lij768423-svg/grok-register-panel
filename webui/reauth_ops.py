# -*- coding: utf-8 -*-
"""Compare local SSO emails with remote Grok2API accounts and re-auth missing ones."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime_platform import popen_group_kwargs, runtime_python
from sso_to_auth_json import list_grok2api_accounts

try:
    from secure_files import (
        atomic_write_text,
        best_effort_fchmod,
        ensure_private_dir,
    )
    from webui.process_utils import (
        find_managed_processes,
        terminate_managed_processes,
        write_pid_file,
    )
    from webui.recovery_ops import (
        ACCOUNTS_DIR,
        CONFIG_FILE,
        PENDING_FILE,
        RECOVERY_SCRIPT,
        _account_records,
        _records_from_file,
    )
except ImportError:
    from secure_files import (  # type: ignore
        atomic_write_text,
        best_effort_fchmod,
        ensure_private_dir,
    )
    from process_utils import (  # type: ignore
        find_managed_processes,
        terminate_managed_processes,
        write_pid_file,
    )
    from recovery_ops import (  # type: ignore
        ACCOUNTS_DIR,
        CONFIG_FILE,
        PENDING_FILE,
        RECOVERY_SCRIPT,
        _account_records,
        _records_from_file,
    )


LOG_DIR = ROOT / "log"
REPORT_FILE = LOG_DIR / "reauth_report.json"
PID_FILE = LOG_DIR / "reauth.pid"
QUEUE_FILE = LOG_DIR / "reauth_sso.txt"
VENV_PY = runtime_python(ROOT)
VALID_SOURCES = ("accounts", "pending")


def _read_config() -> dict:
    if not CONFIG_FILE.is_file():
        return {}
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8") or "{}")
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _normalize_email(value: object) -> str:
    text = str(value or "").strip().lower()
    if "@" not in text or any(ch.isspace() for ch in text):
        return ""
    return text


def _sso_records(source: str) -> dict[str, str]:
    kind = str(source or "accounts").strip().lower()
    if kind not in VALID_SOURCES:
        raise ValueError("对照来源无效")
    if kind == "pending":
        return _records_from_file(PENDING_FILE)
    return _account_records()


def _sso_emails(records: dict[str, str]) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for email in records.values():
        key = _normalize_email(email)
        if not key or key in seen:
            continue
        seen.add(key)
        found.append(key)
    return found


def _job_running() -> dict:
    jobs = find_managed_processes(ROOT, ("sso_to_auth_json.py",))
    return {
        "running": bool(jobs),
        "pid": jobs[0]["pid"] if jobs else None,
    }


def reauth_status() -> dict:
    cfg = _read_config()
    job = _job_running()
    return {
        "ok": True,
        "remote_configured": bool(str(cfg.get("grok2api_remote_url") or "").strip()),
        "job": job,
        "compare": {
            "source": "",
            "sso_count": 0,
            "remote_count": 0,
            "present": [],
            "missing": [],
            "error": "",
        },
    }


def compare_sso_to_remote(
    source: str = "accounts",
    *,
    list_accounts=None,
) -> dict:
    cfg = _read_config()
    remote_url = str(cfg.get("grok2api_remote_url") or "").strip()
    username = str(cfg.get("grok2api_username") or "").strip()
    password = str(cfg.get("grok2api_password") or "")
    if not remote_url:
        raise ValueError("未配置 grok2api_remote_url")
    if not username or not password:
        raise ValueError("未配置 Grok2API 登录账号密码")
    records = _sso_records(source)
    sso_emails = _sso_emails(records)
    fetcher = list_accounts or list_grok2api_accounts
    remote_rows = fetcher(
        remote_url,
        username,
        password,
    )
    remote_emails = {
        _normalize_email(item.get("email"))
        for item in remote_rows
        if isinstance(item, dict)
    }
    remote_emails.discard("")
    present = [email for email in sso_emails if email in remote_emails]
    missing = [email for email in sso_emails if email not in remote_emails]
    job = _job_running()
    return {
        "ok": True,
        "remote_configured": True,
        "job": job,
        "compare": {
            "source": str(source or "accounts"),
            "sso_count": len(sso_emails),
            "remote_count": len(remote_emails),
            "present": present,
            "missing": missing,
            "error": "",
        },
        "summary": {
            "sso": len(sso_emails),
            "remote": len(remote_emails),
            "present": len(present),
            "missing": len(missing),
        },
    }


def start_reauth_missing(
    source: str = "accounts",
    emails: list[str] | None = None,
    *,
    list_accounts=None,
) -> dict:
    if find_managed_processes(ROOT, ("run_until_100.py", "run_batch_headless.py")):
        return {"ok": False, "error": "registration task is running"}
    existing = find_managed_processes(ROOT, ("sso_to_auth_json.py",))
    if existing:
        return {"ok": False, "error": "reauth already running", "pid": existing[0]["pid"]}
    if not VENV_PY.is_file():
        return {"ok": False, "error": f"missing runtime python: {VENV_PY}"}
    if not CONFIG_FILE.is_file():
        return {"ok": False, "error": f"missing config: {CONFIG_FILE}"}

    compared = compare_sso_to_remote(source, list_accounts=list_accounts)
    wanted = {
        _normalize_email(item)
        for item in (emails or compared["compare"]["missing"])
    }
    wanted.discard("")
    if not wanted:
        return {"ok": False, "error": "没有缺失的 SSO 账号", "status": compared}

    records = _sso_records(source)
    lines: list[str] = []
    seen_sso: set[str] = set()
    for sso, email in records.items():
        key = _normalize_email(email)
        if key not in wanted or sso in seen_sso:
            continue
        seen_sso.add(sso)
        lines.append(f"{key}----{sso}\n")
    if not lines:
        return {"ok": False, "error": "缺失邮箱在 SSO 库存中找不到 cookie", "status": compared}

    ensure_private_dir(LOG_DIR)
    atomic_write_text(QUEUE_FILE, "".join(lines))
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    log_path = LOG_DIR / f"reauth-{timestamp}.log"
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    best_effort_fchmod(fd, 0o600)
    output = os.fdopen(fd, "w", encoding="utf-8")
    command = [
        str(VENV_PY),
        "-u",
        str(RECOVERY_SCRIPT),
        "--from-config",
        str(CONFIG_FILE),
        "--sso",
        str(QUEUE_FILE),
        "--no-skip-existing",
        "--report-json",
        str(REPORT_FILE),
    ]
    try:
        process = subprocess.Popen(
            command,
            cwd=str(ROOT),
            stdout=output,
            stderr=subprocess.STDOUT,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
            **popen_group_kwargs(),
        )
    finally:
        output.close()
    write_pid_file(PID_FILE, process.pid)
    return {
        "ok": True,
        "running": True,
        "pid": process.pid,
        "input_count": len(lines),
        "log": log_path.name,
        "compare": compared["compare"],
        "summary": compared["summary"],
    }


def stop_reauth() -> dict:
    killed = terminate_managed_processes(ROOT, ("sso_to_auth_json.py",))
    return {"ok": True, "killed": killed, "job": _job_running()}
