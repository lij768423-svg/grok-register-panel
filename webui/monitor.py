#!/usr/bin/env python3
"""Grok register batch live monitor — bind Tailscale, control + blacklist panel."""
from __future__ import annotations

import json
import ipaddress
import os
import re
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secure_files import atomic_write_json, best_effort_fchmod, ensure_private_dir
from batch_traffic import read_metrics as read_batch_traffic
from runtime_platform import (
    batch_launch_command,
    batch_runtime_error,
    beijing_strftime,
    now_beijing,
    popen_group_kwargs,
    runtime_python,
)

try:
    from webui.blacklist_store import read_blacklist as read_blacklist_state
    from webui.proxy_store import (
        delete_proxy,
        import_legacy_proxies,
        import_proxies,
        read_proxy_pool,
        start_proxy_tests,
        update_proxy,
    )
    from webui.email_domain_store import (
        delete_domain,
        import_domains,
        read_email_domain_pool,
        reset_domain,
        update_domain,
        update_settings as update_email_domain_settings,
    )
    from webui.email_provider_store import (
        read_email_provider_config,
        save_email_provider_config,
        test_email_provider_config,
    )
    from webui.process_utils import (
        find_managed_processes,
        terminate_managed_processes,
        write_pid_file,
    )
    from webui.recovery_ops import recovery_status, start_recovery, stop_recovery
    from webui.bfs_ops import bfs_status, check_token_text, run_bfs_scan
    from webui.security_utils import (
        check_token_optional_read,
        expected_token,
        mask_email,
        redact_log_line,
        redact_proxy,
    )
except ImportError:  # running as script from webui/
    from blacklist_store import read_blacklist as read_blacklist_state  # type: ignore
    from proxy_store import (  # type: ignore
        delete_proxy,
        import_legacy_proxies,
        import_proxies,
        read_proxy_pool,
        start_proxy_tests,
        update_proxy,
    )
    from email_domain_store import (  # type: ignore
        delete_domain,
        import_domains,
        read_email_domain_pool,
        reset_domain,
        update_domain,
        update_settings as update_email_domain_settings,
    )
    from email_provider_store import (  # type: ignore
        read_email_provider_config,
        save_email_provider_config,
        test_email_provider_config,
    )
    from process_utils import (  # type: ignore
        find_managed_processes,
        terminate_managed_processes,
        write_pid_file,
    )
    from recovery_ops import recovery_status, start_recovery, stop_recovery  # type: ignore
    from bfs_ops import bfs_status, check_token_text, run_bfs_scan  # type: ignore
    from security_utils import (  # type: ignore
        check_token_optional_read,
        expected_token,
        mask_email,
        redact_log_line,
        redact_proxy,
    )
LOG_DIR = ROOT / "log"
BATCH_TRAFFIC = LOG_DIR / "batch_traffic.json"
CPA_DIR = Path(os.environ.get("CPA_AUTH_DIR", str(ROOT / "cpa_auth")))
ASSET_DIR = Path(__file__).resolve().parent / "assets"
FONT_ASSETS = {
    "/assets/geist.woff2": ASSET_DIR / "geist-latin-wght-normal.woff2",
    "/assets/geist-mono.woff2": ASSET_DIR / "geist-mono-latin-wght-normal.woff2",
}
MONITOR_TOKEN_ENV = "MONITOR_TOKEN"
PANEL_INCLUDE_TAIL = os.environ.get("PANEL_INCLUDE_TAIL", "0").strip() in ("1", "true", "yes")


def _configured_process_roots(
    current_root: Path = ROOT,
    environ=None,
) -> tuple[Path, ...]:
    """Return exact project roots allowed for cross-release process discovery."""
    env = os.environ if environ is None else environ
    roots = [Path(current_root).resolve()]
    raw = str(env.get("GROK_COMPAT_PROCESS_ROOTS", "") or "").strip()
    for item in raw.split(os.pathsep):
        value = item.strip()
        if not value:
            continue
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            continue
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved.is_dir() and resolved not in roots:
            roots.append(resolved)
    return tuple(roots)


MANAGED_PROCESS_ROOTS = _configured_process_roots()


def _find_managed_processes(script_names) -> list[dict]:
    found = {}
    for root in MANAGED_PROCESS_ROOTS:
        for item in find_managed_processes(root, script_names):
            found[int(item["pid"])] = item
    return sorted(found.values(), key=lambda item: int(item["pid"]))


def _terminate_managed_processes(script_names) -> list[int]:
    killed = set()
    for root in MANAGED_PROCESS_ROOTS:
        killed.update(terminate_managed_processes(root, script_names))
    return sorted(killed)


BASE_FILE = LOG_DIR / "batch1000.base"
ORCH_PID = LOG_DIR / "orch100.pid"
BATCH_PID = LOG_DIR / "batch100.pid"
CONTROL_FILE = LOG_DIR / "monitor_control.json"
STATS_CACHE = LOG_DIR / "monitor_stats.json"
BIND_HOST = os.environ.get("MONITOR_HOST", "127.0.0.1")
BIND_PORT = int(os.environ.get("MONITOR_PORT", "8787"))
VENV_PY = runtime_python(ROOT)
ORCH_SCRIPT = ROOT / "run_until_100.py"
CONTROL_LOCK = threading.RLock()
START_LOCK = threading.Lock()
MAX_REQUEST_BODY = 64 * 1024

RE_OK = re.compile(r"\[\+\] 注册成功")
RE_FAIL = re.compile(r"\[-\] 失败")
RE_DOMAIN = re.compile(r"\[-\] 域名拒绝")
RE_SKIP = re.compile(r"\[-\] 卡住跳过")
RE_BOT0 = re.compile(r"botFlagSource=0")
RE_BOT1 = re.compile(r"botFlagSource=1")
RE_BFS = re.compile(r"JWT bfs 标记|bfs=yes|kind=bfs_flagged|has_bfs")
RE_EMAIL_OK = re.compile(r"\[\+\] 注册成功(?:（[^）]*）)?:\s*(\S+)")
RE_FAIL_KIND = re.compile(r"\[-\] 失败 \[([^\]]+)\]:\s*(.*)")
RE_WORKER = re.compile(r"\[W(\d+)\]")
RE_BATCH = re.compile(r"\[batch\] count=(\d+) workers=(\d+)")
RE_START = re.compile(r"终端模式启动，目标数量:\s*(\d+)\s*\|\s*并发:\s*(\d+)")
RE_END = re.compile(r"任务结束。成功\s*(\d+)\s*\|\s*失败\s*(\d+)")
RE_ADDED_BL = re.compile(r"ADDED blacklist AS(\d+)")
RE_LOOKUP_FAIL = re.compile(r"lookup fail", re.I)
RE_ANALYZE_ERR = re.compile(r"analyze error", re.I)


def _read_json(path: Path, default=None):
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8") or "{}")
    except Exception:
        pass
    return default if default is not None else {}


def _write_json(path: Path, data: dict):
    atomic_write_json(path, data)


def load_control() -> dict:
    with CONTROL_LOCK:
        c = _read_json(CONTROL_FILE, {})
        c.setdefault("workers", 3)
        c.setdefault("risk_pause", 10)
        c.setdefault("batch_count", 40)
        c.setdefault("add_count", 40)  # 再跑 N 个
        c.setdefault("mode", "orch")  # orch | batch
        return c


def save_control(updates: dict) -> dict:
    allowed = {
        "workers",
        "risk_pause",
        "batch_count",
        "add_count",
        "mode",
        "base_cpa",
        "target_cpa",
    }
    with CONTROL_LOCK:
        c = load_control()
        c.update({key: value for key, value in (updates or {}).items() if key in allowed})
        try:
            c["workers"] = max(1, min(24, int(c.get("workers", 3))))
        except Exception:
            c["workers"] = 3
        try:
            c["risk_pause"] = max(1, min(50, int(c.get("risk_pause", 10))))
        except Exception:
            c["risk_pause"] = 10
        try:
            c["batch_count"] = max(1, min(200, int(c.get("batch_count", 40))))
        except Exception:
            c["batch_count"] = 40
        try:
            c["add_count"] = max(1, min(500, int(c.get("add_count", 40))))
        except Exception:
            c["add_count"] = 40
        c["mode"] = c.get("mode") if c.get("mode") in ("orch", "batch") else "orch"
        for key in ("base_cpa", "target_cpa"):
            if c.get(key) is None or str(c.get(key)).strip() == "":
                c.pop(key, None)
                continue
            try:
                c[key] = max(0, int(c[key]))
            except Exception:
                c.pop(key, None)
        c["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        _write_json(CONTROL_FILE, c)
        return c


def discover_log():
    env = os.environ.get("BATCH_LOG")
    if env and Path(env).is_file():
        return Path(env)
    cands = sorted(LOG_DIR.glob("batch*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
    cands = [p for p in cands if "sticky" not in p.name and "rotate" not in p.name]
    return cands[0] if cands else None


def read_base():
    """Prefer control.base_cpa; fall back to batch1000.base file if present."""
    try:
        c = load_control()
        if c.get("base_cpa") is not None and str(c.get("base_cpa")).strip() != "":
            return int(c["base_cpa"])
    except Exception:
        pass
    try:
        return int(BASE_FILE.read_text().strip())
    except Exception:
        return 0


def process_running():
    """Detect orch and/or batch workers."""
    info = {
        "running": False,
        "pid": None,
        "etime": None,
        "cmd": None,
        "orch_running": False,
        "orch_pid": None,
        "orch_etime": None,
        "batch_running": False,
        "batch_pid": None,
        "batch_etime": None,
    }
    orch = _find_managed_processes(("run_until_100.py",))
    batch = _find_managed_processes(("run_batch_headless.py",))

    def primary(items):
        if not items:
            return None
        return next((item for item in items if item.get("pgid") == item.get("pid")), items[0])

    orch_item = primary(orch)
    batch_item = primary(batch)
    if orch_item:
        info["orch_running"] = True
        info["orch_pid"] = orch_item["pid"]
        info["orch_etime"] = orch_item.get("etime")
        info["running"] = True
        info["pid"] = orch_item["pid"]
        info["etime"] = orch_item.get("etime")
        info["cmd"] = orch_item.get("cmd")
    if batch_item:
        info["batch_running"] = True
        info["batch_pid"] = batch_item["pid"]
        info["batch_etime"] = batch_item.get("etime")
        if not info["running"]:
            info["running"] = True
            info["pid"] = batch_item["pid"]
            info["etime"] = batch_item.get("etime")
            info["cmd"] = batch_item.get("cmd")
    return info


def parse_log(path, max_tail=400_000):
    if not path or not path.is_file():
        return {"error": "no log"}
    size = path.stat().st_size
    with path.open("rb") as f:
        if size > max_tail:
            f.seek(size - max_tail)
            f.readline()
        text = f.read().decode("utf-8", errors="replace")

    lines = text.splitlines()
    ok = fail = domain = skip = bot0 = bot1 = bfs_hits = 0
    count = workers = None
    ended = None
    recent_ok = []
    recent_fail = []
    fail_kinds = {}
    worker_ok = {}
    worker_fail = {}

    for line in lines:
        m = RE_BATCH.search(line) or RE_START.search(line)
        if m:
            count, workers = int(m.group(1)), int(m.group(2))
        m = RE_END.search(line)
        if m:
            ended = {"success": int(m.group(1)), "fail": int(m.group(2))}

        if RE_OK.search(line):
            ok += 1
            em = RE_EMAIL_OK.search(line)
            email = em.group(1) if em else ""
            wm = RE_WORKER.search(line)
            w = f"W{wm.group(1)}" if wm else "?"
            worker_ok[w] = worker_ok.get(w, 0) + 1
            ts = line[1:9] if line.startswith("[") else ""
            recent_ok.append({"t": ts, "w": w, "email": mask_email(email)})
        if RE_FAIL.search(line):
            fail += 1
            fm = RE_FAIL_KIND.search(line)
            kind = fm.group(1) if fm else "其它"
            msg = fm.group(2) if fm else line[-120:]
            if "inputs=none" in msg:
                kind = "空页UI"
            if "Turnstile" in msg or "Turnstile" in kind:
                kind = "资料页Turnstile" if "Turnstile" in msg else kind
            fail_kinds[kind] = fail_kinds.get(kind, 0) + 1
            wm = RE_WORKER.search(line)
            w = f"W{wm.group(1)}" if wm else "?"
            worker_fail[w] = worker_fail.get(w, 0) + 1
            ts = line[1:9] if line.startswith("[") else ""
            recent_fail.append({"t": ts, "w": w, "kind": kind, "msg": redact_log_line(msg[:160])})
        if RE_DOMAIN.search(line):
            domain += 1
        if RE_SKIP.search(line):
            skip += 1
        if RE_BOT0.search(line):
            bot0 += 1
        if RE_BOT1.search(line):
            bot1 += 1
        if RE_BFS.search(line):
            bfs_hits += 1

    last_lines = lines[-40:]
    if size > max_tail:
        def gcount(pat):
            r = subprocess.run(["grep", "-c", pat, str(path)], capture_output=True, text=True)
            try:
                return int(r.stdout.strip() or 0)
            except Exception:
                return 0

        ok = gcount("注册成功")
        fail = gcount(r"\[-\] 失败")
        bot0 = gcount("botFlagSource=0")
        bot1 = gcount("botFlagSource=1")
        bfs_hits = gcount("JWT bfs 标记") + gcount("bfs_flagged")

    return {
        "log": path.name,
        "log_name": path.name,
        "log_size": size,
        "mtime": path.stat().st_mtime,
        "count_target": count,
        "workers": workers,
        "ok": ok,
        "fail": fail,
        "domain": domain,
        "skip": skip,
        "bot0": bot0,
        "bot1": bot1,
        "bfs": bfs_hits,
        "ended": ended,
        "fail_kinds": fail_kinds,
        "worker_ok": worker_ok,
        "worker_fail": worker_fail,
        # 前端分页每页 10 条；后端多留一些供翻页
        "recent_ok": recent_ok[-80:][::-1],
        "recent_fail": recent_fail[-80:][::-1],
        "tail": [redact_log_line(line) for line in last_lines],
    }


def cpa_count():
    try:
        return sum(1 for p in CPA_DIR.iterdir() if p.is_file() and p.name.startswith("xai-"))
    except Exception:
        try:
            return sum(1 for _ in CPA_DIR.iterdir() if _.is_file())
        except Exception:
            return 0


def read_blacklist():
    return read_blacklist_state()


def blacklist_update_errors():
    """Count blacklist expansion / ASN lookup errors from orch logs."""
    added = []
    lookup_fails = 0
    analyze_errors = 0
    hit_pause = 0
    try:
        logs = sorted(LOG_DIR.glob("orch100*.log"), key=lambda p: p.stat().st_mtime, reverse=True)[:8]
        logs += sorted(LOG_DIR.glob("orch100-stdout.log"), key=lambda p: p.stat().st_mtime, reverse=True)[:1]
        seen = set()
        for path in logs:
            if str(path) in seen or not path.is_file():
                continue
            seen.add(str(path))
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for line in text.splitlines():
                m = RE_ADDED_BL.search(line)
                if m:
                    added.append({"asn": int(m.group(1)), "line": line[-120:], "log": path.name})
                if RE_LOOKUP_FAIL.search(line):
                    lookup_fails += 1
                if RE_ANALYZE_ERR.search(line):
                    analyze_errors += 1
                if "pause+blacklist" in line or "HIT" in line and "注册风控" in line:
                    hit_pause += 1
    except Exception:
        pass
    # unique recent added (last 30)
    uniq = []
    seen_a = set()
    for a in reversed(added):
        if a["asn"] in seen_a:
            continue
        seen_a.add(a["asn"])
        uniq.append(a)
        if len(uniq) >= 30:
            break
    uniq.reverse()
    return {
        "lookup_fail_count": lookup_fails,
        "analyze_error_count": analyze_errors,
        "error_count": lookup_fails + analyze_errors,
        "hit_pause_count": hit_pause,
        "recent_added": uniq[-15:],
        "added_total": len(added),
    }


def success_stats():
    """Aggregate success stats: CPA + jsonl + time-window rates + latest batch."""
    from datetime import datetime, timezone, timedelta
    from runtime_platform import TZ_BEIJING

    cpa = cpa_count()
    configured_base = read_base()
    base_stale = configured_base < 0 or configured_base > cpa
    base = cpa if base_stale else configured_base
    jsonl_ok = 0
    jsonl_risk = 0
    jsonl_fail = 0
    by_day = {}
    results = LOG_DIR / "register_results.jsonl"

    # windows in hours -> counters（按北京时间窗口）
    windows_h = (1, 3, 12)
    now = now_beijing()
    win = {
        h: {
            "ok": 0,
            "fail": 0,
            "risk": 0,
            "total": 0,
            "since": (now - timedelta(hours=h)).strftime("%Y-%m-%d %H:%M:%S"),
        }
        for h in windows_h
    }

    def _parse_ts(ts: str):
        if not ts:
            return None
        s = str(ts).strip()
        try:
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(TZ_BEIJING)
        except Exception:
            return None

    try:
        if results.exists():
            size = results.stat().st_size
            # last 8MB covers 12h under high volume
            with results.open("rb") as f:
                if size > 8_000_000:
                    f.seek(size - 8_000_000)
                    f.readline()
                for line in f:
                    try:
                        o = json.loads(line.decode("utf-8", errors="replace"))
                    except Exception:
                        continue
                    st = o.get("status")
                    dt = _parse_ts(o.get("ts") or "")
                    # 按日统计用北京日期
                    day = dt.strftime("%Y-%m-%d") if dt else (o.get("ts") or "")[:10]
                    if day:
                        by_day.setdefault(day, {"ok": 0, "risk": 0, "fail": 0})
                    if st == "ok":
                        jsonl_ok += 1
                        if day:
                            by_day[day]["ok"] += 1
                    elif st == "risk":
                        jsonl_risk += 1
                        if day:
                            by_day[day]["risk"] += 1
                    elif st:
                        jsonl_fail += 1
                        if day:
                            by_day[day]["fail"] += 1

                    if not dt:
                        continue
                    age = now - dt
                    for h in windows_h:
                        if age <= timedelta(hours=h):
                            bucket = win[h]
                            if st == "ok":
                                bucket["ok"] += 1
                            elif st == "risk":
                                bucket["risk"] += 1
                            elif st:
                                bucket["fail"] += 1
                            if st in ("ok", "risk", "fail", "sso_timeout", "browser", "other"):
                                bucket["total"] += 1
                            elif st:
                                bucket["total"] += 1
    except Exception:
        pass

    # normalize window rates
    rates = {}
    for h, b in win.items():
        # total attempts that finished with a status
        total = int(b["ok"]) + int(b["fail"]) + int(b["risk"])
        ok = int(b["ok"])
        rate = round(100.0 * ok / total, 1) if total else None
        rates[f"{h}h"] = {
            "hours": h,
            "ok": ok,
            "fail": int(b["fail"]),
            "risk": int(b["risk"]),
            "total": total,
            "success_rate": rate,
            "since": b["since"],
        }

    log = discover_log()
    parsed = parse_log(log) if log else {}
    batch_ok = parsed.get("ok") or 0
    batch_fail = parsed.get("fail") or 0
    data = {
        "cpa": cpa,
        "base_cpa": base,
        "base_cpa_stale": base_stale,
        "cpa_delta": cpa - base,
        "jsonl_ok": jsonl_ok,
        "jsonl_risk": jsonl_risk,
        "jsonl_fail": jsonl_fail,
        "batch_ok": batch_ok,
        "batch_fail": batch_fail,
        "batch_log": parsed.get("log_name"),
        "by_day": by_day,
        "rates": rates,
        "refreshed_at": beijing_strftime("%Y-%m-%d %H:%M:%S"),
    }
    try:
        _write_json(STATS_CACHE, data)
    except Exception:
        pass
    return data




def _parse_etime(s):
    if not s:
        return None
    s = s.strip()
    try:
        days = 0
        if "-" in s:
            d, s = s.split("-", 1)
            days = int(d)
        parts = [int(x) for x in s.split(":")]
        if len(parts) == 3:
            h, m, sec = parts
        elif len(parts) == 2:
            h = 0
            m, sec = parts
        else:
            return None
        return days * 86400 + h * 3600 + m * 60 + sec
    except Exception:
        return None


def kill_all():
    """Stop only orchestrator and batch processes under this project root."""
    killed = _terminate_managed_processes(
        ("run_until_100.py", "run_batch_headless.py")
    )
    return {"ok": True, "killed": killed}


def _runtime_prerequisite_error() -> str | None:
    if not VENV_PY.is_file():
        return f"missing runtime python: {VENV_PY}"
    if not (ROOT / "config.json").is_file():
        return f"missing config: {ROOT / 'config.json'}"
    launch_error = batch_runtime_error()
    if launch_error:
        return launch_error
    return None


def _registration_env() -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    env.setdefault("GROK_STATIC_ASSET_CACHE", "1")
    env.setdefault(
        "GROK_STATIC_CACHE_DIR",
        str(LOG_DIR / "static-asset-cache"),
    )
    return env


def _start_orch_unlocked():
    proc = process_running()
    if proc.get("orch_running") or proc.get("batch_running"):
        return {"ok": False, "error": "already running", "process": proc}
    if _find_managed_processes(("sso_to_auth_json.py",)):
        return {"ok": False, "error": "account recovery is running"}
    prerequisite_error = _runtime_prerequisite_error()
    if prerequisite_error:
        return {"ok": False, "error": prerequisite_error}
    c = load_control()
    now = cpa_count()
    add_count = c.get("add_count")
    try:
        add_count = int(add_count) if add_count is not None else 0
    except Exception:
        add_count = 0
    target = c.get("target_cpa")
    try:
        target = int(target) if target is not None else None
    except Exception:
        target = None
    if add_count > 0:
        c["base_cpa"] = now
        c["target_cpa"] = now + add_count
    elif target is None or target <= now:
        n = int(c.get("batch_count") or 40)
        c["add_count"] = n
        c["base_cpa"] = now
        c["target_cpa"] = now + n
        add_count = n
    c = save_control(c)
    need = int(c.get("target_cpa") or 0) - now
    ensure_private_dir(LOG_DIR)
    stdout_path = LOG_DIR / "orch100-stdout.log"
    fd = os.open(stdout_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    best_effort_fchmod(fd, 0o600)
    stdout = os.fdopen(fd, "a", encoding="utf-8")
    stdout.write(
        f"\n--- monitor start {time.strftime('%Y-%m-%dT%H:%M:%SZ')} "
        f"workers={c.get('workers')} cpa={now} target={c.get('target_cpa')} need={need} ---\n"
    )
    stdout.flush()
    try:
        p = subprocess.Popen(
            [str(VENV_PY), "-u", str(ORCH_SCRIPT)],
            cwd=str(ROOT),
            stdout=stdout,
            stderr=subprocess.STDOUT,
            env=_registration_env(),
            **popen_group_kwargs(),
        )
    finally:
        stdout.close()
    write_pid_file(ORCH_PID, p.pid)
    return {
        "ok": True,
        "pid": p.pid,
        "mode": "orch",
        "workers": c.get("workers"),
        "cpa_now": now,
        "target_cpa": c.get("target_cpa"),
        "need": need,
        "add_count": add_count or c.get("add_count"),
        "control": c,
        "message": f"已启动 orch pid={p.pid} 目标 CPA {c.get('target_cpa')} (再跑 {need})",
    }


def start_orch():
    with START_LOCK:
        return _start_orch_unlocked()



def _start_batch_only_unlocked():
    proc = process_running()
    if proc.get("batch_running") or proc.get("orch_running"):
        return {"ok": False, "error": "already running", "process": proc}
    if _find_managed_processes(("sso_to_auth_json.py",)):
        return {"ok": False, "error": "account recovery is running"}
    prerequisite_error = _runtime_prerequisite_error()
    if prerequisite_error:
        return {"ok": False, "error": prerequisite_error}
    c = load_control()
    workers = int(c.get("workers") or 3)
    count = int(c.get("batch_count") or 40)
    now = cpa_count()
    c["base_cpa"] = now
    c["target_cpa"] = now + count
    c = save_control(c)
    logname = LOG_DIR / f"batch-orch-{time.strftime('%Y%m%d-%H%M%S')}-n{count}.log"
    ensure_private_dir(LOG_DIR)
    fd = os.open(logname, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    best_effort_fchmod(fd, 0o600)
    fout = os.fdopen(fd, "w", encoding="utf-8")
    try:
        p = subprocess.Popen(
            batch_launch_command(
                ROOT,
                count,
                workers,
                python_path=VENV_PY,
            ),
            cwd=str(ROOT),
            stdout=fout,
            stderr=subprocess.STDOUT,
            env=_registration_env(),
            **popen_group_kwargs(),
        )
    finally:
        fout.close()
    write_pid_file(BATCH_PID, p.pid)
    return {
        "ok": True,
        "pid": p.pid,
        "mode": "batch",
        "workers": workers,
        "count": count,
        "log": logname.name,
    }


def start_batch_only():
    with START_LOCK:
        return _start_batch_only_unlocked()


def snapshot():
    log = discover_log()
    parsed = parse_log(log) if log else {"error": "no log"}
    cpa = cpa_count()
    configured_base = read_base()
    base_stale = configured_base < 0 or configured_base > cpa
    base = cpa if base_stale else configured_base
    proc = process_running()
    control = load_control()
    bl = read_blacklist()
    bl_err = blacklist_update_errors()
    try:
        rates = success_stats().get("rates") or {}
    except Exception:
        rates = {}
    target = parsed.get("count_target") or control.get("batch_count") or 40
    ok = parsed.get("ok") or 0
    fail = parsed.get("fail") or 0
    done = ok + fail
    pct = round(100.0 * ok / target, 2) if target else 0
    eta = None
    rate_per_min = None
    etime = proc.get("etime") or proc.get("batch_etime") or ""
    secs = _parse_etime(etime)
    if secs and ok > 0:
        rate_per_min = round(ok / (secs / 60.0), 2)
        remain = max(target - ok, 0)
        if rate_per_min > 0:
            eta_min = remain / rate_per_min
            eta = f"{int(eta_min)}m" if eta_min < 120 else f"{eta_min/60:.1f}h"
    workers_show = parsed.get("workers") or control.get("workers")
    traffic = read_batch_traffic(BATCH_TRAFFIC)
    if traffic.get("running") and not proc.get("running"):
        traffic["running"] = False
    return {
        "ts": time.time(),
        "ts_human": beijing_strftime("%Y-%m-%d %H:%M:%S"),
        "base_cpa": base,
        "base_cpa_stale": base_stale,
        "cpa": cpa,
        "cpa_delta": cpa - base,
        "process": proc,
        "control": control,
        "target": target,
        "done_attempts": done,
        "progress_pct": pct,
        "success_rate": round(100.0 * ok / done, 1) if done else None,
        "rate_per_min": rate_per_min,
        "eta": eta,
        "traffic": traffic,
        "blacklist": {
            "count": bl.get("count"),
            "asns": bl.get("asns"),
            "items": bl.get("items"),
            "isp_keywords": bl.get("isp_keywords"),
            "mtime_human": bl.get("mtime_human"),
            "ok": bl.get("ok"),
            "error": bl.get("error"),
            "errors": bl.get("errors"),
        },
        "blacklist_update": bl_err,
        "rates": rates,
        **{k: v for k, v in parsed.items() if k != "tail"},
        "workers": workers_show,
        "tail": (parsed.get("tail") or []) if PANEL_INCLUDE_TAIL else ["(raw log tail disabled; set PANEL_INCLUDE_TAIL=1)"],
    }


HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="theme-color" content="#f3f4f1" id="theme-color"/>
<title>GrokRegister</title>
<script>
  (function () {
    const key = "GROK_REGISTER_THEME";
    let theme = "";
    try { theme = localStorage.getItem(key) || ""; } catch (e) {}
    if (theme !== "light" && theme !== "dark") {
      theme = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    }
    document.documentElement.dataset.theme = theme;
    document.getElementById("theme-color").content = theme === "dark" ? "#171815" : "#f3f4f1";
  })();
</script>
<style>
  /* Hallmark · macrostructure: Workbench · tone: utilitarian · anchor hue: oxide-red
   * pre-emit critique: P4 H5 E5 S5 R5 V4 · component: batch traffic KPI
   * contrast: inherited pass · mobile: verified at 320/375/414/768
   */
  @font-face {
    font-family: "Geist";
    src: url("/assets/geist.woff2") format("woff2");
    font-style: normal;
    font-weight: 100 900;
    font-display: swap;
  }
  @font-face {
    font-family: "Geist Mono";
    src: url("/assets/geist-mono.woff2") format("woff2");
    font-style: normal;
    font-weight: 100 900;
    font-display: swap;
  }
  :root {
    color-scheme: light;
    --bg: #f3f4f1;
    --surface: #e9eae6;
    --surface-raised: #f8f9f6;
    --surface-soft: #eff0ec;
    --surface-deep: #d9dad5;
    --border: rgba(21, 22, 19, .16);
    --border-strong: rgba(21, 22, 19, .46);
    --text: #151613;
    --text-secondary: #383a35;
    --muted: #696b64;
    --placeholder: #85877f;
    --ok: #237a57;
    --fail: #b83f3f;
    --warn: #8a6400;
    --accent: #b93b28;
    --accent-hover: #9f2f1f;
    --accent-ink: #f8f9f6;
    --focus: #b93b28;
    --button: #f8f9f6;
    --button-hover: #e1e2dd;
    --hover-border: rgba(21, 22, 19, .46);
    --focus-shadow: rgba(185, 59, 40, .16);
    --primary-bg: #151613;
    --primary-text: #f8f9f6;
    --primary-hover: #2e302b;
    --danger-border: rgba(184, 63, 63, .45);
    --danger-hover-bg: rgba(184, 63, 63, .08);
    --danger-hover-border: rgba(184, 63, 63, .72);
    --header: rgba(243, 244, 241, .88);
    --progress-track: #d9dad5;
    --row-hover: rgba(21, 22, 19, .035);
    --tail-bg: #151613;
    --tail-text: #d3d5ce;
    --grid-line: rgba(21, 22, 19, .055);
  }
  * { box-sizing: border-box; }
  [hidden] { display: none !important; }
  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
  }
  html {
    overflow-x: clip;
    background: var(--bg);
    transition: background-color 180ms ease, color 180ms ease;
  }
  body {
    overflow-x: clip;
    margin: 0;
    min-height: 100dvh;
    background-color: var(--bg);
    background-image:
      linear-gradient(to right, var(--grid-line) 1px, transparent 1px),
      linear-gradient(to bottom, var(--grid-line) 1px, transparent 1px);
    background-size: 40px 40px;
    background-attachment: fixed;
    color: var(--text);
    font-family: "Geist", "Noto Sans CJK SC", "Noto Sans SC", "PingFang SC", "Microsoft YaHei", system-ui, sans-serif;
    font-size: 14px;
    line-height: 1.45;
    letter-spacing: 0;
    transition: background-color 180ms ease, color 180ms ease;
  }
  ::selection { background: var(--accent); color: var(--accent-ink); }
  header {
    position: sticky;
    top: 0;
    z-index: 10;
    border-bottom: 1px solid var(--border);
    background: var(--header);
    backdrop-filter: blur(18px) saturate(118%);
    -webkit-backdrop-filter: blur(18px) saturate(118%);
    transition: background-color 180ms ease, border-color 180ms ease;
  }
  .topbar {
    width: min(calc(100% - 64px), 1480px);
    height: 68px;
    margin: 0 auto;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 20px;
  }
  .brand { min-width: 0; }
  h1 {
    margin: 0;
    color: var(--text);
    font-size: 17px;
    line-height: 1.2;
    font-weight: 800;
  }
  h1::after {
    content: "";
    width: 5px;
    height: 5px;
    display: inline-block;
    margin-left: 5px;
    background: var(--accent);
    transition: background-color 180ms ease;
  }
  .page-heading {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: 20px;
    margin: 2px 0 20px;
  }
  .page-heading > div { min-width: 0; }
  .page-title { margin: 0; color: var(--text); font-size: 28px; line-height: 1.18; font-weight: 680; }
  .brand-subtitle {
    margin-top: 7px;
    color: var(--muted);
    font-size: 11px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .status-cluster {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 8px;
    flex-wrap: nowrap;
  }
  .badge {
    min-height: 28px;
    display: inline-flex;
    align-items: center;
    gap: 7px;
    padding: 4px 10px;
    border: 1px solid var(--border);
    border-radius: 2px;
    background: transparent;
    color: var(--text-secondary);
    font-size: 12px;
    font-weight: 560;
    white-space: nowrap;
  }
  .dot { width: 7px; height: 7px; flex: 0 0 auto; border-radius: 50%; background: var(--muted); }
  .dot.on { background: var(--ok); }
  .dot.done { background: var(--ok); }
  .dot.off { background: var(--muted); }
  main { width: min(calc(100% - 64px), 1480px); margin: 0 auto; padding: 28px 0 48px; }
  .panel-gap { margin-top: 14px; }
  .card {
    min-width: 0;
    background: var(--surface-raised);
    border: 1px solid var(--border);
    border-radius: 0;
    padding: 16px;
    transition: background-color 180ms ease, border-color 180ms ease, color 180ms ease, transform 180ms cubic-bezier(.16, 1, .3, 1);
  }
  @media (hover: hover) {
    .card:hover { border-color: var(--border-strong); transform: translateY(-2px); }
  }
  .panel { margin-top: 14px; }
  .panel.no-margin { margin-top: 0; }
  .panel h2, .card h2 {
    margin: 0;
    color: var(--text);
    font-size: 13px;
    font-weight: 620;
  }
  .ok { color: var(--ok); } .fail { color: var(--fail); } .warn { color: var(--warn); } .accent { color: var(--accent); }
  .section-head {
    min-height: 32px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    margin-bottom: 14px;
  }
  .section-meta { color: var(--muted); font-size: 12px; text-align: right; }
  .list-pager {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    margin-top: 10px;
    flex-wrap: wrap;
  }
  .list-pager .pager-info { color: var(--muted); font-size: 12px; }
  .list-pager .pager-btns { display: flex; gap: 6px; align-items: center; }
  .list-pager button {
    min-height: 30px;
    padding: 4px 10px;
    font-size: 12px;
  }
  .list-pager button:disabled { opacity: .4; cursor: not-allowed; }
  .control-grid {
    display: grid;
    grid-template-columns: minmax(220px, 1.6fr) minmax(150px, .9fr) repeat(4, minmax(100px, .55fr)) minmax(258px, auto);
    gap: 12px;
    align-items: end;
  }
  .control-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
  }
  .control-panel { padding: 12px 16px; }
  .control-panel .section-head { min-height: 24px; margin-bottom: 8px; }
  .control-panel .msg:empty { display: none; }
  .field { min-width: 0; display: flex; flex-direction: column; gap: 6px; }
  .field label { color: var(--muted); font-size: 12px; font-weight: 560; }
  input, select, textarea, button { font: inherit; letter-spacing: 0; }
  input, select, textarea {
    width: 100%;
    min-height: 38px;
    border: 1px solid var(--border-strong);
    border-radius: 2px;
    background: var(--surface-soft);
    color: var(--text);
    padding: 8px 10px;
    outline: none;
  }
  textarea { resize: vertical; }
  input::placeholder, textarea::placeholder { color: var(--placeholder); opacity: 1; }
  input:hover, select:hover, textarea:hover { border-color: var(--hover-border); }
  input:focus, select:focus, textarea:focus { border-color: var(--focus); box-shadow: 0 0 0 3px var(--focus-shadow); }
  button {
    min-height: 38px;
    border: 1px solid var(--border-strong);
    border-radius: 2px;
    background: var(--button);
    color: var(--text);
    padding: 8px 14px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    transition: background-color 180ms ease, border-color 180ms ease, color 180ms ease, transform 180ms cubic-bezier(.16, 1, .3, 1);
    white-space: nowrap;
  }
  button:hover { background: var(--button-hover); border-color: var(--hover-border); }
  button:active { transform: translateY(2px); }
  button:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
  button.primary { background: var(--primary-bg); border-color: var(--primary-bg); color: var(--primary-text); }
  button.primary:hover { background: var(--primary-hover); border-color: var(--primary-hover); }
  button.danger { background: transparent; border-color: var(--danger-border); color: var(--fail); }
  button.danger:hover { background: var(--danger-hover-bg); border-color: var(--danger-hover-border); }
  button:disabled { opacity: .42; cursor: not-allowed; transform: none; }
  button.view-switch {
    min-width: 68px;
    min-height: 30px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 0 9px;
    border-color: var(--border);
    background: var(--surface-soft);
    color: var(--text-secondary);
    font-size: 11px;
    font-weight: 620;
    line-height: 1;
  }
  button.view-switch:hover { border-color: var(--hover-border); color: var(--text); }
  button.view-switch[data-active="true"] {
    border-color: var(--accent);
    background: var(--accent);
    color: var(--accent-ink);
  }
  .theme-switch {
    flex: 0 0 auto;
    display: inline-flex;
    align-items: center;
    gap: 2px;
    padding: 2px;
    border: 1px solid var(--border);
    border-radius: 2px;
    background: var(--surface-soft);
  }
  button.theme-option {
    min-height: 24px;
    padding: 3px 8px;
    border: 0;
    border-radius: 1px;
    background: transparent;
    color: var(--muted);
    font-size: 11px;
    font-weight: 560;
    line-height: 1;
  }
  button.theme-option:hover { border: 0; background: var(--button-hover); color: var(--text); }
  button.theme-option[aria-pressed="true"] { background: var(--accent); color: var(--accent-ink); }
  .metric-grid {
    display: grid;
    grid-template-columns: repeat(6, minmax(0, 1fr));
    gap: 1px;
    overflow: hidden;
    border: 1px solid var(--border);
    border-radius: 0;
    background: var(--border);
  }
  #kpis { margin-top: 10px; }
  .metric {
    min-width: 0;
    padding: 10px 14px;
    background: var(--surface);
    transition: background-color 180ms ease, color 180ms ease;
  }
  .metric:hover { background: var(--surface-raised); }
  .metric .label { color: var(--muted); font-size: 11px; }
  .metric .value {
    margin-top: 4px;
    font-size: 23px;
    line-height: 1.05;
    font-weight: 730;
    font-variant-numeric: tabular-nums;
    overflow-wrap: anywhere;
  }
  .metric .sub { min-height: 16px; margin-top: 4px; color: var(--muted); font-size: 11px; }
  .rate-panel { margin-top: 10px; padding: 12px 16px 14px; }
  .rate-panel .section-head { min-height: 24px; margin-bottom: 8px; }
  .rate-panel .section-meta { font-size: 11px; }
  .rate-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    border: 1px solid var(--border);
    border-radius: 0;
    overflow: hidden;
  }
  .rate-item { min-width: 0; padding: 10px 12px; background: var(--surface-soft); transition: background-color 180ms ease; }
  .rate-item + .rate-item { border-left: 1px solid var(--border); }
  .rate-top { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; }
  .rate-label { color: var(--text-secondary); font-size: 12px; }
  .rate-total { color: var(--muted); font-size: 11px; white-space: nowrap; }
  .rate-value { margin-top: 4px; font-size: 23px; line-height: 1; font-weight: 730; font-variant-numeric: tabular-nums; }
  .rate-breakdown { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 6px; color: var(--muted); font-size: 11px; }
  .progress-head { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; margin-bottom: 10px; }
  .bar-wrap { height: 8px; overflow: hidden; border-radius: 1px; background: var(--progress-track); }
  .bar { height: 100%; width: 0%; background: var(--accent); transition: width 420ms cubic-bezier(.16, 1, .3, 1), background-color 180ms ease; }
  .progress-sub { margin-top: 9px; color: var(--muted); font-size: 12px; }
  .two { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 14px; }
  .three { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.15fr) minmax(0, .95fr); gap: 14px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 9px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { color: var(--muted); font-weight: 620; font-size: 11px; }
  td { color: var(--text-secondary); }
  tbody tr:last-child td { border-bottom: 0; }
  tr:hover td { background: var(--row-hover); }
  .table-scroll { width: 100%; overflow: auto; }
  .mono { font-family: "Geist Mono", "SFMono-Regular", Consolas, monospace; font-size: 12px; }
  .tail {
    max-height: 360px;
    overflow: auto;
    border: 1px solid var(--border);
    border-radius: 2px;
    background: var(--tail-bg);
    padding: 12px;
    color: var(--tail-text);
    font-size: 11.5px;
    line-height: 1.55;
    white-space: pre-wrap;
    word-break: break-word;
  }
  .chips { display: flex; flex-wrap: wrap; gap: 7px; }
  .card > h2 + .chips { margin-top: 14px; }
  .chip {
    min-width: 84px;
    border: 1px solid var(--border);
    border-radius: 2px;
    background: var(--surface-soft);
    padding: 8px 9px;
  }
  .chip b { display: block; margin-top: 2px; font-size: 17px; font-variant-numeric: tabular-nums; }
  .chip span { color: var(--muted); font-size: 11px; }
  .bl-list {
    max-height: 260px;
    overflow: auto;
    border: 1px solid var(--border);
    border-radius: 2px;
    background: var(--surface-soft);
  }
  .bl-list table { font-size: 12px; }
  .msg { font-size: 12px; color: var(--muted); min-height: 18px; margin-top: 8px; }
  .msg.err { color: var(--fail); } .msg.ok { color: var(--ok); }
  .button-group { display: flex; align-items: center; justify-content: flex-end; gap: 7px; flex-wrap: wrap; }
  .recovery-layout { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
  .recovery-layout .chips { flex: 1 1 auto; }
  .recovery-actions { flex: 0 0 auto; }
  body.proxy-view-open { overflow: hidden; }
  body.proxy-view-open #dashboard-view > :not(#proxy-view) { display: none; }
  .proxy-view {
    position: fixed;
    inset: 68px 0 0;
    z-index: 8;
    overflow-y: auto;
    overscroll-behavior: contain;
    background-color: var(--bg);
    background-image:
      linear-gradient(to right, var(--grid-line) 1px, transparent 1px),
      linear-gradient(to bottom, var(--grid-line) 1px, transparent 1px);
    background-size: 40px 40px;
  }
  .proxy-view[hidden] { display: none; }
  .proxy-view-inner {
    width: min(calc(100% - 64px), 1280px);
    margin: 0 auto;
    padding: 28px 0 48px;
  }
  .proxy-view-heading {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 20px;
    padding-bottom: 20px;
    border-bottom: 1px solid var(--border);
  }
  .proxy-view-subtitle { margin: 7px 0 0; color: var(--muted); font-size: 12px; }
  .proxy-summary {
    display: grid;
    grid-template-columns: repeat(5, minmax(0, 1fr));
    overflow: hidden;
    border: 1px solid var(--border);
    background: var(--border);
    gap: 1px;
  }
  .proxy-summary-item { min-width: 0; padding: 12px 14px; background: var(--surface); }
  .proxy-summary-label { color: var(--muted); font-size: 11px; }
  .proxy-summary-value { margin-top: 4px; font-family: "Geist Mono", monospace; font-size: 22px; line-height: 1; font-weight: 720; }
  .proxy-import {
    display: grid;
    grid-template-columns: minmax(0, 1.5fr) minmax(260px, .5fr);
    gap: 16px;
    align-items: stretch;
    margin-top: 14px;
    padding: 16px 0;
    border-top: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
  }
  #proxy-input {
    min-height: 126px;
    font-family: "Geist Mono", monospace;
    font-size: 12px;
    line-height: 1.55;
  }
  .proxy-import-actions { display: flex; flex-direction: column; justify-content: space-between; gap: 12px; }
  .proxy-import-actions .button-group { justify-content: flex-start; }
  .proxy-format { margin: 0; color: var(--muted); font-size: 11px; line-height: 1.6; }
  .proxy-list-section { margin-top: 18px; }
  .proxy-list-head { display: flex; align-items: center; justify-content: space-between; gap: 14px; margin-bottom: 10px; }
  .proxy-list-head h2 { margin: 0; font-size: 13px; }
  .proxy-table-wrap { overflow: auto; border: 1px solid var(--border); background: var(--surface-raised); }
  .proxy-table { min-width: 990px; table-layout: fixed; }
  .proxy-table th:nth-child(1) { width: 82px; }
  .proxy-table th:nth-child(2) { width: 260px; }
  .proxy-table th:nth-child(3) { width: 150px; }
  .proxy-table th:nth-child(4) { width: 86px; }
  .proxy-table th:nth-child(5) { width: 180px; }
  .proxy-table th:nth-child(6) { width: 96px; }
  .proxy-table th:nth-child(7) { width: 190px; }
  .proxy-endpoint { overflow-wrap: anywhere; }
  .proxy-meta { margin-top: 3px; color: var(--muted); font-size: 10px; }
  .proxy-state {
    min-height: 24px;
    display: inline-flex;
    align-items: center;
    padding: 3px 7px;
    border: 1px solid var(--border);
    border-radius: 2px;
    color: var(--text-secondary);
    font-size: 11px;
    white-space: nowrap;
  }
  .proxy-state.healthy { border-color: color-mix(in srgb, var(--ok) 55%, var(--border)); color: var(--ok); }
  .proxy-state.unhealthy { border-color: color-mix(in srgb, var(--fail) 55%, var(--border)); color: var(--fail); }
  .proxy-state.cooldown { border-color: color-mix(in srgb, var(--warn) 55%, var(--border)); color: var(--warn); }
  .proxy-state.testing { border-color: color-mix(in srgb, var(--accent) 55%, var(--border)); color: var(--accent); }
  .proxy-actions { display: flex; align-items: center; gap: 6px; }
  .proxy-actions button { min-height: 30px; padding: 5px 9px; font-size: 11px; }
  .proxy-toggle { width: 16px; height: 16px; min-height: 0; accent-color: var(--accent); }
  .proxy-empty { padding: 38px 18px !important; color: var(--muted); text-align: center; }
  .proxy-job { color: var(--muted); font-size: 11px; }
  body.domain-view-open { overflow: hidden; }
  body.domain-view-open #dashboard-view > :not(#domain-view) { display: none; }
  .domain-view {
    position: fixed;
    inset: 68px 0 0;
    z-index: 8;
    overflow-y: auto;
    overscroll-behavior: contain;
    background-color: var(--bg);
    background-image:
      linear-gradient(to right, var(--grid-line) 1px, transparent 1px),
      linear-gradient(to bottom, var(--grid-line) 1px, transparent 1px);
    background-size: 40px 40px;
  }
  .domain-view[hidden] { display: none; }
  .domain-view-inner {
    width: min(calc(100% - 64px), 1280px);
    margin: 0 auto;
    padding: 28px 0 48px;
  }
  .domain-view-heading {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 20px;
    padding-bottom: 20px;
    border-bottom: 1px solid var(--border);
  }
  .domain-view-subtitle { margin: 7px 0 0; color: var(--muted); font-size: 12px; }
  .mail-source-kicker {
    margin-bottom: 5px;
    color: var(--accent);
    font-size: 10px;
    font-weight: 760;
    text-transform: uppercase;
  }
  .mail-provider-panel {
    padding: 18px;
    border: 1px solid var(--border-strong);
    background: var(--surface-raised);
  }
  .mail-provider-toolbar {
    display: grid;
    grid-template-columns: minmax(280px, 1fr) auto;
    align-items: end;
    gap: 18px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--border);
  }
  .mail-provider-toolbar .field { max-width: 520px; }
  .mail-provider-status { display: flex; align-items: center; gap: 8px; min-height: 38px; }
  .mail-provider-status-label { color: var(--muted); font-size: 11px; }
  .mail-provider-fields {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 14px 16px;
    padding: 18px 0;
  }
  .mail-provider-fields .field { min-width: 0; gap: 5px; }
  .mail-provider-fields input,
  .mail-provider-fields select { width: 100%; min-height: 40px; }
  .mail-secret-wrap { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 6px; }
  .mail-secret-wrap button { min-width: 54px; min-height: 40px; padding-inline: 10px; font-size: 11px; }
  .mail-secret-wrap.pending-clear input { border-color: var(--warn); }
  .mail-secret-note { min-height: 14px; color: var(--muted); font-size: 10px; }
  .mail-secret-note.warn { color: var(--warn); }
  .mail-provider-actions {
    display: flex;
    align-items: center;
    gap: 8px;
    padding-top: 14px;
    border-top: 1px solid var(--border);
  }
  .mail-provider-actions .mail-provider-meta { margin-left: auto; color: var(--muted); font-size: 11px; }
  .mail-provider-result { min-height: 18px; margin-top: 10px; }
  .domain-advanced { margin-top: 20px; border-top: 1px solid var(--border-strong); border-bottom: 1px solid var(--border-strong); }
  .domain-advanced > summary {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
    min-height: 52px;
    padding: 10px 2px;
    color: var(--text);
    cursor: pointer;
    list-style: none;
  }
  .domain-advanced > summary::-webkit-details-marker { display: none; }
  .domain-advanced > summary::after { content: "+"; color: var(--accent); font-family: "Geist Mono", monospace; font-size: 18px; }
  .domain-advanced[open] > summary::after { content: "-"; }
  .domain-advanced-title { font-size: 13px; font-weight: 680; }
  .domain-advanced-meta { color: var(--muted); font-size: 11px; font-weight: 450; }
  .domain-advanced-body { padding: 4px 0 24px; }
  .domain-advanced-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 12px; }
  .domain-summary {
    display: grid;
    grid-template-columns: repeat(5, minmax(0, 1fr));
    overflow: hidden;
    border: 1px solid var(--border);
    background: var(--border);
    gap: 1px;
  }
  .domain-summary-item { min-width: 0; padding: 12px 14px; background: var(--surface); }
  .domain-summary-label { color: var(--muted); font-size: 11px; }
  .domain-summary-value { margin-top: 4px; font-family: "Geist Mono", monospace; font-size: 22px; line-height: 1; font-weight: 720; }
  .domain-import {
    display: grid;
    grid-template-columns: minmax(0, 1.25fr) minmax(300px, .75fr);
    gap: 16px;
    align-items: stretch;
    margin-top: 14px;
    padding: 16px 0;
    border-top: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
  }
  #domain-input {
    min-height: 126px;
    font-family: "Geist Mono", monospace;
    font-size: 12px;
    line-height: 1.55;
  }
  .domain-import-actions { display: flex; flex-direction: column; justify-content: space-between; gap: 12px; }
  .domain-import-actions .button-group { justify-content: flex-start; }
  .domain-format { margin: 0; color: var(--muted); font-size: 11px; line-height: 1.6; }
  .domain-settings { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; }
  .domain-settings .field { gap: 4px; }
  .domain-settings input, .domain-settings select { min-height: 34px; }
  .domain-list-section { margin-top: 18px; }
  .domain-list-head { display: flex; align-items: center; justify-content: space-between; gap: 14px; margin-bottom: 10px; }
  .domain-list-head h2 { margin: 0; font-size: 13px; }
  .domain-table-wrap { overflow: auto; border: 1px solid var(--border); background: var(--surface-raised); }
  .domain-table { min-width: 960px; table-layout: fixed; }
  .domain-table th:nth-child(1) { width: 92px; }
  .domain-table th:nth-child(2) { width: 230px; }
  .domain-table th:nth-child(3) { width: 130px; }
  .domain-table th:nth-child(4) { width: 150px; }
  .domain-table th:nth-child(5) { width: 220px; }
  .domain-table th:nth-child(6) { width: 72px; }
  .domain-table th:nth-child(7) { width: 170px; }
  .domain-name { overflow-wrap: anywhere; }
  .domain-meta { margin-top: 3px; color: var(--muted); font-size: 10px; }
  .domain-state {
    min-height: 24px;
    display: inline-flex;
    align-items: center;
    padding: 3px 7px;
    border: 1px solid var(--border);
    border-radius: 2px;
    color: var(--text-secondary);
    font-size: 11px;
    white-space: nowrap;
  }
  .domain-state.active { border-color: color-mix(in srgb, var(--ok) 55%, var(--border)); color: var(--ok); }
  .domain-state.standby { border-color: color-mix(in srgb, var(--accent) 55%, var(--border)); color: var(--accent); }
  .domain-state.blocked { border-color: color-mix(in srgb, var(--fail) 55%, var(--border)); color: var(--fail); }
  .domain-state.disabled { border-color: var(--border); color: var(--muted); }
  .domain-actions { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
  .domain-actions button { min-height: 30px; padding: 5px 9px; font-size: 11px; }
  .domain-toggle { width: 16px; height: 16px; min-height: 0; accent-color: var(--accent); }
  .domain-empty { padding: 38px 18px !important; color: var(--muted); text-align: center; }
  .domain-job { color: var(--muted); font-size: 11px; }
  body.help-view-open { overflow: hidden; }
  body.help-view-open #dashboard-view > :not(#help-view) { display: none; }
  .help-view {
    position: fixed;
    inset: 68px 0 0;
    z-index: 8;
    overflow-y: auto;
    overscroll-behavior: contain;
    background-color: var(--bg);
    background-image:
      linear-gradient(to right, var(--grid-line) 1px, transparent 1px),
      linear-gradient(to bottom, var(--grid-line) 1px, transparent 1px);
    background-size: 40px 40px;
  }
  .help-view[hidden] { display: none; }
  .help-view-inner {
    width: min(calc(100% - 64px), 1120px);
    margin: 0 auto;
    padding: 28px 0 48px;
  }
  .help-view-heading {
    margin-bottom: 20px;
    padding-bottom: 20px;
    border-bottom: 1px solid var(--border);
  }
  .help-view-subtitle {
    margin: 7px 0 0;
    color: var(--muted);
    font-size: 12px;
  }
  .help-body { min-width: 0; }
  .help-toolbar {
    min-height: 42px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 16px;
  }
  .help-tabs {
    display: inline-flex;
    gap: 2px;
    padding: 2px;
    border: 1px solid var(--border);
    border-radius: 2px;
    background: var(--surface-soft);
  }
  button.help-tab {
    min-height: 28px;
    padding: 5px 10px;
    border: 0;
    border-radius: 1px;
    background: transparent;
    color: var(--muted);
    font-size: 12px;
  }
  button.help-tab:hover { border: 0; color: var(--text); }
  button.help-tab[aria-selected="true"] { background: var(--accent); color: var(--accent-ink); }
  .help-guide-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 1px;
    border: 1px solid var(--border);
    background: var(--border);
  }
  .help-guide-item { min-width: 0; min-height: 132px; padding: 14px; background: var(--surface-soft); }
  .help-guide-item h3 { margin: 0; color: var(--text); font-size: 13px; font-weight: 650; }
  .help-guide-item p { margin: 9px 0 0; color: var(--text-secondary); font-size: 12px; line-height: 1.65; }
  .help-guide-item code, .faq-answer code {
    color: var(--accent);
    font-family: "Geist Mono", monospace;
    font-size: .94em;
    overflow-wrap: anywhere;
  }
  .help-note {
    margin: 14px 0 0;
    padding-top: 12px;
    border-top: 1px solid var(--border);
    color: var(--muted);
    font-size: 11px;
    line-height: 1.6;
  }
  .faq-tools {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 4px;
  }
  #faq-search { min-height: 36px; max-width: 360px; }
  .faq-count { flex: 0 0 auto; color: var(--muted); font-size: 11px; }
  .faq-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); column-gap: 24px; }
  .faq-item { min-width: 0; border-top: 1px solid var(--border); }
  .faq-item summary {
    padding: 13px 2px;
    color: var(--text);
    font-size: 12px;
    font-weight: 620;
    line-height: 1.45;
    cursor: pointer;
  }
  .faq-item summary::marker { color: var(--accent); }
  .faq-item[open] summary { color: var(--accent); }
  .faq-answer { padding: 0 18px 14px; color: var(--text-secondary); font-size: 12px; line-height: 1.65; }
  .faq-empty { margin: 16px 0 2px; color: var(--muted); font-size: 12px; }
  footer { margin-top: 16px; color: var(--muted); font-size: 11px; overflow-wrap: anywhere; }
  main > :not(.help-view) {
    animation: panel-enter 520ms cubic-bezier(.16, 1, .3, 1) both;
  }
  main > :nth-child(2) { animation-delay: 45ms; }
  main > :nth-child(3) { animation-delay: 90ms; }
  main > :nth-child(4) { animation-delay: 135ms; }
  main > :nth-child(5) { animation-delay: 180ms; }
  main > :nth-child(6) { animation-delay: 225ms; }
  main > :nth-child(7) { animation-delay: 270ms; }
  main > :nth-child(8) { animation-delay: 315ms; }
  main > :nth-child(9) { animation-delay: 360ms; }
  main > :nth-child(n + 10) { animation-delay: 405ms; }
  @keyframes panel-enter {
    from { opacity: 0; transform: translateY(12px); }
    to { opacity: 1; transform: translateY(0); }
  }
  @media (min-width: 1121px) {
    .control-panel .control-grid { gap: 10px; }
    .control-panel .field { gap: 4px; }
    .control-panel .field label { font-size: 11px; }
    .control-panel .control-actions { gap: 6px; }
    .control-panel input,
    .control-panel select,
    .control-panel .control-actions button {
      min-height: 34px;
      padding-block: 6px;
    }
  }
  @media (max-width: 1120px) {
    .control-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .field-token { grid-column: span 2; }
    .control-actions { grid-column: 1 / -1; padding-top: 14px; border-top: 1px solid var(--border); }
    .metric-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .three { grid-template-columns: minmax(0, 1fr); }
    .help-guide-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .mail-provider-fields { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  }
  @media (max-width: 760px) {
    .topbar { width: calc(100% - 32px); height: 60px; align-items: center; flex-direction: row; gap: 10px; }
    .brand { width: auto; }
    .status-cluster { width: auto; justify-content: flex-end; margin-left: auto; }
    #clock, #sync-label { display: none; }
    main { width: calc(100% - 24px); padding: 20px 0 34px; }
    .page-heading { margin-bottom: 16px; }
    .page-title { font-size: 22px; }
    .card { padding: 14px; }
    .control-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .field-token, .field-mode { grid-column: 1 / -1; }
    .control-actions { justify-content: stretch; }
    .control-actions button { flex: 1 1 0; padding-inline: 8px; }
    .metric-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .metric { padding: 14px; }
    .metric .value { font-size: 23px; }
    .rate-grid, .two { grid-template-columns: minmax(0, 1fr); }
    .rate-item + .rate-item { border-left: 0; border-top: 1px solid var(--border); }
    .section-head { align-items: flex-start; }
    .section-meta { max-width: 48%; }
    .help-view { inset-block-start: 60px; }
    .help-view-inner { width: calc(100% - 24px); padding: 20px 0 34px; }
    .help-view-heading { margin-bottom: 16px; padding-bottom: 16px; }
    .help-toolbar, .faq-tools { align-items: stretch; flex-direction: column; }
    .help-toolbar { min-height: 0; }
    .help-tabs { width: 100%; }
    button.help-tab { flex: 1 1 0; }
    .help-guide-grid, .faq-grid { grid-template-columns: 1fr; }
    #faq-search { max-width: none; }
    .recovery-layout { align-items: stretch; flex-direction: column; }
    .recovery-actions { justify-content: stretch; }
    .recovery-actions button { flex: 1 1 0; }
    .proxy-view { inset-block-start: 60px; }
    .proxy-view-inner { width: calc(100% - 24px); padding: 20px 0 34px; }
    .proxy-view-heading { align-items: flex-start; flex-direction: column; margin-bottom: 16px; padding-bottom: 16px; }
    .proxy-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .proxy-summary-item:last-child { grid-column: 1 / -1; }
    .proxy-import { grid-template-columns: minmax(0, 1fr); }
    .proxy-import-actions .button-group { justify-content: stretch; }
    .proxy-import-actions button { flex: 1 1 auto; }
    .proxy-list-head { align-items: flex-start; flex-direction: column; }
    .domain-view { inset-block-start: 60px; }
    .domain-view-inner { width: calc(100% - 24px); padding: 20px 0 34px; }
    .domain-view-heading { align-items: flex-start; flex-direction: column; margin-bottom: 16px; padding-bottom: 16px; }
    .mail-provider-panel { padding: 14px; }
    .mail-provider-toolbar { grid-template-columns: minmax(0, 1fr); gap: 10px; }
    .mail-provider-toolbar .field { max-width: none; }
    .mail-provider-fields { grid-template-columns: minmax(0, 1fr); }
    .mail-provider-actions { align-items: stretch; flex-wrap: wrap; }
    .mail-provider-actions button { flex: 1 1 0; }
    .mail-provider-actions .mail-provider-meta { width: 100%; margin-left: 0; }
    .domain-advanced-head { align-items: flex-start; flex-direction: column; }
    .domain-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .domain-summary-item:last-child { grid-column: 1 / -1; }
    .domain-import { grid-template-columns: minmax(0, 1fr); }
    .domain-settings { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .domain-import-actions .button-group { justify-content: stretch; }
    .domain-import-actions button { flex: 1 1 auto; }
    .domain-list-head { align-items: flex-start; flex-direction: column; }
  }
  @media (max-width: 420px) {
    .topbar { gap: 6px; }
    .brand { flex: 0 0 auto; }
    h1 { font-size: 0; }
    h1::before { content: "GR"; font-size: 15px; }
    .status-cluster { min-width: 0; gap: 4px; }
    .badge { font-size: 11px; }
    .run-status { width: 30px; min-width: 30px; justify-content: center; padding-inline: 0; }
    #run-label { display: none; }
    .card { padding: 13px; }
    .control-actions { flex-wrap: wrap; }
    .control-actions button { flex-basis: calc(50% - 4px); }
    .control-actions button:last-child { flex-basis: 100%; }
    .metric .sub { font-size: 11px; }
    .button-group { justify-content: flex-start; }
    #run-status { display: none; }
    button.view-switch { min-width: 0; padding-inline: 6px; }
    #domain-view-label, #proxy-view-label, #help-view-label { font-size: 0; }
    #domain-view-label::after { content: "邮箱"; font-size: 11px; }
    #proxy-view-label::after { content: "代理"; font-size: 11px; }
    #help-view-label::after { content: "问题"; font-size: 11px; }
    #domain-view-toggle[data-active="true"] #domain-view-label::after,
    #proxy-view-toggle[data-active="true"] #proxy-view-label::after,
    #help-view-toggle[data-active="true"] #help-view-label::after { content: "返回"; }
    button.theme-option { padding-inline: 6px; }
    .domain-settings { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .domain-settings .field:first-child { grid-column: 1 / -1; }
  }
  @media (max-width: 340px) {
    .run-status { display: none; }
  }
  html[data-theme="dark"] {
      color-scheme: dark;
      --bg: #171815;
      --surface: #20211e;
      --surface-raised: #242622;
      --surface-soft: #1d1e1b;
      --surface-deep: #30322d;
      --border: rgba(240, 241, 237, .16);
      --border-strong: rgba(240, 241, 237, .42);
      --text: #f0f1ed;
      --text-secondary: #d3d5ce;
      --muted: #a5a79f;
      --placeholder: #777971;
      --ok: #69c493;
      --fail: #f27c71;
      --warn: #d7ae58;
      --accent: #f06449;
      --accent-hover: #ff7a60;
      --accent-ink: #171815;
      --focus: #f06449;
      --button: #242622;
      --button-hover: #30322d;
      --hover-border: rgba(240, 241, 237, .42);
      --focus-shadow: rgba(240, 100, 73, .18);
      --primary-bg: #f0f1ed;
      --primary-text: #171815;
      --primary-hover: #d3d5ce;
      --danger-border: rgba(242, 124, 113, .48);
      --danger-hover-bg: rgba(242, 124, 113, .09);
      --danger-hover-border: rgba(242, 124, 113, .75);
      --header: rgba(23, 24, 21, .88);
      --progress-track: #30322d;
      --row-hover: rgba(240, 241, 237, .035);
      --tail-bg: #11120f;
      --tail-text: #d3d5ce;
      --grid-line: rgba(240, 241, 237, .045);
  }
  @media (prefers-reduced-motion: reduce) {
    html { scroll-behavior: auto; }
    *, *::before, *::after {
      animation-duration: .01ms !important;
      animation-iteration-count: 1 !important;
      transition-duration: .01ms !important;
    }
    .card:hover { transform: none; }
  }
</style>
</head>
<body>
<header>
  <div class="topbar">
    <div class="brand">
      <h1>GrokRegister</h1>
    </div>
    <div class="status-cluster">
      <button type="button" class="view-switch" id="domain-view-toggle" aria-label="打开邮箱服务" title="邮箱服务" aria-controls="domain-view" aria-expanded="false" data-active="false" onclick="toggleDomainView()">
        <span id="domain-view-label" aria-hidden="true">邮箱服务</span>
      </button>
      <button type="button" class="view-switch" id="proxy-view-toggle" aria-label="打开代理池" title="代理池" aria-controls="proxy-view" aria-expanded="false" data-active="false" onclick="toggleProxyView()">
        <span id="proxy-view-label" aria-hidden="true">代理池</span>
      </button>
      <button type="button" class="view-switch" id="help-view-toggle" aria-label="打开问题和使用" title="问题和使用" aria-controls="help-view" aria-expanded="false" data-active="false" onclick="toggleAppView()">
        <span id="help-view-label" aria-hidden="true">问题和使用</span>
      </button>
      <div class="theme-switch" role="group" aria-label="界面主题">
        <button type="button" class="theme-option" data-theme-choice="light" aria-pressed="false" onclick="setTheme('light')">浅色</button>
        <button type="button" class="theme-option" data-theme-choice="dark" aria-pressed="false" onclick="setTheme('dark')">深色</button>
      </div>
      <span class="badge run-status" id="run-status" aria-label="任务状态：加载中" aria-live="polite" aria-atomic="true"><span class="dot" id="run-dot"></span><span id="run-label">加载中</span></span>
      <span class="badge mono" id="clock">--</span>
      <span class="badge" id="sync-label">实时更新</span>
    </div>
  </div>
</header>
<main id="dashboard-view" aria-label="注册控制台">
  <div class="page-heading">
    <div>
      <div class="page-title">注册控制台</div>
      <div class="brand-subtitle mono" id="logname">--</div>
    </div>
  </div>
  <section class="card control-panel">
    <div class="section-head">
      <h2>任务控制</h2>
      <span class="section-meta mono" id="ctrl-status"></span>
    </div>
    <div class="control-grid">
      <div class="field field-token">
        <label for="monitor-token">访问令牌</label>
        <input id="monitor-token" type="password" autocomplete="off" placeholder="MONITOR_TOKEN" onchange="getToken(); refresh(); refreshRecovery(); refreshProxies(); refreshEmailProvider(); refreshEmailDomains()" onblur="getToken()"/>
      </div>
      <div class="field field-mode">
        <label for="mode">运行模式</label>
        <select id="mode">
          <option value="orch">持续编排</option>
          <option value="batch">单批运行</option>
        </select>
      </div>
      <div class="field"><label for="workers-input">并发数</label>
        <input type="number" id="workers-input" min="1" max="24" value="3"/>
      </div>
      <div class="field"><label for="batch_count">单批数量</label>
        <input type="number" id="batch_count" min="1" max="200" value="40"/>
      </div>
      <div class="field"><label for="add_count">追加目标</label>
        <input type="number" id="add_count" min="1" max="500" value="40" title="每次启动从当前 CPA 再注册 N 个"/>
      </div>
      <div class="field"><label for="risk_pause">风控阈值</label>
        <input type="number" id="risk_pause" min="1" max="50" value="10"/>
      </div>
      <div class="control-actions">
        <button class="primary" id="btn-start" onclick="doStart()">启动任务</button>
        <button class="danger" id="btn-stop" onclick="doStop()">停止任务</button>
        <button onclick="saveCtrl()">保存设置</button>
      </div>
    </div>
    <div class="msg" id="ctrl-msg" role="status" aria-live="polite"></div>
  </section>

  <section class="help-view" id="help-view" aria-labelledby="help-view-title" hidden>
    <div class="help-view-inner">
      <div class="help-view-heading">
        <div class="page-title" id="help-view-title">使用帮助</div>
        <p class="help-view-subtitle">运行方法与故障排查</p>
      </div>
      <div class="help-body" id="help-body">
      <div class="help-toolbar">
        <div class="help-tabs" role="tablist" aria-label="帮助内容" onkeydown="handleHelpTabKey(event)">
          <button type="button" class="help-tab" id="help-tab-guide" role="tab" aria-selected="true" aria-controls="help-guide" data-help-tab="guide" onclick="setHelpTab('guide')">快速使用</button>
          <button type="button" class="help-tab" id="help-tab-faq" role="tab" aria-selected="false" aria-controls="help-faq" data-help-tab="faq" tabindex="-1" onclick="setHelpTab('faq')">常见问题</button>
        </div>
      </div>

      <div id="help-guide" role="tabpanel" aria-labelledby="help-tab-guide">
        <div class="help-guide-grid">
          <div class="help-guide-item">
            <h3>准备环境</h3>
            <p>确认 Camoufox 引擎已安装、邮箱服务可用、CPA auth 目录可写。直连可用时不必额外配置代理。</p>
          </div>
          <div class="help-guide-item">
            <h3>选择模式</h3>
            <p><code>持续编排</code>按追加目标多轮运行；<code>单批运行</code>只执行单批数量。首次建议并发 2-3。</p>
          </div>
          <div class="help-guide-item">
            <h3>保存并启动</h3>
            <p>输入当前面板令牌，先保存设置再启动。追加目标表示从现有 CPA 数量继续增加多少。</p>
          </div>
          <div class="help-guide-item">
            <h3>观察结果</h3>
            <p>优先看注册风控、时段成功率和日志尾部。连续风控时先换出口或邮箱域名，不要继续提高并发。</p>
          </div>
        </div>
        <p class="help-note">停止任务会结束当前编排和批处理进程。重置黑名单会恢复基线规则，不等于清空所有风控判断。</p>
      </div>

      <div id="help-faq" role="tabpanel" aria-labelledby="help-tab-faq" hidden>
        <div class="faq-tools">
          <label class="sr-only" for="faq-search">搜索常见问题</label>
          <input id="faq-search" type="search" placeholder="搜索错误码或现象" autocomplete="off" oninput="filterFaq(this.value)"/>
          <span class="faq-count mono" id="faq-count">12 项</span>
        </div>
        <div class="faq-grid" id="faq-grid">
          <details class="faq-item" data-faq-item data-search="令牌 token unauthorized 401 保存设置 启动">
            <summary>提示访问令牌不匹配或 401</summary>
            <div class="faq-answer">重新输入当前面板令牌并保存。令牌只保存在当前浏览器的 localStorage 中，换端口、设备或浏览器后需要重新输入。</div>
          </details>
          <details class="faq-item" data-faq-item data-search="启动 立即结束 目标 cpa add_count 追加目标">
            <summary>点击启动后立即结束</summary>
            <div class="faq-answer">通常是 CPA 已达到旧目标。提高“追加目标”后再启动；持续编排会以当前 CPA 为基线增加 N，单批运行只执行“单批数量”。</div>
          </details>
          <details class="faq-item" data-faq-item data-search="风控 policy deny registration risk botFlagSource ip 邮箱 域名">
            <summary>出现 policy=deny 或注册风控</summary>
            <div class="faq-answer">该账号已被注册风控拒绝，不要反复重转同一 SSO。先更换质量更好的出口并给 IP 冷却时间，邮箱优先使用稳定的子域名，并发先保持 2-3。</div>
          </details>
          <details class="faq-item" data-faq-item data-search="bfs jwt claim access_token 标记 flagged 风控 检测 scan">
            <summary>什么是 bfs，和 botFlagSource 有何不同</summary>
            <div class="faq-answer"><code>bfs</code> 是 xAI access_token / SSO JWT 里的风险 claim：payload 里<strong>出现该字段</strong>即视为标记（常见值 2）。它与 grok.com 页面的 <code>botFlagSource</code> / <code>policy=deny</code> 独立。注册换 token 后会自动检测；也可在控制台“BFS 检测”扫描 CPA 目录，导出 <code>log/bfs_flagged.jsonl</code>。配置 <code>bfs_skip_cpa</code> 可跳过入库，<code>bfs_disable_cpa</code> 可写 disabled。</div>
          </details>
          <details class="faq-item" data-faq-item data-search="卡住 浏览器 启动失败 turnstile 资料页 空页 并发 camoufox">
            <summary>注册卡在验证码、资料页或浏览器启动</summary>
            <div class="faq-answer">先从失败分类和日志尾部确认具体阶段。连续浏览器启动失败时降低并发，并检查是否执行过 <code>camoufox fetch</code>；资料页失败也可能是 Turnstile 未通过。</div>
          </details>
          <details class="faq-item" data-faq-item data-search="cpa 没新增 invalid_grant access denied 503 auth unavailable oauth 入库 目录 管理密钥">
            <summary>CPA 没新增，或出现 invalid_grant / 503</summary>
            <div class="faq-answer">先检查 <code>cpa_auto_add</code>、auth 目录、远程 CPA 地址和管理密钥。<code>invalid_grant Access denied</code> 表示 OAuth 交换被拒；503 表示 CPA 当前没有可用 xAI auth。</div>
          </details>
          <details class="faq-item" data-faq-item data-search="permission denied access chat endpoint referrer grok build base_url oauth">
            <summary>调用模型提示 permission-denied</summary>
            <div class="faq-answer">常见原因是 token 缺少 <code>referrer=grok-build</code>，或 <code>base_url</code> 指向了 <code>api.x.ai</code>。使用项目的 Authorization Code + PKCE 流程重新生成，并指向 Build 通道。</div>
          </details>
          <details class="faq-item" data-faq-item data-search="出口 ip 代理 无法解析 流量 住宅 链式 dialer">
            <summary>无法解析出口 IP，或代理流量消耗很高</summary>
            <div class="faq-answer">先单独测试代理端口是否可用。住宅代理可能同时计算上下行流量，实际每 GB 产出没有固定值；降低并发并避免重复失败重试。链式代理应在代理客户端配置。</div>
          </details>
          <details class="faq-item" data-faq-item data-search="邮箱 api 401 超时 cloudflare workers key auth_mode proxy">
            <summary>邮箱 API 返回 401 或请求超时</summary>
            <div class="faq-answer">401 先检查对应邮箱服务的 key 和 <code>auth_mode</code>。访问 workers.dev 超时时，在配置中显式填写代理，不要只依赖桌面进程可能无法继承的 HTTP_PROXY 环境变量。</div>
          </details>
          <details class="faq-item" data-faq-item data-search="邮箱服务 provider cloudflare duckmail yyds mailnest cloudmail moemail api 测试 域名轮换">
            <summary>如何配置邮箱服务</summary>
            <div class="faq-answer">打开顶部“邮箱服务”，选择当前使用的服务商后填写对应 API 配置，保存并测试连通性。自有域名轮换位于同页高级设置；只有 xAI 明确拒绝域名才累计，邮箱 API 和验证码异常不会处罚域名。</div>
          </details>
          <details class="faq-item" data-faq-item data-search="黑名单 asn 清除 重置 baseline 风控 出口">
            <summary>黑名单有什么作用，可以清除吗</summary>
            <div class="faq-answer">黑名单用于避开持续触发风控的出口 ASN。面板“重置”会恢复基线熔断规则；不清楚影响时不要清空全部规则，重复命中通常说明出口质量需要调整。</div>
          </details>
          <details class="faq-item" data-faq-item data-search="accounts txt sso 导入 cpa json sub2api 转换">
            <summary>已有 accounts 文本怎么导入 CPA 或 sub2api</summary>
            <div class="faq-answer">控制台的“账号补录”可处理待补录队列，也可扫描全部 accounts 文本；已存在 CPA 的账号会跳过，成功项会从待补录队列移除。面板不直接导入 sub2api，需要按目标系统的数据结构另行转换。</div>
          </details>
          <details class="faq-item" data-faq-item data-search="搜索 模型 grok build 4.5 能力 api">
            <summary>注册成功但搜索或某个模型不可用</summary>
            <div class="faq-answer">注册成功不代表所有上游能力都会开放。确认请求走 Grok Build 通道；搜索和具体模型可用性仍可能随账号状态和上游策略变化。</div>
          </details>
          <details class="faq-item" data-faq-item data-search="体验额度 429 quota rate limit 免费 余额">
            <summary>体验额度有多少，出现 429 怎么办</summary>
            <div class="faq-answer">体验额度由上游按账号分配，面板无法推算准确余额。429 通常表示额度耗尽或触发速率限制，需要等待恢复或更换仍有可用额度的 auth。</div>
          </details>
        </div>
        <p class="faq-empty" id="faq-empty" hidden>没有匹配的问题，请换一个错误码或现象关键词。</p>
      </div>
      </div>
    </div>
  </section>

  <section class="proxy-view" id="proxy-view" aria-labelledby="proxy-view-title" hidden>
    <div class="proxy-view-inner">
      <div class="proxy-view-heading">
        <div>
          <div class="page-title" id="proxy-view-title">外部代理池</div>
          <p class="proxy-view-subtitle">凭据仅保存在本机，注册中途不会切换出口</p>
        </div>
        <span class="proxy-job mono" id="proxy-updated">等待读取</span>
      </div>

      <div class="proxy-summary" id="proxy-summary" aria-label="代理池状态">
        <div class="proxy-summary-item"><div class="proxy-summary-label">总数</div><div class="proxy-summary-value">--</div></div>
        <div class="proxy-summary-item"><div class="proxy-summary-label">可用</div><div class="proxy-summary-value">--</div></div>
        <div class="proxy-summary-item"><div class="proxy-summary-label">异常</div><div class="proxy-summary-value">--</div></div>
        <div class="proxy-summary-item"><div class="proxy-summary-label">冷却</div><div class="proxy-summary-value">--</div></div>
        <div class="proxy-summary-item"><div class="proxy-summary-label">未检测</div><div class="proxy-summary-value">--</div></div>
      </div>

      <div class="proxy-import">
        <div class="field">
          <label for="proxy-input">代理地址（每行一条）</label>
          <textarea id="proxy-input" spellcheck="false" autocomplete="off" placeholder="http://user:password@host:port&#10;host:port:user:password"></textarea>
        </div>
        <div class="proxy-import-actions">
          <p class="proxy-format">支持 http、https、socks5、socks5h，以及 host:port:user:password。导入后先检测，只有健康且启用的代理会分配给新账号。</p>
          <div class="button-group">
            <button class="primary" id="proxy-import-button" onclick="importProxyInput()">导入代理</button>
            <button id="proxy-legacy-button" onclick="importLegacyProxies()">导入 proxies.txt</button>
          </div>
        </div>
      </div>
      <div class="msg" id="proxy-msg" role="status" aria-live="polite"></div>

      <div class="proxy-list-section">
        <div class="proxy-list-head">
          <div>
            <h2>代理明细</h2>
            <div class="proxy-job mono" id="proxy-test-status" role="status" aria-live="polite">未开始检测</div>
          </div>
          <button id="proxy-test-all" onclick="testProxies()">检测全部</button>
        </div>
        <div class="proxy-table-wrap">
          <table class="proxy-table">
            <thead><tr><th>状态</th><th>代理端点</th><th>出口 / ASN</th><th>延迟</th><th>最近状态</th><th>启用</th><th>操作</th></tr></thead>
            <tbody id="proxy-body"><tr><td colspan="7" class="proxy-empty">正在读取代理池</td></tr></tbody>
          </table>
        </div>
      </div>
    </div>
  </section>

  <section class="domain-view" id="domain-view" aria-labelledby="domain-view-title" hidden>
    <div class="domain-view-inner">
      <div class="domain-view-heading">
        <div>
          <div class="mail-source-kicker">Mail source</div>
          <div class="page-title" id="domain-view-title">邮箱服务</div>
          <p class="domain-view-subtitle" id="mail-provider-subtitle">读取当前邮箱服务配置</p>
        </div>
        <span class="domain-job" id="mail-provider-heading-label">--</span>
      </div>

      <section class="mail-provider-panel" aria-labelledby="mail-provider-label">
        <div class="mail-provider-toolbar">
          <div class="field">
            <label for="mail-provider-select" id="mail-provider-label">邮箱提供商</label>
            <select id="mail-provider-select" onchange="selectEmailProvider(this.value)">
              <option value="">正在读取</option>
            </select>
          </div>
          <div class="mail-provider-status">
            <span class="mail-provider-status-label">当前状态</span>
            <span class="badge" id="mail-provider-status" role="status" aria-live="polite">读取中</span>
          </div>
        </div>
        <div class="mail-provider-fields" id="mail-provider-fields" aria-live="polite">
          <div class="field"><label>服务配置</label><input disabled value="正在读取"/></div>
        </div>
        <div class="mail-provider-actions">
          <button class="primary" id="mail-provider-save" onclick="saveEmailProviderConfig()">保存配置</button>
          <button id="mail-provider-test" onclick="testEmailProviderConnection()">测试当前提供商</button>
          <span class="mail-provider-meta mono" id="mail-provider-updated">尚未读取</span>
        </div>
        <div class="msg mail-provider-result" id="mail-provider-msg" role="status" aria-live="polite"></div>
      </section>

      <details class="domain-advanced" id="domain-advanced">
        <summary>
          <span class="domain-advanced-title">域名轮换 <span class="domain-advanced-meta">高级设置</span></span>
          <span class="domain-advanced-meta mono" id="domain-advanced-count">0 个域名</span>
        </summary>
        <div class="domain-advanced-body">
          <div class="domain-advanced-head">
            <span class="domain-advanced-meta">仅 xAI 明确拒绝域名时累计失败</span>
            <span class="domain-job mono" id="domain-updated">等待读取</span>
          </div>

          <div class="domain-summary" id="domain-summary" aria-label="邮箱域名轮换状态">
            <div class="domain-summary-item"><div class="domain-summary-label">总数</div><div class="domain-summary-value">--</div></div>
            <div class="domain-summary-item"><div class="domain-summary-label">轮换中</div><div class="domain-summary-value">--</div></div>
            <div class="domain-summary-item"><div class="domain-summary-label">待命</div><div class="domain-summary-value">--</div></div>
            <div class="domain-summary-item"><div class="domain-summary-label">已拉黑</div><div class="domain-summary-value">--</div></div>
            <div class="domain-summary-item"><div class="domain-summary-label">已停用</div><div class="domain-summary-value">--</div></div>
          </div>

          <div class="domain-import">
            <div class="field">
              <label for="domain-input">域名或子域名（每行一条）</label>
              <textarea id="domain-input" spellcheck="false" autocomplete="off" placeholder="mail.example.com&#10;inbox.example.net"></textarea>
            </div>
            <div class="domain-import-actions">
              <div class="domain-settings">
                <div class="field">
                  <label for="domain-provider">邮箱服务商</label>
                  <select id="domain-provider">
                    <option value="cloudflare">Cloudflare</option>
                    <option value="cloudmail">CloudMail</option>
                    <option value="moemail">MoeMail</option>
                    <option value="yyds">YYDS</option>
                  </select>
                </div>
                <div class="field">
                  <label for="domain-threshold">拒绝阈值</label>
                  <input type="number" id="domain-threshold" min="1" max="20" value="3"/>
                </div>
                <div class="field">
                  <label for="domain-max-active">每个服务商活跃数</label>
                  <input type="number" id="domain-max-active" min="0" max="100" value="0" title="0 表示不限"/>
                </div>
              </div>
              <p class="domain-format">Cloudflare、CloudMail、MoeMail 与 YYDS 可绑定自有域名；0 表示不限制活跃数。</p>
              <div class="button-group">
                <button class="primary" id="domain-import-button" onclick="importDomainInput()">导入域名</button>
                <button id="domain-settings-button" onclick="saveDomainSettings()">保存规则</button>
              </div>
            </div>
          </div>
          <div class="msg" id="domain-msg" role="status" aria-live="polite"></div>

          <div class="domain-list-section">
            <div class="domain-list-head">
              <div>
                <h2>域名明细</h2>
                <div class="domain-job mono" id="domain-status" role="status" aria-live="polite">未导入域名</div>
              </div>
              <button id="domain-refresh-button" onclick="refreshEmailDomains(false)">刷新</button>
            </div>
            <div class="domain-table-wrap">
              <table class="domain-table">
                <thead><tr><th>状态</th><th>域名</th><th>服务商</th><th>拒绝次数</th><th>最近状态</th><th>启用</th><th>操作</th></tr></thead>
                <tbody id="domain-body"><tr><td colspan="7" class="domain-empty">正在读取邮箱域名轮换</td></tr></tbody>
              </table>
            </div>
          </div>
        </div>
      </details>
    </div>
  </section>

  <section class="metric-grid panel-gap" id="kpis" aria-label="核心指标"></section>

  <section class="card panel rate-panel">
    <div class="section-head">
      <h2>时段成功率</h2>
      <span class="section-meta mono" id="rates-updated">register_results.jsonl</span>
    </div>
    <div class="rate-grid" id="rate-kpis"></div>
  </section>

  <section class="card panel">
    <div class="progress-head">
      <h2>当前批次</h2>
      <div class="mono" id="prog-text">--</div>
    </div>
    <div class="bar-wrap"><div class="bar" id="bar"></div></div>
    <div class="progress-sub" id="prog-sub"></div>
  </section>

  <section class="card panel recovery-panel" aria-labelledby="recovery-title">
    <div class="section-head">
      <h2 id="recovery-title">账号补录</h2>
      <span class="section-meta mono" id="recovery-status">等待检查</span>
    </div>
    <div class="recovery-layout">
      <div class="chips" id="recovery-kpis"></div>
      <div class="button-group recovery-actions">
        <button id="recovery-pending" onclick="startRecovery('pending')">补录待处理</button>
        <button id="recovery-accounts" onclick="startRecovery('accounts')">扫描全部账号</button>
        <button class="danger" id="recovery-stop" onclick="stopRecovery()">停止补录</button>
      </div>
    </div>
    <div class="msg" id="recovery-msg" role="status" aria-live="polite"></div>
  </section>

  <section class="card panel" aria-labelledby="bfs-title">
    <div class="section-head">
      <h2 id="bfs-title">BFS 检测</h2>
      <span class="section-meta mono" id="bfs-status">JWT claim</span>
    </div>
    <p style="margin:0 0 10px;color:var(--muted);font-size:13px;line-height:1.5">
      解码 CPA / Grok2API auth 中的 access_token，检查是否含 <code>bfs</code> claim（与 botFlagSource 独立）。
      注册换 token 后会自动检测并写入 <code>accounts/sso_bfs_flagged.txt</code>。
    </p>
    <div class="chips" id="bfs-kpis"></div>
    <div class="button-group" style="margin-top:10px">
      <button id="bfs-scan" onclick="runBfsScan()">扫描 auth 目录</button>
      <button onclick="refreshBfs()">刷新状态</button>
    </div>
    <div class="msg" id="bfs-msg" role="status" aria-live="polite"></div>
    <div class="table-scroll" style="margin-top:10px;max-height:220px">
      <table>
        <thead><tr><th>邮箱</th><th>bfs</th><th>来源</th><th>文件</th></tr></thead>
        <tbody id="bfs-body"></tbody>
      </table>
    </div>
  </section>

  <div class="three panel-gap">
    <div class="card">
      <div class="section-head">
        <h2>成功统计</h2>
        <button onclick="refreshStats()">刷新</button>
      </div>
      <div class="chips" id="stats-chips"></div>
      <div class="msg" id="stats-msg" role="status" aria-live="polite"></div>
      <div class="table-scroll">
        <table><thead><tr><th>日期</th><th>成功</th><th>风控</th><th>失败</th></tr></thead>
        <tbody id="stats-day"></tbody></table>
      </div>
    </div>
    <div class="card">
      <div class="section-head">
        <h2>黑名单</h2>
        <div class="button-group">
          <button onclick="refreshBlacklist()">刷新</button>
          <button class="danger" onclick="resetBlacklist('baseline')">重置</button>
        </div>
      </div>
      <div class="chips" id="bl-kpis"></div>
      <div class="msg" id="bl-msg" role="status" aria-live="polite"></div>
      <div class="bl-list" style="margin-top:10px">
        <table><thead><tr><th>ASN</th><th>备注</th></tr></thead><tbody id="bl-body"></tbody></table>
      </div>
    </div>
    <div class="card">
      <div class="section-head"><h2>黑名单更新记录</h2></div>
      <div class="chips" id="bl-err-chips"></div>
      <div class="table-scroll">
        <table><thead><tr><th>新增 ASN</th><th>来源</th></tr></thead>
        <tbody id="bl-added"></tbody></table>
      </div>
    </div>
  </div>

  <div class="two panel-gap">
    <div class="card"><h2>Worker 成功 / 失败</h2><div class="chips" id="workers-stats"></div></div>
    <div class="card"><h2>失败分类</h2><div class="chips" id="fails"></div></div>
  </div>
  <div class="two panel-gap">
    <div class="card">
      <div class="section-head">
        <h2>最近成功</h2>
        <span class="section-meta" id="ok-page-meta"></span>
      </div>
      <div class="table-scroll"><table><thead><tr><th>时间</th><th>W</th><th>邮箱</th></tr></thead><tbody id="ok-body"></tbody></table></div>
      <div class="list-pager" id="ok-pager">
        <span class="pager-info" id="ok-pager-info"></span>
        <div class="pager-btns">
          <button type="button" id="ok-prev" aria-label="上一页">上一页</button>
          <button type="button" id="ok-next" aria-label="下一页">下一页</button>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="section-head">
        <h2>最近失败</h2>
        <span class="section-meta" id="fail-page-meta"></span>
      </div>
      <div class="table-scroll"><table><thead><tr><th>时间</th><th>W</th><th>类型</th><th>摘要</th></tr></thead><tbody id="fail-body"></tbody></table></div>
      <div class="list-pager" id="fail-pager">
        <span class="pager-info" id="fail-pager-info"></span>
        <div class="pager-btns">
          <button type="button" id="fail-prev" aria-label="上一页">上一页</button>
          <button type="button" id="fail-next" aria-label="下一页">下一页</button>
        </div>
      </div>
    </div>
  </div>
  <section class="card panel">
    <div class="section-head"><h2>日志尾部</h2></div>
    <div class="tail mono" id="tail"></div>
  </section>
  <footer id="footer"></footer>
</main>
<script>
let last = null;
let proxyData = null;
let domainData = null;
let emailProviderData = null;
let selectedEmailProvider = "";
const clearedEmailSecrets = new Set();
const THEME_KEY = "GROK_REGISTER_THEME";
const APP_VIEW_KEY = "GROK_REGISTER_APP_VIEW";
const HELP_TAB_KEY = "GROK_REGISTER_HELP_TAB";
const LIST_PAGE_SIZE = 10;
let okPage = 1;
let failPage = 1;
let okRowsCache = [];
let failRowsCache = [];
// 完整成功统计（jsonl / by_day）；2s 轮询只更新本批数字，不能冲掉
let lastFullStats = null;
function syncThemeButtons() {
  const theme = document.documentElement.dataset.theme || "light";
  document.querySelectorAll("[data-theme-choice]").forEach(button => {
    button.setAttribute("aria-pressed", String(button.dataset.themeChoice === theme));
  });
  const color = document.getElementById("theme-color");
  if (color) color.content = theme === "dark" ? "#171815" : "#f3f4f1";
}
function setTheme(theme) {
  if (theme !== "light" && theme !== "dark") return;
  document.documentElement.dataset.theme = theme;
  try { localStorage.setItem(THEME_KEY, theme); } catch (e) {}
  syncThemeButtons();
}
function setAppView(view, options = {}) {
  if (view !== "dashboard" && view !== "help" && view !== "proxies" && view !== "domains") return;
  const dashboard = document.getElementById("dashboard-view");
  const help = document.getElementById("help-view");
  const proxies = document.getElementById("proxy-view");
  const domains = document.getElementById("domain-view");
  const domainToggle = document.getElementById("domain-view-toggle");
  const domainLabel = document.getElementById("domain-view-label");
  const toggle = document.getElementById("help-view-toggle");
  const label = document.getElementById("help-view-label");
  const proxyToggle = document.getElementById("proxy-view-toggle");
  const proxyLabel = document.getElementById("proxy-view-label");
  if (!dashboard || !help || !proxies || !domains || !domainToggle || !domainLabel || !toggle || !label || !proxyToggle || !proxyLabel) return;
  const isHelp = view === "help";
  const isProxies = view === "proxies";
  const isDomains = view === "domains";
  const isOverlay = isHelp || isProxies || isDomains;
  const dashboardChildren = Array.from(dashboard.children).filter(element => element !== help && element !== proxies && element !== domains);
  dashboardChildren.forEach(element => {
    element.inert = isOverlay;
    if (isOverlay) element.setAttribute("aria-hidden", "true");
    else element.removeAttribute("aria-hidden");
  });
  help.hidden = !isHelp;
  help.inert = !isHelp;
  proxies.hidden = !isProxies;
  proxies.inert = !isProxies;
  domains.hidden = !isDomains;
  domains.inert = !isDomains;
  document.body.classList.toggle("help-view-open", isHelp);
  document.body.classList.toggle("proxy-view-open", isProxies);
  document.body.classList.toggle("domain-view-open", isDomains);
  toggle.dataset.active = String(isHelp);
  toggle.setAttribute("aria-expanded", String(isHelp));
  toggle.setAttribute("aria-label", isHelp ? "返回控制台" : "打开问题和使用");
  toggle.title = isHelp ? "返回控制台" : "问题和使用";
  label.textContent = isHelp ? "返回控制台" : "问题和使用";
  proxyToggle.dataset.active = String(isProxies);
  proxyToggle.setAttribute("aria-expanded", String(isProxies));
  proxyToggle.setAttribute("aria-label", isProxies ? "返回控制台" : "打开代理池");
  proxyToggle.title = isProxies ? "返回控制台" : "代理池";
  proxyLabel.textContent = isProxies ? "返回控制台" : "代理池";
  domainToggle.dataset.active = String(isDomains);
  domainToggle.setAttribute("aria-expanded", String(isDomains));
  domainToggle.setAttribute("aria-label", isDomains ? "返回控制台" : "打开邮箱服务");
  domainToggle.title = isDomains ? "返回控制台" : "邮箱服务";
  domainLabel.textContent = isDomains ? "返回控制台" : "邮箱服务";
  if (options.persist !== false) {
    try { localStorage.setItem(APP_VIEW_KEY, view); } catch (e) {}
  }
  if (isProxies) refreshProxies();
  if (isDomains) {
    refreshEmailProvider();
    refreshEmailDomains();
  }
  if (options.focus) {
    requestAnimationFrame(() => {
      const target = isHelp
        ? document.querySelector('[data-help-tab][aria-selected="true"]')
        : (isProxies ? document.getElementById("proxy-input") : (isDomains ? document.getElementById("mail-provider-select") : (view === "dashboard" ? domainToggle : toggle)));
      if (target) target.focus();
    });
  }
}
function toggleAppView() {
  const isHelp = document.body.classList.contains("help-view-open");
  setAppView(isHelp ? "dashboard" : "help", { focus: true });
}
function toggleProxyView() {
  const isProxies = document.body.classList.contains("proxy-view-open");
  setAppView(isProxies ? "dashboard" : "proxies", { focus: true });
}
function toggleDomainView() {
  const isDomains = document.body.classList.contains("domain-view-open");
  setAppView(isDomains ? "dashboard" : "domains", { focus: true });
}
function setHelpTab(name) {
  if (name !== "guide" && name !== "faq") return;
  document.querySelectorAll("[data-help-tab]").forEach(button => {
    const selected = button.dataset.helpTab === name;
    button.setAttribute("aria-selected", String(selected));
    button.tabIndex = selected ? 0 : -1;
  });
  const guide = document.getElementById("help-guide");
  const faq = document.getElementById("help-faq");
  if (guide) guide.hidden = name !== "guide";
  if (faq) faq.hidden = name !== "faq";
  try { localStorage.setItem(HELP_TAB_KEY, name); } catch (e) {}
}
function handleHelpTabKey(event) {
  if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
  const tabs = Array.from(document.querySelectorAll("[data-help-tab]"));
  const current = tabs.indexOf(document.activeElement);
  if (current < 0) return;
  event.preventDefault();
  const next = event.key === "ArrowRight" ? (current + 1) % tabs.length : (current - 1 + tabs.length) % tabs.length;
  tabs[next].focus();
  setHelpTab(tabs[next].dataset.helpTab);
}
function filterFaq(value) {
  const query = String(value || "").trim().toLocaleLowerCase();
  const items = Array.from(document.querySelectorAll("[data-faq-item]"));
  const matches = [];
  items.forEach(item => {
    const haystack = ((item.dataset.search || "") + " " + item.textContent).toLocaleLowerCase();
    const matched = !query || haystack.includes(query);
    item.hidden = !matched;
    if (matched) matches.push(item);
  });
  if (query && matches.length === 1) matches[0].open = true;
  const count = document.getElementById("faq-count");
  const empty = document.getElementById("faq-empty");
  if (count) count.textContent = matches.length + " 项";
  if (empty) empty.hidden = matches.length > 0;
}
function showHelpFor(query) {
  setAppView("help", { focus: false });
  setHelpTab("faq");
  const search = document.getElementById("faq-search");
  if (search) search.value = query || "";
  filterFaq(query || "");
  if (search) requestAnimationFrame(() => search.focus());
}
function initHelp() {
  let view = "dashboard";
  let tab = "guide";
  try {
    view = localStorage.getItem(APP_VIEW_KEY) || "dashboard";
    tab = localStorage.getItem(HELP_TAB_KEY) || "guide";
  } catch (e) {}
  if (!["dashboard", "help", "proxies", "domains"].includes(view)) view = "dashboard";
  setHelpTab(tab);
  filterFaq("");
  setAppView(view, { persist: false, focus: false });
}
document.addEventListener("keydown", event => {
  if (event.key === "Escape" && (document.body.classList.contains("help-view-open") || document.body.classList.contains("proxy-view-open") || document.body.classList.contains("domain-view-open"))) {
    setAppView("dashboard", { focus: true });
  }
});
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
}
function formatBytes(value) {
  const bytes = Math.max(0, Number(value) || 0);
  if (bytes < 1024) return Math.round(bytes) + " B";
  const units = ["KB", "MB", "GB", "TB"];
  let scaled = bytes / 1024;
  let unit = units[0];
  for (let i = 1; i < units.length && scaled >= 1024; i += 1) {
    scaled /= 1024;
    unit = units[i];
  }
  const digits = scaled >= 100 ? 0 : (scaled >= 10 ? 1 : 2);
  return scaled.toFixed(digits) + " " + unit;
}
function setMsg(id, text, cls) {
  const el = document.getElementById(id);
  el.textContent = text || "";
  el.className = "msg" + (cls ? " " + cls : "");
}
function getToken() {
  const el = document.getElementById("monitor-token");
  const fromInput = el ? (el.value || "").trim() : "";
  const tok = (fromInput || window.MONITOR_TOKEN || localStorage.getItem("MONITOR_TOKEN") || "").trim();
  if (fromInput) try { localStorage.setItem("MONITOR_TOKEN", fromInput); } catch (e) {}
  return tok;
}
function loadTokenField() {
  const el = document.getElementById("monitor-token");
  if (!el) return;
  if (!el.value) {
    try { el.value = localStorage.getItem("MONITOR_TOKEN") || window.MONITOR_TOKEN || ""; } catch (e) {}
  }
}
async function api(path, opts) {
  opts = Object.assign({}, opts || {});
  const authHelp = opts.authHelp !== false;
  delete opts.authHelp;
  const headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
  const tok = getToken();
  if (tok) headers["Authorization"] = "Bearer " + tok;
  const r = await fetch(path, Object.assign({}, opts, { headers }));
  const j = await r.json().catch(() => ({}));
  if (!r.ok) {
    if (r.status === 401) {
      if (authHelp) showHelpFor("令牌");
      throw new Error("访问令牌不匹配，请重新输入当前面板令牌");
    }
    throw new Error(j.error || j.detail || r.statusText || "request failed");
  }
  if (j && j.ok === false) throw new Error(j.error || j.message || "request failed");
  return j;
}
function proxyStatusLabel(status) {
  return ({ healthy: "健康", unhealthy: "异常", cooldown: "冷却", testing: "检测中", unknown: "未检测" })[status] || "未检测";
}
function proxyTime(value) {
  if (!value) return "--";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  // 统一北京时间展示（服务器可能是 UTC）
  return date.toLocaleString("zh-CN", {
    timeZone: "Asia/Shanghai",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}
function cooldownText(item) {
  const seconds = Number(item.cooldown_remaining_seconds || 0);
  if (seconds <= 0) return "";
  const value = seconds >= 3600 ? Math.ceil(seconds / 3600) + " 小时" : Math.ceil(seconds / 60) + " 分钟";
  return (item.cooldown_reason === "risk" ? "风控冷却 " : "网络冷却 ") + value;
}
function renderProxyPool(data) {
  proxyData = data || {};
  const summary = proxyData.summary || {};
  const values = [
    ["总数", summary.total ?? 0, ""],
    ["可用", summary.usable ?? 0, "ok"],
    ["异常", summary.unhealthy ?? 0, (summary.unhealthy || 0) > 0 ? "fail" : ""],
    ["冷却", summary.cooldown ?? 0, (summary.cooldown || 0) > 0 ? "warn" : ""],
    ["未检测", summary.unknown ?? 0, (summary.unknown || 0) > 0 ? "accent" : ""],
  ];
  document.getElementById("proxy-summary").innerHTML = values.map(([label, value, cls]) =>
    `<div class="proxy-summary-item"><div class="proxy-summary-label">${esc(label)}</div><div class="proxy-summary-value ${cls}">${esc(value)}</div></div>`
  ).join("");
  document.getElementById("proxy-updated").textContent = proxyData.updated_at ? ("更新 " + proxyTime(proxyData.updated_at)) : "尚未写入";

  const legacy = proxyData.legacy || {};
  const legacyButton = document.getElementById("proxy-legacy-button");
  legacyButton.disabled = !legacy.available;
  legacyButton.textContent = legacy.available ? ("导入 proxies.txt (" + (legacy.count || 0) + ")") : "无 proxies.txt";

  const job = proxyData.test_job || {};
  const testButton = document.getElementById("proxy-test-all");
  testButton.disabled = !!job.running || !(summary.enabled > 0);
  document.getElementById("proxy-test-status").textContent = job.running
    ? ("检测中 " + (job.completed || 0) + "/" + (job.total || 0) + "，健康 " + (job.healthy || 0) + "，失败 " + (job.failed || 0))
    : (job.finished_at ? ("上次检测：健康 " + (job.healthy || 0) + "，失败 " + (job.failed || 0)) : "未开始检测");

  const items = proxyData.items || [];
  document.getElementById("proxy-body").innerHTML = items.length ? items.map(item => {
    const status = item.status || "unknown";
    const stateClass = ["healthy", "unhealthy", "cooldown", "testing"].includes(status) ? status : "";
    const exit = item.exit_ip ? esc(item.exit_ip) : "--";
    const asn = item.asn ? ("AS" + esc(item.asn)) : "--";
    const org = item.asn_org ? `<div class="proxy-meta">${esc(item.asn_org)}</div>` : "";
    const latency = item.latency_ms == null ? "--" : (esc(item.latency_ms) + " ms");
    const cooldown = cooldownText(item);
    const detail = cooldown || item.last_error || (item.last_checked_at ? ("检测 " + proxyTime(item.last_checked_at)) : "尚未检测");
    const count = (item.failure_count || 0) > 0 ? `<div class="proxy-meta">失败 ${esc(item.failure_count)} / 风控 ${esc(item.risk_count || 0)}</div>` : "";
    return `<tr>
      <td><span class="proxy-state ${stateClass}">${esc(proxyStatusLabel(status))}</span></td>
      <td><div class="mono proxy-endpoint">${esc(item.display_url || "")}</div><div class="proxy-meta">${item.has_auth ? "凭据已隐藏" : "无鉴权"} / ${esc(item.source || "panel")}</div></td>
      <td><div class="mono">${exit}</div><div class="proxy-meta mono">${asn}</div>${org}</td>
      <td class="mono">${latency}</td>
      <td title="${esc(item.last_error || "")}">${esc(detail)}${count}</td>
      <td><input class="proxy-toggle" type="checkbox" aria-label="启用 ${esc(item.display_url || "代理")}" ${item.enabled ? "checked" : ""} onchange="setProxyEnabled('${item.id}', this.checked)"/></td>
      <td><div class="proxy-actions"><button ${status === "testing" ? "disabled" : ""} onclick="testProxies('${item.id}')">检测</button><button class="danger" onclick="deleteProxyItem('${item.id}')">删除</button></div></td>
    </tr>`;
  }).join("") : '<tr><td colspan="7" class="proxy-empty">代理池为空，可在上方导入单条或批量代理</td></tr>';
}
async function refreshProxies(authHelp = false) {
  try {
    const data = await api("/api/proxies?_=" + Date.now(), { authHelp });
    renderProxyPool(data);
    if (!data.ok && data.error) setMsg("proxy-msg", data.error, "err");
  } catch (e) {
    const message = String(e.message || e);
    document.getElementById("proxy-updated").textContent = message.includes("令牌") ? "等待令牌" : "读取失败";
    setMsg("proxy-msg", message, "err");
  }
}
function proxyImportMessage(result, prefix) {
  const errors = result.errors || [];
  const errorText = errors.length ? ("，跳过 " + errors.length + " 条：" + errors.slice(0, 2).map(item => "第 " + item.line + " 行 " + item.error).join("；")) : "";
  return prefix + (result.imported_count || 0) + " 条，重复 " + (result.duplicate_count || 0) + " 条" + errorText;
}
async function startImportedProxyTests(result) {
  const ids = result.imported_ids || [];
  if (!ids.length) return false;
  await api("/api/proxies/test", { method: "POST", body: JSON.stringify({ ids }) });
  return true;
}
async function importProxyInput() {
  const input = document.getElementById("proxy-input");
  const button = document.getElementById("proxy-import-button");
  const value = (input.value || "").trim();
  if (!value) { setMsg("proxy-msg", "请输入至少一条代理", "err"); input.focus(); return; }
  button.disabled = true;
  setMsg("proxy-msg", "正在导入…", "");
  try {
    const result = await api("/api/proxies/import", { method: "POST", body: JSON.stringify({ proxies: value }) });
    renderProxyPool(result);
    input.value = "";
    const testing = await startImportedProxyTests(result);
    setMsg("proxy-msg", proxyImportMessage(result, "已导入 ") + (testing ? "，已开始检测" : ""), result.errors && result.errors.length ? "" : "ok");
    setTimeout(() => refreshProxies(false), 300);
  } catch (e) { setMsg("proxy-msg", String(e.message || e), "err"); }
  button.disabled = false;
}
async function importLegacyProxies() {
  const button = document.getElementById("proxy-legacy-button");
  button.disabled = true;
  try {
    const result = await api("/api/proxies/import", { method: "POST", body: JSON.stringify({ legacy: true }) });
    renderProxyPool(result);
    const testing = await startImportedProxyTests(result);
    setMsg("proxy-msg", proxyImportMessage(result, "已从 proxies.txt 导入 ") + (testing ? "，已开始检测" : ""), "ok");
    setTimeout(() => refreshProxies(false), 300);
  } catch (e) { setMsg("proxy-msg", String(e.message || e), "err"); }
  button.disabled = false;
}
async function testProxies(id) {
  const ids = id ? [id] : [];
  setMsg("proxy-msg", id ? "正在检测该代理…" : "正在启动批量检测…", "");
  try {
    await api("/api/proxies/test", { method: "POST", body: JSON.stringify({ ids }) });
    setMsg("proxy-msg", "检测任务已启动", "ok");
    await refreshProxies(false);
  } catch (e) { setMsg("proxy-msg", String(e.message || e), "err"); }
}
async function setProxyEnabled(id, enabled) {
  try {
    const result = await api("/api/proxies/" + id, { method: "PATCH", body: JSON.stringify({ enabled }) });
    renderProxyPool(result);
    setMsg("proxy-msg", enabled ? "代理已启用" : "代理已停用", "ok");
  } catch (e) {
    setMsg("proxy-msg", String(e.message || e), "err");
    await refreshProxies(false);
  }
}
async function deleteProxyItem(id) {
  const item = (proxyData && proxyData.items || []).find(value => value.id === id);
  if (!confirm("删除代理 " + (item ? item.display_url : "") + "？")) return;
  try {
    const result = await api("/api/proxies/" + id, { method: "DELETE" });
    renderProxyPool(result);
    setMsg("proxy-msg", "代理已删除", "ok");
  } catch (e) { setMsg("proxy-msg", String(e.message || e), "err"); }
}
function currentEmailProviderDefinition(provider = selectedEmailProvider) {
  return (emailProviderData && emailProviderData.providers || []).find(item => item.id === provider) || null;
}
function emailProviderFieldControl(field) {
  const id = "mail-field-" + field.name;
  const raw = emailProviderData && emailProviderData.values ? emailProviderData.values[field.name] : "";
  const value = raw ?? field.default ?? "";
  if (field.type === "select") {
    const options = (field.options || []).map(option => {
      const optionValue = typeof option === "object" ? option.value : option;
      const optionLabel = typeof option === "object" ? option.label : option;
      return `<option value="${esc(optionValue)}" ${String(optionValue) === String(value) ? "selected" : ""}>${esc(optionLabel)}</option>`;
    }).join("");
    return `<select id="${esc(id)}" data-mail-field="${esc(field.name)}">${options}</select>`;
  }
  const isSecret = field.secret === true;
  const configured = isSecret && emailProviderData && emailProviderData.secret_configured && emailProviderData.secret_configured[field.name];
  const placeholder = configured ? "已配置，留空保留" : (field.placeholder || "");
  const type = isSecret ? "password" : (["url", "email"].includes(field.type) ? field.type : "text");
  const input = `<input id="${esc(id)}" data-mail-field="${esc(field.name)}" type="${type}" value="${isSecret ? "" : esc(value)}" placeholder="${esc(placeholder)}" autocomplete="${isSecret ? "new-password" : "off"}" spellcheck="false" ${isSecret ? `oninput="emailProviderSecretInput('${field.name}')"` : ""}/>`;
  if (!isSecret) return input;
  const clear = configured ? `<button type="button" data-mail-secret-button="${esc(field.name)}" onclick="toggleEmailProviderSecret('${field.name}')">清除</button>` : "";
  const note = configured ? "已保存密钥" : "尚未配置";
  return `<div class="mail-secret-wrap" data-mail-secret-wrap="${esc(field.name)}">${input}${clear}</div><div class="mail-secret-note" data-mail-secret-note="${esc(field.name)}">${note}</div>`;
}
function renderEmailProviderFields(provider) {
  const definition = currentEmailProviderDefinition(provider);
  if (!definition) return;
  selectedEmailProvider = definition.id;
  clearedEmailSecrets.clear();
  const select = document.getElementById("mail-provider-select");
  if (select) select.value = definition.id;
  document.getElementById("mail-provider-heading-label").textContent = definition.label;
  const persisted = emailProviderData && emailProviderData.provider === definition.id;
  document.getElementById("mail-provider-subtitle").textContent = persisted
    ? ("当前注册任务使用 " + definition.label)
    : ("待切换到 " + definition.label);
  const status = document.getElementById("mail-provider-status");
  status.textContent = definition.configured ? "已配置" : "待配置";
  status.className = "badge " + (definition.configured ? "ok" : "warn");
  document.getElementById("mail-provider-fields").innerHTML = (definition.fields || []).map(field =>
    `<div class="field"><label for="mail-field-${esc(field.name)}">${esc(field.label)}</label>${emailProviderFieldControl(field)}</div>`
  ).join("") || '<div class="field"><label>服务配置</label><input disabled value="该服务商没有可编辑字段"/></div>';
  const domainProvider = document.getElementById("domain-provider");
  if (domainProvider && ["cloudflare", "cloudmail", "moemail", "yyds"].includes(definition.id)) {
    domainProvider.value = definition.id;
    if (domainData) renderEmailDomainPool(domainData);
  }
}
function renderEmailProviderConfig(data) {
  emailProviderData = data || {};
  const select = document.getElementById("mail-provider-select");
  const providers = emailProviderData.providers || [];
  select.innerHTML = providers.map(provider =>
    `<option value="${esc(provider.id)}">${esc(provider.label)}</option>`
  ).join("");
  const provider = providers.some(item => item.id === emailProviderData.provider)
    ? emailProviderData.provider
    : (providers[0] && providers[0].id || "");
  const updated = emailProviderData.mtime ? new Date(emailProviderData.mtime * 1000) : null;
  document.getElementById("mail-provider-updated").textContent = updated && !Number.isNaN(updated.getTime())
    ? ("config.json " + updated.toLocaleString("zh-CN", {
        timeZone: "Asia/Shanghai",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      }))
    : "config.json 尚未创建";
  renderEmailProviderFields(provider);
}
function selectEmailProvider(provider) {
  renderEmailProviderFields(provider);
  setMsg("mail-provider-msg", "", "");
}
function toggleEmailProviderSecret(name) {
  const clearing = !clearedEmailSecrets.has(name);
  if (clearing) clearedEmailSecrets.add(name);
  else clearedEmailSecrets.delete(name);
  const wrap = document.querySelector(`[data-mail-secret-wrap="${name}"]`);
  const button = document.querySelector(`[data-mail-secret-button="${name}"]`);
  const note = document.querySelector(`[data-mail-secret-note="${name}"]`);
  if (wrap) wrap.classList.toggle("pending-clear", clearing);
  if (button) button.textContent = clearing ? "撤销" : "清除";
  if (note) {
    note.textContent = clearing ? "保存后清除密钥" : "已保存密钥";
    note.className = "mail-secret-note" + (clearing ? " warn" : "");
  }
}
function emailProviderSecretInput(name) {
  const input = document.getElementById("mail-field-" + name);
  if (input && input.value && clearedEmailSecrets.has(name)) toggleEmailProviderSecret(name);
}
function collectEmailProviderSettings() {
  const definition = currentEmailProviderDefinition();
  const settings = {};
  (definition && definition.fields || []).forEach(field => {
    const input = document.getElementById("mail-field-" + field.name);
    if (!input) return;
    settings[field.name] = field.name === "moemail_expiry_ms" ? Number(input.value) : input.value;
  });
  return settings;
}
async function refreshEmailProvider(authHelp = false) {
  try {
    const data = await api("/api/email-provider?_=" + Date.now(), { authHelp });
    renderEmailProviderConfig(data);
    if (!data.ok && data.error) setMsg("mail-provider-msg", data.error, "err");
  } catch (e) {
    const message = String(e.message || e);
    document.getElementById("mail-provider-heading-label").textContent = message.includes("令牌") ? "等待令牌" : "读取失败";
    setMsg("mail-provider-msg", message, "err");
  }
}
async function saveEmailProviderConfig() {
  const button = document.getElementById("mail-provider-save");
  button.disabled = true;
  setMsg("mail-provider-msg", "正在保存…", "");
  try {
    const result = await api("/api/email-provider", { method: "POST", body: JSON.stringify({
      provider: selectedEmailProvider,
      settings: collectEmailProviderSettings(),
      clear_secrets: Array.from(clearedEmailSecrets),
    }) });
    renderEmailProviderConfig(result);
    setMsg("mail-provider-msg", result.provider_label + " 配置已保存", "ok");
  } catch (e) { setMsg("mail-provider-msg", String(e.message || e), "err"); }
  button.disabled = false;
}
async function testEmailProviderConnection() {
  const button = document.getElementById("mail-provider-test");
  button.disabled = true;
  setMsg("mail-provider-msg", "正在测试连通性…", "");
  try {
    const result = await api("/api/email-provider/test", { method: "POST", body: JSON.stringify({
      provider: selectedEmailProvider,
      settings: collectEmailProviderSettings(),
      clear_secrets: Array.from(clearedEmailSecrets),
    }) });
    setMsg("mail-provider-msg", result.detail || "连接正常", "ok");
  } catch (e) { setMsg("mail-provider-msg", String(e.message || e), "err"); }
  button.disabled = false;
}
function domainStatusLabel(status) {
  return ({ active: "轮换中", standby: "待命", blocked: "已拉黑", disabled: "已停用" })[status] || "待命";
}
function renderEmailDomainPool(data) {
  domainData = data || {};
  const summary = domainData.summary || {};
  const values = [
    ["总数", summary.total ?? 0, ""],
    ["轮换中", summary.active ?? 0, "ok"],
    ["待命", summary.standby ?? 0, (summary.standby || 0) > 0 ? "accent" : ""],
    ["已拉黑", summary.blocked ?? 0, (summary.blocked || 0) > 0 ? "fail" : ""],
    ["已停用", summary.disabled ?? 0, (summary.disabled || 0) > 0 ? "warn" : ""],
  ];
  document.getElementById("domain-summary").innerHTML = values.map(([label, value, cls]) =>
    `<div class="domain-summary-item"><div class="domain-summary-label">${esc(label)}</div><div class="domain-summary-value ${cls}">${esc(value)}</div></div>`
  ).join("");
  document.getElementById("domain-advanced-count").textContent = (summary.total ?? 0) + " 个域名";
  document.getElementById("domain-updated").textContent = domainData.updated_at ? ("更新 " + proxyTime(domainData.updated_at)) : "尚未写入";
  const settings = domainData.settings || {};
  const focused = document.activeElement && ["domain-threshold", "domain-max-active"].includes(document.activeElement.id);
  if (!focused) {
    document.getElementById("domain-threshold").value = settings.failure_threshold ?? 3;
    document.getElementById("domain-max-active").value = settings.max_active_domains ?? 0;
  }
  const provider = document.getElementById("domain-provider").value || "cloudflare";
  const providerLabel = domainData.provider_labels && domainData.provider_labels[provider] || provider;
  const providerCount = domainData.providers && domainData.providers[provider] || 0;
  document.getElementById("domain-status").textContent = providerCount
    ? (providerLabel + " 已配置 " + providerCount + " 个域名")
    : "尚未导入当前服务商域名";
  const items = domainData.items || [];
  document.getElementById("domain-body").innerHTML = items.length ? items.map(item => {
    const status = item.status || "standby";
    const stateClass = ["active", "standby", "blocked", "disabled"].includes(status) ? status : "standby";
    const threshold = item.failure_threshold || settings.failure_threshold || 3;
    const rejected = Number(item.consecutive_rejections || 0);
    const total = Number(item.total_rejections || 0);
    const counts = `${rejected}/${threshold}<div class="domain-meta">累计 ${total} / 成功 ${Number(item.success_count || 0)}</div>`;
    const latest = item.last_error || (item.last_rejected_at ? ("拒绝 " + proxyTime(item.last_rejected_at)) : (item.last_success_at ? ("接受 " + proxyTime(item.last_success_at)) : "暂无结果"));
    const resetButton = rejected > 0 || status === "blocked" ? `<button onclick="resetEmailDomain('${item.id}')">重置</button>` : "";
    return `<tr>
      <td><span class="domain-state ${stateClass}">${esc(domainStatusLabel(status))}</span></td>
      <td><div class="mono domain-name">${esc(item.domain)}</div><div class="domain-meta">${esc(item.source || "panel")}</div></td>
      <td>${esc(item.provider_label || item.provider || "")}</td>
      <td class="mono">${counts}</td>
      <td title="${esc(item.last_error || "")}">${esc(latest)}</td>
      <td><input class="domain-toggle" type="checkbox" aria-label="启用 ${esc(item.domain)}" ${item.enabled ? "checked" : ""} onchange="setEmailDomainEnabled('${item.id}', this.checked)"/></td>
      <td><div class="domain-actions">${resetButton}<button class="danger" onclick="deleteEmailDomain('${item.id}')">删除</button></div></td>
    </tr>`;
  }).join("") : '<tr><td colspan="7" class="domain-empty">域名池为空，可在上方导入自有域名或子域名</td></tr>';
}
async function refreshEmailDomains(authHelp = false) {
  try {
    const data = await api("/api/email-domains?_=" + Date.now(), { authHelp });
    renderEmailDomainPool(data);
    if (!data.ok && data.error) setMsg("domain-msg", data.error, "err");
  } catch (e) {
    const message = String(e.message || e);
    document.getElementById("domain-updated").textContent = message.includes("令牌") ? "等待令牌" : "读取失败";
    setMsg("domain-msg", message, "err");
  }
}
function domainImportMessage(result) {
  const errors = result.errors || [];
  const errorText = errors.length ? ("，跳过 " + errors.length + " 条：" + errors.slice(0, 2).map(item => "第 " + item.line + " 行 " + item.error).join("；")) : "";
  return "已导入 " + (result.imported_count || 0) + " 个域名，重复 " + (result.duplicate_count || 0) + " 个" + errorText;
}
async function importDomainInput() {
  const input = document.getElementById("domain-input");
  const button = document.getElementById("domain-import-button");
  const value = (input.value || "").trim();
  if (!value) { setMsg("domain-msg", "请输入至少一个域名", "err"); input.focus(); return; }
  button.disabled = true;
  setMsg("domain-msg", "正在导入…", "");
  try {
    const result = await api("/api/email-domains/import", { method: "POST", body: JSON.stringify({ domains: value, provider: document.getElementById("domain-provider").value }) });
    renderEmailDomainPool(result);
    input.value = "";
    setMsg("domain-msg", domainImportMessage(result), result.errors && result.errors.length ? "" : "ok");
  } catch (e) { setMsg("domain-msg", String(e.message || e), "err"); }
  button.disabled = false;
}
async function saveDomainSettings() {
  const button = document.getElementById("domain-settings-button");
  button.disabled = true;
  try {
    const result = await api("/api/email-domains/settings", { method: "POST", body: JSON.stringify({
      failure_threshold: Number(document.getElementById("domain-threshold").value || 3),
      max_active_domains: Number(document.getElementById("domain-max-active").value || 0),
    }) });
    renderEmailDomainPool(result);
    setMsg("domain-msg", "域名池规则已保存", "ok");
  } catch (e) { setMsg("domain-msg", String(e.message || e), "err"); }
  button.disabled = false;
}
async function setEmailDomainEnabled(id, enabled) {
  try {
    const result = await api("/api/email-domains/" + id, { method: "PATCH", body: JSON.stringify({ enabled }) });
    renderEmailDomainPool(result);
    setMsg("domain-msg", enabled ? "域名已启用" : "域名已停用", "ok");
  } catch (e) {
    setMsg("domain-msg", String(e.message || e), "err");
    await refreshEmailDomains(false);
  }
}
async function resetEmailDomain(id) {
  try {
    const result = await api("/api/email-domains/reset", { method: "POST", body: JSON.stringify({ id }) });
    renderEmailDomainPool(result);
    setMsg("domain-msg", "域名失败计数已重置", "ok");
  } catch (e) { setMsg("domain-msg", String(e.message || e), "err"); }
}
async function deleteEmailDomain(id) {
  const item = (domainData && domainData.items || []).find(value => value.id === id);
  if (!confirm("删除域名 " + (item ? item.domain : "") + "？")) return;
  try {
    const result = await api("/api/email-domains/" + id, { method: "DELETE" });
    renderEmailDomainPool(result);
    setMsg("domain-msg", "域名已删除", "ok");
  } catch (e) { setMsg("domain-msg", String(e.message || e), "err"); }
}
async function refresh() {
  try {
    const d = await api("/api/status?_=" + Date.now(), { authHelp: false });
    last = d;
    render(d);
  } catch (e) {
    const message = String(e.message || e);
    document.getElementById("clock").textContent = message.includes("令牌") ? "需要令牌" : "连接异常";
    const sync = document.getElementById("sync-label");
    if (sync) {
      sync.textContent = message.includes("令牌") ? "等待令牌" : "更新失败";
      sync.className = "badge fail";
    }
    if (message.includes("令牌")) setMsg("ctrl-msg", message, "err");
  }
}
function fillControl(d) {
  const c = d.control || {};
  if (document.activeElement && ["workers-input","batch_count","add_count","risk_pause","mode"].includes(document.activeElement.id)) return;
  if (c.workers != null) document.getElementById("workers-input").value = c.workers;
  if (c.batch_count != null) document.getElementById("batch_count").value = c.batch_count;
  if (c.add_count != null && document.getElementById("add_count")) document.getElementById("add_count").value = c.add_count;
  if (c.risk_pause != null) document.getElementById("risk_pause").value = c.risk_pause;
  if (c.mode) document.getElementById("mode").value = c.mode;
}
function controlBody() {
  return {
    workers: Number(document.getElementById("workers-input").value || 3),
    batch_count: Number(document.getElementById("batch_count").value || 40),
    add_count: Number((document.getElementById("add_count") || {}).value || 40),
    risk_pause: Number(document.getElementById("risk_pause").value || 10),
    mode: document.getElementById("mode").value || "orch",
  };
}
async function saveCtrl() {
  try {
    const j = await api("/api/control", { method: "POST", body: JSON.stringify(controlBody()) });
    setMsg("ctrl-msg", "设置已保存，并发数 " + j.workers, "ok");
  } catch (e) { setMsg("ctrl-msg", String(e.message || e), "err"); }
}
async function doStart() {
  document.getElementById("btn-start").disabled = true;
  setMsg("ctrl-msg", "正在启动…", "");
  try {
    await api("/api/control", { method: "POST", body: JSON.stringify(controlBody()) });
    const j = await api("/api/start", { method: "POST", body: JSON.stringify(controlBody()) });
    if (j.ok === false) throw new Error(j.error || "start failed");
    const msg = j.message || ("已启动，进程 " + (j.pid || "?") + "，模式 " + (j.mode || ""));
    setMsg("ctrl-msg", msg + (j.need != null ? "，剩余 " + j.need : ""), "ok");
    setTimeout(refresh, 1000);
    setTimeout(refresh, 3000);
  } catch (e) { setMsg("ctrl-msg", String(e.message || e), "err"); }
  document.getElementById("btn-start").disabled = false;
}
async function doStop() {
  document.getElementById("btn-stop").disabled = true;
  try {
    const j = await api("/api/stop", { method: "POST", body: "{}" });
    setMsg("ctrl-msg", "已停止 killed=" + JSON.stringify(j.killed || []), "ok");
    setTimeout(refresh, 800);
  } catch (e) { setMsg("ctrl-msg", String(e.message || e), "err"); }
  document.getElementById("btn-stop").disabled = false;
}
async function resetBlacklist(mode) {
  mode = mode || "baseline";
  if (!confirm(mode === "empty" ? "清空全部黑名单？" : "重置为基线熔断？")) return;
  try {
    const j = await api("/api/blacklist/reset", { method: "POST", body: JSON.stringify({ mode }) });
    setMsg("bl-msg", j.message || "已重置", "ok");
    setTimeout(refresh, 500);
  } catch (e) { setMsg("bl-msg", String(e.message || e), "err"); }
}
async function refreshBlacklist() {
  try {
    const j = await api("/api/blacklist?_=" + Date.now());
    renderBlacklist(j, last && last.blacklist_update);
    setMsg("bl-msg", "已刷新 / " + (j.mtime_human || "") + " / " + (j.count || 0) + " ASN", "ok");
  } catch (e) { setMsg("bl-msg", String(e.message || e), "err"); }
}
async function refreshStats(authHelp = true) {
  try {
    const j = await api("/api/stats?_=" + Date.now(), { authHelp });
    // 完整统计入库；后续 2s 快照只合并本批字段
    lastFullStats = Object.assign({}, lastFullStats || {}, j || {});
    renderStats(lastFullStats);
    setMsg("stats-msg", "统计已刷新 " + (j.refreshed_at || ""), "ok");
  } catch (e) { setMsg("stats-msg", String(e.message || e), "err"); }
}
function renderRecovery(data) {
  data = data || {};
  const report = data.last_report || {};
  document.getElementById("recovery-kpis").innerHTML = [
    ["待处理", data.pending_count ?? 0, (data.pending_count || 0) > 0 ? "warn" : "ok"],
    ["账号记录", data.account_record_count ?? 0, ""],
    ["可补录", data.recoverable_count ?? 0, (data.recoverable_count || 0) > 0 ? "accent" : "ok"],
    ["上次成功", report.success_count ?? "--", "ok"],
    ["上次失败", report.failure_count ?? "--", (report.failure_count || 0) > 0 ? "fail" : ""],
  ].map(([label, value, cls]) => `<div class="chip"><span>${esc(label)}</span><b class="${cls}">${esc(value)}</b></div>`).join("");
  document.getElementById("recovery-status").textContent = data.running ? ("补录中 #" + (data.pid || "?")) : "空闲";
  document.getElementById("recovery-pending").disabled = !!data.running || !(data.pending_count > 0);
  document.getElementById("recovery-accounts").disabled = !!data.running || !(data.recoverable_count > 0);
  document.getElementById("recovery-stop").disabled = !data.running;
}
async function refreshRecovery() {
  try {
    const data = await api("/api/recovery?_=" + Date.now(), { authHelp: false });
    renderRecovery(data);
  } catch (e) {
    const message = String(e.message || e);
    document.getElementById("recovery-status").textContent = message.includes("令牌") ? "等待令牌" : "检查失败";
  }
}
async function startRecovery(scope) {
  if (scope === "accounts" && !confirm("扫描全部账号文本并补录缺失 CPA？此操作可能持续较长时间。")) return;
  setMsg("recovery-msg", "正在启动补录…", "");
  try {
    const data = await api("/api/recovery/start", { method: "POST", body: JSON.stringify({ scope }) });
    setMsg("recovery-msg", "补录已启动，共 " + (data.input_count || 0) + " 条", "ok");
    await refreshRecovery();
  } catch (e) { setMsg("recovery-msg", String(e.message || e), "err"); }
}
async function stopRecovery() {
  try {
    const data = await api("/api/recovery/stop", { method: "POST", body: "{}" });
    setMsg("recovery-msg", "补录已停止，结束进程 " + JSON.stringify(data.killed || []), "ok");
    await refreshRecovery();
  } catch (e) { setMsg("recovery-msg", String(e.message || e), "err"); }
}
function renderBfs(data) {
  data = data || {};
  const last = data.last_report || {};
  const rj = data.results_jsonl || {};
  const el = document.getElementById("bfs-kpis");
  if (!el) return;
  el.innerHTML = [
    ["上次扫描", last.total ?? "--", ""],
    ["BFS", last.bfs_count ?? "--", (last.bfs_count || 0) > 0 ? "warn" : "ok"],
    ["Clean", last.clean_count ?? "--", "ok"],
    ["比率", last.bfs_rate != null ? (last.bfs_rate + "%") : "--", (last.bfs_rate || 0) > 0 ? "warn" : ""],
    ["队列文件", data.flagged_file_count ?? 0, (data.flagged_file_count || 0) > 0 ? "warn" : ""],
    ["jsonl bfs", rj.bfs ?? 0, (rj.bfs || 0) > 0 ? "warn" : ""],
  ].map(([label, value, cls]) => `<div class="chip"><span>${esc(label)}</span><b class="${cls}">${esc(value)}</b></div>`).join("");
  const st = document.getElementById("bfs-status");
  if (st) st.textContent = last.scanned_at ? ("扫描 " + last.scanned_at) : "尚未扫描";
  const body = document.getElementById("bfs-body");
  if (body && Array.isArray(data.items)) {
    const rows = data.items.filter(it => it.has_bfs).slice(0, 50);
    body.innerHTML = rows.length ? rows.map(it =>
      `<tr><td class="mono">${esc(it.email || "-")}</td><td class="warn">${esc(it.bfs != null ? it.bfs : "yes")}</td><td class="mono">${esc(it.source || "")}</td><td class="mono">${esc(it.file || "")}</td></tr>`
    ).join("") : '<tr><td colspan="4" style="color:var(--muted)">无 bfs 记录（先点扫描）</td></tr>';
  }
}
async function refreshBfs(authHelp = false) {
  try {
    const data = await api("/api/bfs?_=" + Date.now(), { authHelp });
    renderBfs(data);
  } catch (e) {
    const st = document.getElementById("bfs-status");
    if (st) st.textContent = String(e.message || e).includes("令牌") ? "等待令牌" : "检查失败";
  }
}
async function runBfsScan() {
  setMsg("bfs-msg", "正在扫描 CPA / Grok2API auth …", "");
  const btn = document.getElementById("bfs-scan");
  if (btn) btn.disabled = true;
  try {
    const data = await api("/api/bfs/scan", { method: "POST", body: JSON.stringify({}) });
    renderBfs(Object.assign({}, data, { last_report: data, items: data.items || [] }));
    setMsg("bfs-msg",
      "完成 total=" + (data.total ?? 0) +
      " bfs=" + (data.bfs_count ?? 0) +
      " clean=" + (data.clean_count ?? 0) +
      " rate=" + (data.bfs_rate ?? 0) + "%" +
      (data.export_path ? (" → " + data.export_path) : ""),
      "ok");
  } catch (e) {
    setMsg("bfs-msg", String(e.message || e), "err");
  } finally {
    if (btn) btn.disabled = false;
  }
}
function renderBlacklist(bl, upd) {
  bl = bl || {};
  upd = upd || {};
  document.getElementById("bl-kpis").innerHTML = [
    ["ASN 数", bl.count ?? 0, "accent"],
    ["ISP 关键字", (bl.isp_keywords || []).length, ""],
    ["解析错误", (bl.errors || []).length, (bl.errors || []).length ? "fail" : "ok"],
  ].map(([l,v,c]) => `<div class="chip"><span>${esc(l)}</span><b class="${c}">${esc(v)}</b></div>`).join("");
  document.getElementById("bl-body").innerHTML = (bl.items || []).map(i =>
    `<tr><td class="mono">AS${esc(i.asn)}</td><td>${esc(i.note || "")}</td></tr>`
  ).join("") || '<tr><td colspan="2" style="color:var(--muted)">空</td></tr>';
  document.getElementById("bl-err-chips").innerHTML = [
    ["更新错误合计", upd.error_count ?? 0, (upd.error_count ? "fail" : "ok")],
    ["lookup 失败", upd.lookup_fail_count ?? 0, "warn"],
    ["analyze 错误", upd.analyze_error_count ?? 0, "warn"],
    ["暂停扩黑次数", upd.hit_pause_count ?? 0, ""],
    ["历史新增记录", upd.added_total ?? 0, "accent"],
  ].map(([l,v,c]) => `<div class="chip"><span>${esc(l)}</span><b class="${c}">${esc(v)}</b></div>`).join("");
  document.getElementById("bl-added").innerHTML = (upd.recent_added || []).slice().reverse().map(a =>
    `<tr><td class="mono">AS${esc(a.asn)}</td><td class="mono">${esc(a.log || "")}</td></tr>`
  ).join("") || '<tr><td colspan="2" style="color:var(--muted)">暂无自动新增</td></tr>';
}

function rateCls(r) {
  if (r == null) return "";
  if (r >= 70) return "ok";
  if (r >= 40) return "warn";
  return "fail";
}
function renderRates(rates) {
  rates = rates || {};
  const order = ["1h", "3h", "12h"];
  const labels = { "1h": "近 1 小时", "3h": "近 3 小时", "12h": "近 12 小时" };
  const cards = order.map(k => {
    const b = rates[k] || {};
    const r = b.success_rate;
    const val = r == null ? "--" : (r + "%");
    return `<div class="rate-item">
      <div class="rate-top">
        <span class="rate-label">${esc(labels[k] || k)}</span>
        <span class="rate-total">${b.total ?? 0} 次</span>
      </div>
      <div class="rate-value ${rateCls(r)}">${esc(val)}</div>
      <div class="rate-breakdown">
        <span class="ok">成功 ${b.ok ?? 0}</span>
        <span class="fail">失败 ${b.fail ?? 0}</span>
        <span class="warn">风控 ${b.risk ?? 0}</span>
      </div>
    </div>`;
  });
  const el = document.getElementById("rate-kpis");
  if (el) el.innerHTML = cards.join("");
}

function renderStats(s, opts) {
  opts = opts || {};
  s = s || {};
  // 快照轻量更新：只覆盖本批/CPA，保留 jsonl / by_day / rates
  if (opts.liveMerge && lastFullStats) {
    s = Object.assign({}, lastFullStats, {
      cpa: s.cpa != null ? s.cpa : lastFullStats.cpa,
      cpa_delta: s.cpa_delta != null ? s.cpa_delta : lastFullStats.cpa_delta,
      base_cpa: s.base_cpa != null ? s.base_cpa : lastFullStats.base_cpa,
      batch_ok: s.batch_ok != null ? s.batch_ok : lastFullStats.batch_ok,
      batch_fail: s.batch_fail != null ? s.batch_fail : lastFullStats.batch_fail,
      // rates 以快照里的为准（snapshot 已算），否则沿用缓存
      rates: (s.rates && Object.keys(s.rates).length) ? s.rates : lastFullStats.rates,
    });
  } else if (!opts.liveMerge && s && (typeof s.jsonl_ok === "number" || (s.by_day && Object.keys(s.by_day).length))) {
    lastFullStats = Object.assign({}, lastFullStats || {}, s);
  }
  if (s.rates) renderRates(s.rates);
  const jsonlOk = (typeof s.jsonl_ok === "number") ? s.jsonl_ok : (lastFullStats && lastFullStats.jsonl_ok);
  const jsonlRisk = (typeof s.jsonl_risk === "number") ? s.jsonl_risk : (lastFullStats && lastFullStats.jsonl_risk);
  document.getElementById("stats-chips").innerHTML = [
    ["CPA", s.cpa ?? "--", "accent"],
    ["CPA 变化", s.cpa_delta ?? "--", "ok"],
    ["本批成功", s.batch_ok ?? 0, "ok"],
    ["本批失败", s.batch_fail ?? 0, "fail"],
    ["jsonl ok", jsonlOk != null ? jsonlOk : "--", "ok"],
    ["jsonl risk", jsonlRisk != null ? jsonlRisk : "--", "warn"],
  ].map(([l,v,c]) => `<div class="chip"><span>${esc(l)}</span><b class="${c}">${esc(v)}</b></div>`).join("");
  const byDay = (s.by_day && Object.keys(s.by_day).length)
    ? s.by_day
    : ((lastFullStats && lastFullStats.by_day) || {});
  const days = Object.entries(byDay).sort((a,b) => b[0].localeCompare(a[0])).slice(0, 10);
  document.getElementById("stats-day").innerHTML = days.length ? days.map(([d, v]) =>
    `<tr><td class="mono">${esc(d)}</td><td class="ok">${v.ok||0}</td><td class="warn">${v.risk||0}</td><td class="fail">${v.fail||0}</td></tr>`
  ).join("") : '<tr><td colspan="4" style="color:var(--muted)">无 jsonl 数据</td></tr>';
  // 保留「统计已刷新」文案，不被 2s 轮询清掉
  if (!opts.liveMerge && s.refreshed_at) {
    const el = document.getElementById("stats-msg");
    if (el && !String(el.textContent || "").includes("失败")) {
      /* refreshed via setMsg in refreshStats */
    }
  }
}
function render(d) {
  document.getElementById("clock").textContent = d.ts_human || "--";
  document.getElementById("logname").textContent =
    (d.log_name || d.log || "--") + (d.process && d.process.etime ? " / 用时 " + d.process.etime : "");
  const on = !!(d.process && d.process.running);
  document.getElementById("run-dot").className = "dot " + (on ? "on" : (d.ended ? "done" : "off"));
  let runLabel = "已停止";
  if (d.process && d.process.orch_running) runLabel = "编排运行 #" + d.process.orch_pid;
  else if (d.process && d.process.batch_running) runLabel = "单批运行 #" + d.process.batch_pid;
  else if (d.ended) runLabel = "已完成";
  document.getElementById("run-label").textContent = runLabel;
  document.getElementById("run-status").setAttribute("aria-label", "任务状态：" + runLabel);
  const sync = document.getElementById("sync-label");
  if (sync) {
    sync.textContent = "实时更新";
    sync.className = "badge";
  }
  document.getElementById("ctrl-status").textContent = on ? "运行中" : "空闲";
  document.getElementById("btn-start").disabled = on;
  document.getElementById("btn-stop").disabled = !on;
  fillControl(d);

  const traffic = d.traffic || {};
  const hasTrafficBatch = !!traffic.batch_id;
  const trafficTotal = Number(traffic.bytes_total) || 0;
  const trafficState = traffic.running ? "运行中" : "上一批";
  const trafficSub = hasTrafficBatch
    ? trafficState + " / 上行 " + formatBytes(traffic.bytes_up) + " / 下行 " + formatBytes(traffic.bytes_down)
      + ((Number(traffic.unmetered_proxies) || 0) > 0 ? " / 未计量 " + traffic.unmetered_proxies : "")
    : "等待批次计量";
  const kpis = [
    ["本批成功", d.ok ?? 0, "ok", "目标 " + (d.target ?? "--")],
    ["本批失败", d.fail ?? 0, "fail", d.success_rate != null ? "成功率 " + d.success_rate + "%" : "暂无数据"],
    ["CPA 总量", d.cpa ?? "--", "accent", "较基线 " + (d.cpa_delta != null ? ((Number(d.cpa_delta) >= 0 ? "+" : "") + d.cpa_delta) : "--")],
    ["正常 / 风控", (d.bot0 ?? 0) + " / " + (d.bot1 ?? 0), (d.bot1 ?? 0) > 0 ? "warn" : "ok", "注册结果采样"],
    ["BFS 标记", d.bfs ?? 0, (d.bfs ?? 0) > 0 ? "warn" : "ok", "JWT claim 命中"],
    ["黑名单 ASN", (d.blacklist && d.blacklist.count) ?? "--", "accent", "更新错误 " + ((d.blacklist_update && d.blacklist_update.error_count) ?? 0)],
    ["本批代理流量", hasTrafficBatch ? formatBytes(trafficTotal) : "--", "accent", trafficSub],
    ["预计完成", d.ended ? "已完成" : (d.eta || "--"), "", "并发 " + (d.workers ?? "--") + (d.rate_per_min != null ? " / " + d.rate_per_min + " 每分钟" : "")],
  ];
  document.getElementById("kpis").innerHTML = kpis.map(([label, val, cls, sub]) =>
    `<div class="metric"><div class="label">${esc(label)}</div><div class="value ${cls}">${esc(val)}</div><div class="sub">${esc(sub)}</div></div>`
  ).join("");
  renderRates(d.rates || {});
  const ru = document.getElementById("rates-updated");
  if (ru && d.ts_human) ru.textContent = "数据更新 " + d.ts_human;

  const pct = Math.min(100, Number(d.progress_pct) || 0);
  document.getElementById("bar").style.width = pct + "%";
  document.getElementById("prog-text").textContent = (d.ok ?? 0) + " / " + (d.target ?? 0) + " (" + pct + "%)";
  document.getElementById("prog-sub").textContent =
    "尝试 " + (d.done_attempts ?? 0) + " / " + (on ? "进程运行中" : "未运行")
    + (d.ended ? " / 结束：成功 " + d.ended.success + "，失败 " + d.ended.fail : "");

  renderBlacklist(d.blacklist, d.blacklist_update);
  // 2s 快照：只更新本批/CPA，绝不清空 jsonl / 按日表
  renderStats({
    cpa: d.cpa,
    cpa_delta: d.cpa_delta,
    base_cpa: d.base_cpa,
    batch_ok: d.ok,
    batch_fail: d.fail,
    rates: d.rates || {},
  }, { liveMerge: true });

  const wset = new Set([...(Object.keys(d.worker_ok || {})), ...(Object.keys(d.worker_fail || {}))]);
  const ws = [...wset].sort((a, b) => parseInt(a.slice(1)) - parseInt(b.slice(1)));
  document.getElementById("workers-stats").innerHTML = ws.length ? ws.map(w =>
    `<div class="chip"><span>${esc(w)}</span><b><span class="ok">${d.worker_ok && d.worker_ok[w] || 0}</span> <span style="color:var(--muted)">/</span> <span class="fail">${d.worker_fail && d.worker_fail[w] || 0}</span></b></div>`
  ).join("") : '<span style="color:var(--muted)">暂无</span>';
  const fk = Object.entries(d.fail_kinds || {}).sort((a, b) => b[1] - a[1]);
  document.getElementById("fails").innerHTML = fk.length ? fk.map(([k, v]) =>
    `<div class="chip"><span>${esc(k)}</span><b class="fail">${v}</b></div>`
  ).join("") : '<span style="color:var(--muted)">暂无失败</span>';
  okRowsCache = Array.isArray(d.recent_ok) ? d.recent_ok.slice() : [];
  failRowsCache = Array.isArray(d.recent_fail) ? d.recent_fail.slice() : [];
  // 新数据到来时，若当前页越界则收回最后一页；用户正在翻页时尽量保留页码
  renderOkPage();
  renderFailPage();
  document.getElementById("tail").textContent = (d.tail || []).join("\n");
  document.getElementById("footer").textContent =
    "服务 " + location.host + " / 日志 " + (d.log || "") + " / 2 秒轮询 / "
    + (d.log_size ? (d.log_size / 1024).toFixed(0) + " KB" : "0 KB")
    + " / 黑名单 " + ((d.blacklist && d.blacklist.count) || 0) + " ASN";
}

function listPageCount(total) {
  return Math.max(1, Math.ceil(Math.max(0, total) / LIST_PAGE_SIZE));
}

function clampPage(page, total) {
  const pages = listPageCount(total);
  let p = Math.max(1, parseInt(page, 10) || 1);
  if (p > pages) p = pages;
  return p;
}

function renderOkPage() {
  const rows = okRowsCache || [];
  okPage = clampPage(okPage, rows.length);
  const pages = listPageCount(rows.length);
  const start = (okPage - 1) * LIST_PAGE_SIZE;
  const slice = rows.slice(start, start + LIST_PAGE_SIZE);
  document.getElementById("ok-body").innerHTML = slice.length
    ? slice.map(r =>
      `<tr><td class="mono">${esc(r.t)}</td><td>${esc(r.w)}</td><td class="mono">${esc(r.email)}</td></tr>`
    ).join("")
    : '<tr><td colspan="3" style="color:var(--muted)">暂无记录</td></tr>';
  const meta = rows.length
    ? `共 ${rows.length} 条 · 第 ${okPage}/${pages} 页`
    : "共 0 条";
  document.getElementById("ok-page-meta").textContent = meta;
  document.getElementById("ok-pager-info").textContent = rows.length
    ? `每页 ${LIST_PAGE_SIZE} 条`
    : "";
  document.getElementById("ok-prev").disabled = okPage <= 1 || !rows.length;
  document.getElementById("ok-next").disabled = okPage >= pages || !rows.length;
}

function renderFailPage() {
  const rows = failRowsCache || [];
  failPage = clampPage(failPage, rows.length);
  const pages = listPageCount(rows.length);
  const start = (failPage - 1) * LIST_PAGE_SIZE;
  const slice = rows.slice(start, start + LIST_PAGE_SIZE);
  document.getElementById("fail-body").innerHTML = slice.length
    ? slice.map(r =>
      `<tr><td class="mono">${esc(r.t)}</td><td>${esc(r.w)}</td><td>${esc(r.kind)}</td><td class="mono">${esc(r.msg)}</td></tr>`
    ).join("")
    : '<tr><td colspan="4" style="color:var(--muted)">暂无记录</td></tr>';
  const meta = rows.length
    ? `共 ${rows.length} 条 · 第 ${failPage}/${pages} 页`
    : "共 0 条";
  document.getElementById("fail-page-meta").textContent = meta;
  document.getElementById("fail-pager-info").textContent = rows.length
    ? `每页 ${LIST_PAGE_SIZE} 条`
    : "";
  document.getElementById("fail-prev").disabled = failPage <= 1 || !rows.length;
  document.getElementById("fail-next").disabled = failPage >= pages || !rows.length;
}

document.getElementById("ok-prev").addEventListener("click", () => {
  okPage = Math.max(1, okPage - 1);
  renderOkPage();
});
document.getElementById("ok-next").addEventListener("click", () => {
  okPage += 1;
  renderOkPage();
});
document.getElementById("fail-prev").addEventListener("click", () => {
  failPage = Math.max(1, failPage - 1);
  renderFailPage();
});
document.getElementById("fail-next").addEventListener("click", () => {
  failPage += 1;
  renderFailPage();
});

syncThemeButtons();
initHelp();
loadTokenField();
refresh();
setInterval(refresh, 2000);
// 完整成功统计：启动拉一次，之后每 30s 刷新（避免 2s 轮询冲掉）
refreshStats(false);
setInterval(() => refreshStats(false), 30000);
refreshRecovery();
setInterval(refreshRecovery, 5000);
refreshBfs();
setInterval(refreshBfs, 15000);
setInterval(() => {
  if (document.body.classList.contains("proxy-view-open")) refreshProxies(false);
  if (document.body.classList.contains("domain-view-open")) refreshEmailDomains(false);
}, 3000);
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "GrokRegister"
    sys_version = ""

    def version_string(self):
        return self.server_version

    def log_message(self, fmt, *args):
        msg = args[0] if args else ""
        if "/api/status" in str(msg):
            return
        super().log_message(fmt, *args)

    def _send(self, code, body, ctype):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=()",
        )
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'none'; object-src 'none'; "
            "frame-ancestors 'none'; form-action 'none'; img-src 'self' data:; "
            "font-src 'self'; connect-src 'self'; "
            "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'",
        )
        # No wildcard CORS — panel is same-origin. Optional explicit origin via env.
        allow = str(os.environ.get("MONITOR_CORS_ORIGIN", "") or "").strip()
        if allow and allow != "*":
            self.send_header("Access-Control-Allow-Origin", allow)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
        self.wfile.write(body)

    def _auth_header(self) -> str:
        return (
            self.headers.get("Authorization")
            or self.headers.get("X-Monitor-Token")
            or ""
        )

    def _require_write(self) -> bool:
        if check_token_optional_read(self._auth_header(), write=True):
            return True
        self._json(401, {"ok": False, "error": "unauthorized: set MONITOR_TOKEN and pass Authorization: Bearer <token>"})
        return False

    def _require_read(self) -> bool:
        if check_token_optional_read(self._auth_header(), write=False):
            return True
        self._json(401, {"ok": False, "error": "unauthorized: enter the current monitor token"})
        return False

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8"), "application/json; charset=utf-8")

    def _read_body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError as exc:
            raise ValueError("invalid Content-Length") from exc
        if n <= 0:
            return {}
        if n > MAX_REQUEST_BODY:
            raise OverflowError("request body too large")
        raw = self.rfile.read(n)
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except Exception as exc:
            raise ValueError("invalid JSON body") from exc
        if not isinstance(body, dict):
            raise ValueError("JSON body must be an object")
        return body

    def do_OPTIONS(self):
        self._send(204, b"", "text/plain")

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            self._send(200, HTML.encode("utf-8"), "text/html; charset=utf-8")
            return
        if u.path in FONT_ASSETS:
            path = FONT_ASSETS[u.path]
            if path.is_file():
                self._send(200, path.read_bytes(), "font/woff2")
            else:
                self._send(404, b"not found", "text/plain")
            return
        if u.path == "/favicon.ico":
            self._send(204, b"", "image/x-icon")
            return
        if u.path == "/api/health":
            self._json(200, {"ok": True})
            return
        if u.path in ("/api/status", "/api/blacklist", "/api/stats", "/api/control", "/api/recovery", "/api/proxies", "/api/email-provider", "/api/email-domains", "/api/bfs"):
            if not self._require_read():
                return
        if u.path == "/api/status":
            try:
                self._json(200, snapshot())
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        if u.path == "/api/blacklist":
            try:
                bl = read_blacklist()
                bl["update"] = blacklist_update_errors()
                self._json(200, bl)
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        if u.path == "/api/stats":
            try:
                self._json(200, success_stats())
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        if u.path == "/api/control":
            self._json(200, load_control())
            return
        if u.path == "/api/recovery":
            try:
                self._json(200, recovery_status())
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})
            return
        if u.path == "/api/bfs":
            try:
                self._json(200, bfs_status())
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/proxies":
            try:
                self._json(200, read_proxy_pool())
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/email-provider":
            try:
                self._json(200, read_email_provider_config())
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/email-domains":
            try:
                self._json(200, read_email_domain_pool())
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        self._send(404, b"not found", "text/plain")

    def do_POST(self):
        u = urlparse(self.path)
        # All POST endpoints require MONITOR_TOKEN
        if not self._require_write():
            return
        try:
            body = self._read_body()
        except OverflowError as exc:
            self._json(413, {"ok": False, "error": str(exc)})
            return
        except ValueError as exc:
            self._json(400, {"ok": False, "error": str(exc)})
            return
        if u.path == "/api/control":
            try:
                self._json(200, save_control(body))
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        if u.path == "/api/start":
            try:
                if body:
                    save_control(body)
                mode = (body or {}).get("mode") or load_control().get("mode") or "orch"
                if mode == "batch":
                    self._json(200, start_batch_only())
                else:
                    self._json(200, start_orch())
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        if u.path == "/api/stop":
            try:
                self._json(200, kill_all())
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        if u.path == "/api/recovery/start":
            try:
                with START_LOCK:
                    result = start_recovery((body or {}).get("scope") or "pending")
                self._json(200 if result.get("ok") else 409, result)
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})
            return
        if u.path == "/api/recovery/stop":
            try:
                self._json(200, stop_recovery())
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})
            return
        if u.path == "/api/bfs/scan":
            try:
                limit = int((body or {}).get("limit") or 0)
                include_clean = bool((body or {}).get("include_clean"))
                result = run_bfs_scan(limit=limit, include_clean=include_clean)
                self._json(200, result)
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/bfs/check":
            try:
                token = str((body or {}).get("token") or "").strip()
                if not token:
                    self._json(400, {"ok": False, "error": "token required"})
                    return
                self._json(200, check_token_text(token))
            except Exception as e:
                self._json(400, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/proxies/import":
            try:
                if body.get("legacy") is True:
                    result = import_legacy_proxies()
                else:
                    result = import_proxies(body.get("proxies"), source="panel")
                self._json(200 if result.get("ok") else 400, result)
            except Exception as e:
                self._json(400, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/proxies/test":
            try:
                result = start_proxy_tests(body.get("ids"))
                if result.get("ok"):
                    code = 202
                elif result.get("running"):
                    code = 409
                else:
                    code = 400
                self._json(code, result)
            except Exception as e:
                self._json(400, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/email-provider":
            try:
                result = save_email_provider_config(
                    body.get("provider"),
                    body.get("settings") or {},
                    clear_secrets=body.get("clear_secrets"),
                )
                self._json(200, result)
            except ValueError as e:
                self._json(400, {"ok": False, "error": redact_log_line(str(e))})
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/email-provider/test":
            try:
                result = test_email_provider_config(
                    body.get("provider"),
                    body.get("settings") or {},
                    clear_secrets=body.get("clear_secrets"),
                )
                self._json(200 if result.get("ok") else 424, result)
            except ValueError as e:
                self._json(400, {"ok": False, "error": redact_log_line(str(e))})
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/email-domains/import":
            try:
                result = import_domains(
                    body.get("domains"),
                    body.get("provider"),
                    source="panel",
                )
                self._json(200 if result.get("ok") else 400, result)
            except Exception as e:
                self._json(400, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/email-domains/settings":
            try:
                result = update_email_domain_settings(
                    failure_threshold=body.get("failure_threshold"),
                    max_active_domains=body.get("max_active_domains"),
                )
                self._json(200, result)
            except ValueError as e:
                self._json(400, {"ok": False, "error": redact_log_line(str(e))})
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/email-domains/reset":
            try:
                result = reset_domain(body.get("id"))
                self._json(200 if result.get("ok", True) else 404, result)
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/blacklist/refresh":
            try:
                bl = read_blacklist()
                bl["update"] = blacklist_update_errors()
                self._json(200, bl)
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        if u.path == "/api/blacklist/reset":
            try:
                from webui.blacklist_ops import reset_blacklist as _reset_bl
            except ImportError:
                try:
                    from blacklist_ops import reset_blacklist as _reset_bl  # type: ignore
                except ImportError:
                    _reset_bl = None
            if _reset_bl is None:
                self._json(501, {"ok": False, "error": "blacklist_ops unavailable"})
                return
            try:
                mode = (body or {}).get("mode") or "baseline"
                self._json(200, _reset_bl(mode))
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})
            return
        if u.path == "/api/stats/refresh":
            try:
                self._json(200, success_stats())
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        self._send(404, b"not found", "text/plain")

    def do_PATCH(self):
        u = urlparse(self.path)
        proxy_match = re.fullmatch(r"/api/proxies/([a-f0-9]{20})", u.path)
        domain_match = re.fullmatch(r"/api/email-domains/([a-f0-9]{20})", u.path)
        if proxy_match is None and domain_match is None:
            self._send(404, b"not found", "text/plain")
            return
        if not self._require_write():
            return
        try:
            body = self._read_body()
        except OverflowError as exc:
            self._json(413, {"ok": False, "error": str(exc)})
            return
        except ValueError as exc:
            self._json(400, {"ok": False, "error": str(exc)})
            return
        try:
            if proxy_match is not None:
                result = update_proxy(proxy_match.group(1), enabled=body.get("enabled"))
            else:
                result = update_domain(domain_match.group(1), enabled=body.get("enabled"))
            self._json(200 if result.get("ok") else 404, result)
        except ValueError as exc:
            self._json(400, {"ok": False, "error": redact_log_line(str(exc))})
        except Exception as exc:
            self._json(500, {"ok": False, "error": redact_log_line(str(exc))})

    def do_DELETE(self):
        u = urlparse(self.path)
        proxy_match = re.fullmatch(r"/api/proxies/([a-f0-9]{20})", u.path)
        domain_match = re.fullmatch(r"/api/email-domains/([a-f0-9]{20})", u.path)
        if proxy_match is None and domain_match is None:
            self._send(404, b"not found", "text/plain")
            return
        if not self._require_write():
            return
        try:
            result = (
                delete_proxy(proxy_match.group(1))
                if proxy_match is not None
                else delete_domain(domain_match.group(1))
            )
            self._json(200 if result.get("ok") else 404, result)
        except Exception as exc:
            self._json(500, {"ok": False, "error": redact_log_line(str(exc))})


def main():
    host = BIND_HOST
    tok = expected_token()
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host.strip().lower() == "localhost"
    if not tok and not loopback:
        raise SystemExit(
            "MONITOR_TOKEN is required when MONITOR_HOST is not loopback"
        )
    ThreadingHTTPServer.allow_reuse_address = True
    try:
        httpd = ThreadingHTTPServer((host, BIND_PORT), Handler)
    except OSError as e1:
        raise SystemExit(
            f"cannot bind {BIND_HOST}:{BIND_PORT} ({e1}); "
            "set MONITOR_HOST/MONITOR_PORT (no 0.0.0.0 fallback)"
        )
    if not tok:
        print(
            "[monitor] WARNING: MONITOR_TOKEN unset — write APIs (start/stop/control) will return 401",
            flush=True,
        )
    print(f"[monitor] http://{host}:{BIND_PORT}/  (bound {host}:{BIND_PORT})", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
