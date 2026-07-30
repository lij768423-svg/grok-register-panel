#!/usr/bin/env python3
"""Grok register batch live monitor — bind Tailscale, control + blacklist panel."""
from __future__ import annotations

import importlib.util
import json
import os
import re
import signal
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
# 加载根目录 __init__.py → 自动读 .env（须在读取 os.environ 之前）
_spec = importlib.util.spec_from_file_location("_project_init", ROOT / "__init__.py")
if _spec and _spec.loader:
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)

try:
    from webui.security_utils import (
        check_token_optional_read,
        expected_token,
        mask_email,
        redact_proxy,
    )
except ImportError:  # running as script from webui/
    from security_utils import (  # type: ignore
        check_token_optional_read,
        expected_token,
        mask_email,
        redact_proxy,
    )

LOG_DIR = ROOT / "log"
CPA_DIR = Path(os.environ.get("CPA_AUTH_DIR", str(ROOT / "cpa_auth")))
BS = ROOT / "browser_session.py"
MONITOR_TOKEN_ENV = "MONITOR_TOKEN"
PANEL_INCLUDE_TAIL = os.environ.get("PANEL_INCLUDE_TAIL", "0").strip() in ("1", "true", "yes")

BASE_FILE = LOG_DIR / "batch1000.base"
ORCH_PID = LOG_DIR / "orch100.pid"
BATCH_PID = LOG_DIR / "batch100.pid"
CONTROL_FILE = LOG_DIR / "monitor_control.json"
STATS_CACHE = LOG_DIR / "monitor_stats.json"
BIND_HOST = os.environ.get("MONITOR_HOST", "127.0.0.1")
BIND_PORT = int(os.environ.get("MONITOR_PORT", "8787"))
VENV_PY = ROOT / ".venv/bin/python"
ORCH_SCRIPT = ROOT / "run_until_100.py"

RE_OK = re.compile(r"\[\+\] 注册成功")
RE_FAIL = re.compile(r"\[-\] 失败")
RE_DOMAIN = re.compile(r"\[-\] 域名拒绝")
RE_SKIP = re.compile(r"\[-\] 卡住跳过")
RE_BOT0 = re.compile(r"botFlagSource=0")
RE_BOT1 = re.compile(r"botFlagSource=1")
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
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_control() -> dict:
    c = _read_json(CONTROL_FILE, {})
    c.setdefault("workers", 3)
    c.setdefault("risk_pause", 10)
    c.setdefault("batch_count", 40)
    c.setdefault("add_count", 40)  # 再跑 N 个
    c.setdefault("mode", "orch")  # orch | batch
    return c


def save_control(updates: dict) -> dict:
    c = load_control()
    c.update(updates or {})
    try:
        c["workers"] = max(1, min(24, int(c.get("workers", 3))))
    except Exception:
        c["workers"] = 3
    try:
        c["risk_pause"] = max(1, int(c.get("risk_pause", 10)))
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


def _ps_lines():
    try:
        return subprocess.check_output(["ps", "-eo", "pid,etime,cmd"], text=True, errors="replace")
    except Exception:
        return ""


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
    out = _ps_lines()
    for line in out.splitlines():
        if "run_until_100.py" in line and "grep" not in line:
            parts = line.split(None, 2)
            if len(parts) >= 3:
                info["orch_running"] = True
                info["orch_pid"] = int(parts[0])
                info["orch_etime"] = parts[1]
                info["running"] = True
                info["pid"] = int(parts[0])
                info["etime"] = parts[1]
                info["cmd"] = parts[2][:160]
        if "run_batch_headless.py" in line and "grep" not in line and "xvfb-run" not in line:
            parts = line.split(None, 2)
            if len(parts) >= 3:
                info["batch_running"] = True
                info["batch_pid"] = int(parts[0])
                info["batch_etime"] = parts[1]
                if not info["running"]:
                    info["running"] = True
                    info["pid"] = int(parts[0])
                    info["etime"] = parts[1]
                    info["cmd"] = parts[2][:160]
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
    ok = fail = domain = skip = bot0 = bot1 = 0
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
            recent_fail.append({"t": ts, "w": w, "kind": kind, "msg": msg[:160]})
        if RE_DOMAIN.search(line):
            domain += 1
        if RE_SKIP.search(line):
            skip += 1
        if RE_BOT0.search(line):
            bot0 += 1
        if RE_BOT1.search(line):
            bot1 += 1

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

    return {
        "log": str(path),
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
        "ended": ended,
        "fail_kinds": fail_kinds,
        "worker_ok": worker_ok,
        "worker_fail": worker_fail,
        "recent_ok": recent_ok[-25:][::-1],
        "recent_fail": recent_fail[-25:][::-1],
        "tail": last_lines,
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
    """Parse ASN blacklist from browser_session.py."""
    errors = []
    items = []
    nums = set()
    isp = []
    try:
        text = BS.read_text(encoding="utf-8")
    except Exception as e:
        return {
            "ok": False,
            "error": str(e),
            "count": 0,
            "asns": [],
            "items": [],
            "isp_keywords": [],
            "errors": [str(e)],
            "mtime": None,
        }
    try:
        m = re.search(r"_BLOCKED_ASN_NUMS\s*=\s*\{([^}]*)\}", text)
        if m:
            for x in re.findall(r"\d+", m.group(1)):
                nums.add(int(x))
        block = re.search(r"_BLOCKED_ASN_SUBSTR\s*=\s*\((.*?)\)", text, re.S)
        if block:
            for line in block.group(1).splitlines():
                am = re.search(r'"AS(\d+)"\s*,?\s*(?:#\s*(.*))?', line)
                if am:
                    n = int(am.group(1))
                    nums.add(n)
                    note = (am.group(2) or "").strip()
                    items.append({"asn": n, "label": f"AS{n}", "note": note})
        isp_block = re.search(r"_BLOCKED_ISP_SUBSTR\s*=\s*\((.*?)\)", text, re.S)
        if isp_block:
            isp = re.findall(r'"([^"]+)"', isp_block.group(1))
        # ensure all nums represented
        labeled = {i["asn"] for i in items}
        for n in sorted(nums):
            if n not in labeled:
                items.append({"asn": n, "label": f"AS{n}", "note": ""})
        items.sort(key=lambda x: x["asn"])
    except Exception as e:
        errors.append(f"parse: {e}")
    try:
        mtime = BS.stat().st_mtime
    except Exception:
        mtime = None
    return {
        "ok": len(errors) == 0,
        "error": errors[0] if errors else None,
        "count": len(nums),
        "asns": sorted(nums),
        "items": items,
        "isp_keywords": isp,
        "errors": errors,
        "mtime": mtime,
        "mtime_human": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime)) if mtime else None,
        "source": str(BS),
    }


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

    cpa = cpa_count()
    base = read_base()
    jsonl_ok = 0
    jsonl_risk = 0
    jsonl_fail = 0
    by_day = {}
    results = LOG_DIR / "register_results.jsonl"

    # windows in hours -> counters
    windows_h = (1, 3, 12)
    now = datetime.now(timezone.utc)
    win = {
        h: {"ok": 0, "fail": 0, "risk": 0, "total": 0, "since": (now - timedelta(hours=h)).strftime("%Y-%m-%dT%H:%M:%SZ")}
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
            return dt.astimezone(timezone.utc)
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
                    day = (o.get("ts") or "")[:10]
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

                    dt = _parse_ts(o.get("ts") or "")
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
        "cpa_delta": cpa - base if base else None,
        "jsonl_ok": jsonl_ok,
        "jsonl_risk": jsonl_risk,
        "jsonl_fail": jsonl_fail,
        "batch_ok": batch_ok,
        "batch_fail": batch_fail,
        "batch_log": parsed.get("log_name"),
        "by_day": by_day,
        "rates": rates,
        "refreshed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
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
    """Stop orch + batch (and xvfb wrappers)."""
    killed = []
    out = _ps_lines()
    pids = set()
    for line in out.splitlines():
        if any(x in line for x in ("run_until_100.py", "run_batch_headless.py")) and "grep" not in line:
            try:
                pids.add(int(line.split(None, 1)[0]))
            except Exception:
                pass
        if "xvfb-run" in line and "run_batch_headless" in line:
            try:
                pids.add(int(line.split(None, 1)[0]))
            except Exception:
                pass
    for pf in (ORCH_PID, BATCH_PID):
        if pf.exists():
            try:
                pids.add(int(pf.read_text().strip()))
            except Exception:
                pass
    for pid in list(pids):
        for sig in (signal.SIGTERM,):
            try:
                os.killpg(pid, sig)
                killed.append(pid)
            except Exception:
                try:
                    os.kill(pid, sig)
                    killed.append(pid)
                except Exception:
                    pass
    time.sleep(1.5)
    for pid in list(pids):
        try:
            os.kill(pid, 0)
            try:
                os.killpg(pid, signal.SIGKILL)
            except Exception:
                try:
                    os.kill(pid, signal.SIGKILL)
                except Exception:
                    pass
        except Exception:
            pass
    return {"ok": True, "killed": sorted(set(killed))}


def start_orch():
    proc = process_running()
    if proc.get("orch_running") or proc.get("batch_running"):
        return {"ok": False, "error": "already running", "process": proc}
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
    LOG_DIR.mkdir(exist_ok=True)
    stdout = open(LOG_DIR / "orch100-stdout.log", "a", encoding="utf-8")
    stdout.write(
        f"\n--- monitor start {time.strftime('%Y-%m-%dT%H:%M:%SZ')} "
        f"workers={c.get('workers')} cpa={now} target={c.get('target_cpa')} need={need} ---\n"
    )
    stdout.flush()
    p = subprocess.Popen(
        [str(VENV_PY), "-u", str(ORCH_SCRIPT)],
        cwd=str(ROOT),
        stdout=stdout,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    ORCH_PID.write_text(str(p.pid))
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



def start_batch_only():
    proc = process_running()
    if proc.get("batch_running") or proc.get("orch_running"):
        return {"ok": False, "error": "already running", "process": proc}
    c = load_control()
    workers = int(c.get("workers") or 3)
    count = int(c.get("batch_count") or 40)
    logname = LOG_DIR / f"batch-orch-{time.strftime('%Y%m%d-%H%M%S')}-n{count}.log"
    fout = open(logname, "w", encoding="utf-8")
    p = subprocess.Popen(
        [
            "xvfb-run", "-a", "-s", "-screen 0 1920x1080x24",
            str(VENV_PY), "-u", str(ROOT / "run_batch_headless.py"),
            str(count), str(workers),
        ],
        cwd=str(ROOT),
        stdout=fout,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    BATCH_PID.write_text(str(p.pid))
    return {
        "ok": True,
        "pid": p.pid,
        "mode": "batch",
        "workers": workers,
        "count": count,
        "log": logname.name,
    }


def snapshot():
    log = discover_log()
    parsed = parse_log(log) if log else {"error": "no log"}
    base = read_base()
    cpa = cpa_count()
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
    return {
        "ts": time.time(),
        "ts_human": time.strftime("%Y-%m-%d %H:%M:%S"),
        "base_cpa": base,
        "cpa": cpa,
        "cpa_delta": cpa - base if base else None,
        "process": proc,
        "control": control,
        "target": target,
        "done_attempts": done,
        "progress_pct": pct,
        "success_rate": round(100.0 * ok / done, 1) if done else None,
        "rate_per_min": rate_per_min,
        "eta": eta,
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
<title>Grok 注册监控</title>
<style>
  :root {
    --bg: #0b0f14; --card: #121a22; --border: #1e2a36;
    --text: #e6edf3; --muted: #8b9bb0; --ok: #3dd68c; --fail: #f87171;
    --warn: #fbbf24; --accent: #38bdf8; --bar: #1e3a4c; --btn: #1a2836;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
    background: radial-gradient(1200px 600px at 10% -10%, #132033 0%, var(--bg) 55%);
    color: var(--text); min-height: 100vh;
  }
  header {
    display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between;
    gap: 12px; padding: 16px 22px; border-bottom: 1px solid var(--border);
    background: rgba(10,14,20,.8); backdrop-filter: blur(8px);
    position: sticky; top: 0; z-index: 10;
  }
  h1 { font-size: 18px; margin: 0; font-weight: 650; }
  .badge {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 600;
    border: 1px solid var(--border); background: var(--card);
  }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--muted); }
  .dot.on { background: var(--ok); box-shadow: 0 0 10px var(--ok); }
  .dot.off { background: var(--fail); }
  main { padding: 18px 22px 40px; max-width: 1320px; margin: 0 auto; }
  .grid { display: grid; grid-template-columns: repeat(6, 1fr); gap: 12px; }
  @media (max-width: 1000px) { .grid { grid-template-columns: repeat(3, 1fr); } }
  @media (max-width: 560px) { .grid { grid-template-columns: repeat(2, 1fr); } }
  .card {
    background: linear-gradient(180deg, #15202b, var(--card));
    border: 1px solid var(--border); border-radius: 14px; padding: 14px;
  }
  .card .label { color: var(--muted); font-size: 12px; margin-bottom: 6px; }
  .card .value { font-size: 26px; font-weight: 700; font-variant-numeric: tabular-nums; }
  .card .sub { color: var(--muted); font-size: 12px; margin-top: 4px; }
  .ok { color: var(--ok); } .fail { color: var(--fail); } .warn { color: var(--warn); } .accent { color: var(--accent); }
  .panel { margin-top: 14px; }
  .panel h2 { font-size: 13px; color: var(--muted); font-weight: 600; margin: 0 0 10px; text-transform: uppercase; letter-spacing: .06em; }
  .bar-wrap { height: 14px; background: var(--bar); border-radius: 999px; overflow: hidden; border: 1px solid var(--border); }
  .bar { height: 100%; background: linear-gradient(90deg, #0ea5e9, #3dd68c); width: 0%; transition: width .4s ease; }
  .two { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .three { display: grid; grid-template-columns: 1.1fr 1fr 1fr; gap: 12px; }
  @media (max-width: 1000px) { .two, .three { grid-template-columns: 1fr; } }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { color: var(--muted); font-weight: 600; font-size: 12px; }
  tr:hover td { background: rgba(255,255,255,.02); }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
  .tail {
    background: #0a1017; border: 1px solid var(--border); border-radius: 12px;
    padding: 12px; max-height: 280px; overflow: auto; font-size: 11.5px; line-height: 1.45;
    color: #9fb0c3; white-space: pre-wrap; word-break: break-all;
  }
  .chips { display: flex; flex-wrap: wrap; gap: 8px; }
  .chip {
    border: 1px solid var(--border); background: #0f1720; border-radius: 10px;
    padding: 8px 10px; min-width: 90px;
  }
  .chip b { display: block; font-size: 18px; }
  .chip span { color: var(--muted); font-size: 11px; }
  footer { color: var(--muted); font-size: 12px; margin-top: 16px; }
  .ctrl-row { display: flex; flex-wrap: wrap; gap: 10px; align-items: flex-end; }
  .field { display: flex; flex-direction: column; gap: 4px; }
  .field label { font-size: 11px; color: var(--muted); }
  input[type=number], select {
    background: #0a1017; border: 1px solid var(--border); color: var(--text);
    border-radius: 8px; padding: 8px 10px; font-size: 13px; min-width: 90px;
  }
  button {
    border: 1px solid var(--border); background: var(--btn); color: var(--text);
    border-radius: 8px; padding: 8px 14px; font-size: 13px; font-weight: 600;
    cursor: pointer; transition: .15s background;
  }
  button:hover { background: #243446; }
  button.primary { background: #0d3b2e; border-color: #1a5c45; color: var(--ok); }
  button.primary:hover { background: #114a39; }
  button.danger { background: #3b1515; border-color: #6b2222; color: var(--fail); }
  button.danger:hover { background: #4a1a1a; }
  button:disabled { opacity: .45; cursor: not-allowed; }
  .bl-list {
    max-height: 220px; overflow: auto; border: 1px solid var(--border);
    border-radius: 10px; background: #0a1017;
  }
  .bl-list table { font-size: 12px; }
  .msg { font-size: 12px; color: var(--muted); min-height: 18px; margin-top: 8px; }
  .msg.err { color: var(--fail); } .msg.ok { color: var(--ok); }
  .section-head { display: flex; justify-content: space-between; align-items: center; gap: 8px; margin-bottom: 10px; }
  .section-head h2 { margin: 0; }
</style>
</head>
<body>
<header>
  <div>
    <h1>Grok Register Live</h1>
    <div class="mono" id="logname" style="color:var(--muted);font-size:12px;margin-top:4px">—</div>
  </div>
  <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
    <span class="badge"><span class="dot" id="run-dot"></span><span id="run-label">…</span></span>
    <span class="badge mono" id="clock">—</span>
    <span class="badge">auto 2s</span>
  </div>
</header>
<main>
  <!-- Control panel -->
  <div class="card panel" style="margin-top:0">
    <div class="section-head"><h2>控制</h2><span class="mono" id="ctrl-status" style="color:var(--muted);font-size:12px"></span></div>
    <div class="ctrl-row">
      <div class="field" style="min-width:220px;flex:1"><label>面板 Token <span style="color:var(--muted);font-weight:400">(localStorage)</span></label>
        <input id="monitor-token" type="password" autocomplete="off" placeholder="MONITOR_TOKEN" style="width:100%" onchange="getToken()" onblur="getToken()"/>
      </div>
      <div class="field"><label>模式</label>
        <select id="mode">
          <option value="orch">Orch (run_until_100)</option>
          <option value="batch">单批 batch</option>
        </select>
      </div>
      <div class="field"><label>并发 workers</label>
        <input type="number" id="workers-input" min="1" max="24" value="3"/>
      </div>
      <div class="field"><label>batch 数量</label>
        <input type="number" id="batch_count" min="1" max="200" value="40"/>
      </div>
      <div class="field"><label>再跑 N 个 (CPA)</label>
        <input type="number" id="add_count" min="1" max="500" value="40" title="每次启动从当前 CPA 再注册 N 个"/>
      </div>
      <div class="field"><label>风控满 N 暂停</label>
        <input type="number" id="risk_pause" min="1" max="50" value="10"/>
      </div>
      <button class="primary" id="btn-start" onclick="doStart()">启动</button>
      <button class="danger" id="btn-stop" onclick="doStop()">停止</button>
      <button onclick="saveCtrl()">保存设置</button>
    </div>
    <div class="msg" id="ctrl-msg"></div>
  </div>

  <div class="grid" id="kpis" style="margin-top:14px"></div>

  <div class="card panel">
    <div class="section-head">
      <h2 style="margin:0">时段成功率</h2>
      <span class="mono" id="rates-updated" style="color:var(--muted);font-size:12px">来自 register_results.jsonl</span>
    </div>
    <div class="grid" id="rate-kpis" style="grid-template-columns:repeat(3,1fr)"></div>
    <div style="margin-top:10px;overflow:auto">
      <table>
        <thead><tr><th>窗口</th><th>成功</th><th>失败</th><th>风控</th><th>合计</th><th>成功率</th></tr></thead>
        <tbody id="rate-body"></tbody>
      </table>
    </div>
  </div>

  <div class="card panel">
    <div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:8px">
      <h2 style="margin:0">进度</h2>
      <div class="mono" id="prog-text">—</div>
    </div>
    <div class="bar-wrap"><div class="bar" id="bar"></div></div>
    <div id="prog-sub" style="margin-top:8px;color:var(--muted);font-size:12px"></div>
  </div>

  <div class="three panel">
    <!-- Success stats -->
    <div class="card">
      <div class="section-head">
        <h2>成功统计</h2>
        <button onclick="refreshStats()">刷新统计</button>
      </div>
      <div class="chips" id="stats-chips"></div>
      <div class="msg" id="stats-msg"></div>
      <table style="margin-top:10px"><thead><tr><th>日期</th><th>ok</th><th>risk</th><th>fail</th></tr></thead>
      <tbody id="stats-day"></tbody></table>
    </div>
    <!-- Blacklist -->
    <div class="card">
      <div class="section-head">
        <h2>黑名单</h2>
        <button onclick="refreshBlacklist()">刷新黑名单</button>
          <button class="danger" onclick="resetBlacklist('baseline')">重置黑名单</button>
      </div>
      <div class="chips" id="bl-kpis"></div>
      <div class="msg" id="bl-msg"></div>
      <div class="bl-list" style="margin-top:10px">
        <table><thead><tr><th>ASN</th><th>备注</th></tr></thead><tbody id="bl-body"></tbody></table>
      </div>
    </div>
    <!-- Blacklist update errors -->
    <div class="card">
      <div class="section-head"><h2>黑名单更新</h2></div>
      <div class="chips" id="bl-err-chips"></div>
      <table style="margin-top:10px"><thead><tr><th>新增 ASN</th><th>来源</th></tr></thead>
      <tbody id="bl-added"></tbody></table>
    </div>
  </div>

  <div class="two panel">
    <div class="card"><h2>Worker 成功 / 失败</h2><div class="chips" id="workers-stats"></div></div>
    <div class="card"><h2>失败分类</h2><div class="chips" id="fails"></div></div>
  </div>
  <div class="two panel">
    <div class="card">
      <h2>最近成功</h2>
      <table><thead><tr><th>时间</th><th>W</th><th>邮箱</th></tr></thead><tbody id="ok-body"></tbody></table>
    </div>
    <div class="card">
      <h2>最近失败</h2>
      <table><thead><tr><th>时间</th><th>W</th><th>类型</th><th>摘要</th></tr></thead><tbody id="fail-body"></tbody></table>
    </div>
  </div>
  <div class="card panel"><h2>日志尾部</h2><div class="tail mono" id="tail"></div></div>
  <footer id="footer"></footer>
</main>
<script>
let last = null;
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
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
  opts = opts || {};
  const headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
  const tok = getToken();
  if (tok) headers["Authorization"] = "Bearer " + tok;
  const r = await fetch(path, Object.assign({}, opts, { headers }));
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || r.statusText || "request failed");
  if (j && j.ok === false) throw new Error(j.error || j.message || "request failed");
  return j;
}
async function refresh() {
  try {
    const d = await api("/api/status?_=" + Date.now());
    last = d;
    render(d);
  } catch (e) {
    document.getElementById("clock").textContent = "fetch error";
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
    setMsg("ctrl-msg", "设置已保存 workers=" + j.workers, "ok");
  } catch (e) { setMsg("ctrl-msg", String(e.message || e), "err"); }
}
async function doStart() {
  document.getElementById("btn-start").disabled = true;
  setMsg("ctrl-msg", "正在启动…", "");
  try {
    await api("/api/control", { method: "POST", body: JSON.stringify(controlBody()) });
    const j = await api("/api/start", { method: "POST", body: JSON.stringify(controlBody()) });
    if (j.ok === false) throw new Error(j.error || "start failed");
    const msg = j.message || ("已启动 pid=" + (j.pid || "?") + " mode=" + (j.mode || ""));
    setMsg("ctrl-msg", msg + (j.need != null ? " · need=" + j.need : ""), "ok");
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
    setMsg("bl-msg", "已刷新 · " + (j.mtime_human || "") + " · " + (j.count || 0) + " ASN", "ok");
  } catch (e) { setMsg("bl-msg", String(e.message || e), "err"); }
}
async function refreshStats() {
  try {
    const j = await api("/api/stats?_=" + Date.now());
    renderStats(j);
    setMsg("stats-msg", "统计已刷新 " + (j.refreshed_at || ""), "ok");
  } catch (e) { setMsg("stats-msg", String(e.message || e), "err"); }
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
    const val = r == null ? "—" : (r + "%");
    const sub = (b.ok ?? 0) + " ok / " + (b.total ?? 0) + " 次";
    return `<div class="card"><div class="label">${esc(labels[k] || k)}</div><div class="value ${rateCls(r)}">${esc(val)}</div><div class="sub">${esc(sub)}</div></div>`;
  });
  const el = document.getElementById("rate-kpis");
  if (el) el.innerHTML = cards.join("");
  const body = document.getElementById("rate-body");
  if (body) {
    body.innerHTML = order.map(k => {
      const b = rates[k] || {};
      const r = b.success_rate;
      return `<tr>
        <td>${esc(labels[k] || k)}</td>
        <td class="ok">${b.ok ?? 0}</td>
        <td class="fail">${b.fail ?? 0}</td>
        <td class="warn">${b.risk ?? 0}</td>
        <td>${b.total ?? 0}</td>
        <td class="${rateCls(r)}"><b>${r == null ? "—" : (r + "%")}</b></td>
      </tr>`;
    }).join("");
  }
}

function renderStats(s) {
  s = s || {};
  if (s.rates) renderRates(s.rates);
  document.getElementById("stats-chips").innerHTML = [
    ["CPA", s.cpa ?? "—", "accent"],
    ["CPA Δ", s.cpa_delta ?? "—", "ok"],
    ["本批成功", s.batch_ok ?? 0, "ok"],
    ["本批失败", s.batch_fail ?? 0, "fail"],
    ["jsonl ok", s.jsonl_ok ?? 0, "ok"],
    ["jsonl risk", s.jsonl_risk ?? 0, "warn"],
  ].map(([l,v,c]) => `<div class="chip"><span>${esc(l)}</span><b class="${c}">${esc(v)}</b></div>`).join("");
  const days = Object.entries(s.by_day || {}).sort((a,b) => b[0].localeCompare(a[0])).slice(0, 10);
  document.getElementById("stats-day").innerHTML = days.length ? days.map(([d, v]) =>
    `<tr><td class="mono">${esc(d)}</td><td class="ok">${v.ok||0}</td><td class="warn">${v.risk||0}</td><td class="fail">${v.fail||0}</td></tr>`
  ).join("") : '<tr><td colspan="4" style="color:var(--muted)">无 jsonl 数据</td></tr>';
}
function render(d) {
  document.getElementById("clock").textContent = d.ts_human || "—";
  document.getElementById("logname").textContent =
    (d.log_name || d.log || "—") + (d.process && d.process.etime ? " · etime " + d.process.etime : "");
  const on = !!(d.process && d.process.running);
  document.getElementById("run-dot").className = "dot " + (on ? "on" : "off");
  let runLabel = "STOPPED";
  if (d.process && d.process.orch_running) runLabel = "ORCH pid " + d.process.orch_pid;
  else if (d.process && d.process.batch_running) runLabel = "BATCH pid " + d.process.batch_pid;
  else if (d.ended) runLabel = "FINISHED";
  document.getElementById("run-label").textContent = runLabel;
  document.getElementById("ctrl-status").textContent = on ? "运行中" : "空闲";
  document.getElementById("btn-start").disabled = on;
  document.getElementById("btn-stop").disabled = !on;
  fillControl(d);

  const kpis = [
    ["成功", d.ok ?? 0, "ok", "目标 " + (d.target ?? "—")],
    ["失败", d.fail ?? 0, "fail", d.success_rate != null ? "成功率 " + d.success_rate + "%" : "—"],
    ["CPA Δ", d.cpa_delta ?? "—", "accent", "现 " + (d.cpa ?? "—") + " / 基线 " + (d.base_cpa ?? "—")],
    ["botFlag 0/1", (d.bot0 ?? 0) + "/" + (d.bot1 ?? 0), "warn", "注册风控采样"],
    ["黑名单 ASN", (d.blacklist && d.blacklist.count) ?? "—", "accent", "更新错误 " + ((d.blacklist_update && d.blacklist_update.error_count) ?? 0)],
    ["ETA", d.eta || "—", "", "并发 " + (d.workers ?? "—") + " · " + (d.rate_per_min != null ? d.rate_per_min + "/min" : "")],
    ["1h 成功率", (d.rates && d.rates["1h"] && d.rates["1h"].success_rate != null) ? (d.rates["1h"].success_rate + "%") : "—", rateCls(d.rates && d.rates["1h"] && d.rates["1h"].success_rate), d.rates && d.rates["1h"] ? ((d.rates["1h"].ok||0) + "/" + (d.rates["1h"].total||0)) : "—"],
    ["3h 成功率", (d.rates && d.rates["3h"] && d.rates["3h"].success_rate != null) ? (d.rates["3h"].success_rate + "%") : "—", rateCls(d.rates && d.rates["3h"] && d.rates["3h"].success_rate), d.rates && d.rates["3h"] ? ((d.rates["3h"].ok||0) + "/" + (d.rates["3h"].total||0)) : "—"],
    ["12h 成功率", (d.rates && d.rates["12h"] && d.rates["12h"].success_rate != null) ? (d.rates["12h"].success_rate + "%") : "—", rateCls(d.rates && d.rates["12h"] && d.rates["12h"].success_rate), d.rates && d.rates["12h"] ? ((d.rates["12h"].ok||0) + "/" + (d.rates["12h"].total||0)) : "—"],
  ];
  document.getElementById("kpis").innerHTML = kpis.map(([label, val, cls, sub]) =>
    `<div class="card"><div class="label">${esc(label)}</div><div class="value ${cls}">${esc(val)}</div><div class="sub">${esc(sub)}</div></div>`
  ).join("");
  renderRates(d.rates || {});
  const ru = document.getElementById("rates-updated");
  if (ru && d.ts_human) ru.textContent = "jsonl 窗口统计 · " + d.ts_human;

  const pct = Math.min(100, Number(d.progress_pct) || 0);
  document.getElementById("bar").style.width = pct + "%";
  document.getElementById("prog-text").textContent = (d.ok ?? 0) + " / " + (d.target ?? 0) + " (" + pct + "%)";
  document.getElementById("prog-sub").textContent =
    "尝试 " + (d.done_attempts ?? 0) + " · " + (on ? "进程运行中" : "未运行")
    + (d.ended ? " · 结束: 成功" + d.ended.success + " 失败" + d.ended.fail : "");

  renderBlacklist(d.blacklist, d.blacklist_update);
  // light stats from snapshot
  renderStats({
    cpa: d.cpa, cpa_delta: d.cpa_delta, base_cpa: d.base_cpa,
    batch_ok: d.ok, batch_fail: d.fail,
    jsonl_ok: "—", jsonl_risk: "—",
    by_day: {}, refreshed_at: d.ts_human,
  });

  const wset = new Set([...(Object.keys(d.worker_ok || {})), ...(Object.keys(d.worker_fail || {}))]);
  const ws = [...wset].sort((a, b) => parseInt(a.slice(1)) - parseInt(b.slice(1)));
  document.getElementById("workers-stats").innerHTML = ws.length ? ws.map(w =>
    `<div class="chip"><span>${esc(w)}</span><b><span class="ok">${d.worker_ok && d.worker_ok[w] || 0}</span> <span style="color:var(--muted)">/</span> <span class="fail">${d.worker_fail && d.worker_fail[w] || 0}</span></b></div>`
  ).join("") : '<span style="color:var(--muted)">暂无</span>';
  const fk = Object.entries(d.fail_kinds || {}).sort((a, b) => b[1] - a[1]);
  document.getElementById("fails").innerHTML = fk.length ? fk.map(([k, v]) =>
    `<div class="chip"><span>${esc(k)}</span><b class="fail">${v}</b></div>`
  ).join("") : '<span style="color:var(--muted)">暂无失败</span>';
  document.getElementById("ok-body").innerHTML = (d.recent_ok || []).map(r =>
    `<tr><td class="mono">${esc(r.t)}</td><td>${esc(r.w)}</td><td class="mono">${esc(r.email)}</td></tr>`
  ).join("") || '<tr><td colspan="3" style="color:var(--muted)">—</td></tr>';
  document.getElementById("fail-body").innerHTML = (d.recent_fail || []).map(r =>
    `<tr><td class="mono">${esc(r.t)}</td><td>${esc(r.w)}</td><td>${esc(r.kind)}</td><td class="mono">${esc(r.msg)}</td></tr>`
  ).join("") || '<tr><td colspan="4" style="color:var(--muted)">—</td></tr>';
  document.getElementById("tail").textContent = (d.tail || []).join("\n");
  document.getElementById("footer").textContent =
    "bind " + location.host + " · log " + (d.log || "") + " · poll 2s · "
    + (d.log_size ? (d.log_size / 1024).toFixed(0) + " KB" : "")
    + " · blacklist " + ((d.blacklist && d.blacklist.count) || 0) + " ASN";
}
loadTokenField();
refresh();
setInterval(refresh, 2000);
// full stats once on load
refreshStats();
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
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
        # No wildcard CORS — panel is same-origin. Optional explicit origin via env.
        allow = str(os.environ.get("MONITOR_CORS_ORIGIN", "") or "").strip()
        if allow and allow != "*":
            self.send_header("Access-Control-Allow-Origin", allow)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
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

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8"), "application/json; charset=utf-8")

    def _read_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0:
            return {}
        raw = self.rfile.read(n)
        try:
            return json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            return {}

    def do_OPTIONS(self):
        self._send(204, b"", "text/plain")

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            self._send(200, HTML.encode("utf-8"), "text/html; charset=utf-8")
            return
        if u.path == "/api/status":
            try:
                self._json(200, snapshot())
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        if u.path == "/api/health":
            self._json(200, {"ok": True})
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
        self._send(404, b"not found", "text/plain")

    def do_POST(self):
        u = urlparse(self.path)
        body = self._read_body()
        # All POST endpoints require MONITOR_TOKEN
        if not self._require_write():
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


def main():
    host = BIND_HOST
    ThreadingHTTPServer.allow_reuse_address = True
    try:
        httpd = ThreadingHTTPServer((host, BIND_PORT), Handler)
    except OSError as e1:
        raise SystemExit(
            f"cannot bind {BIND_HOST}:{BIND_PORT} ({e1}); "
            "set MONITOR_HOST/MONITOR_PORT (no 0.0.0.0 fallback)"
        )
    tok = expected_token()
    if not tok:
        print(
            "[monitor] WARNING: MONITOR_TOKEN unset — write APIs (start/stop/control) will return 401",
            flush=True,
        )
    print(f"[monitor] http://{host}:{BIND_PORT}/  (bound {host}:{BIND_PORT})", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
