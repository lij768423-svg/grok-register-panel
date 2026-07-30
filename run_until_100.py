#!/usr/bin/env python3
"""Orch: run batches until CPA target. Workers/risk pause from monitor_control.json."""
from __future__ import annotations

import importlib.util
import json
import os
import re
import signal
import subprocess
import time
import urllib.request
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
# 加载根目录 __init__.py → 自动读 .env（须在读取 os.environ 之前）
_spec = importlib.util.spec_from_file_location("_project_init", ROOT / "__init__.py")
if _spec and _spec.loader:
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)

AUTHS = Path(os.environ.get("CPA_AUTH_DIR", str(ROOT / "cpa_auth")))
BS = ROOT / "browser_session.py"
LOG_DIR = ROOT / "log"
RESULTS = LOG_DIR / "register_results.jsonl"
ORCH_LOG = LOG_DIR / f"orch100-fixed-{time.strftime('%Y%m%d-%H%M%S')}.log"
WORKERS = 3
BASE0 = int(os.environ.get("ORCH_BASE_CPA", "0") or 0)
TARGET_CPA = BASE0 + int(os.environ.get("ORCH_ADD_COUNT", "100") or 100)
RISK_PAUSE = 10
MAX_ROUNDS = 60
CONTROL_FILE = LOG_DIR / "monitor_control.json"


def load_control() -> dict:
    try:
        if CONTROL_FILE.exists():
            return json.loads(CONTROL_FILE.read_text() or "{}")
    except Exception:
        pass
    return {}


def apply_control() -> None:
    global WORKERS, RISK_PAUSE, TARGET_CPA, BASE0
    c = load_control()
    if c.get("workers"):
        try:
            WORKERS = max(1, min(24, int(c["workers"])))
        except Exception:
            pass
    if c.get("risk_pause"):
        try:
            RISK_PAUSE = max(1, int(c["risk_pause"]))
        except Exception:
            pass
    # 再跑 N 个：以当前 CPA 为基线
    add_count = c.get("add_count")
    if add_count is not None and str(add_count).strip() != "":
        try:
            n = max(1, int(add_count))
            now = len(list(AUTHS.glob("xai-*.json")))
            BASE0 = now
            TARGET_CPA = now + n
            return
        except Exception:
            pass
    if c.get("target_cpa"):
        try:
            TARGET_CPA = int(c["target_cpa"])
        except Exception:
            pass
    if c.get("base_cpa") is not None:
        try:
            BASE0 = int(c["base_cpa"])
        except Exception:
            pass

os.chdir(ROOT)
LOG_DIR.mkdir(exist_ok=True)


def log(msg: str) -> None:
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    with open(ORCH_LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def cpa_count() -> int:
    return len(list(AUTHS.glob("xai-*.json")))


def kill_batch() -> None:
    """Kill run_batch_headless and its process group (xvfb-run)."""
    out = subprocess.check_output(["ps", "-ef"], text=True)
    pids = set()
    for line in out.splitlines():
        if "run_batch_headless.py" in line and "awk" not in line:
            pids.add(int(line.split()[1]))
        if "xvfb-run" in line and "run_batch_headless" in line:
            pids.add(int(line.split()[1]))
    # also pid file
    pf = LOG_DIR / "batch100.pid"
    if pf.exists():
        try:
            pids.add(int(pf.read_text().strip()))
        except Exception:
            pass
    for pid in list(pids):
        try:
            # kill whole group if started with start_new_session
            os.killpg(pid, signal.SIGTERM)
        except Exception:
            try:
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass
        try:
            kids = subprocess.check_output(["ps", "--ppid", str(pid), "-o", "pid="], text=True).split()
            for k in kids:
                try:
                    os.kill(int(k), signal.SIGTERM)
                except Exception:
                    pass
        except Exception:
            pass
    time.sleep(2)
    for pid in list(pids):
        try:
            os.killpg(pid, signal.SIGKILL)
        except Exception:
            try:
                os.kill(pid, signal.SIGKILL)
            except Exception:
                pass
    # reap zombies: kill leftover python run_batch
    out = subprocess.check_output(["ps", "-ef"], text=True)
    for line in out.splitlines():
        if "run_batch_headless.py" in line and "awk" not in line:
            try:
                os.kill(int(line.split()[1]), signal.SIGKILL)
            except Exception:
                pass


def start_batch(count: int):
    logname = LOG_DIR / f"batch-orch-{time.strftime('%Y%m%d-%H%M%S')}-n{count}.log"
    fout = open(logname, "w")
    proc = subprocess.Popen(
        [
            "xvfb-run",
            "-a",
            "-s",
            "-screen 0 1920x1080x24",
            str(ROOT / ".venv/bin/python"),
            "-u",
            str(ROOT / "run_batch_headless.py"),
            str(count),
            str(WORKERS),
        ],
        cwd=str(ROOT),
        stdout=fout,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    (LOG_DIR / "batch100.pid").write_text(str(proc.pid))
    log(f"started pid={proc.pid} count={count} workers={WORKERS} log={logname.name}")
    return proc.pid, logname


def read_blocklist_asns() -> set:
    text = BS.read_text()
    nums: set = set()
    m = re.search(r"_BLOCKED_ASN_NUMS\s*=\s*\{([^}]*)\}", text)
    if m:
        nums |= {int(x) for x in re.findall(r"\d+", m.group(1))}
    block = re.search(r"_BLOCKED_ASN_SUBSTR\s*=\s*\((.*?)\)", text, re.S)
    if block:
        nums |= {int(x) for x in re.findall(r"AS(\d+)", block.group(1))}
    return nums or {7922, 5650}


def add_asn_to_blocklist(asn: int, isp_hint: str = "") -> bool:
    text = BS.read_text()
    nums = read_blocklist_asns()
    if asn in nums:
        log(f"ASN{asn} already blocked")
        return False
    nums.add(int(asn))
    new_nums = "_BLOCKED_ASN_NUMS = {" + ", ".join(str(n) for n in sorted(nums)) + "}"
    if "_BLOCKED_ASN_NUMS" in text:
        text = re.sub(r"_BLOCKED_ASN_NUMS\s*=\s*\{[^}]*\}", new_nums, text, count=1)
    else:
        text = text.replace(
            "_BLOCKED_ASN_SUBSTR = (",
            new_nums + "\n_BLOCKED_ASN_SUBSTR = (",
            1,
        )
    if f'"AS{asn}"' not in text:
        text = text.replace(
            "_BLOCKED_ASN_SUBSTR = (",
            f'_BLOCKED_ASN_SUBSTR = (\n    "AS{asn}",  # auto {isp_hint[:50]}\n',
            1,
        )
    BS.write_text(text)
    log(f"ADDED blacklist AS{asn} ({isp_hint})")
    return True


def lookup_asn(ip: str, timeout: float = 5.0) -> dict:
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        data = json.loads(opener.open(f"http://ipwho.is/{ip}", timeout=timeout).read())
        conn = data.get("connection") or {}
        return {
            "asn": conn.get("asn"),
            "isp": conn.get("isp") or "",
            "org": conn.get("org") or "",
            "city": data.get("city") or "",
        }
    except Exception as e:
        return {"error": str(e)}


def count_risk(logpath: Path) -> int:
    """只计注册风控拒绝次数（SSO超时/其它失败不计）。

    优先 [结果] status=risk（每号一行）；否则 失败 [注册风控]。
    """
    if not logpath.exists():
        return 0
    text = logpath.read_text(errors="replace")
    n = len(re.findall(r"\[结果\] status=risk\b", text))
    if n > 0:
        return n
    return len(re.findall(r"\[-\] 失败 \[注册风控\]", text))


def count_ok(logpath: Path) -> int:
    if not logpath.exists():
        return 0
    return len(re.findall(r"\[\+\] 注册成功:", logpath.read_text(errors="replace")))


def analyze_risks_and_expand(logpath: Path) -> list:
    """Add ASN to blacklist if risk-only and enough samples. Bounded time."""
    added = []
    t0 = time.time()
    blocked = read_blocklist_asns()
    risk_ips: list[str] = []
    ok_ips: list[str] = []

    if logpath.exists():
        text = logpath.read_text(errors="replace")
        worker_ip: dict[str, str] = {}
        for line in text.splitlines():
            m = re.match(r"\[\d+:\d+:\d+\] \[(W\d+)\] (.*)", line)
            if not m:
                continue
            w, msg = m.group(1), m.group(2)
            im = re.search(r"出口IP=([\d.]+)", msg)
            if im:
                worker_ip[w] = im.group(1)
            # only count unique risk via result line or failure line once
            if "[结果] status=risk" in msg:
                im2 = re.search(r"ip=([\d.]+)", msg)
                if im2:
                    risk_ips.append(im2.group(1))
                elif worker_ip.get(w):
                    risk_ips.append(worker_ip[w])
            elif "[-] 失败 [注册风控]" in msg and worker_ip.get(w):
                # only if no result line captured this ip already this second - still may dup
                risk_ips.append(worker_ip[w])
            if "[结果] status=ok" in msg:
                im2 = re.search(r"ip=([\d.]+)", msg)
                if im2:
                    ok_ips.append(im2.group(1))

    # dedupe preserve order
    def uniq(seq):
        seen = set()
        out = []
        for x in seq:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    risk_ips = uniq(risk_ips)
    ok_ips = uniq(ok_ips)

    risk_as: Counter = Counter()
    ok_as: Counter = Counter()
    meta_by_as = {}

    # cap lookups
    for ip in risk_ips[:20]:
        if time.time() - t0 > 45:
            log("analyze timeout, stop ASN lookups")
            break
        meta = lookup_asn(ip, timeout=5)
        a = meta.get("asn")
        if a is None:
            log(f"  lookup fail ip={ip} {meta.get('error')}")
            continue
        risk_as[a] += 1
        meta_by_as[a] = meta
    for ip in ok_ips[:30]:
        if time.time() - t0 > 55:
            break
        meta = lookup_asn(ip, timeout=5)
        a = meta.get("asn")
        if a is None:
            continue
        ok_as[a] += 1

    log(f"analyze risk_ips={risk_ips} risk_as={dict(risk_as)} ok_as={dict(ok_as)}")
    for asn, nbad in risk_as.most_common():
        if asn in blocked:
            continue
        nok = ok_as.get(asn, 0)
        meta = meta_by_as.get(asn) or {}
        isp = meta.get("isp") or meta.get("org") or ""
        # only-bad with >=2 unique risk IPs, or >=3 risk hits
        if nok == 0 and nbad >= 2:
            if add_asn_to_blocklist(int(asn), isp):
                added.append(asn)
                blocked.add(asn)
        elif nok == 0 and nbad >= 1 and len(risk_ips) >= 5:
            # after full pause at 5 risks, allow single-ASN only-bad add
            if add_asn_to_blocklist(int(asn), isp):
                added.append(asn)
                blocked.add(asn)
    log(f"analyze done in {time.time()-t0:.1f}s added={added}")
    return added


def batch_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        # check any run_batch still
        return "run_batch_headless.py" in subprocess.check_output(["ps", "-ef"], text=True)
    # defunct parent still "alive" but child gone
    try:
        # if process is zombie, treat as dead
        with open(f"/proc/{pid}/stat") as f:
            stat = f.read()
        if " Z " in f" {stat} " or " Z\n" in stat or ") Z " in stat:
            return "run_batch_headless.py" in subprocess.check_output(["ps", "-ef"], text=True)
    except Exception:
        pass
    return "run_batch_headless.py" in subprocess.check_output(["ps", "-ef"], text=True)


def main():
    apply_control()
    kill_batch()
    log(f"ORCH fixed start cpa_now={cpa_count()} base0={BASE0} target={TARGET_CPA} need={TARGET_CPA - cpa_count()}")
    need0 = TARGET_CPA - cpa_count()
    if need0 <= 0:
        log(f"TARGET already met (need={need0}). Set monitor add_count / target_cpa then restart.")
        log(f"ORCH DONE cpa={cpa_count()} delta={cpa_count() - BASE0} target={TARGET_CPA} rounds=0")
        log(f"final blocklist={sorted(read_blocklist_asns())}")
        return

    log(f"rules: workers={WORKERS} pause_on_risk_only={RISK_PAUSE} SSO ignored block={sorted(read_blocklist_asns())}")
    
    round_i = 0
    while cpa_count() < TARGET_CPA and round_i < MAX_ROUNDS:
        round_i += 1
        need = TARGET_CPA - cpa_count()
        batch_n = min(max(need + 8, 15), 40)
        log(f"=== ROUND {round_i} need={need} batch_n={batch_n} cpa={cpa_count()} block={sorted(read_blocklist_asns())} ===")
        try:
            pid, logpath = start_batch(batch_n)
        except Exception as e:
            log(f"start_batch failed: {e}")
            time.sleep(5)
            continue
        t0 = time.time()
        while True:
            time.sleep(15)
            try:
                alive = batch_alive(pid)
            except Exception:
                alive = False
            risks = count_risk(logpath)
            oks = count_ok(logpath)
            delta = cpa_count() - BASE0
            log(f"  mon ok={oks} risk={risks} cpa_delta={delta}/100 alive={alive}")
            if cpa_count() >= TARGET_CPA:
                log("TARGET reached")
                kill_batch()
                break
            if risks >= RISK_PAUSE:
                log(f"  HIT {RISK_PAUSE} 注册风控 rejects (risk={risks}), pause+blacklist")
                kill_batch()
                try:
                    added = analyze_risks_and_expand(logpath)
                    log(f"  added={added} block={sorted(read_blocklist_asns())}")
                except Exception as e:
                    log(f"  analyze error (continue anyway): {e}")
                break
            if not alive:
                log("  batch exited")
                try:
                    analyze_risks_and_expand(logpath)
                except Exception as e:
                    log(f"  analyze error: {e}")
                break
            if time.time() - t0 > 2400:
                log("  round timeout 40m, restart")
                kill_batch()
                break
        time.sleep(3)
        if cpa_count() >= TARGET_CPA:
            break

    final = cpa_count()
    log(f"ORCH DONE cpa={final} delta={final - BASE0} target={TARGET_CPA} rounds={round_i}")
    log(f"final blocklist={sorted(read_blocklist_asns())}")
    print(f"SUMMARY delta={final - BASE0} cpa={final} log={ORCH_LOG}", flush=True)


if __name__ == "__main__":
    main()
