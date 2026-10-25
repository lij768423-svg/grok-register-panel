# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import tempfile
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

try:
    import grok_register_ttk as register
except ModuleNotFoundError as exc:  # 无 tkinter 的解释器（如 Homebrew Python）
    if exc.name not in {"tkinter", "_tkinter"}:
        raise
    if "pytest" in sys.modules:
        import pytest

        pytest.skip("当前 Python 缺少 tkinter，跳过依赖 grok_register_ttk 的测试", allow_module_level=True)
    print("SKIP: 当前 Python 缺少 tkinter，跳过依赖 grok_register_ttk 的测试")
    sys.exit(0)
from webui import proxy_store


def test_worker_hot_reload_only_changes_next_account_proxy():
    previous_paths = (
        proxy_store.STATE_PATH,
        proxy_store.LOCK_PATH,
        proxy_store.LEGACY_PATH,
    )
    previous_proxy = register.config.get("proxy")
    previous_workers = register.config.get("register_workers")
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        try:
            proxy_store.STATE_PATH = base / "log" / "proxy_pool.json"
            proxy_store.LOCK_PATH = base / "log" / "proxy_pool.json.lock"
            proxy_store.LEGACY_PATH = base / "proxies.txt"
            register.config["proxy"] = "http://legacy.example:7890"
            register.config["register_workers"] = 2

            assert register.load_proxy_pool() == ["http://legacy.example:7890"]

            imported = proxy_store.import_proxies(
                "a.example:8000:user:pass\nb.example:8001:user:pass"
            )
            assert register.load_proxy_pool() == []
            try:
                register.pick_proxy_for_worker(0, 0)
            except RuntimeError as exc:
                assert "没有健康且启用的代理" in str(exc)
            else:
                raise AssertionError("unknown managed proxies must not reach workers")

            for offset, item in enumerate(imported["items"]):
                proxy_store._apply_probe_result(
                    item["id"],
                    {
                        "ok": True,
                        "exit_ip": f"198.51.100.{10 + offset}",
                        "asn": 64510 + offset,
                        "asn_org": "Worker Test",
                        "latency_ms": 100 + offset,
                        "checked_at": "2026-07-30T00:00:00Z",
                    },
                )

            register.release_proxy_lease()
            current = register.pick_proxy_for_worker(0, 0)
            register.set_thread_proxy(current)
            assert "a.example:8000" in current
            proxy_store.record_proxy_result(current, "risk", "policy deny")

            # State changes do not mutate the current account's bound proxy.
            assert register.get_thread_proxy() == current
            next_account = register.pick_proxy_for_worker(0, 1)
            assert next_account != current
            assert "b.example:8001" in next_account
        finally:
            proxy_store.STATE_PATH, proxy_store.LOCK_PATH, proxy_store.LEGACY_PATH = previous_paths
            register.config["proxy"] = previous_proxy
            register.config["register_workers"] = previous_workers


def test_pick_proxy_skips_other_worker_lease():
    previous_paths = (
        proxy_store.STATE_PATH,
        proxy_store.LOCK_PATH,
        proxy_store.LEGACY_PATH,
    )
    previous_proxy = register.config.get("proxy")
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        try:
            proxy_store.STATE_PATH = base / "log" / "proxy_pool.json"
            proxy_store.LOCK_PATH = base / "log" / "proxy_pool.json.lock"
            proxy_store.LEGACY_PATH = base / "proxies.txt"
            register.config["proxy"] = "http://legacy.example:7890"
            imported = proxy_store.import_proxies(
                "a.example:8000:user:pass\nb.example:8001:user:pass"
            )
            for offset, item in enumerate(imported["items"]):
                proxy_store._apply_probe_result(
                    item["id"],
                    {
                        "ok": True,
                        "exit_ip": f"198.51.100.{10 + offset}",
                        "asn": 64510 + offset,
                        "asn_org": "Worker Test",
                        "latency_ms": 100 + offset,
                        "checked_at": "2026-07-30T00:00:00Z",
                    },
                )
            register.release_proxy_lease()
            first = register.pick_proxy_for_worker(0, 0)
            # (1+1) % 2 == 0 would collide with worker 0 without leases
            second = register.pick_proxy_for_worker(1, 1)
            assert first != second
        finally:
            register.release_proxy_lease()
            proxy_store.STATE_PATH, proxy_store.LOCK_PATH, proxy_store.LEGACY_PATH = previous_paths
            register.config["proxy"] = previous_proxy


def test_pick_proxy_risk_rotate_skips_self_and_others():
    previous_paths = (
        proxy_store.STATE_PATH,
        proxy_store.LOCK_PATH,
        proxy_store.LEGACY_PATH,
    )
    previous_proxy = register.config.get("proxy")
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        try:
            proxy_store.STATE_PATH = base / "log" / "proxy_pool.json"
            proxy_store.LOCK_PATH = base / "log" / "proxy_pool.json.lock"
            proxy_store.LEGACY_PATH = base / "proxies.txt"
            register.config["proxy"] = "http://legacy.example:7890"
            imported = proxy_store.import_proxies(
                "a.example:8000:user:pass\n"
                "b.example:8001:user:pass\n"
                "c.example:8002:user:pass"
            )
            for offset, item in enumerate(imported["items"]):
                proxy_store._apply_probe_result(
                    item["id"],
                    {
                        "ok": True,
                        "exit_ip": f"198.51.100.{10 + offset}",
                        "asn": 64510 + offset,
                        "asn_org": "Worker Test",
                        "latency_ms": 100 + offset,
                        "checked_at": "2026-07-30T00:00:00Z",
                    },
                )
            register.release_proxy_lease()
            w0 = register.pick_proxy_for_worker(0, 0)
            w1 = register.pick_proxy_for_worker(1, 0)
            rotated = register.pick_proxy_for_worker(0, 1)
            assert rotated != w0
            assert rotated != w1
        finally:
            register.release_proxy_lease()
            proxy_store.STATE_PATH, proxy_store.LOCK_PATH, proxy_store.LEGACY_PATH = previous_paths
            register.config["proxy"] = previous_proxy


def test_pick_proxy_prefers_ip_unused_for_40_minutes():
    previous_paths = (
        proxy_store.STATE_PATH,
        proxy_store.LOCK_PATH,
        proxy_store.LEGACY_PATH,
    )
    previous_proxy = register.config.get("proxy")
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        try:
            proxy_store.STATE_PATH = base / "log" / "proxy_pool.json"
            proxy_store.LOCK_PATH = base / "log" / "proxy_pool.json.lock"
            proxy_store.LEGACY_PATH = base / "proxies.txt"
            register.config["proxy"] = "http://legacy.example:7890"
            imported = proxy_store.import_proxies(
                "127.0.0.1:8003\n127.0.0.1:8004\n127.0.0.1:8005"
            )
            from datetime import datetime, timedelta, timezone

            now = datetime.now(timezone.utc)
            for offset, item in enumerate(imported["items"]):
                proxy_store._apply_probe_result(
                    item["id"],
                    {
                        "ok": True,
                        "exit_ip": f"203.0.113.{offset + 1}",
                        "asn": 64510 + offset,
                        "asn_org": "Home",
                        "latency_ms": 100,
                        "checked_at": "2026-08-15T00:00:00Z",
                    },
                )
            state = json.loads(proxy_store.STATE_PATH.read_text(encoding="utf-8"))
            # first two IPs used 2 minutes ago; third used 50 minutes ago
            state["items"][0]["last_used_at"] = (now - timedelta(minutes=2)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            state["items"][1]["last_used_at"] = (now - timedelta(minutes=2)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            state["items"][2]["last_used_at"] = (now - timedelta(minutes=50)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            proxy_store.STATE_PATH.write_text(json.dumps(state), encoding="utf-8")
            register.release_proxy_lease()
            picked = register.pick_proxy_for_worker(0, 0)
            assert picked.endswith(":8005")
        finally:
            register.release_proxy_lease()
            proxy_store.STATE_PATH, proxy_store.LOCK_PATH, proxy_store.LEGACY_PATH = previous_paths
            register.config["proxy"] = previous_proxy


def test_reserve_signup_submit_slot_staggers():
    register._next_submit_at = 0.0
    first = register.reserve_signup_submit_slot(7)
    second = register.reserve_signup_submit_slot(7)
    third = register.reserve_signup_submit_slot(7)
    assert first == 0
    assert 6 <= second <= 8
    assert 13 <= third <= 16


if __name__ == "__main__":
    test_worker_hot_reload_only_changes_next_account_proxy()
    test_pick_proxy_skips_other_worker_lease()
    test_pick_proxy_risk_rotate_skips_self_and_others()
    test_pick_proxy_prefers_ip_unused_for_40_minutes()
    test_reserve_signup_submit_slot_staggers()
    print("OK proxy worker integration")
