# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secure_files import (
    append_private_text,
    atomic_write_text,
    best_effort_fchmod,
    ensure_private_dir,
)
from webui import blacklist_store, process_utils


def test_private_file_helpers():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp) / "private"
        ensure_private_dir(root)
        path = root / "secret.txt"
        append_private_text(path, "one\n")
        atomic_write_text(path, "two\n")
        assert path.read_text() == "two\n"
        if os.name == "posix":
            assert stat.S_IMODE(root.stat().st_mode) == 0o700
            assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_best_effort_fchmod_handles_missing_windows_api():
    sentinel = object()
    original = getattr(os, "fchmod", sentinel)
    try:
        os.fchmod = None
        best_effort_fchmod(-1, 0o600)
    finally:
        if original is sentinel:
            delattr(os, "fchmod")
        else:
            os.fchmod = original


def test_runtime_entrypoints_use_cross_platform_fchmod_helper():
    for relative in (
        "run_until_100.py",
        "webui/monitor.py",
        "webui/recovery_ops.py",
    ):
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert "os.fchmod" not in source
        assert "best_effort_fchmod" in source


def test_blacklist_state_is_data_and_sanitized():
    with tempfile.TemporaryDirectory() as temp:
        original_state = blacklist_store.STATE_PATH
        original_lock = blacklist_store.LOCK_PATH
        try:
            blacklist_store.STATE_PATH = Path(temp) / "blacklist.json"
            blacklist_store.LOCK_PATH = Path(temp) / "blacklist.json.lock"
            assert blacklist_store.add_asn(64512, "test\n); injected = True")
            result = blacklist_store.read_blacklist()
            item = next(item for item in result["items"] if item["asn"] == 64512)
            assert "\n" not in item["note"]
            assert result["source"].endswith("blacklist.json")
            assert "injected" in item["note"]
        finally:
            blacklist_store.STATE_PATH = original_state
            blacklist_store.LOCK_PATH = original_lock


def test_process_discovery_is_root_scoped():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        script = root / "managed_probe.py"
        script.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")
        process = subprocess.Popen([sys.executable, str(script)], cwd=root)
        try:
            for _ in range(30):
                if process_utils.process_matches(process.pid, root, (script.name,)):
                    break
                time.sleep(0.05)
            assert process_utils.process_matches(process.pid, root, (script.name,))
            assert not process_utils.process_matches(process.pid, ROOT, (script.name,))
            killed = process_utils.terminate_managed_processes(root, (script.name,), grace_seconds=0.5)
            assert process.pid in killed
            process.wait(timeout=3)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=3)


def test_process_discovery_works_without_direct_proc_access():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp).resolve()

        class FakeProcess:
            def __init__(self, pid, cwd, command):
                self.info = {
                    "pid": pid,
                    "cwd": str(cwd),
                    "cmdline": command,
                    "create_time": time.time() - 65,
                }

        processes = [
            FakeProcess(123456, root, [sys.executable, str(root / "managed.py")]),
            FakeProcess(123457, ROOT, [sys.executable, str(ROOT / "managed.py")]),
        ]
        original_process_iter = process_utils.psutil.process_iter
        try:
            process_utils.psutil.process_iter = lambda **_kwargs: iter(processes)
            found = process_utils.find_managed_processes(root, ("managed.py",))
        finally:
            process_utils.psutil.process_iter = original_process_iter

        assert [item["pid"] for item in found] == [123456]
        assert found[0]["etime"] == "01:05"


def test_process_discovery_reports_missing_process_table():
    original_process_iter = process_utils.psutil.process_iter

    def unavailable(**_kwargs):
        raise FileNotFoundError("process table unavailable")

    try:
        process_utils.psutil.process_iter = unavailable
        try:
            process_utils.find_managed_processes(ROOT, ("run_until_100.py",))
        except process_utils.ProcessInspectionError as exc:
            message = str(exc)
        else:
            raise AssertionError("missing process table must fail closed")
    finally:
        process_utils.psutil.process_iter = original_process_iter

    assert "/proc" in message
    assert "psutil" in message


def test_process_discovery_source_has_no_direct_proc_reads():
    source = (ROOT / "webui" / "process_utils.py").read_text(encoding="utf-8")
    assert 'Path("/proc")' not in source
    assert "os.readlink" not in source


def test_no_network_metadata_is_written_to_source():
    orchestrator = (ROOT / "run_until_100.py").read_text(encoding="utf-8")
    browser = (ROOT / "browser_session.py").read_text(encoding="utf-8")
    assert "BS.write_text" not in orchestrator
    assert "http://ipwho.is" not in orchestrator
    assert "http://ipwho.is" not in browser
    assert "_pid_alive(owner_pid)" in browser


def test_permission_hardener_covers_runtime_pools_without_following_symlinks():
    if os.name != "posix":
        return
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        root = base / "runtime"
        external = base / "external-accounts"
        root.mkdir()
        external.mkdir()
        external_secret = external / "secret.txt"
        external_secret.write_text("outside\n", encoding="utf-8")
        external_secret.chmod(0o644)
        (root / "accounts").symlink_to(external, target_is_directory=True)
        proxy_pool = root / "proxies.raw.txt"
        sticky_pool = root / "stickies-us.txt"
        cache_file = root / ".next_action_id.cache"
        state_pool = root / "log" / "proxy_pool.json"
        domain_pool = root / "log" / "email_domain_pool.json"
        state_pool.parent.mkdir()
        for path in (proxy_pool, sticky_pool, cache_file, state_pool, domain_pool):
            path.write_text("secret\n", encoding="utf-8")
            path.chmod(0o644)

        subprocess.run(
            [sys.executable, str(ROOT / "scripts/harden_runtime_permissions.py"), str(root)],
            check=True,
            capture_output=True,
            text=True,
        )

        for path in (proxy_pool, sticky_pool, cache_file, state_pool, domain_pool):
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(external_secret.stat().st_mode) == 0o644


if __name__ == "__main__":
    test_private_file_helpers()
    test_best_effort_fchmod_handles_missing_windows_api()
    test_runtime_entrypoints_use_cross_platform_fchmod_helper()
    test_blacklist_state_is_data_and_sanitized()
    test_process_discovery_is_root_scoped()
    test_process_discovery_works_without_direct_proc_access()
    test_process_discovery_reports_missing_process_table()
    test_process_discovery_source_has_no_direct_proc_reads()
    test_no_network_metadata_is_written_to_source()
    test_permission_hardener_covers_runtime_pools_without_following_symlinks()
    print("OK runtime security")
