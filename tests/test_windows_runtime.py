#!/usr/bin/env python3
from __future__ import annotations

import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import batch_supervisor
import browser_session
import grok_register_ttk


def test_windows_profile_root_uses_local_app_data():
    with tempfile.TemporaryDirectory() as temp:
        root = browser_session._profile_root(
            platform_name="nt",
            environ={"LOCALAPPDATA": temp},
        )
        assert root.resolve() == (
            Path(temp) / "GrokRegister" / "grok-register-camoufox"
        ).resolve()
        assert root.is_dir()
        if sys.platform != "win32":
            assert stat.S_IMODE(root.stat().st_mode) == 0o700
        assert browser_session._is_managed_profile_dir(
            str(root / "123-456-abcdef12")
        )


def test_proxy_ip_validation_is_strict():
    assert browser_session._normalize_ip_candidate("203.0.113.8\n") == "203.0.113.8"
    assert browser_session._normalize_ip_candidate("2001:db8::1") == "2001:db8::1"
    assert browser_session._normalize_ip_candidate("999.999.999.999") == ""
    assert browser_session._normalize_ip_candidate("not-an-ip") == ""


def test_account_gap_sleep_is_cancelable():
    started = time.monotonic()
    grok_register_ttk._sleep_cancelable(2, lambda: True)
    assert time.monotonic() - started < 0.5


class FakePsutilError(Exception):
    pass


class FakeTrackedProcess:
    def __init__(self, pid):
        self.pid = pid
        self.terminated = False
        self.killed = False
        self._children = []

    def children(self, recursive=False):
        assert recursive is True
        return list(self._children)

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True


class FakePopen:
    def __init__(self, pid):
        self.pid = pid
        self.terminated = False
        self.killed = False

    def send_signal(self, _signal):
        pass

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        return 0


class FakePsutil:
    Error = FakePsutilError

    def __init__(self):
        self.child = FakeTrackedProcess(102)
        self.root = FakeTrackedProcess(101)
        self.root._children = [self.child]
        self.wait_calls = 0

    def Process(self, pid):
        assert pid == 101
        return self.root

    def wait_procs(self, processes, timeout):
        assert timeout > 0
        self.wait_calls += 1
        return [], list(processes)


def test_windows_process_tree_terminates_descendants():
    fake_psutil = FakePsutil()
    batch_supervisor._terminate_windows_process_tree(
        FakePopen(101),
        grace_seconds=0.2,
        psutil_module=fake_psutil,
    )
    assert fake_psutil.root.terminated and fake_psutil.child.terminated
    assert fake_psutil.root.killed and fake_psutil.child.killed
    source = (ROOT / "batch_supervisor.py").read_text(encoding="utf-8")
    assert "selectors.DefaultSelector" not in source
    assert "target=_read_pipe" in source


def test_outlook_pool_and_registration_regressions():
    # Keep these checks on the existing Windows CI entry point as well as the
    # full release suite. Separate interpreters isolate provider/config patches.
    for test_file in ("test_outlook.py", "test_outlook_worker_integration.py"):
        subprocess.run(
            [sys.executable, str(ROOT / "tests" / test_file)],
            cwd=ROOT,
            check=True,
            timeout=90,
        )


if __name__ == "__main__":
    test_windows_profile_root_uses_local_app_data()
    test_proxy_ip_validation_is_strict()
    test_account_gap_sleep_is_cancelable()
    test_windows_process_tree_terminates_descendants()
    test_outlook_pool_and_registration_regressions()
    print("OK windows runtime")
