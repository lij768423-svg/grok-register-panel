#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import connectivity
try:
    import grok_register_ttk
except ModuleNotFoundError as exc:  # 无 tkinter 的解释器（如 Homebrew Python）
    if exc.name not in {"tkinter", "_tkinter"}:
        raise
    if "pytest" in sys.modules:
        import pytest

        pytest.skip("当前 Python 缺少 tkinter，跳过依赖 grok_register_ttk 的测试", allow_module_level=True)
    print("SKIP: 当前 Python 缺少 tkinter，跳过依赖 grok_register_ttk 的测试")
    sys.exit(0)
import retry_policy


def test_defaults_are_bounded_and_overridable():
    assert retry_policy.browser_start_attempts({}) == 2
    assert retry_policy.proxy_boot_rotations({}) == 3
    assert retry_policy.slot_retries({}) == 1
    assert retry_policy.orchestrator_failure_limit({}) == 2
    assert retry_policy.browser_start_attempts({"GROK_BROWSER_START_ATTEMPTS": "99"}) == 4
    assert retry_policy.proxy_boot_rotations({"GROK_PROXY_BOOT_ROTATIONS": "-4"}) == 0
    assert retry_policy.slot_retries({"GROK_SLOT_RETRIES": "invalid"}) == 1


def test_xai_failure_is_explicitly_non_retryable():
    failed = [(connectivity.XAI_SIGNUP_CHECK_NAME, False, "HTTP 503")]
    try:
        connectivity.require_xai_signup(failed)
    except connectivity.XaiSignupPrecheckFailed:
        pass
    else:
        raise AssertionError("xAI signup failure must abort the batch")
    connectivity.require_xai_signup(
        [(connectivity.XAI_SIGNUP_CHECK_NAME, True, "HTTP 200")]
    )
    source = (ROOT / "run_batch_headless.py").read_text(encoding="utf-8")
    assert "has_blocking_xai_failure = lambda" not in source
    assert "PRECHECK_EXIT_CODE" in source


def test_xai_precheck_failure_updates_managed_proxy_health():
    calls = []
    previous = grok_register_ttk._record_managed_proxy_result
    grok_register_ttk._record_managed_proxy_result = (
        lambda proxy, outcome, detail: calls.append((proxy, outcome, detail)) or True
    )
    try:
        assert grok_register_ttk._record_proxy_precheck_failure(
            "http://proxy.example:8080",
            [(connectivity.XAI_SIGNUP_CHECK_NAME, False, "TLS connect error")],
        )
    finally:
        grok_register_ttk._record_managed_proxy_result = previous
    assert calls
    assert calls[0][0] == "http://proxy.example:8080"
    assert calls[0][1] == "network"


if __name__ == "__main__":
    test_defaults_are_bounded_and_overridable()
    test_xai_failure_is_explicitly_non_retryable()
    test_xai_precheck_failure_updates_managed_proxy_health()
    print("OK retry policy")
