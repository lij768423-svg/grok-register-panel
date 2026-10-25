# -*- coding: utf-8 -*-
from __future__ import annotations

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


def test_registration_risk_policy_classifier_still_parses():
    """The historical classifier stays for the deprecated SSO panel."""
    blocked_cases = (
        ({"denied": True}, "policy=deny,event=$registration"),
        ({"bot_flag_source": 1}, "botFlagSource=1"),
        ({"bot_flag_source": 2}, "botFlagSource=2"),
        (
            {"policy": "deny", "event": "$login"},
            "policy=deny,event=$login",
        ),
    )
    for state, expected_detail in blocked_cases:
        blocked, detail = register._registration_risk_should_block(state)
        assert blocked is True
        assert detail == expected_detail

    for state in (
        {"found": True, "bot_flag_source": 0},
        {"found": False},
        {},
        None,
    ):
        assert register._registration_risk_should_block(state) == (False, "")


def test_oauth_gate_no_longer_inspects_sso_botflag():
    previous_auto_add = register.config.get("cpa_auto_add")
    previous_functions = (
        register._resolve_cpa_proxy,
        register._s2cpa.inspect_sso_account_state,
        register._append_sso_risk_rejected,
        register.record_register_result,
    )
    inspected = []
    quarantined = []
    recorded = []
    register.config["cpa_auto_add"] = False
    register._resolve_cpa_proxy = lambda: ""
    register._s2cpa.inspect_sso_account_state = (
        lambda sso, **_kwargs: inspected.append(sso)
        or {
            "found": True,
            "bot_flag_source": 2,
            "bot_flag_details": "risk=0.95,policy=allow,event=$registration",
            "policy": "allow",
            "event": "$registration",
            "denied": False,
        }
    )
    register._append_sso_risk_rejected = (
        lambda email, sso, details, **_kwargs: quarantined.append(
            (email, sso, details)
        )
    )
    register.record_register_result = (
        lambda status, email, **kwargs: recorded.append((status, email, kwargs))
    )
    try:
        state = register.ensure_sso_oauth_eligible(
            "sso=quarantined-token",
            email="risk@example.test",
        )
    finally:
        (
            register._resolve_cpa_proxy,
            register._s2cpa.inspect_sso_account_state,
            register._append_sso_risk_rejected,
            register.record_register_result,
        ) = previous_functions
        if previous_auto_add is None:
            register.config.pop("cpa_auto_add", None)
        else:
            register.config["cpa_auto_add"] = previous_auto_add

    assert state.get("skipped") is True
    assert state.get("error") == "sso_botflag_deprecated"
    assert inspected == []
    assert quarantined == []
    assert recorded == []


def test_unknown_state_continues_without_quarantine():
    previous_functions = (
        register._resolve_cpa_proxy,
        register._s2cpa.inspect_sso_account_state,
        register._append_sso_risk_rejected,
    )
    quarantined = []
    register._resolve_cpa_proxy = lambda: ""
    register._s2cpa.inspect_sso_account_state = lambda *_args, **_kwargs: {
        "found": False,
        "bot_flag_source": None,
        "error": "unavailable",
    }
    register._append_sso_risk_rejected = (
        lambda *_args, **_kwargs: quarantined.append(True)
    )
    try:
        state = register.ensure_sso_oauth_eligible("clean-or-unknown-token")
    finally:
        (
            register._resolve_cpa_proxy,
            register._s2cpa.inspect_sso_account_state,
            register._append_sso_risk_rejected,
        ) = previous_functions

    assert state.get("skipped") is True
    assert quarantined == []


if __name__ == "__main__":
    test_registration_risk_policy_classifier_still_parses()
    test_oauth_gate_no_longer_inspects_sso_botflag()
    test_unknown_state_continues_without_quarantine()
    print("OK registration risk gate")
