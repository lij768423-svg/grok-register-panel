# -*- coding: utf-8 -*-
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import grok_register_ttk as register


def test_registration_risk_policy():
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


def test_risk_gate_runs_when_cpa_auto_add_is_disabled():
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
        try:
            register.ensure_sso_oauth_eligible(
                "sso=quarantined-token",
                email="risk@example.test",
            )
        except register.RegistrationRiskDenied:
            pass
        else:
            raise AssertionError("risk SSO was not blocked")
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

    assert inspected == ["quarantined-token"]
    assert quarantined == [
        (
            "risk@example.test",
            "quarantined-token",
            "risk=0.95,policy=allow,event=$registration",
        )
    ]
    assert len(recorded) == 1
    assert recorded[0][0:2] == ("risk", "risk@example.test")
    assert recorded[0][2]["kind"] == register.FAIL_RISK


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

    assert state["found"] is False
    assert quarantined == []


if __name__ == "__main__":
    test_registration_risk_policy()
    test_risk_gate_runs_when_cpa_auto_add_is_disabled()
    test_unknown_state_continues_without_quarantine()
    print("OK registration risk gate")
