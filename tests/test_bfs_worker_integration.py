# -*- coding: utf-8 -*-
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import grok_register_ttk as register


def test_unknown_bfs_is_queued_when_skip_enabled():
    config_keys = (
        "cpa_auto_add",
        "cpa_auth_dir",
        "cpa_remote_url",
        "cpa_management_key",
        "grok2api_auth_dir",
        "bfs_check",
        "bfs_skip_cpa",
        "cpa_token_mode",
    )
    previous_config = {key: register.config.get(key) for key in config_keys}
    previous_functions = (
        register._resolve_cpa_proxy,
        register._s2cpa.sso_to_token,
        register._s2cpa.inspect_token_bundle_bfs,
        register._s2cpa.token_to_cpa_record,
        register._append_sso_pending,
    )
    queued = []
    record_calls = []
    with tempfile.TemporaryDirectory() as temp:
        register.config.update(
            {
                "cpa_auto_add": True,
                "cpa_auth_dir": str(Path(temp) / "cpa_auth"),
                "cpa_remote_url": "",
                "cpa_management_key": "",
                "grok2api_auth_dir": "",
                "bfs_check": True,
                "bfs_skip_cpa": True,
                "cpa_token_mode": "device_protocol",
            }
        )
        register._resolve_cpa_proxy = lambda: ""
        register._s2cpa.sso_to_token = lambda *_args, **_kwargs: {
            "access_token": "opaque-access-token",
            "refresh_token": "opaque-refresh-token",
        }
        register._s2cpa.inspect_token_bundle_bfs = lambda **_kwargs: {
            "ok": False,
            "has_bfs": False,
            "bfs": None,
            "source": "",
        }
        register._s2cpa.token_to_cpa_record = (
            lambda *_args, **kwargs: record_calls.append(kwargs) or {}
        )
        register._append_sso_pending = (
            lambda email, sso, **_kwargs: queued.append((email, sso))
        )
        try:
            result = register.add_sso_to_cpa(
                "sso=test-sso-token",
                email="unknown@example.test",
            )
        finally:
            (
                register._resolve_cpa_proxy,
                register._s2cpa.sso_to_token,
                register._s2cpa.inspect_token_bundle_bfs,
                register._s2cpa.token_to_cpa_record,
                register._append_sso_pending,
            ) = previous_functions
            for key, value in previous_config.items():
                if value is None:
                    register.config.pop(key, None)
                else:
                    register.config[key] = value

    assert result is False
    assert queued == [("unknown@example.test", "test-sso-token")]
    assert record_calls == []


def test_grok2api_remote_only_target_is_uploaded():
    config_keys = (
        "cpa_auto_add",
        "cpa_auth_dir",
        "cpa_remote_url",
        "cpa_management_key",
        "grok2api_auth_dir",
        "grok2api_remote_url",
        "grok2api_username",
        "grok2api_password",
        "bfs_check",
        "cpa_token_mode",
    )
    previous_config = {key: register.config.get(key) for key in config_keys}
    previous_functions = (
        register._resolve_cpa_proxy,
        register._s2cpa.sso_to_token,
        register._s2cpa.token_to_cpa_record,
        register._s2cpa.upload_grok2api_auth_remote,
    )
    uploaded = []
    with tempfile.TemporaryDirectory() as temp:
        register.config.update(
            {
                "cpa_auto_add": True,
                "cpa_auth_dir": "",
                "cpa_remote_url": "",
                "cpa_management_key": "",
                "grok2api_auth_dir": "",
                "grok2api_remote_url": "https://grok2api.example.test",
                "grok2api_username": "admin-fixture",
                "grok2api_password": "password-fixture",
                "bfs_check": False,
                "cpa_token_mode": "device_protocol",
            }
        )
        register._resolve_cpa_proxy = lambda: ""
        register._s2cpa.sso_to_token = lambda *_args, **_kwargs: {
            "access_token": "opaque-access-token",
            "refresh_token": "opaque-refresh-token",
        }
        register._s2cpa.token_to_cpa_record = lambda *_args, **_kwargs: {}

        def fake_upload(base_url, account, **kwargs):
            uploaded.append((base_url, account, kwargs))
            return "g2a-person@example.test.json"

        register._s2cpa.upload_grok2api_auth_remote = fake_upload
        try:
            result = register.add_sso_to_cpa(
                "sso=test-sso-token",
                email="person@example.test",
            )
        finally:
            (
                register._resolve_cpa_proxy,
                register._s2cpa.sso_to_token,
                register._s2cpa.token_to_cpa_record,
                register._s2cpa.upload_grok2api_auth_remote,
            ) = previous_functions
            for key, value in previous_config.items():
                if value is None:
                    register.config.pop(key, None)
                else:
                    register.config[key] = value

    assert result is True
    assert len(uploaded) == 1
    assert uploaded[0][0] == "https://grok2api.example.test"
    assert uploaded[0][1]["email"] == "person@example.test"
    kwargs = uploaded[0][2]
    assert kwargs["username"] == "admin-fixture"
    assert kwargs["password"] == "password-fixture"
    assert "auth_state" in kwargs
    assert "proxy" not in kwargs
    assert "management_key" not in kwargs


if __name__ == "__main__":
    test_unknown_bfs_is_queued_when_skip_enabled()
    test_grok2api_remote_only_target_is_uploaded()
    print("OK bfs worker integration")
