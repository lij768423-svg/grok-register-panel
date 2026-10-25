# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import sys
import tempfile
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
from sso_to_auth_json import write_grok2api_auth


CONFIG_KEYS = (
    "cpa_auto_add",
    "cpa_auth_dir",
    "cpa_remote_url",
    "cpa_management_key",
    "grok2api_auth_dir",
    "bfs_check",
    "bfs_skip_cpa",
    "cpa_token_mode",
    "quality_probe_on_register",
)


def _fake_stamp(record, proxy="", log=print, **_kwargs):
    record["quality_verdict"] = "healthy"
    record["quality_has_thinking"] = True
    record["quality_early_stop"] = True
    record["quality_tps"] = 12.0
    log("  ✅ 降智测试: healthy")
    return {
        "verdict": "healthy",
        "has_thinking": True,
        "tps": 12.0,
        "early_stop": True,
        "status_code": 200,
        "error": "",
    }


def test_add_sso_to_cpa_stamps_quality_before_write():
    previous_config = {key: register.config.get(key) for key in CONFIG_KEYS}
    previous_functions = (
        register._resolve_cpa_proxy,
        register._s2cpa.sso_to_token,
        register._s2cpa.stamp_converted_record_quality,
    )
    with tempfile.TemporaryDirectory() as temp:
        cpa_dir = Path(temp) / "cpa_auth"
        g2a_dir = Path(temp) / "grok2api_auth"
        register.config.update(
            {
                "cpa_auto_add": True,
                "cpa_auth_dir": str(cpa_dir),
                "cpa_remote_url": "",
                "cpa_management_key": "",
                "grok2api_auth_dir": str(g2a_dir),
                "bfs_check": False,
                "bfs_skip_cpa": False,
                "cpa_token_mode": "device_protocol",
                "quality_probe_on_register": True,
            }
        )
        register._resolve_cpa_proxy = lambda: "http://127.0.0.1:8001"
        register._s2cpa.sso_to_token = lambda *_args, **_kwargs: {
            "access_token": "opaque-access-token",
            "refresh_token": "opaque-refresh-token",
        }
        register._s2cpa.stamp_converted_record_quality = _fake_stamp
        try:
            result = register.add_sso_to_cpa(
                "sso=test-sso-token",
                email="auto@example.test",
            )
            assert result is True
            cpa_files = list(cpa_dir.glob("*.json"))
            assert len(cpa_files) == 1
            cpa = json.loads(cpa_files[0].read_text(encoding="utf-8"))
            assert cpa["quality_verdict"] == "healthy"
            assert cpa["quality_has_thinking"] is True
            assert "opaque-access-token" in cpa.get("access_token", "")
            g2a_files = list(g2a_dir.glob("*.json"))
            assert len(g2a_files) == 1
            g2a = json.loads(g2a_files[0].read_text(encoding="utf-8"))
            nested = next(value for value in g2a.values() if isinstance(value, dict))
            assert nested["quality_verdict"] == "healthy"
        finally:
            (
                register._resolve_cpa_proxy,
                register._s2cpa.sso_to_token,
                register._s2cpa.stamp_converted_record_quality,
            ) = previous_functions
            for key, value in previous_config.items():
                if value is None:
                    register.config.pop(key, None)
                else:
                    register.config[key] = value


def test_add_sso_to_cpa_can_skip_quality_probe():
    previous_config = {key: register.config.get(key) for key in CONFIG_KEYS}
    previous_functions = (
        register._resolve_cpa_proxy,
        register._s2cpa.sso_to_token,
        register._s2cpa.stamp_converted_record_quality,
    )
    called = []
    with tempfile.TemporaryDirectory() as temp:
        cpa_dir = Path(temp) / "cpa_auth"
        register.config.update(
            {
                "cpa_auto_add": True,
                "cpa_auth_dir": str(cpa_dir),
                "cpa_remote_url": "",
                "cpa_management_key": "",
                "grok2api_auth_dir": "",
                "bfs_check": False,
                "bfs_skip_cpa": False,
                "cpa_token_mode": "device_protocol",
                "quality_probe_on_register": False,  # default is also off
            }
        )
        register._resolve_cpa_proxy = lambda: ""
        register._s2cpa.sso_to_token = lambda *_args, **_kwargs: {
            "access_token": "opaque-access-token",
            "refresh_token": "opaque-refresh-token",
        }
        register._s2cpa.stamp_converted_record_quality = (
            lambda *args, **kwargs: called.append(1) or {}
        )
        try:
            result = register.add_sso_to_cpa(
                "sso=test-sso-token",
                email="skip@example.test",
            )
            assert result is True
            assert called == []
            payload = json.loads(next(cpa_dir.glob("*.json")).read_text(encoding="utf-8"))
            assert "quality_verdict" not in payload
        finally:
            (
                register._resolve_cpa_proxy,
                register._s2cpa.sso_to_token,
                register._s2cpa.stamp_converted_record_quality,
            ) = previous_functions
            for key, value in previous_config.items():
                if value is None:
                    register.config.pop(key, None)
                else:
                    register.config[key] = value


def test_write_grok2api_auth_keeps_quality_extra():
    with tempfile.TemporaryDirectory() as temp:
        path = write_grok2api_auth(
            Path(temp),
            {"access_token": "tok", "refresh_token": "rt"},
            email="g2a@example.test",
            extra={"quality_verdict": "hard", "unrelated": "nope"},
        )
        data = json.loads(path.read_text(encoding="utf-8"))
        nested = next(value for value in data.values() if isinstance(value, dict))
        assert nested["quality_verdict"] == "hard"
        assert "unrelated" not in nested


if __name__ == "__main__":
    test_add_sso_to_cpa_stamps_quality_before_write()
    test_add_sso_to_cpa_can_skip_quality_probe()
    test_write_grok2api_auth_keeps_quality_extra()
    print("OK quality register")
