# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secure_files import atomic_write_json
from webui import email_provider_store


class IsolatedConfig:
    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.previous = (
            email_provider_store.CONFIG_PATH,
            email_provider_store.LOCK_PATH,
        )
        email_provider_store.CONFIG_PATH = base / "config.json"
        email_provider_store.LOCK_PATH = base / "config.json.lock"
        return email_provider_store.CONFIG_PATH

    def __exit__(self, exc_type, exc, tb):
        email_provider_store.CONFIG_PATH, email_provider_store.LOCK_PATH = self.previous
        self.temp.cleanup()


def assert_config_error(callback):
    try:
        callback()
    except email_provider_store.EmailProviderConfigError:
        return
    raise AssertionError("expected EmailProviderConfigError")


def test_provider_schema_and_defaults():
    with IsolatedConfig():
        state = email_provider_store.read_email_provider_config()
        assert state["ok"] is True
        assert state["provider"] == "cloudflare"
        assert state["config_exists"] is False
        providers = {item["id"]: item for item in state["providers"]}
        assert set(providers) == {
            "cloudflare",
            "duckmail",
            "yyds",
            "mailnest",
            "cloudmail",
            "moemail",
            "outlook_rt",
            "cf_outlook",
            "inbucket",
        }
        assert providers["outlook_rt"]["configured"] is False
        assert providers["cf_outlook"]["configured"] is False
        assert any(
            field["name"] == "cf_outlook_api_key" and field["secret"] is True
            for field in providers["cf_outlook"]["fields"]
        )
        assert any(
            field["name"] == "outlook_rt_inventory"
            for field in providers["outlook_rt"]["fields"]
        )
        assert providers["duckmail"]["configured"] is True
        assert providers["cloudmail"]["configured"] is False
        assert providers["inbucket"]["configured"] is False
        assert {field["name"] for field in providers["inbucket"]["fields"]} == {
            "inbucket_api_base",
            "inbucket_domain",
            "inbucket_random_levels",
        }
        random_levels = next(
            field
            for field in providers["inbucket"]["fields"]
            if field["name"] == "inbucket_random_levels"
        )
        assert random_levels["default"] == "0"
        assert {item["value"] for item in random_levels["options"]} == {
            "0",
            "1",
            "2",
            "1-2",
            "1-3",
        }
        random_subdomain = next(
            field
            for field in providers["cloudflare"]["fields"]
            if field["name"] == "cloudflare_randomize_subdomain"
        )
        assert random_subdomain["default"] == "true"
        assert {item["value"] for item in random_subdomain["options"]} == {
            "true",
            "false",
        }
        assert any(
            field["name"] == "cloudmail_password" and field["secret"] is True
            for field in providers["cloudmail"]["fields"]
        )


def test_secret_masking_preservation_clear_and_private_file():
    with IsolatedConfig() as config_path:
        atomic_write_json(config_path, {"unrelated_setting": 42})
        saved = email_provider_store.save_email_provider_config(
            "cloudmail",
            {
                "cloudmail_url": "https://mail.example.com/",
                "cloudmail_admin_email": "admin@example.com",
                "cloudmail_password": "test-password-value",
                "defaultDomains": "Mail.Example.com, mail.example.com",
            },
        )
        assert saved["provider"] == "cloudmail"
        assert saved["configured"] is True
        assert saved["values"]["cloudmail_password"] == ""
        assert saved["secret_configured"]["cloudmail_password"] is True
        raw = json.loads(config_path.read_text(encoding="utf-8"))
        assert raw["cloudmail_password"] == "test-password-value"
        assert raw["cloudmail_url"] == "https://mail.example.com"
        assert raw["defaultDomains"] == "mail.example.com"
        assert raw["unrelated_setting"] == 42
        if os.name == "posix":
            assert stat.S_IMODE(config_path.stat().st_mode) == 0o600
            assert stat.S_IMODE(email_provider_store.LOCK_PATH.stat().st_mode) == 0o600

        email_provider_store.save_email_provider_config(
            "cloudmail",
            {
                "cloudmail_url": "https://mail-two.example.com",
                "cloudmail_admin_email": "admin@example.com",
                "cloudmail_password": "",
                "defaultDomains": "mail.example.com",
            },
        )
        preserved = json.loads(config_path.read_text(encoding="utf-8"))
        assert preserved["cloudmail_password"] == "test-password-value"

        cleared = email_provider_store.save_email_provider_config(
            "cloudmail",
            {},
            clear_secrets=["cloudmail_password"],
        )
        assert cleared["secret_configured"]["cloudmail_password"] is False
        assert cleared["configured"] is False


def test_validation_rejects_unknown_fields_and_unsafe_values():
    with IsolatedConfig():
        assert_config_error(
            lambda: email_provider_store.save_email_provider_config(
                "cloudflare", {"proxy": "http://not-allowed.example"}
            )
        )
        assert_config_error(
            lambda: email_provider_store.save_email_provider_config(
                "cloudflare",
                {"cloudflare_api_base": "https://user:pass@mail.example.com"},
            )
        )
        assert_config_error(
            lambda: email_provider_store.save_email_provider_config(
                "cloudflare", {"cloudflare_path_accounts": "accounts"}
            )
        )
        assert_config_error(
            lambda: email_provider_store.save_email_provider_config(
                "cloudmail", {"defaultDomains": "https://mail.example.com"}
            )
        )


def test_connectivity_uses_unsaved_form_and_preserves_saved_secret():
    class Response:
        status_code = 200

    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return Response()

    with IsolatedConfig() as config_path:
        email_provider_store.save_email_provider_config(
            "yyds", {"yyds_api_key": "saved-test-key", "yyds_jwt": ""}
        )
        before = config_path.read_text(encoding="utf-8")
        result = email_provider_store.test_email_provider_config(
            "yyds",
            {"yyds_api_key": "", "yyds_jwt": "", "yyds_default_domain": ""},
            http_get=fake_get,
            http_post=lambda *_args, **_kwargs: Response(),
        )
        assert result["ok"] is True
        assert result["provider"] == "yyds"
        assert calls[0][0].endswith("/v1/domains")
        assert calls[0][1]["headers"]["X-API-Key"] == "saved-test-key"
        assert config_path.read_text(encoding="utf-8") == before


def test_cloudflare_connectivity_uses_configured_port():
    import connectivity

    calls = []
    previous_tcp_open = connectivity._tcp_open
    connectivity._tcp_open = lambda host, port: calls.append((host, port)) or True
    try:
        result = connectivity.check_email_api(
            "cloudflare",
            {
                "cloudflare_api_base": "http://mail.example.com:8793",
                "cloudflare_auth_mode": "none",
            },
            lambda *_args, **_kwargs: None,
            lambda *_args, **_kwargs: None,
        )
    finally:
        connectivity._tcp_open = previous_tcp_open

    assert result[1] is True
    assert calls == [("mail.example.com", 8793)]


def test_cloudflare_direct_create_does_not_probe_admin_domains():
    import connectivity

    tcp_calls = []
    http_calls = []
    previous_tcp_open = connectivity._tcp_open
    connectivity._tcp_open = lambda host, port: tcp_calls.append((host, port)) or True
    try:
        result = connectivity.check_email_api(
            "cloudflare",
            {
                "cloudflare_api_base": "https://mail.example.com",
                "cloudflare_auth_mode": "x-admin-auth",
                "cloudflare_api_key": "test-admin-key",
                "cloudflare_path_accounts": "/api/new_address",
            },
            lambda *args, **kwargs: http_calls.append((args, kwargs)),
            lambda *_args, **_kwargs: None,
        )
    finally:
        connectivity._tcp_open = previous_tcp_open

    assert result[1] is True
    assert tcp_calls == [("mail.example.com", 443)]
    assert http_calls == []


def test_cloudflare_admin_create_does_not_probe_mailbox_domains():
    import connectivity

    tcp_calls = []
    http_calls = []
    previous_tcp_open = connectivity._tcp_open
    connectivity._tcp_open = lambda host, port: tcp_calls.append((host, port)) or True
    try:
        result = connectivity.check_email_api(
            "cloudflare",
            {
                "cloudflare_api_base": "https://mail.example.com",
                "cloudflare_auth_mode": "x-admin-auth",
                "cloudflare_api_key": "test-admin-key",
                "cloudflare_path_accounts": "/admin/new_address",
            },
            lambda *args, **kwargs: http_calls.append((args, kwargs)),
            lambda *_args, **_kwargs: None,
        )
    finally:
        connectivity._tcp_open = previous_tcp_open

    assert result[1] is True
    assert "管理员建号模式" in result[2]
    assert tcp_calls == [("mail.example.com", 443)]
    assert http_calls == []


def test_inbucket_requires_base_and_domain():
    with IsolatedConfig() as config_path:
        saved = email_provider_store.save_email_provider_config(
            "inbucket",
            {
                "inbucket_api_base": "http://127.0.0.1:9000/",
                "inbucket_domain": "Mail.Example.com, box.example.net，mail.example.com",
                "inbucket_random_levels": "1-3",
            },
        )
        assert saved["provider"] == "inbucket"
        assert saved["configured"] is True
        assert saved["values"]["inbucket_api_base"] == "http://127.0.0.1:9000"
        raw = json.loads(config_path.read_text(encoding="utf-8"))
        # 多根域名：去重、小写、逗号分隔
        assert raw["inbucket_domain"] == "mail.example.com,box.example.net"
        assert raw["inbucket_random_levels"] == "1-3"

        partial = email_provider_store.save_email_provider_config(
            "inbucket",
            {"inbucket_api_base": "http://127.0.0.1:9000", "inbucket_domain": ""},
        )
        assert partial["configured"] is False

        assert_config_error(
            lambda: email_provider_store.save_email_provider_config(
                "inbucket",
                {"inbucket_api_base": "https://user:pass@inbucket.example.com"},
            )
        )
        assert_config_error(
            lambda: email_provider_store.save_email_provider_config(
                "inbucket", {"inbucket_random_levels": "9"}
            )
        )


def test_cf_outlook_schema_and_secret_preservation():
    with IsolatedConfig() as config_path:
        with tempfile.TemporaryDirectory() as tmp:
            inventory = Path(tmp) / "mailboxes.txt"
            inventory.write_text("mailbox@example.test\n", encoding="utf-8")
            saved = email_provider_store.save_email_provider_config(
                "cf_outlook",
                {
                    "cf_outlook_api_base": "https://mail.example.com/",
                    "cf_outlook_api_key": "test-api-key",
                    "cf_outlook_inventory": str(inventory),
                },
            )
            assert saved["configured"] is True
            assert saved["values"]["cf_outlook_api_key"] == ""
            assert saved["secret_configured"]["cf_outlook_api_key"] is True
            raw = json.loads(config_path.read_text(encoding="utf-8"))
            assert raw["cf_outlook_api_key"] == "test-api-key"
            email_provider_store.save_email_provider_config(
                "cf_outlook",
                {"cf_outlook_api_key": ""},
            )
            preserved = json.loads(config_path.read_text(encoding="utf-8"))
            assert preserved["cf_outlook_api_key"] == "test-api-key"


def test_cf_outlook_api_mode_does_not_require_inventory():
    with IsolatedConfig():
        saved = email_provider_store.save_email_provider_config(
            "cf_outlook",
            {
                "cf_outlook_api_base": "https://mail.example.com",
                "cf_outlook_api_key": "test-api-key",
                "cf_outlook_inventory": "",
            },
        )
        assert saved["configured"] is True


if __name__ == "__main__":
    test_provider_schema_and_defaults()
    test_secret_masking_preservation_clear_and_private_file()
    test_validation_rejects_unknown_fields_and_unsafe_values()
    test_connectivity_uses_unsaved_form_and_preserves_saved_secret()
    test_cloudflare_connectivity_uses_configured_port()
    test_cloudflare_direct_create_does_not_probe_admin_domains()
    test_cloudflare_admin_create_does_not_probe_mailbox_domains()
    test_inbucket_requires_base_and_domain()
    test_cf_outlook_schema_and_secret_preservation()
    print("OK email provider store")
