# -*- coding: utf-8 -*-
from __future__ import annotations

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
from webui import email_domain_store


def test_managed_domains_reach_all_supported_provider_adapters():
    previous_paths = (email_domain_store.STATE_PATH, email_domain_store.LOCK_PATH)
    previous_config = {
        key: register.config.get(key)
        for key in (
            "email_provider",
            "cloudflare_api_base",
            "cloudflare_randomize_subdomain",
            "cloudmail_url",
            "cloudmail_admin_email",
            "cloudmail_password",
            "moemail_api_base",
            "moemail_api_key",
            "yyds_api_key",
            "yyds_jwt",
        )
    }
    previous_functions = (
        register.cloudflare_provider.create_temp_address,
        register.cloudmail_provider.create_mailbox,
        register.moemail_provider.create_mailbox,
        register.yyds_create_account,
    )
    observed = {}
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        email_domain_store.STATE_PATH = base / "log" / "email_domain_pool.json"
        email_domain_store.LOCK_PATH = base / "log" / "email_domain_pool.json.lock"
        register.config.update(
            {
                "cloudflare_api_base": "https://cloudflare.example.com",
                "cloudflare_randomize_subdomain": True,
                "cloudmail_url": "https://cloudmail.example.com",
                "cloudmail_admin_email": "admin@example.com",
                "cloudmail_password": "not-used-in-test",
                "moemail_api_base": "https://moemail.example.com",
                "moemail_api_key": "not-used-in-test",
                "yyds_api_key": "not-used-in-test",
                "yyds_jwt": "",
            }
        )

        def fake_cloudflare(*_args, **kwargs):
            observed["cloudflare"] = kwargs["domain"]
            assert kwargs["randomize_subdomain"] is True
            return f"user@{kwargs['domain']}", "cloudflare-token"

        def fake_cloudmail(_post, _url, _email, _password, domains, username=""):
            observed["cloudmail"] = domains[0]
            return f"{username or 'user'}@{domains[0]}", "cloudmail-token"

        def fake_moemail(*_args, **kwargs):
            observed["moemail"] = kwargs["domain"]
            return f"user@{kwargs['domain']}", "moemail-token"

        def fake_yyds(*, local_part=None, domain=None, api_key=None, jwt=None):
            observed["yyds"] = domain
            return {"address": f"{local_part}@{domain}", "token": "yyds-token"}

        register.cloudflare_provider.create_temp_address = fake_cloudflare
        register.cloudmail_provider.create_mailbox = fake_cloudmail
        register.moemail_provider.create_mailbox = fake_moemail
        register.yyds_create_account = fake_yyds
        domains = {
            "cloudflare": "cf-mail.example.com",
            "cloudmail": "cloudmail.example.com",
            "moemail": "moe-mail.example.com",
            "yyds": "yyds-mail.example.com",
        }
        try:
            for provider, domain in domains.items():
                email_domain_store.import_domains(domain, provider)
                register.config["email_provider"] = provider
                email, token = register.get_email_and_token()
                assert email.endswith(f"@{domain}")
                assert token
            assert observed == domains
        finally:
            (
                register.cloudflare_provider.create_temp_address,
                register.cloudmail_provider.create_mailbox,
                register.moemail_provider.create_mailbox,
                register.yyds_create_account,
            ) = previous_functions
            email_domain_store.STATE_PATH, email_domain_store.LOCK_PATH = previous_paths
            register.config.update(previous_config)


def test_managed_domain_is_passed_to_provider_and_blocks_without_fallback():
    previous_paths = (email_domain_store.STATE_PATH, email_domain_store.LOCK_PATH)
    previous_config = {
        key: register.config.get(key)
        for key in (
            "email_provider",
            "defaultDomains",
            "cloudmail_url",
            "cloudmail_admin_email",
            "cloudmail_password",
        )
    }
    previous_create = register.cloudmail_provider.create_mailbox
    calls = []
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        email_domain_store.STATE_PATH = base / "log" / "email_domain_pool.json"
        email_domain_store.LOCK_PATH = base / "log" / "email_domain_pool.json.lock"
        register.config.update(
            {
                "email_provider": "cloudmail",
                "defaultDomains": "legacy.example.com",
                "cloudmail_url": "https://mail.example.com",
                "cloudmail_admin_email": "admin@example.com",
                "cloudmail_password": "not-used-in-test",
            }
        )

        def fake_create(_post, _url, _email, _password, domains, username=""):
            calls.append(list(domains))
            return f"{username or 'user'}@{domains[0]}", "cloudmail-token"

        register.cloudmail_provider.create_mailbox = fake_create
        try:
            imported = email_domain_store.import_domains(
                "managed-a.example.com\nmanaged-b.example.com",
                "cloudmail",
            )
            first_email, _ = register.get_email_and_token()
            assert first_email.endswith("@managed-a.example.com")
            assert calls[-1] == ["managed-a.example.com"]

            register._record_email_domain_rejected(
                first_email, "xAI rejected this email domain"
            )
            register._record_email_domain_rejected(
                first_email, "xAI rejected this email domain"
            )
            email_domain_store.update_settings(failure_threshold=2)
            # Rejection feedback uses the current threshold. Block the first item
            # explicitly after the setting change as a regression guard.
            email_domain_store.record_domain_result(
                "cloudmail",
                first_email,
                "rejected",
                "xAI rejected this email domain",
            )
            next_email, _ = register.get_email_and_token()
            assert next_email.endswith("@managed-b.example.com")
            assert calls[-1] == ["managed-b.example.com"]

            email_domain_store.record_domain_result(
                "cloudmail",
                next_email,
                "rejected",
                "xAI rejected this email domain",
            )
            email_domain_store.record_domain_result(
                "cloudmail",
                next_email,
                "rejected",
                "xAI rejected this email domain",
            )
            try:
                register.get_email_and_token()
            except RuntimeError as exc:
                assert "没有可用的 CloudMail 域名" in str(exc)
            else:
                raise AssertionError("managed pool must not fall back to config domains")

            # A successful email submission clears consecutive rejection state.
            register._record_email_domain_accepted(first_email)
            state = email_domain_store.read_email_domain_pool()
            accepted = next(
                item
                for item in state["items"]
                if item["id"] == imported["items"][0]["id"]
            )
            assert accepted["consecutive_rejections"] == 0
            assert accepted["success_count"] == 1
        finally:
            register.cloudmail_provider.create_mailbox = previous_create
            email_domain_store.STATE_PATH, email_domain_store.LOCK_PATH = previous_paths
            register.config.update(previous_config)


def test_cloudflare_combined_error_is_redacted():
    secret = "provider-secret-value-123456"
    redacted = register.redact_sensitive_log_line(
        f"token={secret} email=person@example.com"
    )
    assert secret not in redacted
    assert "person@example.com" not in redacted


def test_mail_direct_uses_configured_provider_bases():
    keys = (
        "cloudflare_api_base",
        "cloudmail_url",
        "moemail_api_base",
        "duckmail_api_base",
    )
    previous = {key: register.config.get(key) for key in keys}
    register.config.update(
        {
            "cloudflare_api_base": "https://cf-mail.example.test",
            "cloudmail_url": "https://cloudmail.example.test",
            "moemail_api_base": "",
            "duckmail_api_base": "",
        }
    )
    try:
        assert register._url_needs_direct(
            "https://cf-mail.example.test/api/new_address"
        )
        assert register._url_needs_direct(
            "https://cloudmail.example.test/api/messages"
        )
        assert not register._url_needs_direct(
            "https://unrelated.example.test/v1/status"
        )
    finally:
        for key, value in previous.items():
            if value is None:
                register.config.pop(key, None)
            else:
                register.config[key] = value


if __name__ == "__main__":
    test_managed_domains_reach_all_supported_provider_adapters()
    test_managed_domain_is_passed_to_provider_and_blocks_without_fallback()
    test_cloudflare_combined_error_is_redacted()
    test_mail_direct_uses_configured_provider_bases()
    print("OK email domain worker integration")
