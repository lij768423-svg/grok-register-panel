# -*- coding: utf-8 -*-
"""Regression tests for local registered-email de-duplication."""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import grok_register_ttk as register  # noqa: E402


def test_local_registered_email_scan_reads_history_but_not_mail_credentials():
    previous_accounts_dir = register.ACCOUNTS_DIR
    previous_config = {
        key: register.config.get(key)
        for key in ("cpa_auth_dir", "grok2api_auth_dir")
    }
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        accounts = root / "accounts"
        cpa = root / "cpa"
        g2a = root / "g2a"
        accounts.mkdir()
        cpa.mkdir()
        g2a.mkdir()
        (accounts / "known@example.test.txt").write_text(
            "known@example.test----password----fixture-sso\n",
            encoding="utf-8",
        )
        (accounts / "sso_pending.txt").write_text(
            "pending@example.test----fixture-sso\n",
            encoding="utf-8",
        )
        (accounts / "mail_credentials.txt").write_text(
            "not-registered@example.test\tfixture-mail-token\n",
            encoding="utf-8",
        )
        (cpa / "xai-cpa.json").write_text(
            json.dumps({"email": "cpa@example.test"}),
            encoding="utf-8",
        )
        (cpa / "legacy-auth.json").write_text(
            json.dumps({"issuer::client": {"email": "legacy@example.test"}}),
            encoding="utf-8",
        )
        (g2a / "g2a-grok.json").write_text(
            json.dumps(
                {"accounts": [{"name": "g2a@example.test", "provider": "grok_build"}]}
            ),
            encoding="utf-8",
        )
        register.ACCOUNTS_DIR = str(accounts)
        register.config.update({"cpa_auth_dir": str(cpa), "grok2api_auth_dir": str(g2a)})
        try:
            result = register.local_registered_emails()
        finally:
            register.ACCOUNTS_DIR = previous_accounts_dir
            register.config.update(previous_config)

    assert result == {
        "known@example.test",
        "pending@example.test",
        "cpa@example.test",
        "legacy@example.test",
        "g2a@example.test",
    }
    assert "not-registered@example.test" not in result


def test_get_email_and_token_changes_duplicate_email():
    previous_accounts_dir = register.ACCOUNTS_DIR
    previous_config = {
        key: register.config.get(key)
        for key in ("email_provider", "cpa_auth_dir", "grok2api_auth_dir")
    }
    previous_buy = register.mailnest_buy_email
    with tempfile.TemporaryDirectory() as temp:
        accounts = Path(temp) / "accounts"
        accounts.mkdir()
        (accounts / "known@example.test.txt").write_text(
            "known@example.test----password----fixture-sso\n",
            encoding="utf-8",
        )
        register.ACCOUNTS_DIR = str(accounts)
        register.config.update(
            {
                "email_provider": "mailnest",
                "cpa_auth_dir": "",
                "grok2api_auth_dir": "",
            }
        )
        candidates = iter(("known@example.test", "fresh@example.test"))
        register.mailnest_buy_email = lambda: next(candidates)
        try:
            email, token = register.get_email_and_token()
        finally:
            register.ACCOUNTS_DIR = previous_accounts_dir
            register.config.update(previous_config)
            register.mailnest_buy_email = previous_buy

    assert email == "fresh@example.test"
    assert token == "_"


if __name__ == "__main__":
    test_local_registered_email_scan_reads_history_but_not_mail_credentials()
    test_get_email_and_token_changes_duplicate_email()
    print("OK local email history")
