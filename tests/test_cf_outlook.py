# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import connectivity
from email_providers import cf_outlook


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code
        self.text = json.dumps(payload)

    def json(self):
        return self.payload


def test_normalize_base_and_inventory_formats():
    assert cf_outlook.normalize_base("mail.example.com/api/") == "https://mail.example.com"
    assert cf_outlook.normalize_base("https://mail.example.com/prefix") == "https://mail.example.com/prefix"
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "mailboxes.jsonl"
        path.write_text(
            '{"email":"a@example.test"}\n'
            "b@example.test\n"
            "a@example.test\n"
            "invalid\n",
            encoding="utf-8",
        )
        assert [row["email"] for row in cf_outlook.load_inventory(str(path))] == [
            "a@example.test",
            "b@example.test",
        ]


def test_take_wait_and_mark_used():
    with tempfile.TemporaryDirectory() as tmp:
        inventory = Path(tmp) / "mailboxes.txt"
        inventory.write_text("first@example.test\nsecond@example.test\n", encoding="utf-8")
        cf_outlook._reserved.clear()
        cf_outlook._sessions.clear()

        email, token_key = cf_outlook.take_mailbox(str(inventory))
        assert email == "first@example.test"
        calls = []

        def http_get(url, **kwargs):
            calls.append((url, kwargs))
            return FakeResponse(
                {
                    "success": True,
                    "data": {
                        "items": [
                            {
                                "id": "m1",
                                "subject": "xAI verification code",
                                "bodyPreview": "Use code QO7-TUD to continue",
                                "body": "Use code QO7-TUD to continue",
                                "receivedDateTime": "2099-01-01T00:00:00Z",
                            }
                        ]
                    },
                }
            )

        logs = []
        code = cf_outlook.wait_for_code(
            http_get,
            "https://mail.example.com",
            "api-key-value",
            token_key,
            email,
            timeout=10,
            poll_interval=0,
            raise_if_cancelled=lambda _callback: None,
            sleep_with_cancel=lambda _seconds, _callback: None,
            log_callback=logs.append,
        )
        assert code == "QO7-TUD"
        assert calls[0][0] == "https://mail.example.com/api/external/emails"
        assert calls[0][1]["headers"]["X-API-Key"] == "api-key-value"
        assert calls[0][1]["params"] == {
            "email": "first@example.test",
            "folder": "all",
            "top": "10",
            "includeBody": "1",
        }
        assert "first@example.test" not in "\n".join(logs)
        assert "first@example.test" in cf_outlook.used_path_for(str(inventory)).read_text(
            encoding="utf-8"
        )


def test_connectivity_probe_is_read_only():
    with tempfile.TemporaryDirectory() as tmp:
        inventory = Path(tmp) / "mailboxes.txt"
        inventory.write_text("probe@example.test\n", encoding="utf-8")
        seen = []

        def http_get(url, **kwargs):
            seen.append((url, kwargs))
            return FakeResponse({"success": True, "data": {"items": []}})

        result = connectivity.check_email_api(
            "cf_outlook",
            {
                "cf_outlook_api_base": "https://mail.example.com",
                "cf_outlook_api_key": "test-key",
                "cf_outlook_inventory": str(inventory),
            },
            http_get,
            lambda *_args, **_kwargs: None,
        )
        assert result[1] is True
        assert "cf_outlook 可达" in result[2]
        assert seen[0][0] == "https://mail.example.com/api/external/emails"
        assert not cf_outlook.used_path_for(str(inventory)).exists()


def test_api_random_account_mode():
    cf_outlook._reserved.clear()
    cf_outlook._sessions.clear()
    calls = []

    def http_get(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse(
            {
                "success": True,
                "data": {"email": "random@example.test", "status": "active"},
            }
        )

    email, token_key = cf_outlook.take_mailbox_from_api(
        http_get,
        "https://mail.example.com",
        "api-key-value",
    )
    assert email == "random@example.test"
    assert token_key.startswith("cf_outlook:")
    assert calls[0][0] == "https://mail.example.com/api/external/accounts/random"
    assert calls[0][1]["headers"]["X-API-Key"] == "api-key-value"
    assert calls[0][1]["params"] == {"status": "active"}
    cf_outlook.release_reservation(token_key, email)


if __name__ == "__main__":
    test_normalize_base_and_inventory_formats()
    test_take_wait_and_mark_used()
    test_connectivity_probe_is_read_only()
    test_api_random_account_mode()
    print("OK cf_outlook")
