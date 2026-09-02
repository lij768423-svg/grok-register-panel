# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import connectivity
from email_providers import icloud
from email_providers.common import extract_verification_code


class FakeResponse:
    def __init__(self, payload, status_code=200, cookies=None):
        self.payload = payload
        self.status_code = status_code
        self.text = json.dumps(payload)
        self.cookies = cookies or {"hme_session": "sess-1"}

    def json(self):
        return self.payload


def _raise_if_cancelled(callback=None):
    if callback and callback():
        raise RuntimeError("cancelled")


def _sleep(_seconds, _callback=None):
    return None


def test_normalize_base():
    assert icloud.normalize_base("") == ""
    assert icloud.normalize_base("127.0.0.1:8081") == "http://127.0.0.1:8081"
    assert icloud.normalize_base("http://127.0.0.1:8081/") == "http://127.0.0.1:8081"


def test_token_roundtrip():
    token = icloud.encode_mailbox_token(
        {"account_id": "acc_1", "anonymous_id": "anon-1", "email": "hide@icloud.com"}
    )
    meta = icloud.decode_mailbox_token(token)
    assert meta["account_id"] == "acc_1"
    assert meta["anonymous_id"] == "anon-1"
    assert meta["email"] == "hide@icloud.com"


def test_create_wait_and_cleanup():
    icloud.reset_runtime_state()
    calls = []

    def http_get(url, **kwargs):
        calls.append(("GET", url, kwargs))
        return FakeResponse(
            {
                "success": True,
                "data": {
                    "messages": [
                        {
                            "id": "1",
                            "to": "hide@icloud.com",
                            "subject": "ABC-123 xAI",
                            "preview": "Your verification code is ABC-123",
                        }
                    ]
                },
            }
        )

    def http_post(url, **kwargs):
        calls.append(("POST", url, kwargs))
        if url.endswith("/api/auth/login"):
            return FakeResponse({"success": True, "data": {"csrf_token": "csrf-1"}})
        return FakeResponse(
            {
                "success": True,
                "data": {
                    "email": "hide@icloud.com",
                    "anonymous_id": "anon-1",
                    "account_id": "acc_1",
                },
            }
        )

    def http_delete(url, **kwargs):
        calls.append(("DELETE", url, kwargs))
        return FakeResponse({"success": True, "data": {"deleted": True}})

    email, token = icloud.create_mailbox(
        http_get,
        http_post,
        http_delete,
        "http://127.0.0.1:8081",
        "admin-pass-2026",
        account_id="acc_1",
    )
    assert email == "hide@icloud.com"
    assert json.loads(token)["anonymous_id"] == "anon-1"
    assert icloud.pending_mailbox_token() == token

    code = icloud.wait_for_code(
        http_get,
        http_post,
        token,
        email,
        api_base="http://127.0.0.1:8081",
        admin_password="admin-pass-2026",
        timeout=5,
        poll_interval=1,
        http_delete=http_delete,
        raise_if_cancelled=_raise_if_cancelled,
        sleep_with_cancel=_sleep,
    )
    assert code == "ABC-123"
    assert icloud.pending_mailbox_token() == ""
    methods = [item[0] for item in calls]
    assert "DELETE" in methods
    delete = [item for item in calls if item[0] == "DELETE"][0]
    assert delete[2]["json"]["anonymous_id"] == "anon-1"
    assert delete[2]["headers"]["X-CSRF-Token"] == "csrf-1"
    assert delete[2]["proxies"] == {}


def test_extract_code_helper():
    assert extract_verification_code("hello", "ABC-123 xAI") == "ABC-123"


def test_connectivity_probe():
    seen = []

    def http_post(url, **kwargs):
        seen.append((url, kwargs))
        return FakeResponse({"success": True, "data": {"csrf_token": "csrf-1"}})

    result = connectivity.check_email_api(
        "icloud",
        {
            "icloud_hme_api_base": "http://127.0.0.1:8081/",
            "icloud_hme_admin_password": "admin-pass-2026",
        },
        lambda *args, **kwargs: None,
        http_post,
    )
    assert result[1] is True
    assert seen[0][0] == "http://127.0.0.1:8081/api/auth/login"
    assert seen[0][1]["proxies"] == {}

    missing = connectivity.check_email_api(
        "icloud",
        {"icloud_hme_api_base": "http://127.0.0.1:8081", "icloud_hme_admin_password": "short"},
        lambda *args, **kwargs: None,
        http_post,
    )
    assert missing[1] is False
    assert "icloud_hme_admin_password" in missing[2]


if __name__ == "__main__":
    test_normalize_base()
    test_token_roundtrip()
    test_create_wait_and_cleanup()
    test_extract_code_helper()
    test_connectivity_probe()
    print("OK icloud")
