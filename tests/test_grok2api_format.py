# -*- coding: utf-8 -*-
"""Regression tests for the Grok2API accounts auth format."""
from __future__ import annotations

import base64
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sso_to_auth_json import (  # noqa: E402
    login_grok2api,
    token_to_grok2api_account,
    upload_grok2api_auth_remote,
    write_grok2api_auth,
)


def _jwt(payload: dict) -> str:
    def encode(value: object) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    return f"{encode({'alg': 'none'})}.{encode(payload)}.fixture-signature"


def test_token_maps_to_grok2api_account():
    access = _jwt(
        {
            "sub": "user-fixture-123",
            "client_id": "client-fixture-123",
            "principal_id": "principal-fixture-123",
            "team_id": "team-fixture-123",
            "exp": 2000000000,
        }
    )
    account = token_to_grok2api_account(
        {
            "access_token": access,
            "refresh_token": "refresh-fixture",
            "token_type": "Bearer",
            "scope": "openid profile",
        },
        email="person@example.test",
    )

    assert account == {
        "provider": "grok_build",
        "name": "person@example.test",
        "client_id": "client-fixture-123",
        "access_token": access,
        "refresh_token": "refresh-fixture",
        "id_token": "",
        "token_type": "Bearer",
        "scope": "openid profile",
        "expires_at": "2033-05-18T03:33:20.000000000Z",
        "expires_in": 0,
        "email": "person@example.test",
        "sub": "user-fixture-123",
        "user_id": "user-fixture-123",
        "principal_id": "principal-fixture-123",
        "team_id": "team-fixture-123",
    }


def test_write_grok2api_auth_uses_accounts_array():
    access = _jwt({"sub": "user-fixture-456", "exp": 2000000000})
    with tempfile.TemporaryDirectory() as temp:
        path = write_grok2api_auth(
            Path(temp),
            {"access_token": access, "refresh_token": "refresh-fixture"},
            email="person@example.test",
        )
        document = json.loads(path.read_text(encoding="utf-8"))

    assert list(document) == ["accounts"]
    assert isinstance(document["accounts"], list)
    assert len(document["accounts"]) == 1
    assert document["accounts"][0]["provider"] == "grok_build"
    assert document["accounts"][0]["email"] == "person@example.test"
    assert document["accounts"][0]["user_id"] == "user-fixture-456"


def test_upload_grok2api_auth_remote_uses_multipart_files(monkeypatch=None):
    import sso_to_auth_json as module

    calls = {}
    multipart_parts = {}

    class Response:
        status_code = 200

    def fake_post(url, **kwargs):
        calls["url"] = url
        calls["kwargs"] = kwargs
        return Response()

    class FakeMultipart:
        @classmethod
        def from_list(cls, parts):
            multipart_parts["parts"] = parts
            return cls()

        def close(self):
            multipart_parts["closed"] = True

    previous = module.requests.post
    previous_mime = module.CurlMime
    module.requests.post = fake_post
    module.CurlMime = FakeMultipart
    try:
        name = upload_grok2api_auth_remote(
            "https://grok2api.example.test",
            "Bearer fixture-management-key",
            {"email": "person@example.test", "provider": "grok_build"},
        )
    finally:
        module.requests.post = previous
        module.CurlMime = previous_mime

    assert name == "g2a-person@example.test.json"
    assert calls["url"] == "https://grok2api.example.test/api/admin/v1/accounts/import"
    assert calls["kwargs"]["headers"] == {
        "Accept": "text/event-stream",
        "Authorization": "Bearer fixture-management-key",
    }
    assert "files" not in calls["kwargs"]
    assert "multipart" in calls["kwargs"]
    assert multipart_parts["closed"] is True
    part = multipart_parts["parts"][0]
    assert part["name"] == "files"
    assert part["filename"] == name
    assert part["content_type"] == "application/json"
    assert json.loads(part["data"].decode("utf-8")) == {
        "accounts": [{"email": "person@example.test", "provider": "grok_build"}]
    }


def test_login_grok2api_reads_access_token(monkeypatch=None):
    import sso_to_auth_json as module

    calls = {}

    class Response:
        status_code = 200

        def json(self):
            return {"data": {"tokens": {"accessToken": "fixture-access-token"}}}

    def fake_post(url, **kwargs):
        calls["url"] = url
        calls["kwargs"] = kwargs
        return Response()

    previous = module.requests.post
    module.requests.post = fake_post
    try:
        token = login_grok2api(
            "https://grok2api.example.test",
            "admin-fixture",
            "password-fixture",
        )
    finally:
        module.requests.post = previous

    assert token == "fixture-access-token"
    assert calls["url"] == "https://grok2api.example.test/api/admin/v1/auth/login"
    assert calls["kwargs"]["json"] == {
        "username": "admin-fixture",
        "password": "password-fixture",
    }


def test_upload_grok2api_auth_remote_can_login_without_management_key():
    import sso_to_auth_json as module

    calls = []

    class Response:
        def __init__(self, status_code, payload=None):
            self.status_code = status_code
            self._payload = payload
            self.text = ""

        def json(self):
            return self._payload

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        if url.endswith("/auth/login"):
            return Response(200, {"data": {"tokens": {"accessToken": "fixture-login-token"}}})
        return Response(200)

    class FakeMultipart:
        @classmethod
        def from_list(cls, parts):
            return cls()

        def close(self):
            pass

    previous_post = module.requests.post
    previous_mime = module.CurlMime
    module.requests.post = fake_post
    module.CurlMime = FakeMultipart
    try:
        upload_grok2api_auth_remote(
            "https://grok2api.example.test",
            "",
            {"email": "person@example.test", "provider": "grok_build"},
            username="admin-fixture",
            password="password-fixture",
            auth_state={},
        )
    finally:
        module.requests.post = previous_post
        module.CurlMime = previous_mime

    assert calls[0][0].endswith("/api/admin/v1/auth/login")
    assert calls[1][1]["headers"]["Authorization"] == "Bearer fixture-login-token"


if __name__ == "__main__":
    test_token_maps_to_grok2api_account()
    test_write_grok2api_auth_uses_accounts_array()
    test_upload_grok2api_auth_remote_uses_multipart_files()
    test_login_grok2api_reads_access_token()
    test_upload_grok2api_auth_remote_can_login_without_management_key()
    print("OK grok2api format")
