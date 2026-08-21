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


class _FakeResponse:
    def __init__(self, status_code, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        return self._payload


class _FakeMultipart:
    def __init__(self):
        self.parts = []
        self.closed = False

    def addpart(self, **kwargs):
        self.parts.append(kwargs)

    def close(self):
        self.closed = True


def _install_fake_http(module, handler, multipart_holder=None):
    class FakeSession:
        def __init__(self, *args, **kwargs):
            pass

        def post(self, url, **kwargs):
            return handler(url, kwargs)

    class TrackingMime(_FakeMultipart):
        def __init__(self):
            super().__init__()
            if multipart_holder is not None:
                multipart_holder.append(self)

    previous_session = module.requests.Session
    previous_mime = module.CurlMime
    module.requests.Session = FakeSession
    module.CurlMime = TrackingMime
    return previous_session, previous_mime


def _restore_fake_http(module, previous_session, previous_mime):
    module.requests.Session = previous_session
    module.CurlMime = previous_mime


def test_upload_grok2api_auth_remote_uses_multipart_files(monkeypatch=None):
    import sso_to_auth_json as module

    calls = {}
    mimes = []

    def handler(url, kwargs):
        calls["url"] = url
        calls["kwargs"] = kwargs
        return _FakeResponse(200)

    previous_session, previous_mime = _install_fake_http(module, handler, mimes)
    try:
        name = upload_grok2api_auth_remote(
            "https://grok2api.example.test",
            "Bearer fixture-management-key",
            {"email": "person@example.test", "provider": "grok_build"},
        )
    finally:
        _restore_fake_http(module, previous_session, previous_mime)

    assert name == "g2a-person@example.test.json"
    assert calls["url"] == "https://grok2api.example.test/api/admin/v1/accounts/import"
    assert calls["kwargs"]["headers"] == {
        "Accept": "text/event-stream",
        "Authorization": "Bearer fixture-management-key",
    }
    assert "files" not in calls["kwargs"]
    assert "multipart" in calls["kwargs"]
    assert "impersonate" not in calls["kwargs"]
    assert calls["kwargs"]["proxies"] == {"http": "", "https": "", "all": ""}
    assert mimes and mimes[0].closed is True
    part = mimes[0].parts[0]
    assert part["name"] == "files"
    assert part["filename"] == name
    assert part["content_type"] == "application/json"
    assert json.loads(part["data"].decode("utf-8")) == {
        "accounts": [{"email": "person@example.test", "provider": "grok_build"}]
    }


def test_login_grok2api_reads_access_token(monkeypatch=None):
    import sso_to_auth_json as module

    calls = {}

    def handler(url, kwargs):
        calls["url"] = url
        calls["kwargs"] = kwargs
        return _FakeResponse(
            200, {"data": {"tokens": {"accessToken": "fixture-access-token"}}}
        )

    previous_session, previous_mime = _install_fake_http(module, handler)
    try:
        token = login_grok2api(
            "https://grok2api.example.test",
            "admin-fixture",
            "password-fixture",
        )
    finally:
        _restore_fake_http(module, previous_session, previous_mime)

    assert token == "fixture-access-token"
    assert calls["url"] == "https://grok2api.example.test/api/admin/v1/auth/login"
    assert calls["kwargs"]["json"] == {
        "username": "admin-fixture",
        "password": "password-fixture",
    }
    assert "impersonate" not in calls["kwargs"]
    assert calls["kwargs"]["proxies"] == {"http": "", "https": "", "all": ""}


def test_upload_grok2api_auth_remote_can_login_without_management_key():
    import sso_to_auth_json as module

    calls = []

    def handler(url, kwargs):
        calls.append((url, kwargs))
        if url.endswith("/auth/login"):
            return _FakeResponse(
                200, {"data": {"tokens": {"accessToken": "fixture-login-token"}}}
            )
        return _FakeResponse(200)

    previous_session, previous_mime = _install_fake_http(module, handler)
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
        _restore_fake_http(module, previous_session, previous_mime)

    assert calls[0][0].endswith("/api/admin/v1/auth/login")
    assert calls[1][1]["headers"]["Authorization"] == "Bearer fixture-login-token"


def test_upload_prefers_password_login_over_stale_management_jwt():
    import sso_to_auth_json as module

    calls = []
    stale = _jwt({"adminId": 1, "sessionId": 9, "exp": 1})

    def handler(url, kwargs):
        calls.append(url)
        if url.endswith("/auth/login"):
            return _FakeResponse(
                200, {"data": {"tokens": {"accessToken": "fixture-fresh-token"}}}
            )
        return _FakeResponse(200)

    previous_session, previous_mime = _install_fake_http(module, handler)
    try:
        upload_grok2api_auth_remote(
            "https://grok2api.example.test/admin",
            stale,
            {"email": "person@example.test", "provider": "grok_build"},
            username="admin-fixture",
            password="password-fixture",
            auth_state={},
        )
    finally:
        _restore_fake_http(module, previous_session, previous_mime)

    assert calls[0].endswith("/api/admin/v1/auth/login")
    assert calls[1] == "https://grok2api.example.test/api/admin/v1/accounts/import"


def test_upload_retries_login_after_401_even_with_management_key():
    import sso_to_auth_json as module

    calls = []
    logins = {"count": 0}

    def handler(url, kwargs):
        auth = kwargs.get("headers", {}).get("Authorization", "")
        calls.append(url)
        if url.endswith("/auth/login"):
            logins["count"] += 1
            return _FakeResponse(
                200,
                {
                    "data": {
                        "tokens": {"accessToken": f"fixture-token-{logins['count']}"}
                    }
                },
            )
        if url.endswith("/auth/refresh"):
            return _FakeResponse(401, text="invalid")
        if url.endswith("/accounts/import"):
            if auth == "Bearer fixture-token-1":
                return _FakeResponse(
                    401,
                    text='{"error":{"code":"adminUnauthorized","message":"管理员登录已失效"}}',
                )
            assert auth == "Bearer fixture-token-2"
            return _FakeResponse(200)
        return _FakeResponse(500, text="unexpected")

    previous_session, previous_mime = _install_fake_http(module, handler)
    try:
        upload_grok2api_auth_remote(
            "https://grok2api.example.test",
            "stale-opaque-key",
            {"email": "person@example.test", "provider": "grok_build"},
            username="admin-fixture",
            password="password-fixture",
            auth_state={},
        )
    finally:
        _restore_fake_http(module, previous_session, previous_mime)

    assert logins["count"] == 2
    assert calls[0].endswith("/auth/login")
    assert calls[-1].endswith("/accounts/import")


if __name__ == "__main__":
    test_token_maps_to_grok2api_account()
    test_write_grok2api_auth_uses_accounts_array()
    test_upload_grok2api_auth_remote_uses_multipart_files()
    test_login_grok2api_reads_access_token()
    test_upload_grok2api_auth_remote_can_login_without_management_key()
    test_upload_prefers_password_login_over_stale_management_jwt()
    test_upload_retries_login_after_401_even_with_management_key()
    print("OK grok2api format")
