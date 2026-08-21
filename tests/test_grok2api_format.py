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

    class Response:
        status_code = 200

    def fake_post(url, **kwargs):
        calls["url"] = url
        calls["kwargs"] = kwargs
        return Response()

    previous = module.requests.post
    module.requests.post = fake_post
    try:
        name = upload_grok2api_auth_remote(
            "https://grok2api.example.test",
            "fixture-management-key",
            {"email": "person@example.test", "provider": "grok_build"},
        )
    finally:
        module.requests.post = previous

    assert name == "g2a-person@example.test.json"
    assert calls["url"] == "https://grok2api.example.test/api/admin/v1/accounts/import"
    assert calls["kwargs"]["headers"] == {
        "Accept": "text/event-stream",
        "Authorization": "Bearer fixture-management-key",
    }
    upload = calls["kwargs"]["files"]["files"]
    assert upload[0] == name
    assert upload[2] == "application/json"
    assert json.loads(upload[1].decode("utf-8")) == {
        "accounts": [{"email": "person@example.test", "provider": "grok_build"}]
    }


if __name__ == "__main__":
    test_token_maps_to_grok2api_account()
    test_write_grok2api_auth_uses_accounts_array()
    test_upload_grok2api_auth_remote_uses_multipart_files()
    print("OK grok2api format")
