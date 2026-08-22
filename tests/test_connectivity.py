# -*- coding: utf-8 -*-
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import connectivity


class FakeResponse:
    def __init__(self, payload=None, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def json(self):
        return self.payload


def test_check_cpa_grok2api_login_probe_uses_http_post():
    posts = []

    def http_post(url, **kwargs):
        posts.append((url, kwargs))
        return FakeResponse({"data": {"tokens": {"accessToken": "fixture-access-token"}}})

    previous = connectivity._tcp_open
    connectivity._tcp_open = lambda host, port: True
    try:
        result = connectivity.check_cpa(
            {
                "cpa_auto_add": True,
                "grok2api_remote_url": "https://grok2api.example.test",
                "grok2api_username": "admin-fixture",
                "grok2api_password": "password-fixture",
            },
            lambda *args, **kwargs: None,
            http_post,
        )
    finally:
        connectivity._tcp_open = previous

    assert result[0] == "CPA"
    assert result[1] is True
    assert "Grok2API登录OK" in result[2]
    assert "http_post" not in result[2]
    assert posts[0][0] == "https://grok2api.example.test/api/admin/v1/auth/login"
    assert posts[0][1]["json"] == {
        "username": "admin-fixture",
        "password": "password-fixture",
    }
    assert posts[0][1]["proxies"] == {"http": "", "https": "", "all": ""}


def test_check_cpa_grok2api_login_probe_reports_invalid_credentials():
    def http_post(url, **kwargs):
        return FakeResponse(status_code=401)

    previous = connectivity._tcp_open
    connectivity._tcp_open = lambda host, port: True
    try:
        result = connectivity.check_cpa(
            {
                "cpa_auto_add": True,
                "grok2api_remote_url": "https://grok2api.example.test",
                "grok2api_username": "admin-fixture",
                "grok2api_password": "wrong-password",
            },
            lambda *args, **kwargs: None,
            http_post,
        )
    finally:
        connectivity._tcp_open = previous

    assert result[1] is False
    assert "登录账号或密码无效" in result[2]


def test_check_cpa_grok2api_remote_requires_login_credentials():
    result = connectivity.check_cpa(
        {
            "cpa_auto_add": True,
            "grok2api_remote_url": "https://grok2api.example.test",
            "grok2api_management_key": "stale-fixture-jwt",
        },
        lambda *args, **kwargs: None,
        lambda *args, **kwargs: None,
    )
    assert result[1] is False
    assert "缺少登录账号密码" in result[2]


def test_run_connectivity_checks_passes_http_post_to_cpa():
    seen = {}

    def http_post(url, **kwargs):
        seen["url"] = url
        return FakeResponse({"data": {"tokens": {"accessToken": "fixture-access-token"}}})

    previous = connectivity._tcp_open
    connectivity._tcp_open = lambda host, port: True
    try:
        results = connectivity.run_connectivity_checks(
            {
                "cpa_auto_add": True,
                "grok2api_remote_url": "https://grok2api.example.test",
                "grok2api_username": "admin-fixture",
                "grok2api_password": "password-fixture",
            },
            lambda *args, **kwargs: FakeResponse(status_code=200),
            http_post,
        )
    finally:
        connectivity._tcp_open = previous

    cpa = next(item for item in results if item[0] == "CPA")
    assert cpa[1] is True
    assert "Grok2API登录OK" in cpa[2]
    assert seen["url"] == "https://grok2api.example.test/api/admin/v1/auth/login"


if __name__ == "__main__":
    test_check_cpa_grok2api_login_probe_uses_http_post()
    test_check_cpa_grok2api_login_probe_reports_invalid_credentials()
    test_check_cpa_grok2api_remote_requires_login_credentials()
    test_run_connectivity_checks_passes_http_post_to_cpa()
    print("OK connectivity")
