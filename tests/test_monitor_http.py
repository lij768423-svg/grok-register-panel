# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webui import monitor
from webui import email_domain_store
from webui import email_provider_store
from webui import process_utils
from webui import proxy_store


def test_compat_process_roots_require_existing_absolute_paths():
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        current = base / "current"
        previous = base / "previous"
        current.mkdir()
        previous.mkdir()
        roots = monitor._configured_process_roots(
            current,
            {
                "GROK_COMPAT_PROCESS_ROOTS": os.pathsep.join(
                    [str(previous), "relative-release", str(base / "missing"), str(current)]
                )
            },
        )
        assert roots == (current.resolve(), previous.resolve())


def test_process_discovery_aggregates_explicit_release_roots():
    previous_roots = monitor.MANAGED_PROCESS_ROOTS
    previous_find = monitor.find_managed_processes
    roots = (Path("/test/current"), Path("/test/previous"))
    calls = []

    def fake_find(root, script_names):
        calls.append((root, script_names))
        pid = 101 if root == roots[0] else 202
        return [{"pid": pid, "pgid": pid, "etime": "00:01", "cmd": "test"}]

    monitor.MANAGED_PROCESS_ROOTS = roots
    monitor.find_managed_processes = fake_find
    try:
        found = monitor._find_managed_processes(("run_until_100.py",))
    finally:
        monitor.MANAGED_PROCESS_ROOTS = previous_roots
        monitor.find_managed_processes = previous_find

    assert [item["pid"] for item in found] == [101, 202]
    assert [call[0] for call in calls] == list(roots)


def request(url: str, *, token: str = "", method: str = "GET", body: bytes | None = None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        response = urllib.request.urlopen(req, timeout=5)
        return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def test_monitor_http_auth_and_headers():
    token = "test-monitor-token-123456"
    previous = os.environ.get("MONITOR_TOKEN")
    os.environ["MONITOR_TOKEN"] = token
    server = monitor.ThreadingHTTPServer(("127.0.0.1", 0), monitor.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        status, headers, _ = request(base + "/api/health")
        assert status == 200
        assert headers.get("X-Frame-Options") == "DENY"
        assert "frame-ancestors 'none'" in headers.get("Content-Security-Policy", "")

        status, _, body = request(base + "/api/status")
        assert status == 401
        assert json.loads(body)["ok"] is False

        status, _, body = request(base + "/api/status", token=token)
        assert status == 200
        status_payload = json.loads(body)
        assert "process" in status_payload
        assert "traffic" in status_payload
        assert "bytes_up" in status_payload["traffic"]
        assert "traffic_summary" in status_payload
        assert "bytes_per_batch" in status_payload["traffic_summary"]
        assert "bytes_per_success" in status_payload["traffic_summary"]

        status, _, _ = request(base + "/api/recovery")
        assert status == 401
        status, _, body = request(base + "/api/recovery", token=token)
        assert status == 200
        assert "pending_count" in json.loads(body)

        status, _, _ = request(base + "/api/sso-state")
        assert status == 401
        status, _, body = request(base + "/api/sso-state", token=token)
        assert status == 200
        assert "sources" in json.loads(body)
        status, _, body = request(
            base + "/api/sso-state/start",
            method="POST",
            body=b'{"source":"paste","text":""}',
        )
        assert status == 401

        status, _, body = request(base + "/api/proxies")
        assert status == 401

        status, _, _ = request(
            base + "/api/control",
            method="POST",
            body=b"not-json",
        )
        assert status == 401

        status, _, _ = request(
            base + "/api/control",
            token=token,
            method="POST",
            body=b"not-json",
        )
        assert status == 400
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        if previous is None:
            os.environ.pop("MONITOR_TOKEN", None)
        else:
            os.environ["MONITOR_TOKEN"] = previous


def test_panel_registration_env_enables_guarded_cache():
    previous_enabled = os.environ.pop("GROK_STATIC_ASSET_CACHE", None)
    previous_dir = os.environ.pop("GROK_STATIC_CACHE_DIR", None)
    try:
        env = monitor._registration_env()
        assert env["GROK_STATIC_ASSET_CACHE"] == "1"
        assert Path(env["GROK_STATIC_CACHE_DIR"]).as_posix().endswith("log/static-asset-cache")
        node_path = Path(str(env.get("PLAYWRIGHT_NODEJS_PATH") or ""))
        if os.name == "nt":
            assert env.get("GROK_HEADLESS") == "1"
            assert env.get("PYTHONUTF8") == "1"
            assert node_path.name != "playwright-node"
        os.environ["GROK_STATIC_ASSET_CACHE"] = "0"
        assert monitor._registration_env()["GROK_STATIC_ASSET_CACHE"] == "0"
    finally:
        if previous_enabled is None:
            os.environ.pop("GROK_STATIC_ASSET_CACHE", None)
        else:
            os.environ["GROK_STATIC_ASSET_CACHE"] = previous_enabled
        if previous_dir is None:
            os.environ.pop("GROK_STATIC_CACHE_DIR", None)
        else:
            os.environ["GROK_STATIC_CACHE_DIR"] = previous_dir


def test_proxy_api_auth_mutations_and_redaction():
    token = "test-proxy-token-123456"
    secret = "proxy-secret-value-99"
    previous_token = os.environ.get("MONITOR_TOKEN")
    previous_paths = (
        proxy_store.STATE_PATH,
        proxy_store.LOCK_PATH,
        proxy_store.LEGACY_PATH,
    )
    with tempfile.TemporaryDirectory() as temp:
        base_path = Path(temp)
        proxy_store.STATE_PATH = base_path / "log" / "proxy_pool.json"
        proxy_store.LOCK_PATH = base_path / "log" / "proxy_pool.json.lock"
        proxy_store.LEGACY_PATH = base_path / "proxies.txt"
        os.environ["MONITOR_TOKEN"] = token
        server = monitor.ThreadingHTTPServer(("127.0.0.1", 0), monitor.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            payload = json.dumps(
                {"proxies": f"proxy.example:8080:worker:{secret}"}
            ).encode("utf-8")
            status, _, _ = request(
                base + "/api/proxies/import",
                method="POST",
                body=payload,
            )
            assert status == 401

            status, _, body = request(
                base + "/api/proxies/import",
                token=token,
                method="POST",
                body=payload,
            )
            assert status == 200
            imported = json.loads(body)
            assert imported["imported_count"] == 1
            assert secret not in body.decode("utf-8")
            proxy_id = imported["items"][0]["id"]

            status, _, body = request(base + "/api/proxies", token=token)
            assert status == 200
            assert secret not in body.decode("utf-8")
            assert json.loads(body)["items"][0]["has_auth"] is True

            status, _, body = request(
                base + f"/api/proxies/{proxy_id}",
                token=token,
                method="PATCH",
                body=b'{"enabled":false}',
            )
            assert status == 200
            assert json.loads(body)["items"][0]["enabled"] is False

            status, _, _ = request(
                base + f"/api/proxies/{proxy_id}",
                method="DELETE",
            )
            assert status == 401
            status, _, body = request(
                base + f"/api/proxies/{proxy_id}",
                token=token,
                method="DELETE",
            )
            assert status == 200
            assert json.loads(body)["summary"]["total"] == 0

            status, _, body = request(
                base + "/api/proxies/import",
                token=token,
                method="POST",
                body=json.dumps(
                    {
                        "proxies": (
                            f"proxy.example:8080:worker:{secret}\n"
                            "http://proxy.example:8081"
                        )
                    }
                ).encode("utf-8"),
            )
            assert status == 200
            assert json.loads(body)["imported_count"] == 2
            status, _, _ = request(base + "/api/proxies", method="DELETE")
            assert status == 401
            status, _, body = request(
                base + "/api/proxies",
                token=token,
                method="DELETE",
            )
            assert status == 200
            cleared = json.loads(body)
            assert cleared["deleted_count"] == 2
            assert cleared["summary"]["total"] == 0
            assert secret not in body.decode("utf-8")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            proxy_store.STATE_PATH, proxy_store.LOCK_PATH, proxy_store.LEGACY_PATH = previous_paths
            if previous_token is None:
                os.environ.pop("MONITOR_TOKEN", None)
            else:
                os.environ["MONITOR_TOKEN"] = previous_token


def test_email_domain_api_auth_and_mutations():
    token = "test-domain-token-123456"
    previous_token = os.environ.get("MONITOR_TOKEN")
    previous_paths = (
        email_domain_store.STATE_PATH,
        email_domain_store.LOCK_PATH,
    )
    with tempfile.TemporaryDirectory() as temp:
        base_path = Path(temp)
        email_domain_store.STATE_PATH = base_path / "log" / "email_domain_pool.json"
        email_domain_store.LOCK_PATH = base_path / "log" / "email_domain_pool.json.lock"
        os.environ["MONITOR_TOKEN"] = token
        server = monitor.ThreadingHTTPServer(("127.0.0.1", 0), monitor.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            status, _, _ = request(base + "/api/email-domains")
            assert status == 401

            payload = json.dumps(
                {
                    "provider": "cloudmail",
                    "domains": "mail.example.com\nmail.example.com\nbad-value",
                }
            ).encode("utf-8")
            status, _, _ = request(
                base + "/api/email-domains/import",
                method="POST",
                body=payload,
            )
            assert status == 401
            status, _, body = request(
                base + "/api/email-domains/import",
                token=token,
                method="POST",
                body=payload,
            )
            assert status == 200
            imported = json.loads(body)
            assert imported["imported_count"] == 1
            assert imported["duplicate_count"] == 1
            assert len(imported["errors"]) == 1
            domain_id = imported["items"][0]["id"]

            status, _, body = request(base + "/api/email-domains", token=token)
            assert status == 200
            assert json.loads(body)["items"][0]["provider"] == "cloudmail"

            status, _, body = request(
                base + "/api/email-domains/settings",
                token=token,
                method="POST",
                body=b'{"failure_threshold":2,"max_active_domains":1}',
            )
            assert status == 200
            assert json.loads(body)["settings"]["failure_threshold"] == 2

            status, _, body = request(
                base + f"/api/email-domains/{domain_id}",
                token=token,
                method="PATCH",
                body=b'{"enabled":false}',
            )
            assert status == 200
            assert json.loads(body)["items"][0]["enabled"] is False

            status, _, body = request(
                base + "/api/email-domains/reset",
                token=token,
                method="POST",
                body=json.dumps({"id": domain_id}).encode("utf-8"),
            )
            assert status == 200
            assert json.loads(body)["items"][0]["consecutive_rejections"] == 0

            status, _, _ = request(
                base + f"/api/email-domains/{domain_id}",
                method="DELETE",
            )
            assert status == 401
            status, _, body = request(
                base + f"/api/email-domains/{domain_id}",
                token=token,
                method="DELETE",
            )
            assert status == 200
            assert json.loads(body)["summary"]["total"] == 0
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            email_domain_store.STATE_PATH, email_domain_store.LOCK_PATH = previous_paths
            if previous_token is None:
                os.environ.pop("MONITOR_TOKEN", None)
            else:
                os.environ["MONITOR_TOKEN"] = previous_token


def test_email_provider_api_auth_secret_masking_and_probe():
    token = "test-email-provider-token-123456"
    secret = "provider-secret-value"
    previous_token = os.environ.get("MONITOR_TOKEN")
    previous_paths = (
        email_provider_store.CONFIG_PATH,
        email_provider_store.LOCK_PATH,
    )
    previous_test = monitor.test_email_provider_config
    calls = []
    with tempfile.TemporaryDirectory() as temp:
        base_path = Path(temp)
        email_provider_store.CONFIG_PATH = base_path / "config.json"
        email_provider_store.LOCK_PATH = base_path / "config.json.lock"

        def fake_test(provider, settings, *, clear_secrets=None):
            calls.append((provider, settings, clear_secrets))
            return {
                "ok": True,
                "provider": provider,
                "provider_label": "CloudMail",
                "detail": "CloudMail HTTP 200",
                "checked_at": "2026-07-31T00:00:00Z",
            }

        monitor.test_email_provider_config = fake_test
        os.environ["MONITOR_TOKEN"] = token
        server = monitor.ThreadingHTTPServer(("127.0.0.1", 0), monitor.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        payload = json.dumps(
            {
                "provider": "cloudmail",
                "settings": {
                    "cloudmail_url": "https://mail.example.com",
                    "cloudmail_admin_email": "admin@example.com",
                    "cloudmail_password": secret,
                    "defaultDomains": "mail.example.com",
                },
            }
        ).encode("utf-8")
        try:
            status, _, _ = request(base + "/api/email-provider")
            assert status == 401
            status, _, _ = request(
                base + "/api/email-provider",
                method="POST",
                body=payload,
            )
            assert status == 401

            status, _, body = request(
                base + "/api/email-provider",
                token=token,
                method="POST",
                body=payload,
            )
            assert status == 200
            assert secret not in body.decode("utf-8")
            saved = json.loads(body)
            assert saved["provider"] == "cloudmail"
            assert saved["secret_configured"]["cloudmail_password"] is True

            status, _, body = request(base + "/api/email-provider", token=token)
            assert status == 200
            assert secret not in body.decode("utf-8")
            assert json.loads(body)["values"]["cloudmail_password"] == ""

            status, _, body = request(
                base + "/api/email-provider/test",
                token=token,
                method="POST",
                body=json.dumps(
                    {
                        "provider": "cloudmail",
                        "settings": {"cloudmail_password": ""},
                    }
                ).encode("utf-8"),
            )
            assert status == 200
            assert json.loads(body)["detail"] == "CloudMail HTTP 200"
            assert calls == [("cloudmail", {"cloudmail_password": ""}, None)]

            status, _, _ = request(
                base + "/api/email-provider",
                token=token,
                method="POST",
                body=b'{"provider":"cloudmail","settings":{"proxy":"bad"}}',
            )
            assert status == 400
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            monitor.test_email_provider_config = previous_test
            email_provider_store.CONFIG_PATH, email_provider_store.LOCK_PATH = previous_paths
            if previous_token is None:
                os.environ.pop("MONITOR_TOKEN", None)
            else:
                os.environ["MONITOR_TOKEN"] = previous_token


def test_non_loopback_requires_token():
    env = dict(os.environ)
    env.pop("MONITOR_TOKEN", None)
    env["MONITOR_HOST"] = "192.0.2.10"
    env["MONITOR_PORT"] = "0"
    result = subprocess.run(
        [sys.executable, "-m", "webui.monitor"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode != 0
    assert "MONITOR_TOKEN is required" in (result.stdout + result.stderr)


def test_start_reports_unavailable_process_table():
    token = "test-runtime-token-123456"
    previous_token = os.environ.get("MONITOR_TOKEN")
    previous_find = monitor.find_managed_processes

    def unavailable(*_args, **_kwargs):
        raise process_utils.ProcessInspectionError(
            "无法读取系统进程列表；Linux 容器请确认 /proc 已挂载"
        )

    os.environ["MONITOR_TOKEN"] = token
    monitor.find_managed_processes = unavailable
    server = monitor.ThreadingHTTPServer(("127.0.0.1", 0), monitor.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, _, body = request(
            f"http://127.0.0.1:{server.server_port}/api/start",
            token=token,
            method="POST",
            body=b"{}",
        )
        payload = json.loads(body)
        assert status == 500
        assert "/proc" in payload["error"]
        assert "已挂载" in payload["error"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        monitor.find_managed_processes = previous_find
        if previous_token is None:
            os.environ.pop("MONITOR_TOKEN", None)
        else:
            os.environ["MONITOR_TOKEN"] = previous_token


if __name__ == "__main__":
    test_compat_process_roots_require_existing_absolute_paths()
    test_process_discovery_aggregates_explicit_release_roots()
    test_monitor_http_auth_and_headers()
    test_panel_registration_env_enables_guarded_cache()
    test_proxy_api_auth_mutations_and_redaction()
    test_email_domain_api_auth_and_mutations()
    test_email_provider_api_auth_secret_masking_and_probe()
    test_non_loopback_requires_token()
    test_start_reports_unavailable_process_table()
    print("OK monitor http")
