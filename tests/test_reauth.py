# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webui import reauth_ops
from webui import recovery_ops


def test_compare_sso_to_remote_marks_missing():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        accounts = base / "accounts"
        accounts.mkdir()
        (accounts / "keep@example.test.txt").write_text(
            "keep@example.test----pass----" + ("k" * 80) + "\n",
            encoding="utf-8",
        )
        (accounts / "need@example.test.txt").write_text(
            "need@example.test----pass----" + ("n" * 80) + "\n",
            encoding="utf-8",
        )
        config = base / "config.json"
        config.write_text(
            json.dumps(
                {
                    "grok2api_remote_url": "https://grok2api.example.test",
                    "grok2api_username": "admin-fixture",
                    "grok2api_password": "password-fixture",
                }
            ),
            encoding="utf-8",
        )
        previous = (
            reauth_ops.CONFIG_FILE,
            reauth_ops.ACCOUNTS_DIR,
            recovery_ops.CONFIG_FILE,
            recovery_ops.ACCOUNTS_DIR,
        )
        reauth_ops.CONFIG_FILE = config
        reauth_ops.ACCOUNTS_DIR = accounts
        recovery_ops.CONFIG_FILE = config
        recovery_ops.ACCOUNTS_DIR = accounts
        try:
            result = reauth_ops.compare_sso_to_remote(
                "accounts",
                list_accounts=lambda *_args, **_kwargs: [
                    {"email": "keep@example.test", "auth_status": "active"}
                ],
            )
        finally:
            (
                reauth_ops.CONFIG_FILE,
                reauth_ops.ACCOUNTS_DIR,
                recovery_ops.CONFIG_FILE,
                recovery_ops.ACCOUNTS_DIR,
            ) = previous
        assert result["ok"] is True
        assert result["summary"]["sso"] == 2
        assert result["summary"]["remote"] == 1
        assert result["compare"]["present"] == ["keep@example.test"]
        assert result["compare"]["missing"] == ["need@example.test"]
        dumped = json.dumps(result)
        assert "k" * 80 not in dumped
        assert "n" * 80 not in dumped


def test_start_reauth_missing_writes_queue_without_skipping():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        accounts = base / "accounts"
        log_dir = base / "log"
        accounts.mkdir()
        log_dir.mkdir()
        (accounts / "need@example.test.txt").write_text(
            "need@example.test----pass----" + ("n" * 80) + "\n",
            encoding="utf-8",
        )
        config = base / "config.json"
        config.write_text(
            json.dumps(
                {
                    "grok2api_remote_url": "https://grok2api.example.test",
                    "grok2api_username": "admin-fixture",
                    "grok2api_password": "password-fixture",
                }
            ),
            encoding="utf-8",
        )
        previous = (
            reauth_ops.CONFIG_FILE,
            reauth_ops.ACCOUNTS_DIR,
            reauth_ops.LOG_DIR,
            reauth_ops.QUEUE_FILE,
            reauth_ops.REPORT_FILE,
            reauth_ops.PID_FILE,
            recovery_ops.CONFIG_FILE,
            recovery_ops.ACCOUNTS_DIR,
        )
        reauth_ops.CONFIG_FILE = config
        reauth_ops.ACCOUNTS_DIR = accounts
        reauth_ops.LOG_DIR = log_dir
        reauth_ops.QUEUE_FILE = log_dir / "reauth_sso.txt"
        reauth_ops.REPORT_FILE = log_dir / "reauth_report.json"
        reauth_ops.PID_FILE = log_dir / "reauth.pid"
        recovery_ops.CONFIG_FILE = config
        recovery_ops.ACCOUNTS_DIR = accounts
        launched = []

        def fake_popen(command, **kwargs):
            launched.append(command)

            class Proc:
                pid = 4242

            return Proc()

        previous_popen = reauth_ops.subprocess.Popen
        previous_find = reauth_ops.find_managed_processes
        previous_write = reauth_ops.write_pid_file
        reauth_ops.subprocess.Popen = fake_popen
        reauth_ops.find_managed_processes = lambda *_args, **_kwargs: []
        reauth_ops.write_pid_file = lambda *_args, **_kwargs: None
        try:
            result = reauth_ops.start_reauth_missing(
                "accounts",
                list_accounts=lambda *_args, **_kwargs: [],
            )
        finally:
            reauth_ops.subprocess.Popen = previous_popen
            reauth_ops.find_managed_processes = previous_find
            reauth_ops.write_pid_file = previous_write
            (
                reauth_ops.CONFIG_FILE,
                reauth_ops.ACCOUNTS_DIR,
                reauth_ops.LOG_DIR,
                reauth_ops.QUEUE_FILE,
                reauth_ops.REPORT_FILE,
                reauth_ops.PID_FILE,
                recovery_ops.CONFIG_FILE,
                recovery_ops.ACCOUNTS_DIR,
            ) = previous
        assert result["ok"] is True
        assert result["input_count"] == 1
        assert "--no-skip-existing" in launched[0]
        queue = Path(launched[0][launched[0].index("--sso") + 1])
        text = queue.read_text(encoding="utf-8")
        assert "need@example.test" in text
        assert "n" * 80 in text


if __name__ == "__main__":
    test_compare_sso_to_remote_marks_missing()
    test_start_reauth_missing_writes_queue_without_skipping()
    print("OK reauth")
