# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sso_to_auth_json import (
    apply_config_defaults,
    consume_successful_records,
    existing_cpa_emails,
    load_sso_records,
    parse_sso_line,
    should_create_default_out_dir,
)


TOKEN_A = "a" * 80
TOKEN_B = "b" * 80


def test_parser_preserves_email_and_password():
    record = parse_sso_line(f"person@example.com----pass123----{TOKEN_A}")
    assert record is not None
    assert record.email == "person@example.com"
    assert record.password == "pass123"
    assert record.sso == TOKEN_A


def test_queue_dedup_and_consume():
    with tempfile.TemporaryDirectory() as temp:
        queue = Path(temp) / "sso_pending.txt"
        queue.write_text(
            f"first@example.com----{TOKEN_A}\n"
            f"first@example.com----merged-pass----{TOKEN_A}\n"
            f"second@example.com----pw----{TOKEN_B}\n",
            encoding="utf-8",
        )
        records = load_sso_records(path=str(queue))
        assert len(records) == 2
        assert records[0].email == "first@example.com"
        assert records[0].password == "merged-pass"
        remaining = consume_successful_records(queue, {TOKEN_A})
        assert remaining == 1
        assert TOKEN_A not in queue.read_text(encoding="utf-8")
        assert TOKEN_B in queue.read_text(encoding="utf-8")
        if os.name == "posix":
            assert stat.S_IMODE(queue.stat().st_mode) == 0o600


def test_account_scan_excludes_quarantined_risk_sso():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        accounts = root / "accounts"
        accounts.mkdir()
        normal = "n" * 80
        quarantined = "q" * 80
        (accounts / "normal@example.test.txt").write_text(
            f"normal@example.test----password----{normal}\n",
            encoding="utf-8",
        )
        (accounts / "sso_risk_rejected.txt").write_text(
            f"risk@example.test----{quarantined}----botFlagSource=2\n",
            encoding="utf-8",
        )

        records = load_sso_records(accounts_dir=str(accounts))

    assert [record.sso for record in records] == [normal]


def test_cpa_only_batch_does_not_create_auth_out():
    args = SimpleNamespace(
        out=None,
        out_dir=None,
        cpa_auth_dir="/tmp/cpa",
        cpa_remote_url=None,
        grok2api_auth_dir=None,
        merge=False,
    )
    assert should_create_default_out_dir(args, 2) is False


def test_existing_cpa_email_detection():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        (root / "xai-person@example.com.json").write_text(
            json.dumps({"email": "Person@Example.com"}),
            encoding="utf-8",
        )
        assert existing_cpa_emails(root) == {"person@example.com"}


def test_bfs_config_defaults_are_loaded_for_cli():
    with tempfile.TemporaryDirectory() as temp:
        config = Path(temp) / "config.json"
        config.write_text(
            json.dumps(
                {
                    "cpa_auth_dir": "cpa",
                    "grok2api_auth_dir": "g2a",
                    "bfs_check": False,
                    "bfs_skip_cpa": True,
                    "bfs_disable_cpa": True,
                }
            ),
            encoding="utf-8",
        )
        args = SimpleNamespace(
            from_config=str(config),
            cpa_auth_dir=None,
            grok2api_auth_dir=None,
            cpa_remote_url=None,
            cpa_management_key=None,
            proxy="",
            prefer=None,
            bfs_check=None,
            bfs_skip_write=None,
            bfs_disable=None,
        )
        apply_config_defaults(args)
        assert args.bfs_check is False
        assert args.bfs_skip_write is True
        assert args.bfs_disable is True
        assert args.cpa_auth_dir == str((Path(temp) / "cpa").resolve())
        assert args.grok2api_auth_dir == str((Path(temp) / "g2a").resolve())


if __name__ == "__main__":
    test_parser_preserves_email_and_password()
    test_queue_dedup_and_consume()
    test_account_scan_excludes_quarantined_risk_sso()
    test_cpa_only_batch_does_not_create_auth_out()
    test_existing_cpa_email_detection()
    test_bfs_config_defaults_are_loaded_for_cli()
    print("OK sso recovery")
