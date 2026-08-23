# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import multiprocessing
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from email_providers import outlook_rt


def _claim_mailbox_worker(inventory: str, ready, release, results) -> None:
    from email_providers import outlook_rt as provider

    email, token = provider.take_mailbox(inventory)
    results.put(email)
    ready.set()
    release.wait(10)
    provider.release_reservation(token, email)


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n",
        encoding="utf-8",
    )


def test_load_jsonl_and_text_formats():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        jsonl = base / "stock.jsonl"
        _write_jsonl(
            jsonl,
            [
                {"email": "a@outlook.com", "refresh_token": "M.C5_AAA"},
                {"email": "b@outlook.com", "refresh_token": "M.C5_BBB", "client_id": "cid-1"},
            ],
        )
        accounts = outlook_rt.load_inventory(str(jsonl))
        assert len(accounts) == 2
        assert accounts[0]["email"] == "a@outlook.com"
        assert accounts[1]["client_id"] == "cid-1"

        txt = base / "stock.txt"
        txt.write_text(
            "c@outlook.com----RT_C\n"
            "d@outlook.com----pass----client-x----RT_D\n",
            encoding="utf-8",
        )
        accounts2 = outlook_rt.load_inventory(str(txt))
        assert {a["email"] for a in accounts2} == {"c@outlook.com", "d@outlook.com"}
        d = next(a for a in accounts2 if a["email"].startswith("d@"))
        assert d["client_id"] == "client-x"
        assert d["refresh_token"] == "RT_D"


def test_take_mark_used_and_stats():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        inv = base / "stock.jsonl"
        _write_jsonl(
            inv,
            [
                {"email": "one@outlook.com", "refresh_token": "RT1"},
                {"email": "two@outlook.com", "refresh_token": "RT2"},
            ],
        )
        # reset module reservation state
        outlook_rt._reserved.clear()
        outlook_rt._token_map.clear()

        email1, token1 = outlook_rt.take_mailbox(str(inv))
        assert email1 == "one@outlook.com"
        assert token1.startswith("outlook_rt:")
        stats = outlook_rt.inventory_stats(str(inv))
        assert stats["total"] == 2
        assert stats["available"] == 1

        email2, _token2 = outlook_rt.take_mailbox(str(inv))
        assert email2 == "two@outlook.com"

        try:
            outlook_rt.take_mailbox(str(inv))
            raise AssertionError("expected inventory exhausted")
        except outlook_rt.InventoryExhausted as exc:
            assert "耗尽" in str(exc)

        outlook_rt.mark_used(email1, str(inv))
        used_file = outlook_rt.used_path_for(str(inv))
        assert used_file.is_file()
        assert "one@outlook.com" in used_file.read_text(encoding="utf-8")


def test_cross_process_claims_are_unique():
    with tempfile.TemporaryDirectory() as tmp:
        inv = Path(tmp) / "stock.jsonl"
        _write_jsonl(
            inv,
            [
                {"email": "first@example.test", "refresh_token": "RT_FIRST"},
                {"email": "second@example.test", "refresh_token": "RT_SECOND"},
            ],
        )
        ctx = multiprocessing.get_context("spawn")
        ready1, ready2 = ctx.Event(), ctx.Event()
        release = ctx.Event()
        results = ctx.Queue()
        workers = [
            ctx.Process(
                target=_claim_mailbox_worker,
                args=(str(inv), ready, release, results),
            )
            for ready in (ready1, ready2)
        ]
        for worker in workers:
            worker.start()
        assert ready1.wait(10) and ready2.wait(10)
        claimed = {results.get(timeout=5), results.get(timeout=5)}
        release.set()
        for worker in workers:
            worker.join(10)
            assert worker.exitcode == 0
        assert claimed == {"first@example.test", "second@example.test"}


def test_find_code_in_messages():
    messages = [
        {
            "id": "1",
            "subject": "QO7-TUD xAI verification code",
            "bodyPreview": "Your verification code is QO7-TUD",
            "body": {"content": "<p>QO7-TUD</p>"},
            "receivedDateTime": "2099-01-01T00:00:00Z",
        }
    ]
    code = outlook_rt.find_code_in_messages(messages, seen=set(), after_ts=0)
    assert code == "QO7-TUD"


def test_graph_timestamp_is_utc_independent_of_host_timezone():
    if not hasattr(time, "tzset"):
        return
    previous = os.environ.get("TZ")
    try:
        os.environ["TZ"] = "America/Los_Angeles"
        time.tzset()
        messages = [{
            "id": "utc",
            "subject": "ABC-123 xAI verification code",
            "bodyPreview": "verification code ABC-123",
            "receivedDateTime": "2026-01-01T00:00:00Z",
        }]
        after = 1767225900.0  # 2026-01-01T00:05:00Z
        assert outlook_rt.find_code_in_messages(messages, after_ts=after) == "ABC-123"
    finally:
        if previous is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = previous
        time.tzset()


def test_wait_for_code_with_fake_http():
    with tempfile.TemporaryDirectory() as tmp:
        inv = Path(tmp) / "stock.jsonl"
        _write_jsonl(
            inv,
            [{"email": "fake@outlook.com", "refresh_token": "RT_FAKE"}],
        )
        outlook_rt._reserved.clear()
        outlook_rt._token_map.clear()
        email, token_key = outlook_rt.take_mailbox(str(inv))

        class Resp:
            def __init__(self, payload, status=200):
                self._payload = payload
                self.status_code = status
                self.text = json.dumps(payload)

            def json(self):
                return self._payload

        def http_post(url, **kwargs):
            assert "oauth" in url or "token" in url or "live.com" in url
            return Resp({"access_token": "AT_TEST", "refresh_token": "RT_NEW"})

        def http_get(url, **kwargs):
            assert "graph.microsoft.com" in url
            return Resp(
                {
                    "value": [
                        {
                            "id": "m1",
                            "subject": "CXX-PC2 xAI",
                            "bodyPreview": "verification code CXX-PC2",
                            "body": {"content": "code CXX-PC2"},
                            "receivedDateTime": "2099-06-01T12:00:00Z",
                        }
                    ]
                }
            )

        logs = []
        code = outlook_rt.wait_for_code(
            http_get,
            http_post,
            token_key,
            email,
            timeout=10,
            poll_interval=0,
            raise_if_cancelled=lambda _c: None,
            sleep_with_cancel=lambda _s, _c: None,
            log_callback=logs.append,
        )
        assert code == "CXX-PC2"
        used = outlook_rt.used_path_for(str(inv)).read_text(encoding="utf-8")
        assert "fake@outlook.com" in used
        # refresh rotation persisted
        row = json.loads(inv.read_text(encoding="utf-8").splitlines()[0])
        assert row["refresh_token"] == "RT_NEW"
        joined = "\n".join(logs)
        assert "fake@outlook.com" not in joined
        assert "CXX-PC2" not in joined
        assert "RT_NEW" not in joined


def test_wait_for_code_reads_junk_and_heartbeats():
    with tempfile.TemporaryDirectory() as tmp:
        inv = Path(tmp) / "stock.jsonl"
        _write_jsonl(
            inv,
            [{"email": "junkbox@outlook.com", "refresh_token": "RT_FAKE"}],
        )
        outlook_rt._reserved.clear()
        outlook_rt._token_map.clear()
        email, token_key = outlook_rt.take_mailbox(str(inv))

        class Resp:
            def __init__(self, payload, status=200):
                self._payload = payload
                self.status_code = status
                self.text = json.dumps(payload)

            def json(self):
                return self._payload

        def http_post(url, **kwargs):
            return Resp({"access_token": "AT_TEST", "expires_in": 3600})

        inbox_calls = {"n": 0}

        def http_get(url, **kwargs):
            if "junkemail" in str(url):
                return Resp(
                    {
                        "value": [
                            {
                                "id": "junk1",
                                "subject": "xAI verification",
                                "bodyPreview": "verification code JNK-441",
                                "body": {"content": "code JNK-441"},
                                "receivedDateTime": "2099-06-01T12:00:00Z",
                            }
                        ]
                    }
                )
            inbox_calls["n"] += 1
            return Resp({"value": []})

        logs = []
        code = outlook_rt.wait_for_code(
            http_get,
            http_post,
            token_key,
            email,
            timeout=10,
            poll_interval=0,
            raise_if_cancelled=lambda _c: None,
            sleep_with_cancel=lambda _s, _c: None,
            log_callback=logs.append,
        )
        assert code == "JNK-441"
        assert inbox_calls["n"] >= 1
        joined = "\n".join(logs)
        assert "JNK-441" not in joined
        assert "junkbox@" not in joined


def test_wait_for_code_heartbeat_uses_info_prefix():
    with tempfile.TemporaryDirectory() as tmp:
        inv = Path(tmp) / "stock.jsonl"
        _write_jsonl(
            inv,
            [{"email": "waitbox@outlook.com", "refresh_token": "RT_FAKE"}],
        )
        outlook_rt._reserved.clear()
        outlook_rt._token_map.clear()
        email, token_key = outlook_rt.take_mailbox(str(inv))

        class Resp:
            def __init__(self, payload, status=200):
                self._payload = payload
                self.status_code = status
                self.text = json.dumps(payload)

            def json(self):
                return self._payload

        def http_post(url, **kwargs):
            return Resp({"access_token": "AT_TEST", "expires_in": 3600})

        calls = {"n": 0}

        def http_get(url, **kwargs):
            if "junkemail" in str(url):
                return Resp({"value": []})
            calls["n"] += 1
            if calls["n"] == 1:
                return Resp({"value": []})
            return Resp(
                {
                    "value": [
                        {
                            "id": "m2",
                            "subject": "xAI verification",
                            "bodyPreview": "verification code HBX-902",
                            "body": {"content": "code HBX-902"},
                            "receivedDateTime": "2099-06-01T12:00:00Z",
                        }
                    ]
                }
            )

        logs = []
        code = outlook_rt.wait_for_code(
            http_get,
            http_post,
            token_key,
            email,
            timeout=10,
            poll_interval=0,
            raise_if_cancelled=lambda _c: None,
            sleep_with_cancel=lambda _s, _c: None,
            log_callback=logs.append,
        )
        assert code == "HBX-902"
        assert any(line.startswith("[*] Outlook RT 等待验证码") for line in logs)
        assert not any("[Debug] Outlook RT 等待验证码" in line for line in logs)


def test_wait_for_code_aborts_empty_inbox_and_marks_used():
    with tempfile.TemporaryDirectory() as tmp:
        inv = Path(tmp) / "stock.jsonl"
        _write_jsonl(
            inv,
            [{"email": "emptybox@outlook.com", "refresh_token": "RT_FAKE"}],
        )
        outlook_rt._reserved.clear()
        outlook_rt._token_map.clear()
        email, token_key = outlook_rt.take_mailbox(str(inv))

        class Resp:
            def __init__(self, payload, status=200):
                self._payload = payload
                self.status_code = status
                self.text = json.dumps(payload)

            def json(self):
                return self._payload

        clock = {"t": 1000.0}
        original_time = outlook_rt.time.time
        outlook_rt.time.time = lambda: clock["t"]

        def http_post(url, **kwargs):
            return Resp({"access_token": "AT_TEST", "expires_in": 3600})

        def http_get(url, **kwargs):
            return Resp({"value": []})

        def sleep_fn(seconds, _cancel):
            clock["t"] += max(1.0, float(seconds or 0) or 1.0)

        logs = []
        try:
            try:
                outlook_rt.wait_for_code(
                    http_get,
                    http_post,
                    token_key,
                    email,
                    timeout=180,
                    poll_interval=15,
                    empty_abort_seconds=20,
                    raise_if_cancelled=lambda _c: None,
                    sleep_with_cancel=sleep_fn,
                    log_callback=logs.append,
                )
                raise AssertionError("expected empty-inbox abort")
            except Exception as exc:
                assert "0 封信" in str(exc) or "收件箱为空" in str(exc)
                assert clock["t"] < 1100
            used = outlook_rt.used_path_for(str(inv)).read_text(encoding="utf-8")
            assert "emptybox@outlook.com" in used
            assert "code_empty_abort" in used
            assert any("记 used 后换号" in line for line in logs)
        finally:
            outlook_rt.time.time = original_time


def test_provider_store_outlook_rt_schema():
    from webui import email_provider_store

    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        prev = email_provider_store.CONFIG_PATH, email_provider_store.LOCK_PATH
        email_provider_store.CONFIG_PATH = base / "config.json"
        email_provider_store.LOCK_PATH = base / "config.json.lock"
        try:
            (base / "a.jsonl").write_text(
                '{"email":"configured@example.test","refresh_token":"RT"}\n',
                encoding="utf-8",
            )
            saved = email_provider_store.save_email_provider_config(
                "outlook_rt",
                {
                    "outlook_rt_inventory": str(base / "a.jsonl"),
                    "outlook_rt_client_id": "9e5f94bc-e8a4-4e73-b8be-63364c29d753",
                },
            )
            assert saved["provider"] == "outlook_rt"
            assert saved["configured"] is True
            assert saved["values"]["outlook_rt_inventory"].endswith("a.jsonl")
        finally:
            email_provider_store.CONFIG_PATH, email_provider_store.LOCK_PATH = prev


def test_take_mailbox_precheck_skips_dead_rt():
    """死 RT 预检失败应 mark used 并自动换下一个。"""
    with tempfile.TemporaryDirectory() as tmp:
        inv = Path(tmp) / "stock.jsonl"
        _write_jsonl(
            inv,
            [
                {"email": "dead@outlook.com", "refresh_token": "RT_DEAD"},
                {"email": "good@outlook.com", "refresh_token": "RT_GOOD"},
            ],
        )
        outlook_rt._reserved.clear()
        outlook_rt._token_map.clear()

        class Resp:
            def __init__(self, payload):
                self.status_code = 400
                self.text = json.dumps(payload)
                self._payload = payload

            def json(self):
                return self._payload

        calls = {"n": 0}

        def http_post(url, data=None, **kwargs):
            calls["n"] += 1
            # data may be dict
            rt = ""
            if isinstance(data, dict):
                rt = str(data.get("refresh_token") or "")
            if rt == "RT_DEAD":
                return Resp(
                    {
                        "error": "invalid_client",
                        "error_description": (
                            "AADSTS700016: The client does not exist or is not "
                            "enabled for consumers."
                        ),
                    }
                )
            return type(
                "R",
                (),
                {
                    "status_code": 200,
                    "text": '{"access_token":"AT","refresh_token":"RT_GOOD2"}',
                    "json": lambda self: {
                        "access_token": "AT",
                        "refresh_token": "RT_GOOD2",
                    },
                },
            )()

        logs = []
        email, token = outlook_rt.take_mailbox(
            str(inv),
            http_post=http_post,
            log_callback=logs.append,
            max_attempts=5,
        )
        assert email == "good@outlook.com"
        assert token.startswith("outlook_rt:")
        used = outlook_rt.used_path_for(str(inv)).read_text(encoding="utf-8")
        assert "dead@outlook.com" in used
        assert "good@outlook.com" not in used.split("----")[0] or "good@" not in used
        # good should not be marked used yet
        assert "good@outlook.com" not in {
            line.split("----", 1)[0].strip().lower()
            for line in used.splitlines()
            if line.strip()
        }


def test_take_mailbox_keeps_empty_inbox_by_default():
    with tempfile.TemporaryDirectory() as tmp:
        inv = Path(tmp) / "stock.jsonl"
        _write_jsonl(
            inv,
            [{"email": "empty@outlook.com", "refresh_token": "RT_EMPTY"}],
        )
        outlook_rt._reserved.clear()
        outlook_rt._token_map.clear()

        class Resp:
            def __init__(self, payload, status=200):
                self._payload = payload
                self.status_code = status
                self.text = json.dumps(payload)

            def json(self):
                return self._payload

        def http_post(url, **kwargs):
            return Resp({"access_token": "AT", "expires_in": 3600})

        def http_get(url, **kwargs):
            return Resp({"totalItemCount": 0, "unreadItemCount": 0})

        logs = []
        email, token = outlook_rt.take_mailbox(
            str(inv),
            http_post=http_post,
            http_get=http_get,
            log_callback=logs.append,
            max_attempts=3,
        )
        assert email == "empty@outlook.com"
        assert token.startswith("outlook_rt:")
        used = outlook_rt.used_path_for(str(inv))
        assert not used.exists() or "empty@outlook.com" not in used.read_text(
            encoding="utf-8"
        )
        assert not any("Inbox=0" in line for line in logs)


def test_take_mailbox_skips_empty_inbox():
    with tempfile.TemporaryDirectory() as tmp:
        inv = Path(tmp) / "stock.jsonl"
        _write_jsonl(
            inv,
            [
                {"email": "empty@outlook.com", "refresh_token": "RT_EMPTY"},
                {"email": "warm@outlook.com", "refresh_token": "RT_WARM"},
            ],
        )
        outlook_rt._reserved.clear()
        outlook_rt._token_map.clear()

        class Resp:
            def __init__(self, payload, status=200):
                self._payload = payload
                self.status_code = status
                self.text = json.dumps(payload)

            def json(self):
                return self._payload

        def http_post(url, **kwargs):
            return Resp({"access_token": "AT", "expires_in": 3600})

        def http_get(url, **kwargs):
            if "mailFolders/inbox" in str(url) and "messages" not in str(url):
                # first claimed empty, then warm
                n = 0 if http_get.calls == 0 else 3
                http_get.calls += 1
                return Resp({"totalItemCount": n, "unreadItemCount": n})
            return Resp({"value": []})

        http_get.calls = 0
        logs = []
        email, token = outlook_rt.take_mailbox(
            str(inv),
            http_post=http_post,
            http_get=http_get,
            log_callback=logs.append,
            max_attempts=5,
            skip_empty_inbox=True,
        )
        assert email == "warm@outlook.com"
        used = outlook_rt.used_path_for(str(inv)).read_text(encoding="utf-8")
        assert "empty@outlook.com" in used
        assert "precheck_empty_inbox" in used
        assert "warm@outlook.com" not in {
            line.split("----", 1)[0].strip().lower()
            for line in used.splitlines()
            if line.strip()
        }
        assert any("Inbox=0" in line for line in logs)


def test_wait_for_code_fast_fail_on_dead_refresh():
    """等码阶段 refresh 死号应秒退并 mark used，不空耗 timeout。"""
    with tempfile.TemporaryDirectory() as tmp:
        inv = Path(tmp) / "stock.jsonl"
        _write_jsonl(
            inv,
            [{"email": "dead2@outlook.com", "refresh_token": "RT_DEAD2"}],
        )
        outlook_rt._reserved.clear()
        outlook_rt._token_map.clear()
        email, token_key = outlook_rt.take_mailbox(str(inv))  # no precheck

        class Resp:
            def __init__(self, payload):
                self.status_code = 400
                self.text = json.dumps(payload)
                self._payload = payload

            def json(self):
                return self._payload

        def http_post(url, **kwargs):
            return Resp(
                {
                    "error": "invalid_grant",
                    "error_description": "AADSTS50173: The grant was expired.",
                }
            )

        def http_get(url, **kwargs):
            raise AssertionError("should not list messages after dead refresh")

        t0 = __import__("time").time()
        try:
            outlook_rt.wait_for_code(
                http_get,
                http_post,
                token_key,
                email,
                timeout=180,
                poll_interval=0,
                raise_if_cancelled=lambda _c: None,
                sleep_with_cancel=lambda _s, _c: None,
            )
            raise AssertionError("expected fail")
        except Exception as exc:
            assert "已弃用" in str(exc) or "refresh" in str(exc).lower()
        elapsed = __import__("time").time() - t0
        assert elapsed < 5, f"should fast-fail, took {elapsed:.1f}s"
        used = outlook_rt.used_path_for(str(inv)).read_text(encoding="utf-8")
        assert "dead2@outlook.com" in used


def test_probe_persists_rotated_refresh_token_without_consuming_inventory():
    with tempfile.TemporaryDirectory() as tmp:
        inv = Path(tmp) / "stock.jsonl"
        _write_jsonl(
            inv,
            [{"email": "probe@example.test", "refresh_token": "RT_ORIGINAL"}],
        )

        class Resp:
            status_code = 200
            text = '{"access_token":"AT","refresh_token":"RT_ROTATED"}'

            def json(self):
                return {"access_token": "AT", "refresh_token": "RT_ROTATED"}

        detail = outlook_rt.probe_inventory(lambda *_a, **_k: Resp(), str(inv))
        assert "refresh OK" in detail
        assert "probe@example.test" not in detail
        row = json.loads(inv.read_text(encoding="utf-8").splitlines()[0])
        assert row["refresh_token"] == "RT_ROTATED"
        stats = outlook_rt.inventory_stats(str(inv))
        assert stats == {"total": 1, "used": 0, "available": 1}


def test_transient_graph_failure_does_not_consume_inventory():
    with tempfile.TemporaryDirectory() as tmp:
        inv = Path(tmp) / "stock.jsonl"
        _write_jsonl(
            inv,
            [{"email": "transient@example.test", "refresh_token": "RT_PRIVATE"}],
        )
        outlook_rt._reserved.clear()
        outlook_rt._token_map.clear()
        email, token_key = outlook_rt.take_mailbox(str(inv))

        class Resp:
            status_code = 200
            text = '{"access_token":"AT"}'

            def json(self):
                return {"access_token": "AT"}

        def fail_graph(*_args, **_kwargs):
            raise RuntimeError("Graph messages HTTP 503 secret=RT_PRIVATE")

        ticks = iter([0.0, 0.0, 0.0, 2.0])
        original_time = outlook_rt.time.time
        outlook_rt.time.time = lambda: next(ticks, 2.0)
        logs = []
        try:
            try:
                outlook_rt.wait_for_code(
                    fail_graph,
                    lambda *_a, **_k: Resp(),
                    token_key,
                    email,
                    timeout=1,
                    poll_interval=0,
                    raise_if_cancelled=lambda _c: None,
                    sleep_with_cancel=lambda _s, _c: None,
                    log_callback=logs.append,
                )
                raise AssertionError("expected timeout")
            except Exception as exc:
                assert "未收到验证码" in str(exc)
        finally:
            outlook_rt.time.time = original_time
        used = outlook_rt.used_path_for(str(inv))
        assert not used.exists() or "transient@example.test" not in used.read_text(
            encoding="utf-8"
        )
        assert "RT_PRIVATE" not in "\n".join(logs)


def test_upsert_inventory_and_unmark_used():
    with tempfile.TemporaryDirectory() as tmp:
        inv = Path(tmp) / "stock.jsonl"
        inv.write_text(
            json.dumps({"email": "keep@example.test", "refresh_token": "RT_OLD"})
            + "\n",
            encoding="utf-8",
        )
        outlook_rt.mark_used("keep@example.test", str(inv), reason="precheck_fail")
        updated = outlook_rt.upsert_inventory_account(
            str(inv), "keep@example.test", "RT_NEW", client_id="cid-1"
        )
        created = outlook_rt.upsert_inventory_account(
            str(inv), "new@example.test", "RT_FRESH"
        )
        assert updated == "updated"
        assert created == "created"
        assert outlook_rt.unmark_used("keep@example.test", str(inv)) is True
        rows = {
            item["email"]: item
            for item in outlook_rt.list_inventory_accounts(str(inv))
        }
        assert rows["keep@example.test"]["refresh_token"] == "RT_NEW"
        assert rows["new@example.test"]["refresh_token"] == "RT_FRESH"


if __name__ == "__main__":
    test_load_jsonl_and_text_formats()
    test_take_mark_used_and_stats()
    test_cross_process_claims_are_unique()
    test_find_code_in_messages()
    test_graph_timestamp_is_utc_independent_of_host_timezone()
    test_wait_for_code_with_fake_http()
    test_wait_for_code_reads_junk_and_heartbeats()
    test_wait_for_code_heartbeat_uses_info_prefix()
    test_wait_for_code_aborts_empty_inbox_and_marks_used()
    test_provider_store_outlook_rt_schema()
    test_take_mailbox_precheck_skips_dead_rt()
    test_take_mailbox_keeps_empty_inbox_by_default()
    test_take_mailbox_skips_empty_inbox()
    test_wait_for_code_fast_fail_on_dead_refresh()
    test_probe_persists_rotated_refresh_token_without_consuming_inventory()
    test_transient_graph_failure_does_not_consume_inventory()
    test_upsert_inventory_and_unmark_used()
    print("ok")
