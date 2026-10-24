"""Offline regression checks for the Outlook IMAP pool provider."""
from __future__ import annotations

import io
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from email_providers import outlook
from email_providers.common import extract_verification_code


def account_line(number=0):
    return f"review-{number}@example.test----fake-password----fake-client----fake-refresh-{number}"


class OutlookPoolTests(unittest.TestCase):
    def setUp(self):
        temp = self.enterContext(tempfile.TemporaryDirectory())
        self.pending = Path(temp).resolve() / "pending.txt"
        self.used = Path(temp).resolve() / "used.txt"
        self.pending.write_text(account_line() + "\n", encoding="utf-8")
        self.enterContext(patch.object(outlook, "refresh_access_token", return_value="fake-access"))
        self.baseline = self.enterContext(patch.object(outlook, "_max_uid", return_value=42))

    def take(self, used=None):
        return outlook.create_mailbox(str(self.pending), str(self.used) if used is None else used)

    def test_blank_used_path_uses_default_and_release_uses_same_file(self):
        with patch.object(outlook, "DEFAULT_USED_FILE", str(self.used)):
            address, token = self.take(used="")
            self.assertEqual(address, "review-0@example.test")
            self.assertTrue(token.endswith("----42"))
            self.assertEqual(self.pending.read_text(), "")
            self.assertEqual(self.used.read_text(), account_line() + "\n")
            self.assertTrue(outlook.release(str(self.pending), "", address))
            self.assertEqual(self.pending.read_text(), account_line() + "\n")
            self.assertEqual(self.used.read_text(), "")

    def test_failed_used_write_keeps_account_available(self):
        original = outlook.atomic_write_text
        def fail_used(path, text):
            if path == self.used:
                raise OSError("simulated used-file failure")
            return original(path, text)
        with patch.object(outlook, "atomic_write_text", side_effect=fail_used):
            with self.assertRaises(OSError):
                self.take()
        self.assertEqual(self.pending.read_text(), account_line() + "\n")
        self.assertFalse(self.used.exists())
        self.assertEqual(self.take()[0], "review-0@example.test")

    def test_successful_release_survives_legacy_console_encoding(self):
        address, _ = self.take()
        output = io.BytesIO()
        console = io.TextIOWrapper(output, encoding="cp1252")
        with patch.object(sys, "stdout", console):
            self.assertTrue(outlook.release(str(self.pending), str(self.used), address))
        console.flush()
        self.assertIn(address, output.getvalue().decode("cp1252"))
        self.assertEqual(self.pending.read_text(), account_line() + "\n")
        self.assertEqual(self.used.read_text(), "")

    def test_failed_pending_write_restores_used_ledger(self):
        self.used.write_text(account_line(99) + "\n", encoding="utf-8")
        original = outlook.atomic_write_text
        def fail_pending(path, text):
            if path == self.pending:
                raise OSError("simulated pending-file failure")
            return original(path, text)
        with patch.object(outlook, "atomic_write_text", side_effect=fail_pending):
            with self.assertRaises(OSError):
                self.take()
        self.assertEqual(self.pending.read_text(), account_line() + "\n")
        self.assertEqual(self.used.read_text(), account_line(99) + "\n")
        self.assertEqual(self.take()[0], "review-0@example.test")

    def test_partial_previous_write_cannot_claim_used_account_again(self):
        self.pending.write_text(account_line() + "\n" + account_line(1) + "\n")
        self.used.write_text(account_line() + "\n")
        self.assertEqual(self.take()[0], "review-1@example.test")
        with self.assertRaisesRegex(Exception, "已耗尽"):
            self.take()

    def test_pending_replace_then_error_keeps_durable_used_copy(self):
        original = outlook.atomic_write_text
        def fail_after_replace(path, text):
            result = original(path, text)
            if path == self.pending:
                raise OSError("simulated error after replace")
            return result
        with patch.object(outlook, "atomic_write_text", side_effect=fail_after_replace):
            with self.assertRaises(OSError):
                self.take()
        self.assertEqual(self.pending.read_text(), "")
        self.assertEqual(self.used.read_text(), account_line() + "\n")
        self.assertTrue(outlook.release(str(self.pending), str(self.used), "review-0@example.test"))
        self.assertEqual(self.pending.read_text(), account_line() + "\n")

    def test_failed_release_cannot_make_used_account_claimable(self):
        address, _ = self.take()
        original = outlook.atomic_write_text
        def fail_used(path, text):
            if path == self.used:
                raise OSError("simulated release failure")
            return original(path, text)
        with patch.object(outlook, "atomic_write_text", side_effect=fail_used):
            self.assertFalse(outlook.release(str(self.pending), str(self.used), address))
        with self.assertRaisesRegex(Exception, "已耗尽"):
            self.take()
        self.assertTrue(outlook.release(str(self.pending), str(self.used), address))
        self.assertEqual(self.pending.read_text(), account_line() + "\n")

    def test_baseline_failure_returns_account_without_submitting_it(self):
        self.baseline.side_effect = OSError("simulated IMAP failure")
        with self.assertRaisesRegex(RuntimeError, "基线 UID 探测失败"):
            self.take()
        self.assertEqual(self.pending.read_text(), account_line() + "\n")
        self.assertEqual(self.used.read_text(), "")

    def test_same_pool_and_used_file_is_rejected_without_modification(self):
        with self.assertRaises(ValueError):
            self.take(used=str(self.pending))
        self.assertEqual(self.pending.read_text(), account_line() + "\n")

    def test_invalid_account_error_does_not_echo_credentials(self):
        self.pending.write_text("review@example.test----fake-password\n")
        with self.assertRaisesRegex(Exception, "四个字段") as caught:
            self.take()
        self.assertNotIn("fake-password", str(caught.exception))
        self.assertIn("fake-password", self.pending.read_text())

    def test_parallel_threads_claim_each_account_once(self):
        self.pending.write_text("\n".join(account_line(i) for i in range(12)) + "\n")
        with ThreadPoolExecutor(max_workers=6) as executor:
            addresses = list(executor.map(lambda _: self.take()[0], range(12)))
        self.assertEqual(len(set(addresses)), 12)
        self.assertEqual(self.pending.read_text(), "")
        self.assertEqual(len(self.used.read_text().splitlines()), 12)

    def test_separate_pools_can_share_used_ledger_without_lost_rows(self):
        pools = [self.pending.with_name(f"pending-{i}.txt") for i in range(12)]
        for i, pool in enumerate(pools):
            pool.write_text(account_line(i) + "\n")
        with ThreadPoolExecutor(max_workers=6) as executor:
            addresses = list(executor.map(
                lambda pool: outlook.create_mailbox(str(pool), str(self.used))[0], pools,
            ))
        self.assertEqual(len(set(addresses)), 12)
        self.assertCountEqual(self.used.read_text().splitlines(), [account_line(i) for i in range(12)])
        self.assertTrue(all(pool.read_text() == "" for pool in pools))

    def test_separate_processes_claim_each_account_once(self):
        self.pending.write_text("\n".join(account_line(i) for i in range(4)) + "\n")
        code = """
import sys
from email_providers import outlook
outlook.refresh_access_token = lambda *args: 'fake-access'
outlook._max_uid = lambda *args: 42
print(outlook.create_mailbox(sys.argv[1], sys.argv[2])[0])
"""
        processes = [subprocess.Popen(
            [sys.executable, "-c", code, str(self.pending), str(self.used)],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ) for _ in range(4)]
        addresses = []
        try:
            for process in processes:
                stdout, stderr = process.communicate(timeout=30)
                self.assertEqual(process.returncode, 0, stderr)
                addresses.append(stdout.strip())
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
        self.assertEqual(len(set(addresses)), 4)
        self.assertEqual(self.pending.read_text(), "")
        self.assertEqual(len(self.used.read_text().splitlines()), 4)


class OutlookImapTests(unittest.TestCase):
    def test_old_uid_is_ignored_until_new_code_arrives(self):
        connection = Mock()
        connection.uid.side_effect = [
            ("OK", [b"42"]),  # Legal result of 43:* with no newer mail.
            ("OK", [b"43"]),
            ("OK", [(b"1 (UID 43)", (
                b"From: noreply@x.ai\r\nSubject: Your confirmation code DEF-456\r\n"
                b"Content-Type: text/plain\r\n\r\nYour code is DEF-456.\r\n"
            ))]),
        ]
        sleep = Mock()
        with patch.object(outlook, "_imap_login", return_value=connection), patch.object(
            outlook, "refresh_access_token", return_value="fake-access"
        ):
            code = outlook.wait_for_code(
                "fake-password----fake-client----fake-refresh----42", "review@example.test",
                extract_code=extract_verification_code, sleep_with_cancel=sleep,
            )
        self.assertEqual(code, "DEF-456")
        self.assertEqual(sleep.call_count, 1)
        fetches = [call for call in connection.uid.call_args_list if call.args[0] == "FETCH"]
        self.assertEqual([call.args[1] for call in fetches], [b"43"])

    def test_baseline_distinguishes_empty_inbox_from_failed_search(self):
        connection = Mock()
        connection.select.return_value = ("OK", [b"0"])
        with patch.object(outlook, "_imap_login", return_value=connection):
            connection.uid.return_value = ("OK", [b""])
            self.assertEqual(outlook._max_uid("review@example.test", "fake-access"), 0)
            connection.uid.return_value = ("OK", [b"7 42 19"])
            self.assertEqual(outlook._max_uid("review@example.test", "fake-access"), 42)
            connection.uid.return_value = ("NO", [b"search failed"])
            with self.assertRaisesRegex(RuntimeError, "基线 UID"):
                outlook._max_uid("review@example.test", "fake-access")
            connection.select.return_value = ("NO", [b"select failed"])
            with self.assertRaisesRegex(RuntimeError, "收件箱"):
                outlook._max_uid("review@example.test", "fake-access")

    def test_provider_imports_without_posix_fcntl(self):
        code = """
import builtins
original_import = builtins.__import__
def without_fcntl(name, *args, **kwargs):
    if name == 'fcntl':
        raise ModuleNotFoundError("No module named 'fcntl'")
    return original_import(name, *args, **kwargs)
builtins.__import__ = without_fcntl
from email_providers import outlook
"""
        result = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
