"""Registration-stage recycling checks without a browser or real accounts."""
from __future__ import annotations

import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import grok_register_ttk as register


class OutlookWorkerTests(unittest.TestCase):
    def run_failure(self, stage):
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            pending = Path(temp) / "pending.txt"
            used = Path(temp) / "used.txt"
            rows = [f"review-{i}@example.test----fake-password----fake-client----fake-refresh" for i in range(2)]
            pending.write_text("\n".join(rows) + "\n")
            stack.enter_context(patch.dict(register.config, {
                "email_provider": "outlook", "register_workers": 2,
                "outlook_accounts_file": str(pending), "outlook_used_file": str(used),
                "enable_nsfw": False, "account_interval": "0",
            }))
            for name in (
                "cli_log", "_cleanup_stale_profiles", "set_thread_proxy", "start_browser",
                "open_signup_page", "record_register_result", "mark_slot_completed",
                "mark_successful_account", "maybe_stop_browser", "release_proxy_lease",
                "ensure_sso_oauth_eligible", "_append_sso_pending",
            ):
                stack.enter_context(patch.object(register, name))
            stack.enter_context(patch.object(register, "_restore_home_proxies", return_value={}))
            stack.enter_context(patch.object(register, "load_proxy_pool", return_value=[]))
            stack.enter_context(patch.object(register, "pick_proxy_for_worker", return_value=""))
            stack.enter_context(patch.object(register, "reserve_signup_submit_slot", return_value=0))
            stack.enter_context(patch.object(register._conn, "run_connectivity_checks", return_value=[]))
            stack.enter_context(patch.object(register._conn, "has_blocking_xai_failure", return_value=False))
            stack.enter_context(patch.object(register.outlook_provider, "refresh_access_token", return_value="fake-access"))
            stack.enter_context(patch.object(register.outlook_provider, "_max_uid", return_value=42))
            stack.enter_context(patch.object(register, "fill_email_and_submit", side_effect=lambda **kwargs:
                register.outlook_provider.create_mailbox(str(pending), str(used))))
            code = stack.enter_context(patch.object(register, "fill_code_and_submit", return_value="ABC-123"))
            profile = stack.enter_context(patch.object(register, "fill_profile_and_submit", return_value={"password": "fake-password"}))
            sso = stack.enter_context(patch.object(register, "wait_for_sso_cookie", return_value="fake-sso"))
            save = stack.enter_context(patch.object(register, "atomic_write_text"))
            stack.enter_context(patch.object(register, "account_file_for_email", return_value=Path(temp) / "account.txt"))
            if stage == "code":
                code.side_effect = RuntimeError("verification email unavailable")
            elif stage == "profile":
                profile.side_effect = RuntimeError("submission outcome unknown")
            elif stage == "sso":
                sso.side_effect = RuntimeError("sso_timeout")
            elif stage == "save":
                save.side_effect = OSError("simulated disk full")
            else:
                raise AssertionError(stage)
            register.run_registration_cli(2)
            self.assertEqual(code.call_count, 2)
            if stage != "code":
                self.assertEqual(profile.call_count, 2)
            if stage in ("sso", "save"):
                self.assertEqual(sso.call_count, 2)
            if stage == "save":
                self.assertEqual(save.call_count, 2)
            return pending.read_text().splitlines(), used.read_text().splitlines(), rows

    def test_failure_before_profile_submission_can_recycle(self):
        pending, used, rows = self.run_failure("code")
        self.assertCountEqual(pending, rows)
        self.assertEqual(used, [])

    def test_unknown_profile_submission_keeps_email_used(self):
        pending, used, rows = self.run_failure("profile")
        self.assertEqual(pending, [])
        self.assertCountEqual(used, rows)

    def test_sso_timeout_does_not_recycle_possibly_registered_account(self):
        pending, used, rows = self.run_failure("sso")
        self.assertEqual(pending, [])
        self.assertCountEqual(used, rows)

    def test_local_save_failure_does_not_recycle_registered_account(self):
        pending, used, rows = self.run_failure("save")
        self.assertEqual(pending, [])
        self.assertCountEqual(used, rows)


if __name__ == "__main__":
    unittest.main()
