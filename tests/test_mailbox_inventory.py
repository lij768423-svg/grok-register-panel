# -*- coding: utf-8 -*-
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import grok_register_ttk as register
from email_providers import outlook_rt


def test_outlook_rt_exhausted_is_classified_as_mailbox():
    exc = register.MailboxInventoryExhausted(
        "Outlook RT 库存耗尽或预检均失败（已用/预留/死号），文件: stock.jsonl"
    )
    assert register.is_mailbox_inventory_exhausted(exc) is True
    assert register.classify_failure(exc) == register.FAIL_MAILBOX
    assert register.FAIL_LABELS[register.FAIL_MAILBOX] == "邮箱库存"


def test_provider_inventory_exhausted_is_detected():
    exc = outlook_rt.InventoryExhausted(
        "Outlook RT 库存耗尽或预检均失败（已用/预留/死号），文件: stock.jsonl"
    )
    assert register.is_mailbox_inventory_exhausted(exc) is True
    assert register.classify_failure(exc) == register.FAIL_MAILBOX


def test_other_failures_do_not_stop_for_inventory():
    assert register.is_mailbox_inventory_exhausted(Exception("未收到验证码")) is False
    assert register.classify_failure(Exception("未收到验证码")) == register.FAIL_CODE


if __name__ == "__main__":
    test_outlook_rt_exhausted_is_classified_as_mailbox()
    test_provider_inventory_exhausted_is_detected()
    test_other_failures_do_not_stop_for_inventory()
    print("OK mailbox inventory")
