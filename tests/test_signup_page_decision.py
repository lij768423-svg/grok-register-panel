"""Decisions that choose blank-reload vs wait, and which requests the cache may touch."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import register_flow
import static_asset_cache
from signup_decisions import (
    email_submit_deny_keywords,
    email_submit_needs_turnstile,
    fill_gave_up_message,
    label_matches_deny,
    native_type_confirmed,
    should_reload_blank,
    signup_block_reason,
    signup_code_sent,
    signup_probe_kind,
)


def test_cloudflare_challenge_is_not_reloaded_at_five_seconds():
    snapshot = {
        "state": "not-ready",
        "title": "Just a moment...",
        "body": "Checking your browser before continuing",
        "inputs": [],
        "buttons": [],
        "iframes": ["https://challenges.cloudflare.com/cdn-cgi/challenge-platform"],
    }
    kind = register_flow.signup_probe_kind(snapshot)
    assert kind == "cf-wait"
    assert signup_probe_kind(snapshot) == "cf-wait"
    assert (
        register_flow.should_reload_blank(
            kind=kind, blank_seconds=5, since_reload=5, reloads=0
        )
        is False
    )
    assert (
        should_reload_blank(kind=kind, blank_seconds=25, since_reload=25, reloads=0)
        is True
    )


def test_empty_document_survives_the_old_five_second_reload():
    snapshot = {"state": "not-ready", "title": "", "body": "", "inputs": [], "buttons": []}
    kind = register_flow.signup_probe_kind(snapshot)
    assert kind == "blank"
    assert (
        register_flow.should_reload_blank(
            kind=kind, blank_seconds=5, since_reload=5, reloads=0
        )
        is False
    )
    assert (
        register_flow.should_reload_blank(
            kind=kind, blank_seconds=8, since_reload=8, reloads=0
        )
        is True
    )


def test_visible_shell_is_not_treated_as_a_blank_document():
    snapshot = {
        "state": "not-ready",
        "inputs": [],
        "buttons": ["Sign up with email"],
    }
    assert register_flow.signup_probe_kind(snapshot) == "shell"
    assert (
        register_flow.should_reload_blank(
            kind="shell", blank_seconds=5, since_reload=5, reloads=0
        )
        is False
    )


def test_static_cache_does_not_intercept_the_signup_document_or_api():
    assert (
        static_asset_cache.is_static_request(
            "https://accounts.x.ai/sign-up?redirect=grok-com",
            "document",
            "GET",
        )
        is False
    )
    assert (
        static_asset_cache.is_static_request(
            "https://accounts.x.ai/api/auth/send-verification-code",
            "fetch",
            "POST",
        )
        is False
    )
    assert (
        static_asset_cache.is_static_request(
            "https://accounts.x.ai/_next/static/chunks/app.js",
            "script",
            "GET",
        )
        is False
    )
    assert (
        static_asset_cache.is_static_request(
            "https://accounts.x.ai/_next/static/css/app.css",
            "stylesheet",
            "GET",
        )
        is True
    )
    assert (
        static_asset_cache.is_static_request(
            "https://accounts.x.ai/_next/static/media/font.woff2",
            "font",
            "GET",
        )
        is True
    )
    globs = static_asset_cache.static_route_globs()
    assert "**/*" not in globs
    assert "**/_next/static/**" not in globs
    assert not any(item.endswith("*.js") for item in globs)
    assert any(item.endswith("*.css") for item in globs)


def test_ready_form_is_not_reported_as_a_blank_document():
    stale = {"state": "not-ready", "url": "https://accounts.x.ai/sign-up", "inputs": [], "buttons": []}
    message = register_flow.fill_gave_up_message(
        stale, form_ready=True, blank_reloads=1, form_ready_hits=1
    )
    assert message == fill_gave_up_message(
        stale, form_ready=True, blank_reloads=1, form_ready_hits=1
    )
    assert "inputs=" not in message
    assert "邮箱框已出现" in message
    blank = register_flow.fill_gave_up_message(
        stale, form_ready=False, blank_reloads=2, form_ready_hits=0
    )
    assert "inputs=none" in blank
    assert "blank_reloads=2" in blank


def test_signup_unavailable_copy_is_a_block_not_a_blank_document():
    snapshot = {
        "state": "not-ready",
        "title": "Sign up",
        "body": "Email sign-up isn't available right now. Sign up another way.",
        "inputs": ["type=email"],
        "buttons": ["Sign up"],
    }
    assert signup_probe_kind(snapshot) == "shell"
    reason = register_flow.signup_block_reason(snapshot)
    assert reason == "email-signup-unavailable"
    assert reason == signup_block_reason(snapshot)


def test_empty_dom_value_does_not_count_as_a_typed_email():
    assert register_flow.native_type_confirmed("", "user@outlook.com") is False
    assert native_type_confirmed("", "user@outlook.com") is False
    assert register_flow.native_type_confirmed("user@outlook.com", "user@outlook.com") is True
    assert register_flow.native_type_confirmed("other@outlook.com", "user@outlook.com") is False


def test_email_entry_button_is_not_the_form_submit():
    deny = email_submit_deny_keywords()
    assert register_flow.label_matches_deny("Sign up with email", deny) is True
    assert label_matches_deny("Continue with Google", deny) is True
    assert register_flow.label_matches_deny("Sign up", deny) is False
    assert register_flow.label_matches_deny("Continue", deny) is False


def test_verify_email_copy_is_a_sent_code_not_a_blank_reload():
    snapshot = {
        "state": "not-ready",
        "title": "Create Your Grok Account | Grok",
        "body": (
            "You are signing into Grok Verify your email "
            "We've emailed a one time security code to a@outlook.com."
        ),
        "inputs": [],
        "buttons": ["Go back"],
    }
    assert signup_code_sent(snapshot) is True
    assert register_flow.signup_code_sent(snapshot) is True
    assert signup_probe_kind(snapshot) == "code"
    assert register_flow.signup_probe_kind(snapshot) == "code"
    assert (
        should_reload_blank(kind="code", blank_seconds=30, since_reload=30, reloads=0)
        is False
    )
    refused = {
        "state": "not-ready",
        "body": "Email sign-up isn't available right now. Sign up another way.",
        "buttons": ["Sign up"],
    }
    assert signup_code_sent(refused) is False


def test_email_submit_waits_for_turnstile_only_when_the_widget_is_present():
    assert email_submit_needs_turnstile(0, True) is True
    assert register_flow.email_submit_needs_turnstile(0, False) is False
    assert register_flow.email_submit_needs_turnstile(80, True) is False


if __name__ == "__main__":
    names = sorted(name for name in globals() if name.startswith("test_"))
    for name in names:
        globals()[name]()
        print("ok", name)
    print("OK signup page decisions")
