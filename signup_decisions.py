"""Pure signup-page decisions. No browser or network I/O."""

from __future__ import annotations

import re

CF_MARKERS = (
    "just a moment",
    "checking your browser",
    "cf-challenge",
    "challenge-platform",
    "challenges.cloudflare.com",
    "attention required",
    "turnstile",
    "cdn-cgi/challenge",
)


def signup_probe_kind(snapshot) -> str:
    """Classify a signup document snapshot.

    Returns ``email`` (form can be filled), ``shell`` (buttons exist, no email
    box yet), ``cf-wait`` (challenge still running), or ``blank``.
    """
    if not isinstance(snapshot, dict):
        return "blank"
    state = str(snapshot.get("state") or "")
    if state in ("filled", "fill-failed", "native-filled", "ready-to-submit"):
        return "email"
    step = str(snapshot.get("step") or "")
    if step in ("wait-cf", "cf"):
        return "cf-wait"
    inputs = snapshot.get("inputs") or []
    buttons = snapshot.get("buttons") or []
    try:
        input_count = int(snapshot.get("inputCount") or 0)
    except (TypeError, ValueError):
        input_count = 0
    try:
        button_count = int(snapshot.get("buttonCount") or 0)
    except (TypeError, ValueError):
        button_count = 0
    blob = " ".join(
        [
            str(snapshot.get("title") or ""),
            str(snapshot.get("body") or ""),
            str(snapshot.get("hint") or ""),
            " ".join(str(item) for item in (snapshot.get("iframes") or [])),
            " ".join(str(item) for item in inputs),
            " ".join(str(item) for item in buttons),
        ]
    ).lower()
    if any(marker in blob for marker in CF_MARKERS):
        return "cf-wait"
    if signup_code_sent(snapshot):
        return "code"
    if inputs or buttons or input_count or button_count:
        return "shell"
    return "blank"


def should_reload_blank(
    *,
    kind: str,
    blank_seconds: float,
    since_reload: float,
    reloads: int,
    max_reloads: int = 4,
) -> bool:
    """Whether a not-ready signup document should be reloaded now.

    A Cloudflare challenge is not an empty document: reloading it at 5s
    restarts the challenge and the email form never appears.
    """
    if reloads >= max_reloads:
        return False
    kind = str(kind or "blank")
    if kind in ("email", "code"):
        return False
    if kind == "cf-wait":
        return blank_seconds >= 25 and since_reload >= 25
    if kind == "shell":
        return blank_seconds >= 12 and since_reload >= 8
    return blank_seconds >= 8 and since_reload >= 8


def label_matches_deny(label: str, deny_keywords) -> bool:
    """True when a visible control is an IdP / email-entry button, not the form submit."""
    compact = re.sub(r"\s+", "", str(label or "")).lower()
    if not compact:
        return True
    for item in deny_keywords or ():
        token = str(item or "").replace(" ", "").lower()
        if token and token in compact:
            return True
    return False


def email_submit_needs_turnstile(token_len, has_frame) -> bool:
    """The email submit should wait for Turnstile only when the widget is on the page.

    A solved token is already long. An empty token with no widget matches the
    2026-10-23 path, which sent the code before any Turnstile wait.
    """
    try:
        length = int(token_len or 0)
    except (TypeError, ValueError):
        length = 0
    return bool(has_frame) and length < 20


def email_submit_deny_keywords() -> tuple[str, ...]:
    """Substrings that must not win the email-form submit click.

    ``signup`` is contained in ``signupwithemail``. Clicking that entry button
    again leaves the email field on screen and no verification mail is sent.
    """
    return (
        "withemail",
        "withgoogle",
        "withapple",
        "withx",
        "使用邮箱",
    )


def native_type_confirmed(current, expected) -> bool:
    """True only when the DOM value matches what we typed.

    An empty read used to count as success (``not current or current == expected``).
    That skipped the JS fill while the email box was still empty, so the submit
    click returned false and the page never left the email step.
    """
    cur = str(current or "").strip()
    exp = str(expected or "").strip()
    return bool(cur) and cur == exp


def signup_code_sent(snapshot) -> bool:
    """True when the document is the post-submit verification step.

    The email box can still be in the DOM while the copy already says the
    one-time code was sent. Reloading that page throws away a live code.
    """
    if not isinstance(snapshot, dict):
        return False
    if signup_block_reason(snapshot):
        return False
    blob = " ".join(
        [
            str(snapshot.get("title") or ""),
            str(snapshot.get("body") or ""),
            str(snapshot.get("hint") or ""),
        ]
    ).lower()
    markers = (
        "verify your email",
        "one time security code",
        "one-time security code",
        "emailed a one time",
        "验证您的邮箱",
        "一次性",
    )
    return any(marker in blob for marker in markers)


def signup_block_reason(snapshot) -> str:
    """Return a short reason when the signup document itself refuses email signup."""
    if not isinstance(snapshot, dict):
        return ""
    blob = " ".join(
        [
            str(snapshot.get("title") or ""),
            str(snapshot.get("body") or ""),
            str(snapshot.get("hint") or ""),
        ]
    ).lower()
    if (
        "isn't available" in blob
        or "isn’t available" in blob
        or "isnt available" in blob
        or "sign up another way" in blob
        or "email-signup-unavailable" in blob
    ):
        return "email-signup-unavailable"
    return ""


def fill_gave_up_message(snapshot, *, form_ready: bool, blank_reloads: int, form_ready_hits: int) -> str:
    """Failure text after the email fill loop.

    A recovery that already saw the email box must not be reported as a blank
    document from an older snapshot.
    """
    probe = f"blank_reloads={int(blank_reloads)} form_ready_hits={int(form_ready_hits)}"
    if form_ready:
        return f"邮箱框已出现但页面未进入验证码 ({probe})"
    if not isinstance(snapshot, dict):
        return f"未找到邮箱输入框或注册按钮 ({probe})"
    inputs = " | ".join(str(item) for item in (snapshot.get("inputs") or [])[:6]) or "none"
    buttons = " | ".join(str(item) for item in (snapshot.get("buttons") or [])[:8]) or "none"
    url = snapshot.get("url") or ""
    return (
        "未找到邮箱输入框或注册按钮，最后页面: "
        f"url={url}; inputs={inputs}; buttons={buttons} ({probe})"
    )
