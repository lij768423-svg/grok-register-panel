# -*- coding: utf-8 -*-
"""注册页流程：打开注册、填邮箱/验证码/资料、等 SSO。"""
from __future__ import annotations

import os
import random
import re
import secrets
import string
import time
from typing import Any, Dict

from playwright._impl._errors import TargetClosedError as PageDisconnectedError

from browser_session import (
    active_browser,
    active_page,
    browser,
    page,
    refresh_active_page,
    restart_browser,
    set_browser_session,
    start_browser,
    stop_browser,
)

SIGNUP_URL = "https://accounts.x.ai/sign-up?redirect=grok-com"


def _hint_is_page_error(hint: str) -> bool:
    """x.ai Next 崩溃页：An error occurred / error loading this page。"""
    low = str(hint or "").lower()
    return (
        "error loading this page" in low
        or ("an error occurred" in low and "correct url" in low)
        or "contact a team admin" in low
    )


def _reload_signup(log_callback=None, reason: str = "页面错误") -> bool:
    refresh_active_page()
    if log_callback:
        log_callback(f"[*] {reason}，重新打开 sign-up ...")
    try:
        page.get(SIGNUP_URL)
        try:
            page.wait.doc_loaded()
        except Exception:
            pass
        time.sleep(0.8)
        return True
    except Exception as exc:
        if log_callback:
            log_callback(f"[Debug] 重开 sign-up 失败: {exc}")
        return False

# 资料页 Cloudflare Turnstile：等待自动通过 + 智能点击，不调用 reset()
CF_FIRST_RETRY_AFTER = 3.0   # 检测到 CF 后 3 秒即开始尝试
CF_RETRY_INTERVAL = 8.0      # 两次完整 getTurnstileToken 间隔（原 15s 过慢）
CF_WAIT_LOG_INTERVAL = 5.0
PROFILE_TIMEOUT = 70         # 资料页总超时（含 Turnstile / OTP 未跳转）
PROFILE_CF_MAX_ROUNDS = 3    # Turnstile 完整复用最大次数，超限换口
PROFILE_PROBE_LOG_INTERVAL = 5.0

_deps: Dict[str, Any] = {}


def configure(**kwargs):
    _deps.update(kwargs)


def _AccountRetryNeeded(msg=""):
    cls = _deps.get("AccountRetryNeeded", Exception)
    return cls(msg)


def raise_if_cancelled(cancel_callback=None):
    fn = _deps.get("raise_if_cancelled")
    if fn:
        return fn(cancel_callback)


def sleep_with_cancel(seconds, cancel_callback=None):
    fn = _deps.get("sleep_with_cancel")
    if fn:
        return fn(seconds, cancel_callback)
    time.sleep(max(seconds, 0))


def _native_attr(element, name: str) -> str:
    try:
        value = element.attr(name)
    except Exception:
        value = ""
    return str(value or "").strip()


def _native_is_usable(element) -> bool:
    try:
        states = element.states
        if getattr(states, "is_alive", True) is False:
            return False
        if getattr(states, "is_displayed", True) is False:
            return False
        if getattr(states, "is_enabled", True) is False:
            return False
    except Exception:
        return False
    return True


def _native_label(element) -> str:
    parts = []
    try:
        parts.append(str(element.text or ""))
    except Exception:
        pass
    for name in ("aria-label", "title", "value", "placeholder", "name", "id", "data-testid", "autocomplete"):
        value = _native_attr(element, name)
        if value:
            parts.append(value)
    return " ".join(parts).replace("\u00a0", " ").strip()


def _native_elements(tag: str):
    try:
        return list(page.eles(f"tag:{tag}") or [])
    except Exception:
        return []


def _native_click_action(keywords, deny_keywords=()) -> str:
    """按可见文本用 CDP 原生事件点击；返回按钮文字。"""
    keys = [str(x).replace(" ", "").lower() for x in keywords]
    denied = [str(x).replace(" ", "").lower() for x in deny_keywords]
    candidates = []
    for tag in ("button", "a", "input"):
        for element in _native_elements(tag):
            if not _native_is_usable(element):
                continue
            if tag == "input" and _native_attr(element, "type").lower() not in (
                "submit",
                "button",
            ):
                continue
            if _native_attr(element, "aria-disabled").lower() == "true":
                continue
            label = _native_label(element)
            compact = re.sub(r"\s+", "", label).lower()
            if not compact or any(item in compact for item in denied):
                continue
            score = max((len(item) for item in keys if item and item in compact), default=0)
            if score:
                candidates.append((score, element, label))
    for _, element, label in sorted(candidates, key=lambda item: item[0], reverse=True):
        try:
            element.click(timeout=3)
            return label
        except Exception:
            # 原生点击失败（可能被 Cookie 横幅等覆盖），尝试 JS 直接点击
            try:
                element.click(by_js=True)
                return label
            except Exception:
                continue
    return ""


def _native_type_element(element, value: str, per_char: bool = True) -> bool:
    """使用 Playwright 真实键盘事件输入，避免 JS setter 产生 isTrusted=false 事件。"""
    if not element or not _native_is_usable(element):
        return False
    text = str(value or "")
    try:
        element.click(timeout=3)
        if per_char:
            for index, char in enumerate(text):
                element.input(char, clear=index == 0, by_js=False)
                if index + 1 < len(text):
                    time.sleep(random.uniform(0.02, 0.06))
        else:
            element.input(text, clear=True, by_js=False)
        try:
            current = str(element.property("value") or "")
        except Exception:
            current = ""
        # 某些 React 控件异步更新 property；调用成功且无法读取值时交给页面推进检查。
        return not current or current.strip() == text.strip()
    except Exception:
        return False


def _native_input_candidates(kind: str):
    scored = []
    for tag in ("input", "textarea"):
        for element in _native_elements(tag):
            if not _native_is_usable(element):
                continue
            typ = _native_attr(element, "type").lower()
            if typ in ("hidden", "submit", "button", "checkbox", "radio", "file", "search"):
                continue
            meta = _native_label(element).lower()
            name = _native_attr(element, "name").lower()
            testid = _native_attr(element, "data-testid").lower()
            autocomplete = _native_attr(element, "autocomplete").lower()
            inputmode = _native_attr(element, "inputmode").lower()
            maxlength = _native_attr(element, "maxlength")
            try:
                max_len = int(maxlength or 0)
            except ValueError:
                max_len = 0
            score = 0
            if kind == "email":
                score = (100 if typ == "email" else 0) + (90 if name == "email" else 0)
                score += 80 if "email" in autocomplete else 0
                score += 70 if "email" in testid else 0
                score += 40 if any(x in meta for x in ("email", "mail", "邮箱")) else 0
            elif kind == "code":
                score = (100 if testid == "code" or name == "code" else 0)
                score += 90 if autocomplete == "one-time-code" else 0
                score += 70 if inputmode in ("numeric", "decimal") else 0
                score += 50 if max_len > 1 else 0
            elif kind == "code_box":
                score = 100 if max_len == 1 else 0
                score += 80 if autocomplete == "one-time-code" else 0
            elif kind == "given":
                score = 100 if testid in ("givenname", "firstname") or name in ("givenname", "firstname") else 0
                score += 90 if autocomplete in ("given-name", "givenname") else 0
                score += 50 if "first name" in meta or "firstname" in meta else 0
                score += 40 if "given" in meta or "名" in meta else 0
            elif kind == "family":
                score = 100 if testid in ("familyname", "lastname") or name in ("familyname", "lastname") else 0
                score += 90 if autocomplete in ("family-name", "familyname") else 0
                score += 50 if "last name" in meta or "lastname" in meta else 0
                score += 40 if "family" in meta or "姓" in meta else 0
            elif kind == "password":
                score = 110 if typ == "password" else 0
                score += 90 if name == "password" or "password" in autocomplete else 0
                score += 60 if "password" in meta or "密码" in meta else 0
            if score:
                scored.append((score, element))
    return [element for _, element in sorted(scored, key=lambda item: item[0], reverse=True)]


def _native_fill_email(email: str) -> bool:
    candidates = _native_input_candidates("email")
    return bool(candidates and _native_type_element(candidates[0], email))


def _native_fill_code(code: str) -> str:
    aggregate = _native_input_candidates("code")
    if aggregate and _native_type_element(aggregate[0], code):
        return "filled-aggregate"
    boxes = _native_input_candidates("code_box")
    if len(boxes) < len(code):
        return "not-ready"
    if all(_native_type_element(box, char, per_char=False) for box, char in zip(boxes, code)):
        return "filled-boxes"
    return "boxes-failed"


def _native_fill_profile(given_name: str, family_name: str, password: str) -> bool:
    given = _native_input_candidates("given")
    family = _native_input_candidates("family")
    secret = _native_input_candidates("password")
    if not given or not family or not secret:
        return False
    return all(
        (
            _native_type_element(given[0], given_name),
            _native_type_element(family[0], family_name),
            _native_type_element(secret[0], password),
        )
    )


_SIGNUP_PROBE_JS = r"""
function isVisible(node, allowHidden) {
  if (!node) return false;
  const style = window.getComputedStyle(node);
  if (style.display === 'none' || style.visibility === 'hidden') return false;
  if (!allowHidden && style.opacity === '0') return false;
  const rect = node.getBoundingClientRect();
  return allowHidden || (rect.width > 0 && rect.height > 0);
}
function pick(sel) {
  return Array.from(document.querySelectorAll(sel)).find((n) => {
    const tag = (n.tagName || '').toLowerCase();
    if (tag !== 'input' && tag !== 'textarea') {
      const inner = n.querySelector('input,textarea');
      return inner && isVisible(inner, false) && !inner.disabled && !inner.readOnly;
    }
    return isVisible(n, n.hasAttribute('data-input-otp')) && !n.disabled && !n.readOnly;
  }) || null;
}
const given = pick('input[data-testid="givenName"], [data-testid="givenName"] input, input[name="givenName"], input[autocomplete="given-name"], input[name="firstName"], input[autocomplete="givenname"]');
const family = pick('input[data-testid="familyName"], [data-testid="familyName"] input, input[name="familyName"], input[autocomplete="family-name"], input[name="lastName"], input[autocomplete="familyname"]');
const password = pick('input[data-testid="password"], [data-testid="password"] input, input[name="password"], input[type="password"], input[autocomplete="new-password"]');
const otp = pick('input[data-input-otp], input[data-input-otp="true"], input[autocomplete="one-time-code"], input[name="code"]');
const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
const cf = !!cfInput
  || !!document.querySelector('iframe[src*="turnstile"], div.cf-turnstile, [data-sitekey], script[src*="turnstile"]');
const body = String(document.body && document.body.innerText || '').replace(/\s+/g, ' ');
const low = body.toLowerCase();
const title = String(document.title || '');
const cfChall = /just a moment|checking your browser|cf-challenge|attention required/.test(low)
  || /just a moment/i.test(title);
const existing = (/already have an account|already exists|existing account|account exists|已有账号|已有帳戶/.test(low)
  && !!password && !given);
const buttons = Array.from(document.querySelectorAll('button, [role="button"], input[type="submit"]'))
  .filter((n) => isVisible(n, false) && !n.disabled)
  .map((n) => String(n.innerText || n.value || n.getAttribute('aria-label') || '').replace(/\s+/g, ' ').trim())
  .filter(Boolean)
  .slice(0, 8);
const pageErr = /error loading this page|contact a team admin/i.test(low)
  || (/an error occurred/i.test(low) && /correct url/i.test(low))
  || /an error occurred/i.test(title);
let step = 'unknown';
if (pageErr) step = 'page-error';
else if (cfChall) step = 'wait-cf';
else if (given && family && password) step = 'profile';
else if (existing) step = 'existing-account';
else if (cf && !given) step = 'wait-cf';
else if (otp || /enter (the )?code|verification code|confirmation code|验证码/.test(low)) step = 'still-otp';
return {
  step: step,
  cf: cf,
  cfChall: cfChall,
  hasGiven: !!given,
  hasFamily: !!family,
  hasPassword: !!password,
  hasOtp: !!otp,
  buttons: buttons,
  title: title.slice(0, 80),
  path: String(location.pathname || '') + String(location.search || ''),
  hint: body.slice(0, 160)
};
"""


def _probe_signup_page() -> dict:
    refresh_active_page()
    if not page:
        return {"step": "no-page"}
    try:
        raw = page.run_js(_SIGNUP_PROBE_JS)
    except Exception as exc:
        return {"step": "probe-error", "hint": str(exc)[:160]}
    if isinstance(raw, dict):
        return raw
    return {"step": "probe-error", "hint": str(raw)[:160]}


def _click_continue_if_any() -> str:
    native = _native_click_action(
        ("确认邮箱", "继续", "下一步", "confirm", "continue", "next", "verify", "submit")
    )
    if native:
        return f"native:{native}"
    try:
        clicked = page.run_js(
            r"""
function isVisible(node) {
  if (!node) return false;
  const style = window.getComputedStyle(node);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
  const rect = node.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}
const form = document.querySelector('form');
if (form && form.requestSubmit) {
  try { form.requestSubmit(); return 'requestSubmit'; } catch (e) {}
}
const buttons = Array.from(document.querySelectorAll('button[type="submit"], button, [role="button"]'))
  .filter((n) => isVisible(n) && !n.disabled);
const btn = buttons.find((n) => {
  const t = String(n.innerText || n.textContent || '').replace(/\s+/g, '').toLowerCase();
  return /确认邮箱|继续|下一步|confirm|continue|next|verify|submit/.test(t);
}) || buttons.find((n) => n.type === 'submit') || null;
if (!btn) return 'no-button';
btn.focus();
btn.click();
return 'clicked';
            """
        )
        return str(clicked or "")
    except Exception:
        return ""


def _try_otp_enter() -> None:
    try:
        page.run_js(
            r"""
const otp = document.querySelector('input[data-input-otp], input[data-input-otp="true"], input[autocomplete="one-time-code"], input[name="code"]');
if (otp) {
  otp.focus();
  otp.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true, key: 'Enter', code: 'Enter' }));
  otp.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, key: 'Enter', code: 'Enter' }));
}
const form = otp && otp.form;
if (form && form.requestSubmit) {
  try { form.requestSubmit(); } catch (e) {}
}
            """
        )
    except Exception:
        pass


def _dismiss_cookie_consent(log_callback=None):
    """尝试关闭 OneTrust / 通用 Cookie 同意横幅，避免遮挡按钮。"""
    try:
        dismissed = page.run_js(r"""
// OneTrust: 点击 "Accept All" / "全部接受" 按钮
const oneTrustBtn = document.querySelector('#onetrust-accept-btn-handler, #accept-recommended-btn-handler');
if (oneTrustBtn) { oneTrustBtn.click(); return 'OneTrust'; }
// 通用：查找带 "Accept" / "接受" / "同意" / "Agree" 文本的按钮
const btns = Array.from(document.querySelectorAll('button, a, [role="button"]'));
for (const b of btns) {
    const t = (b.innerText || b.textContent || '').trim().toLowerCase();
    if (t === 'accept all' || t === 'accept' || t === 'agree' || t === '同意' || t === '全部接受' || t === '接受') {
        b.click(); return 'generic:' + t;
    }
}
return '';
        """)
        if dismissed and log_callback:
            log_callback(f"[*] 已关闭 Cookie 横幅: {dismissed}")
    except Exception:
        pass



def _page_has_email_form():
    """注册页是否已出现邮箱输入框（SPA 水合完成）。"""
    refresh_active_page()
    if not page:
        return False
    try:
        return bool(
            page.run_js(
                r"""
function isVisible(node) {
  if (!node) return false;
  const style = window.getComputedStyle(node);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
  const rect = node.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}
const nodes = Array.from(document.querySelectorAll(
  'input[data-testid="email"], input[name="email"], input[type="email"], input[autocomplete="email"], input[placeholder*="mail" i], input[aria-label*="mail" i]'
));
return nodes.some((n) => isVisible(n) && !n.disabled && !n.readOnly);
"""
            )
        )
    except Exception:
        return False


def _page_shell_ready():
    """注册页是否至少有可点按钮/输入（非完全空白壳）。"""
    refresh_active_page()
    if not page:
        return False
    try:
        return bool(
            page.run_js(
                r"""
function isVisible(node) {
  if (!node) return false;
  const style = window.getComputedStyle(node);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
  const rect = node.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}
const inputs = Array.from(document.querySelectorAll('input, textarea')).filter((n) => isVisible(n));
const actions = Array.from(document.querySelectorAll('button, a, [role="button"]')).filter(
  (n) => isVisible(n) && !n.disabled
);
return inputs.length + actions.length > 0;
"""
            )
        )
    except Exception:
        return False


def _wait_signup_shell(timeout=20, log_callback=None, cancel_callback=None):
    deadline = time.time() + timeout
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        if _page_has_email_form() or _page_shell_ready():
            return True
        sleep_with_cancel(0.5, cancel_callback)
    return _page_has_email_form() or _page_shell_ready()


def _wait_email_form(timeout=20, log_callback=None, cancel_callback=None):
    deadline = time.time() + timeout
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        if _page_has_email_form():
            return True
        sleep_with_cancel(0.45, cancel_callback)
    return _page_has_email_form()


def _reload_signup_and_open_email(log_callback=None, cancel_callback=None):
    """空页恢复：reload 或重开 sign-up，再点邮箱注册。"""
    raise_if_cancelled(cancel_callback)
    refresh_active_page()
    try:
        if page:
            try:
                page.refresh()
            except Exception:
                try:
                    page.get(SIGNUP_URL)
                except Exception:
                    pass
            try:
                page.wait.doc_loaded()
            except Exception:
                pass
        sleep_with_cancel(1.2, cancel_callback)
        _wait_signup_shell(timeout=20, log_callback=log_callback, cancel_callback=cancel_callback)
        if _page_has_email_form():
            if log_callback:
                log_callback("[*] 空页恢复：reload 后已有邮箱框")
            return True
        click_email_signup_button(
            timeout=10, log_callback=log_callback, cancel_callback=cancel_callback
        )
        ok = _wait_email_form(timeout=20, log_callback=log_callback, cancel_callback=cancel_callback)
        if log_callback:
            log_callback(f"[*] 空页恢复：重新点击邮箱注册 form_ready={ok}")
        return ok
    except Exception as exc:
        if log_callback:
            log_callback(f"[!] 空页恢复失败: {exc}")
        return False


def click_email_signup_button(timeout=25, log_callback=None, cancel_callback=None):
    deadline = time.time() + timeout
    first_attempt = True
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        if first_attempt:
            _dismiss_cookie_consent(log_callback)
            first_attempt = False
        if log_callback:
            log_callback('[Debug] 尝试查找「使用邮箱注册」按钮...')

        native_clicked = _native_click_action(
            (
                "使用邮箱注册", "signup with email", "continue with email", "sign up with email",
                # 西班牙语
                "regístrate con correo", "registrate con correo",
                # 法语
                "s'inscrire avec", "inscrire avec l",
                # 德语
                "mit e-mail registrieren", "mit email registrieren",
                # 葡萄牙语
                "inscrever-se com email", "inscreverse com email",
                # 意大利语
                "registrati con email",
            ),
        )
        if native_clicked:
            if log_callback:
                log_callback(f"[*] 已点击「使用邮箱注册」按钮（原生事件）: {native_clicked}")
            sleep_with_cancel(0.8, cancel_callback)
            return True

        try:
            clicked = page.run_js(r"""
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
function nodeText(node) {
    return [
        node.innerText,
        node.textContent,
        node.getAttribute('aria-label'),
        node.getAttribute('title'),
        node.getAttribute('href'),
    ].filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
}
function scoreEntry(node) {
    // data-testid 不受页面语言影响，最可靠
    const testid = (node.getAttribute('data-testid') || '').toLowerCase();
    if (testid.includes('email') && (testid.includes('signup') || testid.includes('continue') || testid.includes('register'))) return 100;
    if (testid === 'signup-email' || testid === 'register-email' || testid === 'email-signup') return 100;

    const compact = nodeText(node).replace(/\s+/g, '');
    const lower = compact.toLowerCase();
    // 中文
    if (compact.includes('使用邮箱注册')) return 100;
    // 英文
    if (lower.includes('signupwithemail')) return 95;
    if (lower.includes('continuewithemail')) return 90;
    // 西班牙语: Regístrate con correo electrónico
    if (lower.includes('regístrateconcorreo') || lower.includes('registrateconcorreo')) return 95;
    // 法语: S'inscrire avec l'e-mail
    if (lower.includes("s'inscrireavecl") || lower.includes('inscrireavecl')) return 95;
    // 德语: Mit E-Mail registrieren
    if (lower.includes('mite-mailregistrieren') || lower.includes('mitemailregistrieren')) return 95;
    // 日语: メールで登録
    if (compact.includes('メールで登録')) return 95;
    // 葡萄牙语: Inscrever-se com email
    if (lower.includes('inscrever-secomemail') || lower.includes('inscreversecomemail')) return 95;
    // 意大利语: Registrati con email
    if (lower.includes('registraticonemail')) return 95;
    // 通用：包含 email + 动词
    if (lower.includes('email') && (lower.includes('sign') || lower.includes('continue') || lower.includes('use') || lower.includes('with') || lower.includes('registr') || lower.includes('inscr') || lower.includes('regíst') || lower.includes('regist'))) return 80;
    // 通用：包含 correo(西语email) + 注册动词
    if (lower.includes('correo') && (lower.includes('registr') || lower.includes('regíst'))) return 80;
    if (lower === 'email' || lower.includes('邮箱')) return 70;
    return 0;
}
const candidates = Array.from(document.querySelectorAll('button, a, [role="button"]'))
    .filter((node) => isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true')
    .map((node) => ({ node, score: scoreEntry(node), text: nodeText(node) }))
    .filter((item) => item.score > 0)
    .sort((a, b) => b.score - a.score);
const target = candidates[0]?.node || null;
if (!target) {
    return false;
}
target.click();
return candidates[0].text || true;
            """)
        except Exception as js_exc:
            if log_callback:
                log_callback(f"[Debug] run_js 异常: {js_exc}")
            clicked = False

        if clicked:
            if log_callback:
                detail = f": {clicked}" if isinstance(clicked, str) else ""
                log_callback(f"[*] 已点击「使用邮箱注册」按钮{detail}")
            sleep_with_cancel(0.8, cancel_callback)
            return True

        if log_callback:
            current_url = page.url if page else "none"
            log_callback(f"[Debug] 当前URL: {current_url}")

        sleep_with_cancel(1, cancel_callback)

    if log_callback:
        page_html = page.html[:500] if page else "no page"
        log_callback(f"[Debug] 页面内容片段: {page_html}")

    raise Exception("未找到「使用邮箱注册」按钮")


def open_signup_page(log_callback=None, cancel_callback=None):
    raise_if_cancelled(cancel_callback)
    if active_browser() is None:
        start_browser(log_callback=log_callback)
        if log_callback:
            log_callback("[*] 浏览器已启动")

    def _navigate_signup():
        # 优先复用已有标签，避免反复 new_tab 堆积空窗口
        browser_obj = active_browser()
        if browser_obj is None:
            start_browser(log_callback=log_callback)
            browser_obj = active_browser()
        try:
            tabs = browser_obj.get_tabs() if browser_obj is not None else []
            page_obj = tabs[-1] if tabs else browser_obj.new_tab()
        except Exception:
            page_obj = browser_obj.new_tab()
        set_browser_session(browser_obj, page_obj)
        page_obj.get(SIGNUP_URL)
        page_obj.wait.doc_loaded()
        # 确认真的进了注册域；about:blank / 错页直接失败
        current = str(getattr(page_obj, "url", "") or "")
        if "accounts.x.ai" not in current and "x.ai" not in current:
            raise Exception(f"打开注册页失败，当前URL: {current or 'empty'}")

    try:
        _navigate_signup()
    except Exception as e:
        if log_callback:
            log_callback(f"[Debug] 打开URL异常: {e}")
        try:
            restart_browser(log_callback=log_callback)
            _navigate_signup()
        except Exception as e2:
            # 导航彻底失败：关掉残留实例，避免空浏览器挂着
            try:
                stop_browser()
            except Exception:
                pass
            raise Exception(f"打开注册页失败: {e2}") from e2

    # 等 SPA/CF 把壳渲染出来，再点邮箱注册
    sleep_with_cancel(1.0, cancel_callback)
    if log_callback:
        log_callback(f"[*] 当前URL: {active_page().url if active_page() else ''}")
    if not _wait_signup_shell(timeout=20, log_callback=log_callback, cancel_callback=cancel_callback):
        if log_callback:
            log_callback("[!] 注册页壳为空，尝试 reload 恢复")
        if not _reload_signup_and_open_email(log_callback=log_callback, cancel_callback=cancel_callback):
            raise Exception(
                f"打开注册页后页面空白: url={active_page().url if active_page() else ''}; inputs=none; buttons=none"
            )
        return
    if _page_has_email_form():
        if log_callback:
            log_callback("[*] 注册页已直接展示邮箱输入框")
        return
    click_email_signup_button(
        log_callback=log_callback, cancel_callback=cancel_callback
    )
    if not _wait_email_form(timeout=20, log_callback=log_callback, cancel_callback=cancel_callback):
        if log_callback:
            log_callback("[!] 点击邮箱注册后仍无输入框，reload 重试")
        if not _reload_signup_and_open_email(log_callback=log_callback, cancel_callback=cancel_callback):
            raise Exception(
                f"未找到邮箱输入框或注册按钮，最后页面: url={active_page().url if active_page() else ''}; inputs=none; buttons=none"
            )


def has_profile_form(log_callback=None):
    refresh_active_page()
    try:
        return bool(
            page.run_js(
                """
const givenInput = document.querySelector('input[data-testid="givenName"], input[name="givenName"], input[autocomplete="given-name"]');
const familyInput = document.querySelector('input[data-testid="familyName"], input[name="familyName"], input[autocomplete="family-name"]');
const passwordInput = document.querySelector('input[data-testid="password"], input[name="password"], input[type="password"]');
return !!(givenInput && familyInput && passwordInput);
            """
            )
        )
    except Exception:
        return False


def detect_email_domain_rejection(email=""):
    """检测 xAI 是否拒绝当前邮箱域名。

    返回拒绝文案字符串；未检测到则返回空字符串。
    """
    if not page:
        return ""
    try:
        result = page.run_js(
            r"""
function collectText() {
    const chunks = [];
    const selectors = [
        '[role="alert"]',
        '[data-testid*="error" i]',
        '[class*="error" i]',
        '[class*="Error"]',
        '[class*="danger" i]',
        '[class*="invalid" i]',
        'p', 'span', 'div', 'li', 'label',
    ];
    for (const sel of selectors) {
        for (const node of Array.from(document.querySelectorAll(sel)).slice(0, 80)) {
            const style = window.getComputedStyle(node);
            if (style.display === 'none' || style.visibility === 'hidden') continue;
            const text = (node.innerText || node.textContent || '').replace(/\s+/g, ' ').trim();
            if (text && text.length >= 8 && text.length <= 400) chunks.push(text);
        }
    }
    const body = (document.body && (document.body.innerText || document.body.textContent) || '')
        .replace(/\s+/g, ' ').trim();
    if (body) chunks.push(body.slice(0, 1200));
    return Array.from(new Set(chunks));
}
const texts = collectText();
const patterns = [
    /邮箱域名[^。\n]{0,80}被拒绝/,
    /域名[^。\n]{0,40}已被拒绝/,
    /已被拒绝[^。\n]{0,40}邮箱/,
    /email domain[^.\n]{0,80}rejected/i,
    /domain[^.\n]{0,40}(has been |is )?rejected/i,
    /please use (a )?different email/i,
    /use another email address/i,
    /请使用其他邮箱/,
    /support@x\.ai/,
];
for (const text of texts) {
    for (const re of patterns) {
        if (re.test(text)) {
            const m = text.match(/.{0,40}(拒绝|rejected|different email|其他邮箱).{0,80}/i);
            return (m && m[0]) || text.slice(0, 180);
        }
    }
}
return '';
            """
        )
        if isinstance(result, str) and result.strip():
            return result.strip()
    except Exception:
        pass
    return ""


def raise_if_email_domain_rejected(email=""):
    message = detect_email_domain_rejection(email)
    if message:
        callback = _deps.get("on_email_domain_rejected")
        if callback:
            try:
                note = str(callback(email, message) or "").strip()
                if note:
                    message = f"{message} | {note}"
            except Exception:
                pass
        raise _deps['EmailDomainRejected'](email=email, message=message)


def _notify_email_accepted(email=""):
    callback = _deps.get("on_email_accepted")
    if not callback:
        return
    try:
        callback(email)
    except Exception:
        pass


def _email_page_advanced_once(email):
    """检测邮箱提交后页面是否真正前进（离开邮箱输入阶段）。

    点击注册按钮只代表触发了点击，不代表表单真的提交成功。
    若 Cloudflare 挑战未过或页面卡住，按钮点击无实际效果，
    邮箱输入框会一直停留，导致后续空等验证码。

    判定“已前进”的依据：
      - 出现验证码输入框（OTP / code 输入），或
      - 原本可见可用的邮箱输入框已消失/不可用

    返回:
      - True：页面已前进，提交生效
      - False：仍停留在邮箱输入页
    """
    # 域名被拒时仍停在邮箱页，优先抛出明确错误
    raise_if_email_domain_rejected(email)
    try:
        return bool(
            page.run_js(
                """
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
function textOf(node) {
    return [
        node.getAttribute('aria-label'),
        node.getAttribute('placeholder'),
        node.getAttribute('name'),
        node.getAttribute('id'),
        node.getAttribute('autocomplete'),
        node.getAttribute('data-testid'),
    ].filter(Boolean).join(' ').replace(/\\s+/g, ' ').trim().toLowerCase();
}
// 1. 出现验证码输入框 => 已前进
const codeInput = Array.from(document.querySelectorAll('input')).find((node) => {
    if (!isVisible(node)) return false;
    const type = (node.getAttribute('type') || '').toLowerCase();
    if (['hidden', 'submit', 'button', 'checkbox', 'radio', 'file'].includes(type)) return false;
    const meta = textOf(node);
    const inMode = (node.getAttribute('inputmode') || '').toLowerCase();
    return (
        meta.includes('code') || meta.includes('otp') || meta.includes('verif') ||
        meta.includes('验证') || meta.includes('one-time') || inMode === 'numeric' ||
        node.getAttribute('autocomplete') === 'one-time-code'
    );
});
if (codeInput) return true;
// 2. 邮箱输入框已消失/不可用 => 已前进
const emailInput = Array.from(document.querySelectorAll('input[data-testid="email"], input[name="email"], input[type="email"], input[autocomplete="email"], input[placeholder*="mail" i], input[aria-label*="mail" i]'))
    .find((node) => isVisible(node) && !node.disabled && !node.readOnly);
if (!emailInput) return true;
return false;
                """
            )
        )
    except Exception as _exc:
        if type(_exc).__name__ == "EmailDomainRejected":
            raise
        return False


def _wait_email_page_advanced(email, wait=4.0, cancel_callback=None):
    """点击提交后，在有限窗口内轮询确认页面确实前进。

    给页面/网络一点反应时间：若窗口内检测到已前进则返回 True，
    否则返回 False，由调用方继续重试点击或最终超时换邮箱。
    """
    deadline = time.time() + wait
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        raise_if_email_domain_rejected(email)
        if _email_page_advanced_once(email):
            return True
        sleep_with_cancel(0.4, cancel_callback)
    raise_if_email_domain_rejected(email)
    return False


def fill_email_and_submit(timeout=25, log_callback=None, cancel_callback=None):
    raise_if_cancelled(cancel_callback)
    email, dev_token = _deps['get_email_and_token']()
    if not email or not dev_token:
        raise Exception("获取邮箱失败")
    if log_callback:
        log_callback(f"[*] 已创建邮箱: {email}")
    try:
        return _fill_email_body(email, dev_token, timeout, log_callback, cancel_callback)
    except BaseException:
        # 取号后在填邮箱/提交环节失败：把未注册的邮箱回收到池尾
        _rel = _deps.get("release_email")
        if _rel and email:
            try:
                _rel(email)
            except Exception:
                pass
        raise


def _fill_email_body(email, dev_token, timeout, log_callback, cancel_callback):
    deadline = time.time() + timeout
    last_diag_time = 0
    last_reclick_time = 0
    # 从进入填邮箱起算：空白满 5s 再 reload，避免一上来狂刷
    last_reload_time = time.time()
    blank_since = time.time()
    blank_reloads = 0
    last_snapshot = None
    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        native_filled = _native_fill_email(email)
        if native_filled:
            filled = {"state": "filled", "source": "native", "url": page.url if page else ""}
        else:
            filled = page.run_js(
                r"""
const email = arguments[0];
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
function textOf(node) {
    return [
        node.innerText,
        node.textContent,
        node.getAttribute('aria-label'),
        node.getAttribute('title'),
        node.getAttribute('placeholder'),
        node.getAttribute('data-testid'),
        node.getAttribute('name'),
        node.getAttribute('id'),
        node.getAttribute('autocomplete'),
    ].filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
}
function describeInput(node) {
    return [
        `type=${node.getAttribute('type') || ''}`,
        `name=${node.getAttribute('name') || ''}`,
        `id=${node.getAttribute('id') || ''}`,
        `placeholder=${node.getAttribute('placeholder') || ''}`,
        `aria=${node.getAttribute('aria-label') || ''}`,
        `testid=${node.getAttribute('data-testid') || ''}`,
    ].join(' ').replace(/\s+/g, ' ').trim().slice(0, 160);
}
function describeAction(node) {
    return textOf(node).slice(0, 120);
}
function emailCandidates() {
    const direct = Array.from(document.querySelectorAll('input[data-testid="email"], input[name="email"], input[type="email"], input[autocomplete="email"], input[placeholder*="mail" i], input[aria-label*="mail" i]'));
    const all = Array.from(document.querySelectorAll('input, textarea'));
    for (const node of all) {
        const type = (node.getAttribute('type') || '').toLowerCase();
        if (['hidden', 'submit', 'button', 'checkbox', 'radio', 'file', 'search'].includes(type)) continue;
        const meta = textOf(node).toLowerCase();
        if (meta.includes('email') || meta.includes('e-mail') || meta.includes('mail') || meta.includes('邮箱') || meta.includes('电子邮件')) {
            direct.push(node);
        }
    }
    return Array.from(new Set(direct));
}
const visibleInputs = Array.from(document.querySelectorAll('input, textarea'))
    .filter((node) => isVisible(node) && !node.disabled && !node.readOnly)
    .map(describeInput)
    .slice(0, 8);
const visibleActions = Array.from(document.querySelectorAll('button, a, [role="button"]'))
    .filter((node) => isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true')
    .map(describeAction)
    .filter(Boolean)
    .slice(0, 10);
const input = emailCandidates().find((node) => isVisible(node) && !node.disabled && !node.readOnly) || null;
if (!input) {
    return {
        state: 'not-ready',
        url: location.href,
        title: document.title,
        inputs: visibleInputs,
        buttons: visibleActions,
    };
}
input.focus(); input.click();
const valueProto = input instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
const valueSetter = Object.getOwnPropertyDescriptor(valueProto, 'value')?.set;
const tracker = input._valueTracker;
if (tracker) tracker.setValue('');
if (valueSetter) valueSetter.call(input, email); else input.value = email;
input.dispatchEvent(new InputEvent('beforeinput', { bubbles: true, data: email, inputType: 'insertText' }));
input.dispatchEvent(new InputEvent('input', { bubbles: true, data: email, inputType: 'insertText' }));
input.dispatchEvent(new Event('change', { bubbles: true }));
const inputType = (input.getAttribute('type') || '').toLowerCase();
const isValid = inputType !== 'email' || input.checkValidity();
if ((input.value || '').trim() !== email || !isValid) {
    return {
        state: 'fill-failed',
        value: input.value || '',
        valid: isValid,
        input: describeInput(input),
        url: location.href,
    };
}
input.blur();
return {
    state: 'filled',
    input: describeInput(input),
    url: location.href,
};
            """,
                email,
            )
        state = filled.get("state") if isinstance(filled, dict) else filled
        if isinstance(filled, dict):
            last_snapshot = filled
        if state != "not-ready":
            blank_since = time.time()  # 有进展则重置空白计时
        if state == "not-ready":
            now = time.time()
            # 无邮箱框：连续 5s 即 reload（不必等满总超时）
            inputs_empty = not (isinstance(filled, dict) and filled.get("inputs"))
            buttons_empty = not (isinstance(filled, dict) and filled.get("buttons"))
            fully_blank = inputs_empty and buttons_empty
            # not-ready = 无可用邮箱框；连续 5s 即 reload（含半载只有按钮的情况）
            if (
                (now - blank_since) >= 5
                and (now - last_reload_time) >= 5
                and blank_reloads < 4
            ):
                last_reload_time = now
                blank_since = now
                blank_reloads += 1
                kind = "全空白" if fully_blank else "无邮箱框"
                if log_callback:
                    log_callback(
                        f"[!] 邮箱页{kind}已满5s，reload 恢复 #{blank_reloads}"
                    )
                _reload_signup_and_open_email(
                    log_callback=log_callback, cancel_callback=cancel_callback
                )
                sleep_with_cancel(0.6, cancel_callback)
                continue
            if now - last_reclick_time >= 3:
                reclicked = page.run_js(r"""
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
function nodeText(node) {
    return [
        node.innerText,
        node.textContent,
        node.getAttribute('aria-label'),
        node.getAttribute('title'),
        node.getAttribute('href'),
    ].filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
}
function scoreEntry(node) {
    // data-testid 不受页面语言影响，最可靠
    const testid = (node.getAttribute('data-testid') || '').toLowerCase();
    if (testid.includes('email') && (testid.includes('signup') || testid.includes('continue') || testid.includes('register'))) return 100;
    if (testid === 'signup-email' || testid === 'register-email' || testid === 'email-signup') return 100;

    const compact = nodeText(node).replace(/\s+/g, '');
    const lower = compact.toLowerCase();
    // 中文
    if (compact.includes('使用邮箱注册')) return 100;
    // 英文
    if (lower.includes('signupwithemail')) return 95;
    if (lower.includes('continuewithemail')) return 90;
    // 西班牙语: Regístrate con correo electrónico
    if (lower.includes('regístrateconcorreo') || lower.includes('registrateconcorreo')) return 95;
    // 法语: S'inscrire avec l'e-mail
    if (lower.includes("s'inscrireavecl") || lower.includes('inscrireavecl')) return 95;
    // 德语: Mit E-Mail registrieren
    if (lower.includes('mite-mailregistrieren') || lower.includes('mitemailregistrieren')) return 95;
    // 日语: メールで登録
    if (compact.includes('メールで登録')) return 95;
    // 葡萄牙语: Inscrever-se com email
    if (lower.includes('inscrever-secomemail') || lower.includes('inscreversecomemail')) return 95;
    // 意大利语: Registrati con email
    if (lower.includes('registraticonemail')) return 95;
    // 通用：包含 email + 动词
    if (lower.includes('email') && (lower.includes('sign') || lower.includes('continue') || lower.includes('use') || lower.includes('with') || lower.includes('registr') || lower.includes('inscr') || lower.includes('regíst') || lower.includes('regist'))) return 80;
    // 通用：包含 correo(西语email) + 注册动词
    if (lower.includes('correo') && (lower.includes('registr') || lower.includes('regíst'))) return 80;
    if (lower === 'email' || lower.includes('邮箱')) return 70;
    return 0;
}
const candidates = Array.from(document.querySelectorAll('button, a, [role="button"]'))
    .filter((node) => isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true')
    .map((node) => ({ node, score: scoreEntry(node), text: nodeText(node) }))
    .filter((item) => item.score > 0)
    .sort((a, b) => b.score - a.score);
if (!candidates.length) return false;
candidates[0].node.click();
return candidates[0].text || true;
                """)
                last_reclick_time = now
                if reclicked and log_callback:
                    detail = f": {reclicked}" if isinstance(reclicked, str) else ""
                    log_callback(f"[Debug] 邮箱输入框未出现，已再次触发邮箱注册入口{detail}")
            if log_callback and now - last_diag_time >= 5:
                last_diag_time = now
                inputs = " | ".join((filled or {}).get("inputs", [])[:6]) if isinstance(filled, dict) else ""
                buttons = " | ".join((filled or {}).get("buttons", [])[:8]) if isinstance(filled, dict) else ""
                url = (filled or {}).get("url", page.url if page else "") if isinstance(filled, dict) else (page.url if page else "")
                log_callback(f"[Debug] 等待邮箱输入框: url={url}; inputs={inputs or 'none'}; buttons={buttons or 'none'}")
            sleep_with_cancel(0.5, cancel_callback)
            continue
        if state != "filled":
            if log_callback:
                log_callback(f"[Debug] 邮箱输入框已出现，但写入失败: {filled}")
            sleep_with_cancel(0.5, cancel_callback)
            continue
        sleep_with_cancel(0.8, cancel_callback)
        clicked = _native_click_action(
            (
                "注册", "继续", "下一步", "确认", "sign up", "signup", "continue", "next", "create account",
                # 西班牙语
                "registr", "finalizar", "continuar",
                # 法语
                "inscrire", "continuer",
                # 德语
                "registrieren", "weiter",
                # 葡萄牙语
                "inscrever", "continuar",
                # 意大利语
                "registrati", "continua",
                # 日语
                "登録",
            ),
        )
        if not clicked:
            clicked = page.run_js(
                r"""
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
function textOf(node) {
    return [
        node.innerText,
        node.textContent,
        node.getAttribute('aria-label'),
        node.getAttribute('title'),
        node.getAttribute('placeholder'),
        node.getAttribute('data-testid'),
        node.getAttribute('name'),
        node.getAttribute('id'),
        node.getAttribute('autocomplete'),
    ].filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
}
function emailCandidates() {
    const direct = Array.from(document.querySelectorAll('input[data-testid="email"], input[name="email"], input[type="email"], input[autocomplete="email"], input[placeholder*="mail" i], input[aria-label*="mail" i]'));
    const all = Array.from(document.querySelectorAll('input, textarea'));
    for (const node of all) {
        const type = (node.getAttribute('type') || '').toLowerCase();
        if (['hidden', 'submit', 'button', 'checkbox', 'radio', 'file', 'search'].includes(type)) continue;
        const meta = textOf(node).toLowerCase();
        if (meta.includes('email') || meta.includes('e-mail') || meta.includes('mail') || meta.includes('邮箱') || meta.includes('电子邮件')) {
            direct.push(node);
        }
    }
    return Array.from(new Set(direct));
}
const input = emailCandidates().find((node) => isVisible(node) && !node.disabled && !node.readOnly) || null;
if (!input || !(input.value || '').trim()) return false;
const inputType = (input.getAttribute('type') || '').toLowerCase();
if (inputType === 'email' && !input.checkValidity()) return false;
const buttons = Array.from(document.querySelectorAll('button[type="submit"], button, [role="button"], input[type="submit"]'))
    .filter((node) => isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true');
const submitButton = buttons.find((node) => {
    const text = textOf(node).replace(/\s+/g, '');
    const lower = text.toLowerCase();
    return (
        text === '注册' ||
        text.includes('注册') ||
        text.includes('继续') ||
        text.includes('下一步') ||
        text.includes('确认') ||
        lower.includes('signup') ||
        lower.includes('sign up') ||
        lower.includes('continue') ||
        lower.includes('next') ||
        lower.includes('createaccount') ||
        lower.includes('submit')
    );
});
if (submitButton) {
    submitButton.click();
    return textOf(submitButton) || true;
}
const form = input.closest('form');
if (form) {
    if (form.requestSubmit) form.requestSubmit();
    else form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    return 'form-submit';
}
input.focus();
input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', bubbles: true, cancelable: true }));
input.dispatchEvent(new KeyboardEvent('keyup', { key: 'Enter', code: 'Enter', bubbles: true, cancelable: true }));
return 'enter';
                """
            )
        if clicked:
            # 点击按钮 != 表单真正提交成功：CF 挑战未过或页面卡住时点击无效果，
            # 邮件不会发出。必须确认页面已离开邮箱输入阶段（邮箱框消失或出现验证码框），
            # 否则继续循环重试点击，最终超时抛异常触发换邮箱重试。
            if _wait_email_page_advanced(email, cancel_callback=cancel_callback):
                if log_callback:
                    detail = f" ({clicked})" if isinstance(clicked, str) else ""
                    log_callback(f"[*] 已填写邮箱并提交: {email}{detail}")
                _notify_email_accepted(email)
                return email, dev_token
            if log_callback and time.time() - last_diag_time >= 5:
                last_diag_time = time.time()
                log_callback(f"[Debug] 已点击注册但页面未前进，重试提交: {email}")
            raise_if_email_domain_rejected(email)
        sleep_with_cancel(0.5, cancel_callback)
    raise_if_email_domain_rejected(email)
    # 超时前最后一次硬恢复
    if log_callback:
        log_callback("[!] 填邮箱超时，最后一次 reload 恢复")
    if _reload_signup_and_open_email(log_callback=log_callback, cancel_callback=cancel_callback):
        try:
            native_filled = _native_fill_email(email)
            if native_filled or _page_has_email_form():
                # 给一次短循环机会
                extra_deadline = time.time() + 8
                while time.time() < extra_deadline:
                    raise_if_cancelled(cancel_callback)
                    if _native_fill_email(email):
                        clicked = page.run_js(
                            r"""
const email = arguments[0];
const input = document.querySelector('input[type="email"], input[name="email"], input[data-testid="email"]');
if (!input) return false;
const buttons = Array.from(document.querySelectorAll('button[type="submit"], button'));
const btn = buttons.find((b) => /sign\s*up|注册|continue|继续/i.test((b.innerText||'') + (b.textContent||'')));
if (btn) { btn.click(); return true; }
return false;
""",
                            email,
                        ) if page else False
                        if clicked and _wait_email_page_advanced(email, wait=5.0, cancel_callback=cancel_callback):
                            if log_callback:
                                log_callback(f"[*] 已填写邮箱并提交: {email} (recovery)")
                            _notify_email_accepted(email)
                            return email, dev_token
                    sleep_with_cancel(0.5, cancel_callback)
        except Exception as rec_exc:
            if log_callback:
                log_callback(f"[!] 最终恢复填表失败: {rec_exc}")
    if last_snapshot:
        inputs = " | ".join(last_snapshot.get("inputs", [])[:6])
        buttons = " | ".join(last_snapshot.get("buttons", [])[:8])
        url = last_snapshot.get("url", page.url if page else "")
        raise Exception(
            f"未找到邮箱输入框或注册按钮，最后页面: url={url}; inputs={inputs or 'none'}; buttons={buttons or 'none'}"
        )
    raise Exception("未找到邮箱输入框或注册按钮")


def fill_code_and_submit(email, dev_token, timeout=45, log_callback=None, cancel_callback=None):
    def _resend_code():
        native = _native_click_action(("重新发送", "再次发送", "resend", "reenviar", "renvoyer", "erneut senden", "再送"))
        if native:
            return True
        return page.run_js(
            r"""
const nodes = Array.from(document.querySelectorAll('button, a, [role="button"]'));
const target = nodes.find((node) => {
  const t = (node.innerText || node.textContent || '').replace(/\s+/g, '').toLowerCase();
  return t.includes('重新发送') || t.includes('resend') || t.includes('再次发送');
});
if (target && !target.disabled) { target.click(); return true; }
return false;
            """
        )

    code = _deps['get_oai_code'](
        dev_token,
        email,
        log_callback=log_callback,
        cancel_callback=cancel_callback,
        resend_callback=_resend_code,
    )
    if not code:
        raise Exception("获取验证码失败")
    clean_code = str(code).replace("-", "").strip()
    deadline = time.time() + timeout

    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        native_filled = _native_fill_code(clean_code)
        if native_filled != "not-ready" and native_filled != "boxes-failed":
            filled = native_filled
        else:
            filled = page.run_js(
                """
const code = String(arguments[0] || '').trim();
if (!code) return 'empty-code';

function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}

function setInputValue(input, value) {
    const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
    const tracker = input._valueTracker;
    if (tracker) tracker.setValue('');
    if (nativeSetter) nativeSetter.call(input, value);
    else input.value = value;
    input.dispatchEvent(new InputEvent('beforeinput', { bubbles: true, data: value, inputType: 'insertText' }));
    input.dispatchEvent(new InputEvent('input', { bubbles: true, data: value, inputType: 'insertText' }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
}

const aggregate = Array.from(document.querySelectorAll(
  'input[data-input-otp], input[data-input-otp=\"true\"], input[name=\"code\"], input[autocomplete=\"one-time-code\"], input[inputmode=\"numeric\"], input[inputmode=\"text\"]'
)).find((node) => {
    const hiddenOtp = node.hasAttribute('data-input-otp');
    return (hiddenOtp || isVisible(node)) && !node.disabled && !node.readOnly && Number(node.maxLength || 6) > 1;
});

if (aggregate) {
    aggregate.focus();
    aggregate.click();
    setInputValue(aggregate, code);
    return String(aggregate.value || '').replace(/\\s+/g, '') ? 'filled-aggregate' : 'aggregate-failed';
}

const otpBoxes = Array.from(document.querySelectorAll('input')).filter((node) => {
    if (!isVisible(node) || node.disabled || node.readOnly) return false;
    const maxLength = Number(node.maxLength || 0);
    const ac = String(node.autocomplete || '').toLowerCase();
    return maxLength === 1 || ac === 'one-time-code';
});

if (otpBoxes.length >= code.length) {
    for (let i = 0; i < code.length; i += 1) {
        const ch = code[i] || '';
        const box = otpBoxes[i];
        box.focus();
        box.click();
        setInputValue(box, ch);
        box.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true, key: ch }));
        box.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, key: ch }));
    }
    const merged = otpBoxes.slice(0, code.length).map((x) => String(x.value || '').trim()).join('');
    return merged.length ? 'filled-boxes' : 'boxes-failed';
}

return 'not-ready';
            """,
                clean_code,
            )

        if filled == "not-ready":
            sleep_with_cancel(0.5, cancel_callback)
            continue
        if "failed" in str(filled):
            if log_callback:
                log_callback(f"[Debug] 验证码填写失败: {filled}")
            sleep_with_cancel(0.5, cancel_callback)
            continue

        clicked = _native_click_action(("确认邮箱", "继续", "下一步", "confirm", "continue", "next", "confirmar", "confirmer", "bestätigen", "確認"))
        if not clicked:
            clicked = page.run_js(
                r"""
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}

const buttons = Array.from(document.querySelectorAll('button[type=\"submit\"], button')).filter((node) => {
    return isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true';
});

const btn = buttons.find((node) => {
    const t = (node.innerText || node.textContent || '').replace(/\\s+/g, '').toLowerCase();
    return (
        t.includes('确认邮箱') ||
        t.includes('继续') ||
        t.includes('下一步') ||
        t.includes('confirm') ||
        t.includes('continue') ||
        t.includes('next')
    );
});

if (!btn) return 'no-button';
btn.focus();
btn.click();
return 'clicked';
                """
            )

        if clicked == "clicked" or clicked == "no-button" or clicked:
            if log_callback:
                log_callback(f"[*] 已填写验证码并提交: {code}")
            _try_otp_enter()
            wait_until = time.time() + 12
            last_step = ""
            while time.time() < wait_until:
                raise_if_cancelled(cancel_callback)
                info = _probe_signup_page()
                step = str(info.get("step") or "")
                if step != last_step and log_callback:
                    log_callback(
                        f"[*] 验证码后页面 step={step} path={info.get('path') or ''} "
                        f"cf={info.get('cf')} buttons={info.get('buttons') or []}"
                    )
                    last_step = step
                if step in ("profile", "wait-cf", "existing-account"):
                    return code
                if step == "still-otp":
                    _click_continue_if_any()
                    _try_otp_enter()
                sleep_with_cancel(0.6, cancel_callback)
            if log_callback:
                info = _probe_signup_page()
                log_callback(
                    f"[!] 验证码已填但未进入资料页 step={info.get('step')} "
                    f"hint={(info.get('hint') or '')[:120]}"
                )
            return code

        sleep_with_cancel(0.5, cancel_callback)

    raise Exception("验证码已获取，但自动填写/提交失败")


def _should_retry_cf(wait_cf_since, last_cf_retry_at, now=None) -> bool:
    """是否应主动调用 getTurnstileToken。

    首次：等满 CF_FIRST_RETRY_AFTER；之后：间隔 CF_RETRY_INTERVAL。
    """
    if wait_cf_since is None:
        return False
    now = time.time() if now is None else now
    if not last_cf_retry_at or last_cf_retry_at <= 0:
        return (now - wait_cf_since) >= CF_FIRST_RETRY_AFTER
    return (now - last_cf_retry_at) >= CF_RETRY_INTERVAL


def _fill_cf_turnstile_token(token) -> Any:
    """把 Turnstile token 写回页面隐藏域。"""
    return page.run_js(
        """
const token = String(arguments[0] || '').trim();
const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
if (!cfInput || !token) return false;
const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
if (nativeSetter) nativeSetter.call(cfInput, token);
else cfInput.value = token;
cfInput.dispatchEvent(new Event('input', { bubbles: true }));
cfInput.dispatchEvent(new Event('change', { bubbles: true }));
return String(cfInput.value || '').trim().length;
        """,
        token,
    )


def _try_sync_turnstile(
    log_callback=None,
    cancel_callback=None,
    reason="自动复用 Turnstile",
) -> bool:
    """主动获取 Turnstile token 并回填；成功返回 True。

    优化：先快速读取已有 token，只有 token 为空时才进入完整获取流程。
    避免每次调用都进入 30 秒循环，导致 widget 被 reset 打断。
    """
    if log_callback:
        log_callback(f"[*] {reason}...")

    # 先快速读取已有 token（不 reset，不阻塞）
    try:
        existing = page.run_js(
            """
try {
  const byInput = String((document.querySelector('input[name="cf-turnstile-response"]') || {}).value || '').trim();
  if (byInput) return byInput;
  if (window.turnstile && typeof turnstile.getResponse === 'function') {
    return String(turnstile.getResponse() || '').trim();
  }
  return '';
} catch(e) { return ''; }
            """
        )
        existing = str(existing or "").strip()
        if len(existing) >= 80:
            synced = _fill_cf_turnstile_token(existing)
            if log_callback:
                log_callback(f"[*] Turnstile token 已就绪，回填长度={synced}")
            return bool(synced and int(synced or 0) >= 80)
    except Exception:
        pass

    # token 为空，进入完整获取流程（被动等待优先，不 reset）
    try:
        token = getTurnstileToken(log_callback=log_callback, cancel_callback=cancel_callback)
        if not token:
            return False
        synced = _fill_cf_turnstile_token(token)
        if log_callback:
            log_callback(f"[*] Turnstile 二次复用完成，回填长度={synced}")
        return bool(synced and int(synced or 0) >= 80)
    except Exception as cf_exc:
        if log_callback:
            log_callback(f"[Debug] Turnstile 二次复用失败: {cf_exc}")
        return False


_turnstile_reset_done = False


def getTurnstileToken(log_callback=None, cancel_callback=None, force_reset=False):
    """获取 Turnstile token（直接点击 + 轮询等待）。

    Turnstile iframe 内无 checkbox DOM 元素（canvas/overlay 渲染），
    managed 模式不会自动通过，所以：
    1. 直接通过 raw_page.frames 定位 frame 并坐标点击
    2. 轮询等待 token 出现
    3. 未通过则间隔重试点击
    """
    if active_page() is None:
        raise Exception("页面未就绪，无法执行 Turnstile")

    click_attempted = False
    last_click_round = -100
    TOTAL_ROUNDS = 20
    POLL_INTERVAL = 2.0

    for _ in range(0, TOTAL_ROUNDS):
        raise_if_cancelled(cancel_callback)
        try:
            token = page.run_js(
                """
try {
  const byInput = String((document.querySelector('input[name="cf-turnstile-response"]') || {}).value || '').trim();
  if (byInput) return byInput;
  if (window.turnstile && typeof turnstile.getResponse === 'function') {
    return String(turnstile.getResponse() || '').trim();
  }
  return '';
} catch(e) { return ''; }
                """
            )
            token = str(token or "").strip()
            if len(token) >= 80:
                if log_callback:
                    log_callback(f"[*] Turnstile 已通过，token长度={len(token)}")
                return token

            # 直接点击（首次或间隔重试）
            if not click_attempted or (_ - last_click_round >= 4):
                if not click_attempted:
                    if log_callback:
                        log_callback("[*] 尝试点击 Turnstile...")
                else:
                    if log_callback:
                        log_callback("[*] 再次尝试点击 Turnstile...")
                _try_click_turnstile_frame(log_callback=log_callback)
                click_attempted = True
                last_click_round = _
                sleep_with_cancel(3.0, cancel_callback)
                continue
        except Exception:
            pass
        sleep_with_cancel(POLL_INTERVAL, cancel_callback)

    raise Exception("Turnstile 获取 token 失败")


def _try_click_turnstile_frame(log_callback=None):
    """通过 Playwright frame API 点击 Turnstile checkbox。

    全链路诊断日志 + 多策略点击：
    1. 遍历 frames 找到 Turnstile frame（日志输出找到/未找到 + frame URL）
    2. 在 frame 内搜索 checkbox 元素（日志输出尝试了哪些选择器）
    3. 找到则点击；未找到则走 body 坐标点击 fallback
    4. frame 内点击失败则尝试 page 级 iframe 坐标点击
    """
    try:
        raw_page = page.raw_page
    except Exception as exc:
        if log_callback:
            log_callback(f"[Debug] Turnstile 点击失败：无法获取 raw_page: {exc}")
        return

    # ---- 遍历 Playwright frames 找到 Turnstile frame ----
    turnstile_frame = None
    all_frame_urls = []
    for frame in raw_page.frames:
        frame_url = str(frame.url or "")
        all_frame_urls.append(frame_url[:80])
        if "challenges.cloudflare.com" in frame_url or "turnstile" in frame_url.lower():
            turnstile_frame = frame
            break

    if not turnstile_frame:
        if log_callback:
            log_callback(
                f"[Debug] Turnstile frame 未找到。当前 frames({len(all_frame_urls)}): "
                f"{all_frame_urls}"
            )
        return

    frame_url = str(turnstile_frame.url or "")
    if log_callback:
        log_callback(f"[Debug] Turnstile frame 已定位: {frame_url[:100]}")

    # ---- 策略 1：frame body 坐标点击（Turnstile 实际交互方式）----
    # Turnstile iframe 内没有 checkbox DOM 元素（inputs=[]），
    # 交互区域是 canvas/overlay，只能通过坐标点击。
    # checkbox 标准位置在 iframe 左侧 24px 处。
    try:
        body_info = turnstile_frame.evaluate(
            """
() => {
  const b = document.body;
  if (!b) return null;
  const r = b.getBoundingClientRect();
  return { w: r.width, h: r.height };
}
            """
        )
        if log_callback:
            bi = body_info or {}
            log_callback(
                f"[Debug] Turnstile frame body: w={bi.get('w', 0):.0f} h={bi.get('h', 0):.0f}"
            )

        if not body_info or body_info.get("w", 0) <= 0:
            if log_callback:
                log_callback("[Debug] Turnstile frame body 未渲染好，跳过")
            return

        click_x = 24
        click_y = body_info["h"] / 2
        turnstile_frame.click("body", position={"x": click_x, "y": click_y}, timeout=3000)
        if log_callback:
            log_callback(f"[*] 已点击 Turnstile frame body ({click_x}, {click_y:.0f})")
        return
    except Exception as frame_click_exc:
        if log_callback:
            log_callback(f"[Debug] Turnstile frame body 点击失败: {frame_click_exc}")

    # ---- 策略 2：page 级 iframe 元素坐标点击（frame 点击被 CSP 拦截时）----
    try:
        iframe_el = raw_page.query_selector(
            'iframe[src*="challenges.cloudflare.com"], iframe[src*="turnstile"]'
        )
        if iframe_el:
            box = iframe_el.bounding_box()
            if box and box["width"] > 0:
                px = box["x"] + 24
                py = box["y"] + box["height"] / 2
                raw_page.mouse.click(px, py)
                if log_callback:
                    log_callback(f"[*] 已在 page 级点击 Turnstile iframe ({px:.0f}, {py:.0f})")
                return
    except Exception as page_click_exc:
        if log_callback:
            log_callback(f"[Debug] Turnstile page 级点击失败: {page_click_exc}")


def build_profile():
    given_name_pool = [
        "Neo", "Ethan", "Liam", "Noah", "Lucas", "Mason", "Ryan", "Leo",
        "Owen", "Aiden", "Elio", "Aron", "Ivan", "Nolan", "Evan", "Kai",
        "Caleb", "Adam", "Ezra", "Miles", "Logan", "Carter", "Hunter", "Jason",
        "Brian", "Dylan", "Alex", "Colin", "Blake", "Gavin", "Henry", "Julian",
        "Kevin", "Louis", "Marcus", "Nathan", "Oscar", "Peter", "Quinn", "Robin",
        "Simon", "Tristan", "Victor", "Wesley", "Xavier", "Yuri", "Zane", "Felix",
        "Aaron", "Damian",
    ]
    family_name_pool = [
        "Lin", "Wang", "Zhao", "Liu", "Chen", "Zhang", "Xu", "Sun",
        "Guo", "He", "Yang", "Wu", "Zhou", "Tang", "Qin", "Shi",
        "Fang", "Peng", "Cao", "Deng", "Fan", "Fu", "Gao", "Han",
        "Hu", "Jiang", "Kong", "Lu", "Ma", "Nie", "Pan", "Qiao",
        "Ren", "Shao", "Tian", "Xie", "Yan", "Yao", "Yu", "Zeng",
        "Bai", "Duan", "Hou", "Jin", "Kang", "Luo", "Mao", "Song",
        "Wei", "Xiong",
    ]
    given_name = random.choice(given_name_pool)
    family_name = random.choice(family_name_pool)
    password = "N" + secrets.token_hex(4) + "!a7#" + secrets.token_urlsafe(6)
    return given_name, family_name, password


def fill_profile_and_submit(timeout=None, log_callback=None, cancel_callback=None):
    """填写资料页姓名/密码并提交。

    timeout 默认 PROFILE_TIMEOUT（45s）。超时按原因抛明确异常：
    - 资料页 Turnstile 超时...
    - 资料页表单未就绪...
    - 资料页无提交按钮...
    - 最终注册页资料填写失败: <state>
    """
    if timeout is None:
        timeout = PROFILE_TIMEOUT
    given_name, family_name, password = build_profile()
    deadline = time.time() + float(timeout)
    form_filled_once = False
    wait_cf_since = None
    last_cf_retry_at = 0.0
    last_cf_log_at = 0.0
    last_logged_token_len = None
    last_state = "init"
    saw_cf_wait = False
    form_seen = False
    cf_rounds = 0
    last_probe_log = 0.0

    def _maybe_log_cf_wait(message, token_len):
        nonlocal last_cf_log_at, last_logged_token_len
        if not log_callback:
            return
        now = time.time()
        token_key = str(token_len)
        if (
            token_key != last_logged_token_len
            or now - last_cf_log_at >= CF_WAIT_LOG_INTERVAL
        ):
            log_callback(message)
            last_cf_log_at = now
            last_logged_token_len = token_key

    def _raise_profile_fail():
        if saw_cf_wait or str(last_state).startswith("wait-cf"):
            raise Exception(
                f"资料页 Turnstile 超时: {last_state} "
                f"(cf_rounds={cf_rounds}/{PROFILE_CF_MAX_ROUNDS}, 建议换出口)"
            )
        if last_state == "not-ready" or not form_seen:
            raise Exception(
                f"资料页表单未就绪: 超时未出现姓名/密码输入框 last={last_state}"
            )
        if str(last_state).startswith("no-submit"):
            raise Exception(f"资料页无提交按钮: {last_state}")
        if last_state == "fill-failed":
            raise Exception(f"资料页输入写入失败: {last_state}")
        raise Exception(f"最终注册页资料填写失败: {last_state}")

    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        if not form_filled_once:
            # React Hook Form 只认真实键盘；JS setter 会留下 “You must provide a first name”
            if _native_fill_profile(given_name, family_name, password):
                filled = "native-filled"
            else:
                filled = page.run_js(
                    """
const givenName = arguments[0];
const familyName = arguments[1];
const password = arguments[2];

function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}

function pickInput(selector) {
    return Array.from(document.querySelectorAll(selector)).find((node) => {
        return isVisible(node) && !node.disabled && !node.readOnly;
    }) || null;
}

function setInputValue(input, value) {
    if (!input) return false;
    input.focus();
    input.click();
    const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
    const tracker = input._valueTracker;
    if (tracker) tracker.setValue('');
    if (nativeSetter) nativeSetter.call(input, value);
    else input.value = value;
    input.dispatchEvent(new InputEvent('beforeinput', { bubbles: true, data: value, inputType: 'insertText' }));
    input.dispatchEvent(new InputEvent('input', { bubbles: true, data: value, inputType: 'insertText' }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
    input.blur();
    return String(input.value || '').trim() === String(value || '').trim();
}

function pickField(selectors) {
    for (const selector of selectors) {
        const hit = pickInput(selector);
        if (hit) return hit;
        const wrap = Array.from(document.querySelectorAll(selector)).find((node) => {
            const inner = node.querySelector && node.querySelector('input,textarea');
            return inner && isVisible(inner) && !inner.disabled && !inner.readOnly;
        });
        if (wrap) {
            const inner = wrap.querySelector('input,textarea');
            if (inner) return inner;
        }
    }
    return null;
}

const givenInput = pickField([
    'input[data-testid="givenName"]', '[data-testid="givenName"]',
    'input[name="givenName"]', 'input[autocomplete="given-name"]',
    'input[name="firstName"]', 'input[autocomplete="givenname"]',
    'input[aria-label*="名"]', 'input[placeholder*="First" i]',
]);
const familyInput = pickField([
    'input[data-testid="familyName"]', '[data-testid="familyName"]',
    'input[name="familyName"]', 'input[autocomplete="family-name"]',
    'input[name="lastName"]', 'input[autocomplete="familyname"]',
    'input[aria-label*="姓"]', 'input[placeholder*="Last" i]',
]);
const passwordInput = pickField([
    'input[data-testid="password"]', '[data-testid="password"]',
    'input[name="password"]', 'input[type="password"]',
    'input[autocomplete="new-password"]',
]);

const cfEarly = document.querySelector('input[name="cf-turnstile-response"]')
  || document.querySelector('iframe[src*="turnstile"], div.cf-turnstile, [data-sitekey], script[src*="turnstile"]');
if ((!givenInput || !familyInput || !passwordInput) && cfEarly) {
    const token = String((document.querySelector('input[name="cf-turnstile-response"]') || {}).value || '').trim();
    return 'wait-cloudflare:' + token.length;
}

if (!givenInput || !familyInput || !passwordInput) return 'not-ready';

const ok1 = setInputValue(givenInput, givenName);
const ok2 = setInputValue(familyInput, familyName);
const ok3 = setInputValue(passwordInput, password);

if (!ok1 || !ok2 || !ok3) return 'fill-failed';

const buttons = Array.from(document.querySelectorAll('button[type="submit"], button, [role="button"], input[type="submit"]')).filter((node) => {
    return isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true';
});
const submitBtn = buttons.find((node) => {
    const t = (node.innerText || node.textContent || '').replace(/\\s+/g, '').toLowerCase();
    const testid = (node.getAttribute('data-testid') || '').toLowerCase();
    if (testid.includes('submit') || testid.includes('signup') || testid.includes('register') || testid.includes('continue')) return true;
    if (t.includes('完成注册') || t.includes('创建账户') || t.includes('signup') || t.includes('createaccount')) return true;
    if (t.includes('registr') || t.includes('inscr') || t.includes('登録') || t.includes('finalizar')) return true;
    return false;
});

const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
const cfPresent = !!cfInput
  || !!document.querySelector('iframe[src*="turnstile"], div.cf-turnstile, [data-sitekey], script[src*="turnstile"]');
if (cfPresent) {
    const token = String((cfInput && cfInput.value) || '').trim();
    const solvedByToken = token.length >= 80;
    if (!solvedByToken) return 'wait-cloudflare:' + token.length;
}

if (submitBtn) {
    return 'ready-to-submit';
}
return 'filled-no-submit';
            """,
                given_name,
                family_name,
                password,
                )

            if isinstance(filled, str) and filled.startswith("wait-cloudflare"):
                # CF 通过前表单可能还没挂上；绝不能标 form_filled_once，
                # 否则 token 到手后会空表提交 → "You must provide a first name"。
                form_seen = True
                saw_cf_wait = True
                token_len = filled.split(":", 1)[1] if ":" in filled else "0"
                last_state = f"wait-cf:{token_len}"
                _maybe_log_cf_wait(
                    f"[*] 资料页等待 Cloudflare 人机验证... token长度={token_len} "
                    f"（验证通过后再填姓名/密码）",
                    token_len,
                )
                now = time.time()
                if wait_cf_since is None:
                    wait_cf_since = now
                    sleep_with_cancel(0.4, cancel_callback)
                if _should_retry_cf(wait_cf_since, last_cf_retry_at, now):
                    cf_rounds += 1
                    if cf_rounds > PROFILE_CF_MAX_ROUNDS:
                        last_state = f"wait-cf:{token_len}"
                        _raise_profile_fail()
                    synced = _try_sync_turnstile(
                        log_callback=log_callback,
                        cancel_callback=cancel_callback,
                        reason="Cloudflare 验证卡住，开始二次复用 Turnstile",
                    )
                    last_cf_retry_at = time.time()
                    if synced:
                        sleep_with_cancel(0.5, cancel_callback)
                        wait_cf_since = None
                        continue
                sleep_with_cancel(0.8, cancel_callback)
                continue

            if filled in ("native-filled", "ready-to-submit", "filled-no-submit"):
                form_filled_once = True
                form_seen = True
                last_state = str(filled)
            elif filled == "fill-failed":
                last_state = "fill-failed"
                if log_callback:
                    log_callback("[Debug] 资料输入失败，重试中...")
                sleep_with_cancel(0.5, cancel_callback)
                continue
            elif filled == "not-ready":
                last_state = "not-ready"
                info = _probe_signup_page()
                step = str(info.get("step") or "")
                now = time.time()
                if log_callback and now - last_probe_log >= PROFILE_PROBE_LOG_INTERVAL:
                    log_callback(
                        f"[Debug] 资料页未就绪 step={step} cf={info.get('cf')} "
                        f"path={info.get('path') or ''} buttons={info.get('buttons') or []} "
                        f"hint={(info.get('hint') or '')[:100]}"
                    )
                    last_probe_log = now
                if step == "wait-cf":
                    form_seen = True
                    saw_cf_wait = True
                    last_state = "wait-cf:probe"
                    token_len = "0"
                    _maybe_log_cf_wait(
                        "[*] 资料页先出现 Cloudflare，等待人机验证后再出表单...",
                        token_len,
                    )
                    if wait_cf_since is None:
                        wait_cf_since = now
                    if _should_retry_cf(wait_cf_since, last_cf_retry_at, now):
                        cf_rounds += 1
                        if cf_rounds > PROFILE_CF_MAX_ROUNDS:
                            _raise_profile_fail()
                        synced = _try_sync_turnstile(
                            log_callback=log_callback,
                            cancel_callback=cancel_callback,
                            reason="资料表单未出，先复用 Turnstile",
                        )
                        last_cf_retry_at = time.time()
                        if synced:
                            wait_cf_since = None
                    sleep_with_cancel(0.8, cancel_callback)
                    continue
                if step == "existing-account":
                    raise Exception(
                        "资料页变成已有账号/登录页，当前邮箱可能已注册: "
                        f"{(info.get('hint') or '')[:80]}"
                    )
                if step == "still-otp":
                    _click_continue_if_any()
                    _try_otp_enter()
                sleep_with_cancel(0.5, cancel_callback)
                continue

        submit_state = page.run_js(
            r"""
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}

const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
const cfPresent = !!cfInput
  || !!document.querySelector('iframe[src*="turnstile"], div.cf-turnstile, [data-sitekey], script[src*="turnstile"]');
if (cfPresent) {
    const token = String((cfInput && cfInput.value) || '').trim();
    const solvedByToken = token.length >= 80;
    if (!solvedByToken) return 'wait-cloudflare:' + token.length;
}

function buttonText(node) {
    return [
        node.innerText,
        node.textContent,
        node.getAttribute('value'),
        node.getAttribute('aria-label'),
        node.getAttribute('title'),
    ].filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
}
const buttons = Array.from(document.querySelectorAll('button[type="submit"], button, [role="button"], input[type="submit"]')).filter((node) => {
    return isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true';
});
const submitBtn = buttons.find((node) => {
    const t = buttonText(node).replace(/\s+/g, '').toLowerCase();
    const testid = (node.getAttribute('data-testid') || '').toLowerCase();
    if (testid.includes('submit') || testid.includes('signup') || testid.includes('register') || testid.includes('continue')) return true;
    if (t.includes('完成注册') || t.includes('创建账户') || t.includes('signup') || t.includes('createaccount')) return true;
    if (t.includes('registr') || t.includes('inscr') || t.includes('登録') || t.includes('finalizar')) return true;
    return false;
});
if (!submitBtn) {
    const visibleTexts = buttons.map(buttonText).filter(Boolean).slice(0, 8).join(' | ');
    return 'no-submit-button:' + visibleTexts;
}
return 'ready-to-submit';
            """
        )

        if isinstance(submit_state, str) and submit_state.startswith("wait-cloudflare"):
            form_seen = True
            saw_cf_wait = True
            token_len = submit_state.split(":", 1)[1] if ":" in submit_state else "0"
            last_state = f"wait-cf:{token_len}"
            _maybe_log_cf_wait(
                f"[*] 等待 Cloudflare 人机验证通过后再提交... 当前token长度={token_len}",
                token_len,
            )
            now = time.time()
            if wait_cf_since is None:
                wait_cf_since = now
            if _should_retry_cf(wait_cf_since, last_cf_retry_at, now):
                cf_rounds += 1
                if cf_rounds > PROFILE_CF_MAX_ROUNDS:
                    _raise_profile_fail()
                synced = _try_sync_turnstile(
                    log_callback=log_callback,
                    cancel_callback=cancel_callback,
                    reason="提交前仍卡住，自动再次复用 Turnstile",
                )
                last_cf_retry_at = time.time()
                if synced:
                    sleep_with_cancel(0.5, cancel_callback)
                    wait_cf_since = None
                    continue
            sleep_with_cancel(0.8, cancel_callback)
            continue

        if submit_state == "ready-to-submit":
            last_state = "ready-to-submit"
            clicked_native = _native_click_action(
                (
                    "完成注册", "创建账户", "signup", "create account", "continue", "next",
                    "registr", "finalizar", "inscrire", "registrieren",
                    "inscrever", "registrati", "登録",
                )
            )
            if clicked_native:
                submit_state = "submitted"
            else:
                submit_state = page.run_js(
                    r"""
const buttons = Array.from(document.querySelectorAll('button[type="submit"], button, [role="button"], input[type="submit"]'));
const btn = buttons.find((node) => {
  const t = [node.innerText, node.textContent, node.value, node.getAttribute('aria-label')]
    .filter(Boolean).join(' ').replace(/\s+/g, '').toLowerCase();
  const testid = (node.getAttribute('data-testid') || '').toLowerCase();
  if (testid.includes('submit') || testid.includes('signup') || testid.includes('register') || testid.includes('continue')) return true;
  if (t.includes('完成注册') || t.includes('创建账户') || t.includes('signup') || t.includes('createaccount')) return true;
  if (t.includes('registr') || t.includes('inscr') || t.includes('登録') || t.includes('finalizar')) return true;
  return false;
});
if (!btn) return 'no-submit-button';
btn.focus(); btn.click(); return 'submitted';
                    """
                )

        if submit_state == "submitted":
            if log_callback:
                log_callback(f"[*] 已点击资料提交: {given_name} {family_name}")
            # 等 createAccount 真正落地：切走 sign-up / 出现 sso / 报错。
            settle_until = time.time() + 12
            last_hint = ""
            while time.time() < settle_until:
                raise_if_cancelled(cancel_callback)
                try:
                    cur = str(getattr(page, "url", "") or "")
                except Exception:
                    cur = ""
                info = _probe_signup_page()
                step = str(info.get("step") or "")
                hint = str(info.get("hint") or "")
                if hint and hint != last_hint and log_callback:
                    log_callback(
                        f"[*] 提交后页面 step={step} path={info.get('path') or cur} "
                        f"hint={hint[:140]}"
                    )
                    last_hint = hint
                if "/sign-in" in cur.lower() or "grok.com" in cur.lower():
                    return {"given_name": given_name, "family_name": family_name, "password": password}
                if step in ("existing-account",):
                    return {"given_name": given_name, "family_name": family_name, "password": password}
                if step == "page-error" or _hint_is_page_error(hint):
                    # Next 崩溃遮罩经常叠在 createAccount 成功之后。
                    # 硬跳 sign-up 会掐断跳转 / 清会话，SSO 必超时。
                    if log_callback:
                        log_callback("[!] 提交后 x.ai 报页面错误，不刷新，继续等跳转/sso")
                    return {
                        "given_name": given_name,
                        "family_name": family_name,
                        "password": password,
                    }
                low = hint.lower()
                if "must provide" in low or "you must" in low or "is required" in low:
                    if log_callback:
                        log_callback("[!] 资料校验失败（姓名/密码未进 React 状态），改用原生键盘重填")
                    form_filled_once = False
                    last_state = "validation-empty"
                    break
                if any(
                    k in low
                    for k in (
                        "already exists",
                        "existing account",
                        "invalid code",
                        "something went wrong",
                        "try again",
                        "unable to",
                        "an error occurred",
                        "error loading this page",
                    )
                ):
                    if log_callback:
                        log_callback(f"[!] 建号接口回报错: {hint[:160]}")
                    return {"given_name": given_name, "family_name": family_name, "password": password}
                sleep_with_cancel(0.5, cancel_callback)
            else:
                return {"given_name": given_name, "family_name": family_name, "password": password}
            continue
        wait_cf_since = None
        if isinstance(submit_state, str) and submit_state.startswith("no-submit-button") and log_callback:
            last_state = str(submit_state)
            visible_buttons = submit_state.split(":", 1)[1] if ":" in submit_state else ""
            suffix = f" 可见按钮: {visible_buttons}" if visible_buttons else ""
            log_callback(f"[Debug] 未找到提交按钮，继续等待页面稳定...{suffix}")

        sleep_with_cancel(0.5, cancel_callback)

    _raise_profile_fail()


def wait_for_sso_cookie(
    timeout=20,
    log_callback=None,
    cancel_callback=None,
    email=None,
    password=None,
):
    """等注册完成后的 sso cookie。

    关键：不要一看到「正在登录」就强制 page.get(grok.com)，
    那会打断 accounts.x.ai 的 redirect / Set-Cookie 链，导致 grok.com 只剩匿名 cookie。

    线上失败主因：资料提交后被甩到 sign-in?redirect=account，
    hold 3s + 总超时 10s 就硬跳 grok.com → 只有匿名 cookie → sso_timeout。

    策略（短超时 + 主动推进，不硬等）：
      1) 若还在 /sign-up：加长 hold，让 createAccount 跑完，禁止硬跳 sign-in
      2) 落到 sign-in 用 email+password 自动登录（先邮箱再密码）
      3) 仍无 sso 再轻量跳 accounts?redirect=grok-com / grok（最多 1 次）
    """
    # 环境可覆盖：SSO_WAIT_TIMEOUT=45
    env_timeout = 0
    try:
        env_timeout = int(os.environ.get("SSO_WAIT_TIMEOUT", "0") or "0")
    except Exception:
        env_timeout = 0
    base_timeout = env_timeout or int(timeout or 35)
    deadline = time.time() + max(base_timeout, 30)
    started = time.time()
    last_seen_names = set()
    last_submit_retry = 0.0
    last_cf_retry_at = 0.0
    last_heartbeat = 0.0
    last_signin_log = 0.0
    last_back_click = 0.0
    last_grok_nudge = 0.0
    last_continue_click = 0.0
    last_signin_attempt = 0.0
    signin_attempt_count = 0
    grok_nudge_count = 0
    final_no_submit_state = ""
    final_no_submit_since = None
    final_no_submit_timeout = 8
    # 短 hold：给 Set-Cookie 留窗口；过早硬跳 grok/sign-in 会打断建号
    accounts_hold_seconds = 12
    grok_nudge_min_elapsed = 22
    max_grok_nudges = 1
    max_signin_attempts = 4
    email_s = str(email or "").strip()
    password_s = str(password or "").strip()

    def _current_url():
        try:
            return str(getattr(page, "url", "") or "")
        except Exception:
            return ""

    def _read_sso_from_cookies():
        cookies = page.cookies(all_domains=True, all_info=True) or []
        names = set()
        sso_val = ""
        sso_rw_val = ""
        for item in cookies:
            if isinstance(item, dict):
                name = str(item.get("name", "")).strip()
                value = str(item.get("value", "")).strip()
            else:
                name = str(getattr(item, "name", "")).strip()
                value = str(getattr(item, "value", "")).strip()
            if name:
                names.add(name)
            if name == "sso" and value and not sso_val:
                sso_val = value
            if name == "sso-rw" and value and not sso_rw_val:
                sso_rw_val = value
        # 优先 sso；少数情况下只有 sso-rw
        return (sso_val or sso_rw_val), names

    def _page_is_signing_in():
        try:
            return bool(
                page.run_js(
                    r"""
const t = ((document.body && document.body.innerText) || '').replace(/\s+/g, '');
const lower = t.toLowerCase();
return t.includes('您正在登录') || t.includes('正在登录')
  || lower.includes('signingyouin') || lower.includes('signinginin')
  || lower.includes('signing in') || lower.includes('logging in')
  || lower.includes('redirecting');
                    """
                )
            )
        except Exception:
            return False

    def _url_is_sign_in(url: str) -> bool:
        low = (url or "").lower()
        return ("/sign-in" in low) or ("signin" in low and "signup" not in low)

    def _page_has_login_password_form():
        """仅识别「登录」密码表单，排除注册资料页的 new-password。"""
        try:
            return bool(
                page.run_js(
                    r"""
function isVisible(node) {
  if (!node) return false;
  const style = window.getComputedStyle(node);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
  const rect = node.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}
// 资料页有 givenName / familyName / new-password，不能当登录页
const profileHint = Array.from(document.querySelectorAll(
  'input[data-testid="givenName"], input[name="givenName"], input[autocomplete="given-name"],'
  + 'input[data-testid="familyName"], input[name="familyName"], input[autocomplete="family-name"],'
  + 'input[autocomplete="new-password"]'
)).some(isVisible);
if (profileHint) return false;
const title = ((document.body && document.body.innerText) || '').slice(0, 1200).toLowerCase();
const looksSignup = title.includes('完成注册') || title.includes('complete your sign')
  || title.includes('create your account') || title.includes('sign up');
if (looksSignup) return false;
const pwd = Array.from(document.querySelectorAll(
  'input[type="password"], input[name="password"], input[autocomplete="current-password"]'
)).find(isVisible);
if (!pwd) return false;
const auto = String(pwd.getAttribute('autocomplete') || '').toLowerCase();
if (auto.includes('new-password')) return false;
return true;
                    """
                )
            )
        except Exception:
            return False

    def _try_sign_in_with_credentials(reason: str) -> str:
        """注册后落到 sign-in 时，用刚设的密码完成登录，拿 sso。返回 sso 或空串。"""
        nonlocal signin_attempt_count, last_signin_attempt
        if not email_s or not password_s:
            return ""
        if signin_attempt_count >= max_signin_attempts:
            return ""
        now_ts = time.time()
        if now_ts - last_signin_attempt < 3.5:
            return ""
        last_signin_attempt = now_ts
        signin_attempt_count += 1
        if log_callback:
            log_callback(
                f"[*] {reason}，自动登录拿 sso"
                f"（第 {signin_attempt_count}/{max_signin_attempts} 次）..."
            )

        # 登录常是两步：先邮箱 Continue，再出密码框。
        def _signin_fields():
            try:
                return page.run_js(
                    r"""
function isVisible(node) {
  if (!node) return false;
  const style = window.getComputedStyle(node);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
  const rect = node.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}
const emailInput = Array.from(document.querySelectorAll(
  'input[type="email"], input[name="email"], input[autocomplete="email"], input[autocomplete="username"], input[data-testid*="email" i]'
)).find(isVisible) || null;
const pwdInput = Array.from(document.querySelectorAll(
  'input[type="password"], input[name="password"], input[autocomplete="current-password"]'
)).find((n) => {
  if (!isVisible(n)) return false;
  const ac = String(n.getAttribute('autocomplete') || '').toLowerCase();
  return !ac.includes('new-password');
}) || null;
return { hasEmail: !!emailInput, hasPwd: !!pwdInput };
                    """
                ) or {}
            except Exception:
                return {}

        fields = _signin_fields()
        if not isinstance(fields, dict):
            fields = {}
        if log_callback:
            log_callback(
                f"[*] 登录表单 hasEmail={bool(fields.get('hasEmail'))} "
                f"hasPwd={bool(fields.get('hasPwd'))}"
            )

        # 1) 原生优先（真实键盘事件）
        filled_email = False
        filled_pwd = False
        try:
            email_cands = _native_input_candidates("email")
            pwd_cands = _native_input_candidates("password")
            if email_cands:
                filled_email = _native_type_element(email_cands[0], email_s)
            if pwd_cands:
                filled_pwd = _native_type_element(pwd_cands[0], password_s)
        except Exception as fill_exc:
            if log_callback:
                log_callback(f"[!] 原生填登录表单失败: {fill_exc}")

        # 2) JS 兜底（React controlled inputs）
        if not (filled_email and filled_pwd):
            try:
                js_state = page.run_js(
                    r"""
const email = String(arguments[0] || '');
const password = String(arguments[1] || '');
function isVisible(node) {
  if (!node) return false;
  const style = window.getComputedStyle(node);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
  const rect = node.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}
function setInputValue(input, value) {
  if (!input) return false;
  input.focus();
  input.click();
  const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
  const tracker = input._valueTracker;
  if (tracker) tracker.setValue('');
  if (nativeSetter) nativeSetter.call(input, value);
  else input.value = value;
  input.dispatchEvent(new InputEvent('beforeinput', { bubbles: true, data: value, inputType: 'insertText' }));
  input.dispatchEvent(new InputEvent('input', { bubbles: true, data: value, inputType: 'insertText' }));
  input.dispatchEvent(new Event('change', { bubbles: true }));
  input.blur();
  return String(input.value || '').trim() === String(value || '').trim();
}
const emailInput = Array.from(document.querySelectorAll(
  'input[type="email"], input[name="email"], input[autocomplete="email"], input[autocomplete="username"], input[data-testid*="email" i]'
)).find(isVisible) || null;
const pwdInput = Array.from(document.querySelectorAll(
  'input[type="password"], input[name="password"], input[autocomplete="current-password"]'
)).find(isVisible) || null;
const okEmail = emailInput ? setInputValue(emailInput, email) : true;
const okPwd = pwdInput ? setInputValue(pwdInput, password) : false;
return { okEmail, okPwd, hasEmail: !!emailInput, hasPwd: !!pwdInput };
                    """,
                    email_s,
                    password_s,
                )
                if isinstance(js_state, dict):
                    filled_email = filled_email or bool(js_state.get("okEmail"))
                    filled_pwd = filled_pwd or bool(js_state.get("okPwd"))
                    if log_callback and not js_state.get("hasPwd"):
                        log_callback("[Debug] sign-in 页未找到密码框")
            except Exception as js_exc:
                if log_callback:
                    log_callback(f"[Debug] JS 填登录表单失败: {js_exc}")

        # 只有邮箱、还没有密码框：先点 Continue 进入下一步
        if filled_email and not filled_pwd and not fields.get("hasPwd"):
            clicked_next = _native_click_action(
                ("继续", "下一步", "continue", "next", "sign in", "登录"),
                deny_keywords=("sign up", "注册", "google", "apple", "github"),
            )
            if log_callback:
                log_callback(f"[*] 登录页仅有邮箱，先点继续: {clicked_next or 'no-button'}")
            for _ in range(8):
                sleep_with_cancel(0.35, cancel_callback)
                fields = _signin_fields()
                if isinstance(fields, dict) and fields.get("hasPwd"):
                    break
            try:
                pwd_cands = _native_input_candidates("password")
                if pwd_cands:
                    filled_pwd = _native_type_element(pwd_cands[0], password_s)
            except Exception:
                filled_pwd = False

        if not filled_pwd:
            if log_callback:
                log_callback("[!] 自动登录：密码未写入，跳过提交")
            return ""

        # 3) 点登录 / 继续
        clicked = _native_click_action(
            (
                "登录",
                "登入",
                "sign in",
                "signin",
                "log in",
                "login",
                "continue",
                "继续",
                "next",
                "下一步",
            ),
            deny_keywords=("sign up", "注册", "create", "google", "apple", "github", "sso"),
        )
        if not clicked:
            try:
                clicked = page.run_js(
                    r"""
function isVisible(node) {
  if (!node) return false;
  const style = window.getComputedStyle(node);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
  const rect = node.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}
const nodes = Array.from(document.querySelectorAll('button[type="submit"], button, [role="button"], input[type="submit"]'));
const btn = nodes.find((n) => {
  if (!isVisible(n) || n.disabled) return false;
  const t = ((n.innerText || n.textContent || '') + ' ' + (n.getAttribute('aria-label') || '')).replace(/\s+/g, ' ').trim().toLowerCase();
  const compact = t.replace(/\s+/g, '');
  if (compact.includes('signup') || compact.includes('注册') || t.includes('google') || t.includes('apple')) return false;
  return compact.includes('登录') || compact.includes('登入') || t.includes('sign in') || t.includes('log in')
    || compact.includes('继续') || t.includes('continue') || t.includes('next') || n.type === 'submit';
});
if (!btn) return '';
btn.focus(); btn.click();
return (btn.innerText || btn.textContent || 'submit').trim().slice(0, 40);
                    """
                ) or ""
            except Exception:
                clicked = ""
        if clicked and log_callback:
            log_callback(f"[*] 自动登录已点击: {clicked}")
        # 短轮询几次，不硬睡
        for _ in range(4):
            sleep_with_cancel(0.35, cancel_callback)
            sso_val, names = _read_sso_from_cookies()
            last_seen_names.update(names)
            if sso_val:
                return sso_val
        return ""

    def _click_continue_if_any(strict: bool = False):
        """点「继续 / 前往 Grok」类按钮，推动自然 redirect。

        strict=True 时只点明确的「前往 Grok / Go to Grok / 开始使用」，
        避免在 sign-up 残留页误点通用 Continue 把链打断到 sign-in。
        """
        try:
            return page.run_js(
                r"""
const strict = !!arguments[0];
function isVisible(node) {
  if (!node) return false;
  const style = window.getComputedStyle(node);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
  const rect = node.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}
const nodes = Array.from(document.querySelectorAll('button, a, [role="button"], input[type="submit"]'));
const btn = nodes.find((n) => {
  if (!isVisible(n) || n.disabled) return false;
  const t = ((n.innerText || n.textContent || '') + ' '
    + (n.getAttribute('aria-label') || '') + ' '
    + (n.getAttribute('href') || '')).replace(/\s+/g, ' ').trim().toLowerCase();
  const compact = t.replace(/\s+/g, '');
  if (compact.includes('返回') || t.includes('back') || t.includes('return')) return false;
  if (compact.includes('signup') || compact.includes('注册') || t.includes('create account')) return false;
  const goGrok = compact.includes('前往') || compact.includes('打开') || t.includes('go to')
    || t.includes('grok.com') || compact.includes('开始使用') || t.includes('open grok');
  if (goGrok) return true;
  if (strict) return false;
  return compact.includes('继续') || t.includes('continue') || t.includes('proceed');
});
if (!btn) return false;
btn.click();
return true;
                """,
                bool(strict),
            )
        except Exception:
            return False

    def _click_back_if_any():
        try:
            return page.run_js(
                r"""
function isVisible(node) {
  if (!node) return false;
  const style = window.getComputedStyle(node);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
  const rect = node.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}
const nodes = Array.from(document.querySelectorAll('button, a, [role="button"]'));
const btn = nodes.find((n) => {
  if (!isVisible(n) || n.disabled) return false;
  const t = ((n.innerText || n.textContent || '') + ' ' + (n.getAttribute('aria-label') || '')).replace(/\s+/g, '');
  const lower = t.toLowerCase();
  return t.includes('返回') || lower.includes('back') || lower.includes('return');
});
if (!btn) return false;
btn.click();
return true;
                """
            )
        except Exception:
            return False

    def _nudge_grok_once(reason):
        nonlocal grok_nudge_count, last_grok_nudge
        if grok_nudge_count >= max_grok_nudges:
            return ""
        # 优先走带 redirect 的 accounts 入口，比直接 grok.com 更不容易丢会话
        targets = (
            "https://accounts.x.ai/sign-in?redirect=grok-com",
            "https://grok.com/",
        )
        target = targets[min(grok_nudge_count, len(targets) - 1)]
        if log_callback:
            log_callback(
                f"[*] {reason}，轻量打开 {target}（第 {grok_nudge_count + 1}/{max_grok_nudges} 次）..."
            )
        try:
            page.get(target)
            try:
                page.wait.doc_loaded()
            except Exception:
                pass
            sleep_with_cancel(0.6, cancel_callback)
            grok_nudge_count += 1
            last_grok_nudge = time.time()
            sso_val, names = _read_sso_from_cookies()
            last_seen_names.update(names)
            return sso_val
        except Exception as nav_exc:
            grok_nudge_count += 1
            last_grok_nudge = time.time()
            if log_callback:
                log_callback(f"[Debug] 跳转取 sso 失败: {nav_exc}")
            return ""

    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        try:
            refresh_active_page()
            if active_page() is None:
                sleep_with_cancel(0.5, cancel_callback)
                continue

            now = time.time()
            elapsed = now - started
            cur_url = _current_url()
            on_accounts = ("accounts.x.ai" in cur_url) or ("auth.x.ai" in cur_url)
            on_grok = "grok.com" in cur_url
            on_sign_in = _url_is_sign_in(cur_url)
            # 只在真正 sign-in URL、或明确登录密码表单时才自动登录
            # （注册资料页也有 password 框，旧逻辑会误判成登录并打断 SSO 链）
            has_login_form = False
            if on_sign_in:
                has_login_form = True
            elif on_accounts and not on_sign_in:
                has_login_form = _page_has_login_password_form()

            # 心跳：避免长时间无日志像卡死（2.5s 一次，不硬等）
            if log_callback and now - last_heartbeat >= 2.5:
                last_heartbeat = now
                remain = max(int(deadline - now), 0)
                log_callback(
                    f"[*] 等待 sso 中... 已等 {int(elapsed)}s，剩余 {remain}s | url={cur_url[:90]}"
                )

            # 优先读 cookie（登录中页面也可能已写入 sso）
            sso_val, names = _read_sso_from_cookies()
            last_seen_names |= names
            if sso_val:
                if log_callback:
                    log_callback("[*] 已获取到 sso cookie")
                return sso_val

            signin_hint = _page_is_signing_in()

            # 阶段0：真正落到 sign-in / 登录表单 → 用注册密码自动登录
            if has_login_form and email_s and password_s:
                if not signin_hint:
                    sso_val = _try_sign_in_with_credentials("注册后落到登录页")
                    if sso_val:
                        if log_callback:
                            log_callback("[*] 已获取到 sso cookie")
                        return sso_val
                    # 登录已点，下一轮继续读 cookie（不硬睡）
                    sleep_with_cancel(0.35, cancel_callback)
                    continue

            # 阶段1：accounts 上「正在登录」→ 短 hold 轮询，不立刻跳 grok
            if signin_hint and on_accounts and elapsed < accounts_hold_seconds:
                if log_callback and now - last_signin_log >= 2.5:
                    last_signin_log = now
                    remain_hold = max(int(accounts_hold_seconds - elapsed), 0)
                    log_callback(
                        f"[*] 页面显示正在登录，先在 accounts.x.ai 等 sso"
                        f"（再等 {remain_hold}s）..."
                    )
                # hold 过半后只点「前往 Grok」类明确按钮，避免误点通用 Continue
                if elapsed >= 2.5 and now - last_continue_click >= 3:
                    last_continue_click = now
                    if _click_continue_if_any(strict=True) and log_callback:
                        log_callback("[*] 已点击前往 Grok 类按钮，等待 redirect...")
                sleep_with_cancel(0.3, cancel_callback)
                continue

            # 阶段2：hold 结束仍在 accounts 且无 sso → 主动推进，不空等
            if on_accounts and elapsed >= accounts_hold_seconds:
                # 仍在 sign-in / 登录表单：立刻自动登录，不要硬跳 grok
                if has_login_form:
                    if email_s and password_s and not signin_hint:
                        sso_val = _try_sign_in_with_credentials("accounts 登录页仍无 sso")
                        if sso_val:
                            if log_callback:
                                log_callback("[*] 已获取到 sso cookie")
                            return sso_val
                    sleep_with_cancel(0.4, cancel_callback)
                    # 登录试过仍无 sso，再轻量跳（最后手段）
                    if (
                        elapsed >= grok_nudge_min_elapsed + 4
                        and grok_nudge_count < max_grok_nudges
                        and now - last_grok_nudge >= 6
                        and signin_attempt_count >= 1
                    ):
                        sso_val = _nudge_grok_once("sign-in 自动登录仍无 sso")
                        if sso_val:
                            if log_callback:
                                log_callback("[*] 已获取到 sso cookie")
                            return sso_val
                    continue

                # 非 sign-in：先点明确「前往」；稍后再允许通用 continue
                if now - last_continue_click >= 3.5:
                    last_continue_click = now
                    strict = elapsed < accounts_hold_seconds + 4
                    if _click_continue_if_any(strict=strict) and log_callback:
                        kind = "前往 Grok" if strict else "继续/前往"
                        log_callback(f"[*] accounts 等待结束，已点击{kind}类按钮...")
                        sleep_with_cancel(0.8, cancel_callback)
                        sso_val, names = _read_sso_from_cookies()
                        last_seen_names |= names
                        if sso_val:
                            if log_callback:
                                log_callback("[*] 已获取到 sso cookie")
                            return sso_val
                still_signup = ("/sign-up" in cur_url.lower()) and not on_sign_in
                if still_signup:
                    info = _probe_signup_page()
                    step = str(info.get("step") or "")
                    hint = str(info.get("hint") or "")
                    if step == "page-error" or _hint_is_page_error(hint):
                        # 遮罩页上点提交/整页重开都会打断登录链；只等跳转或稍后再试登录。
                        if now - last_submit_retry >= 6:
                            last_submit_retry = now
                            if log_callback:
                                log_callback("[!] sign-up 仍是错误遮罩，不刷新，继续等 sso")
                            if email_s and password_s:
                                sso_val = _try_sign_in_with_credentials(
                                    "错误遮罩后改走登录"
                                )
                                if sso_val:
                                    if log_callback:
                                        log_callback("[*] 已获取到 sso cookie")
                                    return sso_val
                        sleep_with_cancel(0.5, cancel_callback)
                        continue
                    # 建号请求可能还在飞，禁止硬跳 sign-in
                    if now - last_submit_retry >= 3:
                        last_submit_retry = now
                        if log_callback:
                            log_callback("[*] 仍在 sign-up，重试点击提交，不跳转 sign-in...")
                        _click_continue_if_any(strict=False)
                    sleep_with_cancel(0.5, cancel_callback)
                    continue
                if (
                    grok_nudge_count < max_grok_nudges
                    and elapsed >= grok_nudge_min_elapsed
                    and now - last_grok_nudge >= 6
                ):
                    sso_val = _nudge_grok_once("accounts 等待结束仍无 sso")
                    if sso_val:
                        if log_callback:
                            log_callback("[*] 已获取到 sso cookie")
                        return sso_val

            # 阶段3：已在 grok.com 仍无 sso → 回 accounts 登录重建，不空刷
            if on_grok and not sso_val:
                if signin_hint and now - last_back_click >= 6:
                    last_back_click = now
                    if _click_back_if_any():
                        if log_callback:
                            log_callback("[*] grok 页无 sso，已点击「返回」尝试重新推进")
                        sleep_with_cancel(0.6, cancel_callback)
                elif (
                    email_s
                    and password_s
                    and signin_attempt_count < max_signin_attempts
                    and elapsed >= 5
                    and now - last_signin_attempt >= 5
                ):
                    # 匿名 grok 会话：回 accounts 登录页用密码建会话
                    if log_callback:
                        log_callback("[*] grok.com 匿名会话，回 accounts 登录页重建 sso...")
                    try:
                        page.get(
                            "https://accounts.x.ai/sign-in?redirect=grok-com"
                        )
                        try:
                            page.wait.doc_loaded()
                        except Exception:
                            pass
                        sleep_with_cancel(0.6, cancel_callback)
                    except Exception as nav_exc:
                        if log_callback:
                            log_callback(f"[Debug] 回 accounts 登录失败: {nav_exc}")
                elif (
                    grok_nudge_count < max_grok_nudges
                    and elapsed >= grok_nudge_min_elapsed + 4
                    and now - last_grok_nudge >= 6
                ):
                    sso_val = _nudge_grok_once("grok.com 仍为匿名会话")
                    if sso_val:
                        if log_callback:
                            log_callback("[*] 已获取到 sso cookie")
                        return sso_val

            # 仍停留在“完成注册”页时，若 Cloudflare 已通过，周期性重试点击提交
            if now - last_submit_retry >= 2.5:
                retried = page.run_js(
                    r"""
function isVisible(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
}
const titleHit = !!Array.from(document.querySelectorAll('h1,h2,div,span')).find((el) => {
    const t = (el.textContent || '').replace(/\s+/g, '');
    const lower = t.toLowerCase();
    return t.includes('完成注册') || lower.includes('completeyoursignup') || lower.includes('completesignup');
});
if (!titleHit) return 'not-final-page';

const cfInput = document.querySelector('input[name="cf-turnstile-response"]');
const cfPresent = !!cfInput
  || !!document.querySelector('iframe[src*="turnstile"], div.cf-turnstile, [data-sitekey], script[src*="turnstile"]');
if (cfPresent) {
    const token = String((cfInput && cfInput.value) || '').trim();
    const solved = token.length >= 80;
    if (!solved) return 'final-page-wait-cf:' + token.length;
}

function buttonText(node) {
    return [
        node.innerText,
        node.textContent,
        node.getAttribute('value'),
        node.getAttribute('aria-label'),
        node.getAttribute('title'),
    ].filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
}
const buttons = Array.from(document.querySelectorAll('button[type="submit"], button, [role="button"], input[type="submit"]')).filter((node) => {
    return isVisible(node) && !node.disabled && node.getAttribute('aria-disabled') !== 'true';
});
const submitBtn = buttons.find((node) => {
    const t = buttonText(node).replace(/\s+/g, '').toLowerCase();
    const testid = (node.getAttribute('data-testid') || '').toLowerCase();
    if (testid.includes('submit') || testid.includes('signup') || testid.includes('register') || testid.includes('continue')) return true;
    if (t.includes('完成注册') || t.includes('创建账户') || t.includes('signup') || t.includes('createaccount')) return true;
    if (t.includes('registr') || t.includes('inscr') || t.includes('登録') || t.includes('finalizar')) return true;
    return false;
});
if (!submitBtn) {
    const visibleTexts = buttons.map(buttonText).filter(Boolean).slice(0, 8).join(' | ');
    return 'final-page-no-submit:' + visibleTexts;
}
submitBtn.focus();
submitBtn.click();
return 'final-page-clicked-submit';
                    """
                )
                last_submit_retry = now
                if log_callback and (retried == "final-page-clicked-submit" or (isinstance(retried, str) and retried.startswith("final-page-no-submit"))):
                    log_callback(f"[Debug] 最终页状态: {retried}")
                if isinstance(retried, str) and retried.startswith("final-page-no-submit"):
                    if retried != final_no_submit_state:
                        final_no_submit_state = retried
                        final_no_submit_since = now
                    elif final_no_submit_since and now - final_no_submit_since >= final_no_submit_timeout:
                         raise _AccountRetryNeeded(
                            f"最终注册页状态 {final_no_submit_timeout}s 未变化且未找到提交按钮，重试当前账号: {retried}"
                        )
                else:
                    final_no_submit_state = ""
                    final_no_submit_since = None
                if isinstance(retried, str) and retried.startswith("final-page-wait-cf"):
                    token_len = retried.split(":", 1)[1] if ":" in retried else "0"
                    if log_callback:
                        log_callback(
                            f"[Debug] 最终页状态: final-page-wait-cf, token长度={token_len}"
                        )
                    # 首次立即尝试，之后按 CF_RETRY_INTERVAL 复用
                    if last_cf_retry_at <= 0 or (now - last_cf_retry_at >= CF_RETRY_INTERVAL):
                        _try_sync_turnstile(
                            log_callback=log_callback,
                            cancel_callback=cancel_callback,
                            reason="最终页 Cloudflare 卡住，自动二次复用 Turnstile",
                        )
                        last_cf_retry_at = time.time()

            # 再读一次 cookie（点击提交后可能刚写入）
            sso_val, names = _read_sso_from_cookies()
            last_seen_names |= names
            if sso_val:
                if log_callback:
                    log_callback("[*] 已获取到 sso cookie")
                return sso_val
        except PageDisconnectedError:
            if log_callback:
                log_callback("[Debug] 页面断开，尝试刷新标签...")
            refresh_active_page()
        except Exception as exc:
            name = type(exc).__name__
            if name in ("AccountRetryNeeded", "RegistrationCancelled"):
                raise
            if log_callback:
                log_callback(f"[Debug] 等待 sso 时异常: {exc}")

        sleep_with_cancel(0.4, cancel_callback)

    final_url = _current_url()
    raise Exception(
        "sso_timeout：等待超时未获取到 sso cookie（多为登录链被打断或未真正建号）。"
        f" url={final_url[:120]} cookies={sorted(last_seen_names)}"
    )


# 点过「允许」后再观察 done 页多久；超时即交由 token 轮询裁决
DEVICE_ALLOW_OBSERVE_SECONDS = 3.0

_DEVICE_ALLOW_KEYS = ("允许", "allow", "approve")  # 勿含 accept，会误点 Accept All Cookies
_DEVICE_CONTINUE_KEYS = ("继续", "continue", "下一步", "next", "确认", "confirm")
_DEVICE_DENY_KEYS = ("拒绝", "deny", "cancel", "取消")


def _click_device_button_native(page_obj, keywords) -> str:
    """用 Playwright 真实事件点击按钮，返回被点按钮文本；未点到返回 ''。

    consent 页两个 submit 按钮都没有 name/value，是 React 的 onClick 负责在提交前
    填充隐藏字段 action=allow。JS 合成 click 会直接触发原生 form submit，抢在
    onClick 之前把 action="" 发出去，服务端返回 Invalid action、授权不落库。
    只有真实事件（isTrusted）才能让 React 正常填值。
    """
    try:
        elements = page_obj.eles("tag:button")
    except Exception:
        return ""
    for ele in elements:
        try:
            text = str(ele.text or "").strip()
        except Exception:
            continue
        if not text:
            continue
        low = text.replace(" ", "").lower()
        if any(k in low for k in _DEVICE_DENY_KEYS):
            continue
        # 跳过 Cookie 横幅按钮
        if any(x in low for x in ("cookie", "cookies", "全部接受", "acceptall", "onetrust", "同意全部")):
            continue
        if not any(k in low for k in keywords):
            continue
        try:
            ele.click()
            return text
        except Exception:
            continue
    return ""


def authorize_device_in_browser(
    user_code: str,
    open_url: str,
    timeout: int = 10,
    log_callback=None,
    cancel_callback=None,
) -> bool:
    """在注册浏览器会话中完成 Device 页「继续」→「允许」。

    对齐 CPA 管理页截图：打开 /oauth2/device?user_code=... 后点继续/允许。
    """
    user_code = str(user_code or "").strip()
    open_url = str(open_url or "").strip()
    if not user_code or not open_url:
        if log_callback:
            log_callback("[!] 浏览器 Device 授权参数不完整")
        return False
    if not open_url.startswith("https://") or "x.ai" not in open_url:
        if log_callback:
            log_callback(f"[!] 不受信的 device URL: {open_url[:120]}")
        return False

    refresh_active_page()
    page_obj = active_page()
    if page_obj is None:
        if log_callback:
            log_callback("[!] 无活动浏览器，无法 Device 授权")
        return False

    if log_callback:
        log_callback(f"[*] 浏览器打开 Device 授权页 user_code={user_code}")

    # Device 授权页可能被 SSO 重定向到 grok.com 中断，重试几次
    device_nav_ok = False
    for nav_attempt in range(2):
        try:
            page_obj.get(open_url)
            page_obj.wait.doc_loaded()
            # 检查是否真的停在了 device 页
            current_url = str(page_obj.url or "")
            if "oauth2/device" in current_url:
                device_nav_ok = True
                break
            if log_callback:
                log_callback(f"[Debug] Device 页导航被重定向到: {current_url}，重试 {nav_attempt + 1}/2")
            sleep_with_cancel(0.5, cancel_callback)
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] Device 页导航异常(第{nav_attempt + 1}次): {exc}")
            sleep_with_cancel(0.5, cancel_callback)

    if not device_nav_ok:
        if log_callback:
            log_callback("[!] 打开 Device 页失败：导航被重定向中断")
        return False
    sleep_with_cancel(0.6, cancel_callback)

    # 卡在授权页就快速失败，交给 device_protocol 回退，别堵整条 worker
    deadline = time.time() + max(8, int(timeout or 10))
    clicked_continue = False
    clicked_allow = False
    # 点过「允许」后只再观察这么久 done 页；成功与否最终由 token 轮询裁决
    allow_observe_deadline = 0.0
    waiting_since = time.time()
    last_stage = ""

    while time.time() < deadline:
        raise_if_cancelled(cancel_callback)
        refresh_active_page()
        page_obj = active_page()
        if page_obj is None:
            return False
        try:
            state = page_obj.run_js(
                r"""
const userCode = String(arguments[0] || '').trim();
function isVisible(node) {
  if (!node) return false;
  const style = window.getComputedStyle(node);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
  const rect = node.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}
function buttonText(node) {
  return [
    node.innerText, node.textContent, node.getAttribute('value'),
    node.getAttribute('aria-label'), node.getAttribute('title'),
  ].filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
}
const url = String(location.href || '');
const bodyText = String(document.body && document.body.innerText || '').slice(0, 4000);
const lowBody = bodyText.toLowerCase();
if (url.includes('/oauth2/device/done') ||
    lowBody.includes('device authorized') ||
    lowBody.includes('you have authorized') ||
    bodyText.includes('设备已授权')) {
  return {ok: true, stage: 'done', url};
}
if (url.includes('sign-in') || url.includes('sign-up')) {
  return {ok: false, stage: 'need-login', url};
}
const buttons = Array.from(document.querySelectorAll('button, [role="button"], input[type="submit"], a')).filter(isVisible);
function findBtn(preds) {
  for (const node of buttons) {
    const t = buttonText(node).replace(/\s+/g, '').toLowerCase();
    for (const p of preds) {
      if (t.includes(p)) return node;
    }
  }
  return null;
}
// 若有 user_code 输入框则填入
const inputs = Array.from(document.querySelectorAll('input')).filter(isVisible);
for (const inp of inputs) {
  const name = String(inp.getAttribute('name') || inp.getAttribute('id') || '').toLowerCase();
  const ph = String(inp.getAttribute('placeholder') || '').toLowerCase();
  if (name.includes('user') || name.includes('code') || ph.includes('code') || ph.includes('代码')) {
    if (userCode && String(inp.value || '').replace(/\s+/g, '') !== userCode.replace(/\s+/g, '')) {
      inp.focus();
      inp.value = userCode;
      inp.dispatchEvent(new Event('input', {bubbles: true}));
      inp.dispatchEvent(new Event('change', {bubbles: true}));
    }
  }
}
// 只做状态检测，不在 JS 里点击：consent 页「允许」是 React 受控 submit，
// 合成 click 会抢在 onClick 填 action 之前触发原生提交，服务端回 Invalid action。
const allowBtn = findBtn(['允许', 'allow', 'approve', '授权', 'accept']);
const continueBtn = findBtn(['继续', 'continue', '下一步', 'next', 'confirm', '确认']);
return {
  ok: false,
  stage: allowBtn ? 'has-allow' : (continueBtn ? 'has-continue' : 'waiting'),
  url,
  text: buttonText(allowBtn || continueBtn || document.createElement('span')),
  buttons: buttons.map(buttonText).filter(Boolean).slice(0, 6),
};
                """,
                user_code,
            )
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] Device 页脚本异常: {exc}")
            sleep_with_cancel(0.8, cancel_callback)
            continue

        if not isinstance(state, dict):
            sleep_with_cancel(0.6, cancel_callback)
            continue
        stage = str(state.get("stage") or "")
        if state.get("ok") or stage == "done":
            if log_callback:
                log_callback("[*] 浏览器 Device 授权完成（done）")
            return True
        if stage == "need-login":
            if clicked_allow:
                break
            if log_callback:
                log_callback("[!] Device 页要求重新登录，SSO 可能无效")
            return False
        if stage == "has-allow" and not clicked_allow:
            text = _click_device_button_native(page_obj, _DEVICE_ALLOW_KEYS)
            if text:
                if log_callback:
                    log_callback(f"[*] 已点击「允许」(原生事件): {text}")
                clicked_allow = True
                waiting_since = time.time()
                allow_observe_deadline = time.time() + DEVICE_ALLOW_OBSERVE_SECONDS
            sleep_with_cancel(0.6, cancel_callback)
            continue
        if clicked_allow and time.time() >= allow_observe_deadline:
            # 已提交授权但页面无已知 done 文案，交给 token 轮询判定真实结果
            break
        if stage == "has-continue" and not clicked_allow:
            text = _click_device_button_native(page_obj, _DEVICE_CONTINUE_KEYS)
            if text and not clicked_continue:
                clicked_continue = True
                waiting_since = time.time()
                if log_callback:
                    log_callback(f"[*] 已点击「继续」(原生事件): {text}")
            sleep_with_cancel(0.6, cancel_callback)
            continue
        # 页面一直 waiting（无继续/允许按钮）超过 8s：直接跳过浏览器路径
        if stage != last_stage:
            last_stage = stage
            waiting_since = time.time()
        if (
            stage == "waiting"
            and not clicked_allow
            and not clicked_continue
            and time.time() - waiting_since >= 5
        ):
            if log_callback:
                log_callback(
                    f"[!] Device 页卡住(stage=waiting>{5}s)，跳过浏览器授权，回退协议路径"
                )
            return False
        # 点过继续但一直出不了允许，12s 也跳过
        if (
            clicked_continue
            and not clicked_allow
            and time.time() - waiting_since >= 8
        ):
            if log_callback:
                log_callback("[!] Device 页点继续后无「允许」，跳过浏览器授权")
            return False
        sleep_with_cancel(0.5, cancel_callback)

    if clicked_allow:
        if log_callback:
            log_callback("[*] 已提交「允许」，未见 done 页；改由 token 轮询判定")
        return True
    if log_callback:
        log_callback(
            f"[!] 浏览器 Device 授权失败：未点到「允许」"
            f"(continue={clicked_continue})"
        )
    return False
