# -*- coding: utf-8 -*-
"""DrissionPage → Camoufox/Playwright 适配层。

把 DrissionPage 的 page/element API 翻译成 Playwright 等价调用，
让 register_flow.py / grok_register_ttk.py 几乎不需要改动。

核心适配：
  page.get(url)       → page.goto(url)
  page.run_js(script, *args) → page.evaluate(wrapped_script, args)
  page.ele(selector)  → page.locator(css_selector)
  page.eles(selector) → page.locator(css_selector).all()
  element.input(text) → locator.fill(text)
  element.click()     → locator.click()
  element.attr(name)  → locator.get_attribute(name)
  element.property("value") → locator.input_value()
  element.text        → locator.inner_text()
  element.parent()    → locator.locator("xpath=..")
  page.cookies()      → context.cookies()
  page.set.cookies() → context.add_cookies()
  page.wait.doc_loaded() → page.wait_for_load_state("domcontentloaded")
"""
from __future__ import annotations

import logging
import re
import time
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ─── DrissionPage 选择器 → CSS 选择器转换 ─────────────────────────────

def _convert_dp_selector(dp_sel: str) -> str:
    """把 DrissionPage 定位语法翻译成 CSS 选择器。

    支持的格式：
      tag:button        → button
      tag:input         → input
      @name=xxx         → [name="xxx"]
      @id=xxx           → #xxx
      @class=xxx        → .xxx
      @type=xxx         → [type="xxx"]
      @data-testid=xxx  → [data-testid="xxx"]
      text:xxx          → text=xxx  (Playwright 文本选择器)
      xpath=//xxx       → xpath=//xxx (直接透传)
      纯 CSS            → 原样返回
    """
    sel = str(dp_sel or "").strip()
    if not sel:
        return ""

    # xpath 直接透传
    if sel.startswith("xpath="):
        return sel

    # tag:xxx → xxx
    if sel.startswith("tag:"):
        tag = sel[4:].strip()
        return tag

    # @attr=value → [attr="value"]
    if sel.startswith("@"):
        body = sel[1:]
        if "=" in body:
            attr, _, val = body.partition("=")
            attr = attr.strip()
            val = val.strip()
            if attr.lower() == "id":
                return f"#{val}"
            if attr.lower() == "class":
                return f".{val}"
            return f'[{attr}="{val}"]'
        return f"[{body}]"

    # text:xxx → Playwright text 选择器
    if sel.startswith("text:"):
        return f"text={sel[5:].strip()}"

    # text=xxx → 透传
    if sel.startswith("text="):
        return sel

    # 原样返回（假设是 CSS）
    return sel


# ─── run_js 适配：arguments[N] → 箭头函数参数 ──────────────────────────

def _wrap_js_for_evaluate(script: str, n_args: int) -> tuple[str, list]:
    """把 DrissionPage 的 run_js(script, *args) 包装成 Playwright evaluate 格式。

    DrissionPage: page.run_js("return arguments[0] + 1", 5)
    Playwright:   page.evaluate("(a) => { return a + 1; }", 5)

    策略：
    1. 把 arguments[0], arguments[1]... 替换为参数名 __cf_a0, __cf_a1...
    2. 用箭头函数包装，无参数时用 IIFE
    """
    script = script.strip()

    if n_args == 0:
        # 无参数：IIFE 包装（支持 return 语句）
        wrapped = f"(() => {{ {script} }})()"
        return wrapped, []

    # 有参数：把 arguments[N] 替换为参数名
    param_names = []
    modified = script
    for i in range(n_args):
        pname = f"__cf_a{i}"
        # 替换 arguments[0], arguments[1] 等
        modified = modified.replace(f"arguments[{i}]", pname)
        param_names.append(pname)

    if n_args == 1:
        wrapped = f"({param_names[0]}) => {{ {modified} }}"
        return wrapped, []
    else:
        # 多参数：用数组解构
        params = ", ".join(param_names)
        wrapped = f"([{params}]) => {{ {modified} }}"
        return wrapped, list(range(n_args))


# ─── Element 适配器 ──────────────────────────────────────────────────

class CamoufoxElement:
    """把 Playwright Locator 包装成 DrissionPage 元素接口。"""

    def __init__(self, locator, page_adapter=None):
        self._locator = locator
        self._page = page_adapter

    # ── 属性 ──
    @property
    def text(self) -> str:
        try:
            return self._locator.inner_text() or ""
        except Exception:
            try:
                return self._locator.text_content() or ""
            except Exception:
                return ""

    @property
    def url(self) -> str:
        try:
            return self._locator.evaluate("el => el.href || ''") or ""
        except Exception:
            return ""

    @property
    def states(self):
        """模拟 DrissionPage 的 .states 属性。"""
        return _ElementStates(self._locator)

    @property
    def shadow_root(self):
        """返回 shadow root 的适配器（或 None）。

        Playwright 的 CSS 选择器默认穿透 open shadow DOM，
        所以 _ShadowRootAdapter 直接在父 locator 上查找即可。
        """
        try:
            has_shadow = self._locator.evaluate("el => el.shadowRoot !== null")
            if has_shadow:
                return _ShadowRootAdapter(self._locator, self._page)
        except Exception:
            pass
        return None

    # ── 方法 ──
    def click(self, by_js: bool = None, timeout: float = 30):
        """点击元素。

        by_js=False/None（默认）→ Playwright 真实点击（isTrusted=true）
        by_js=True             → JS click（不触发真实鼠标事件）

        人类化策略：点击前 50-200ms 随机延迟
        """
        import random

        if not by_js:
            time.sleep(random.uniform(0.05, 0.20))
        if by_js:
            self._locator.evaluate("el => el.click()")
        else:
            self._locator.click(timeout=int(timeout * 1000))

    def input(self, text: str, clear: bool = True, by_js: bool = False, **kw):
        """输入文本。

        by_js=False（默认）→ Playwright 真实键盘事件（isTrusted=true）
        by_js=True        → 用 evaluate 直接设值

        人类化策略：
        - 每字符间延迟随机化（30-120ms），避免机械等速
        - 偶尔短暂停顿（模拟思考）
        """
        import random

        text = str(text or "")
        if by_js:
            self._locator.evaluate(
                "(el, val) => { const setter = Object.getOwnPropertyDescriptor("
                "window.HTMLInputElement.prototype, 'value')?.set || "
                "Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value')?.set; "
                "if (setter) setter.call(el, val); else el.value = val; "
                "el.dispatchEvent(new Event('input', {bubbles:true})); "
                "el.dispatchEvent(new Event('change', {bubbles:true})); }",
                text,
            )
            return
        if clear:
            self._locator.fill("")
        # 人类化输入：每字符随机延迟 30-120ms
        for i, char in enumerate(text):
            self._locator.press_sequentially(char, delay=0)
            # 每 5-8 个字符偶尔插入一次较长停顿（120-300ms）
            if (i + 1) % random.randint(5, 8) == 0 and i + 1 < len(text):
                time.sleep(random.uniform(0.12, 0.30))
            else:
                time.sleep(random.uniform(0.03, 0.12))

    def attr(self, name: str) -> str:
        try:
            return self._locator.get_attribute(name) or ""
        except Exception:
            return ""

    # 内部：暴露原始 locator 供高级操作（必须在 def property 之前定义，
    # 否则 @property 装饰器会被下面的 property() 方法遮蔽）
    @property
    def _raw(self):
        return self._locator

    def property(self, name: str) -> str:
        if name == "value":
            try:
                return self._locator.input_value()
            except Exception:
                try:
                    return self._locator.evaluate("el => el.value || ''") or ""
                except Exception:
                    return ""
        try:
            return self._locator.evaluate(f"el => el.{name}")
        except Exception:
            return ""

    def parent(self):
        """返回父元素。"""
        parent_locator = self._locator.locator("xpath=..")
        return CamoufoxElement(parent_locator, self._page)

    def ele(self, selector: str, timeout: float = None):
        """在当前元素下查找子元素。"""
        css = _convert_dp_selector(selector)
        child = self._locator.locator(css)
        return CamoufoxElement(child, self._page)

    def eles(self, selector: str):
        """在当前元素下查找所有匹配子元素。"""
        css = _convert_dp_selector(selector)
        locators = self._locator.locator(css).all()
        return [CamoufoxElement(l, self._page) for l in locators]

    def run_js(self, script: str, *args):
        """在当前元素上执行 JS。"""
        script = script.strip()
        if not args:
            wrapped = f"(() => {{ {script} }})()"
        else:
            param_names = []
            modified = script
            for i in range(len(args)):
                pname = f"__cf_a{i}"
                modified = modified.replace(f"arguments[{i}]", pname)
                param_names.append(pname)
            if len(args) == 1:
                wrapped = f"({param_names[0]}) => {{ {modified} }}"
                return self._locator.evaluate(wrapped, args[0])
            else:
                params = ", ".join(param_names)
                wrapped = f"([{params}]) => {{ {modified} }}"
                return self._locator.evaluate(wrapped, list(args))
        return self._locator.evaluate(wrapped)


class _ElementStates:
    """模拟 DrissionPage element.states 的属性。"""

    def __init__(self, locator):
        self._locator = locator

    @property
    def is_displayed(self) -> bool:
        try:
            return self._locator.is_visible()
        except Exception:
            return False

    @property
    def is_enabled(self) -> bool:
        try:
            return self._locator.is_enabled()
        except Exception:
            return False

    @property
    def is_alive(self) -> bool:
        try:
            self._locator.is_visible()
            return True
        except Exception:
            return False


class _ShadowRootAdapter:
    """模拟 DrissionPage 的 shadow_root 对象，支持 .ele() 链式调用。"""

    def __init__(self, parent_locator, page_adapter=None):
        self._parent = parent_locator
        self._page = page_adapter

    def ele(self, selector: str, timeout: float = None):
        css = _convert_dp_selector(selector)
        # Playwright CSS 选择器默认穿透 shadow DOM
        child = self._parent.locator(css)
        return CamoufoxElement(child, self._page)

    def eles(self, selector: str):
        css = _convert_dp_selector(selector)
        locators = self._parent.locator(css).all()
        return [CamoufoxElement(l, self._page) for l in locators]

    def run_js(self, script: str, *args):
        """在 shadow root 宿主元素上执行 JS。"""
        script = script.strip()
        if not args:
            wrapped = f"(() => {{ {script} }})()"
        else:
            modified = script
            for i in range(len(args)):
                modified = modified.replace(f"arguments[{i}]", f"__cf_a{i}")
            params = ", ".join(f"__cf_a{i}" for i in range(len(args)))
            wrapped = f"([{params}]) => {{ {modified} }}"
        return self._parent.evaluate(wrapped, list(args) if len(args) > 1 else (args[0] if args else None))


# ─── Page 适配器 ──────────────────────────────────────────────────────

class CamoufoxPage:
    """把 Playwright Page + Context 包装成 DrissionPage page 接口。"""

    def __init__(self, page, context=None):
        self._page = page
        self._context = context or page.context

    # ── 导航 ──
    def get(self, url: str, **kw):
        # load 事件要等全部第三方资源（Turnstile/Castle/字体），住宅出口下常挂
        # 60s goto 超时；后续流程都是轮询元素，domcontentloaded 足够。
        kw.setdefault("wait_until", "domcontentloaded")
        self._page.goto(url, **kw)

    def back(self):
        self._page.go_back()

    def forward(self):
        self._page.go_forward()

    def reload(self):
        self._page.reload()

    # ── 属性 ──
    @property
    def url(self) -> str:
        return self._page.url or ""

    @property
    def html(self) -> str:
        return self._page.content() or ""

    @property
    def title(self) -> str:
        try:
            return self._page.title() or ""
        except Exception:
            return ""

    @property
    def raw_page(self):
        """暴露原始 Playwright Page（高级操作用）。"""
        return self._page

    @property
    def raw_context(self):
        return self._context

    # ── JS 执行 ──
    def run_js(self, script: str, *args):
        """执行 JS，兼容 DrissionPage 的 arguments[N] 传参。"""
        script = script.strip()
        if not args:
            wrapped = f"(() => {{ {script} }})()"
            return self._page.evaluate(wrapped)
        else:
            param_names = []
            modified = script
            for i in range(len(args)):
                pname = f"__cf_a{i}"
                modified = modified.replace(f"arguments[{i}]", pname)
                param_names.append(pname)
            if len(args) == 1:
                wrapped = f"({param_names[0]}) => {{ {modified} }}"
                return self._page.evaluate(wrapped, args[0])
            else:
                params = ", ".join(param_names)
                wrapped = f"([{params}]) => {{ {modified} }}"
                return self._page.evaluate(wrapped, list(args))

    # ── 元素查找 ──
    def ele(self, selector: str, timeout: float = None):
        css = _convert_dp_selector(selector)
        locator = self._page.locator(css).first
        return CamoufoxElement(locator, self)

    def eles(self, selector: str):
        css = _convert_dp_selector(selector)
        locators = self._page.locator(css).all()
        return [CamoufoxElement(l, self) for l in locators]

    # ── Cookie ──
    def cookies(self, all_domains: bool = False, all_info: bool = False):
        """读取所有 Cookie，返回 dict 列表。"""
        raw = self._context.cookies()
        result = []
        for c in raw:
            result.append({
                "name": c.get("name", ""),
                "value": c.get("value", ""),
                "domain": c.get("domain", ""),
                "path": c.get("path", "/"),
                "expires": c.get("expires", -1),
                "httpOnly": c.get("httpOnly", False),
                "secure": c.get("secure", False),
                "sameSite": c.get("sameSite", "Lax"),
            })
        return result

    # ── set 命名空间 ──
    @property
    def set(self):
        return _PageSetter(self)

    # ── wait 命名空间 ──
    @property
    def wait(self):
        return _PageWaiter(self._page)

    # ── 标签管理 ──
    def close(self):
        self._page.close()

    def run_js_loaded(self, script: str, *args):
        """等 DOM 加载后执行 JS。"""
        self._page.wait_for_load_state("domcontentloaded")
        return self.run_js(script, *args)

    def screenshot(self, path: str = None, **kw):
        return self._page.screenshot(path=path, **kw)

    def wait_for_selector(self, selector: str, timeout: int = 30000):
        css = _convert_dp_selector(selector)
        self._page.wait_for_selector(css, timeout=timeout)

    def scroll(self, x: int = 0, y: int = 0):
        self._page.evaluate(f"window.scrollTo({x}, {y})")

    def run_js_on_document(self, script: str):
        """在 document 上下文执行 JS（Playwright add_init_script 的替代）。"""
        self._page.evaluate(script)


class _PageSetter:
    """模拟 DrissionPage page.set.* 命名空间。"""

    def __init__(self, page_adapter: CamoufoxPage):
        self._adapter = page_adapter
        self.window = _WindowSetter(page_adapter)
        self.cookies = _CookieSetter(page_adapter)
        self.tab = _TabSetter(page_adapter)


class _WindowSetter:
    def __init__(self, page_adapter: CamoufoxPage):
        self._adapter = page_adapter

    def location(self, x: int, y: int):
        page = self._adapter.raw_page
        try:
            page.evaluate(f"window.moveTo({x}, {y});")
        except Exception:
            pass

    def size(self, w: int, h: int):
        page = self._adapter.raw_page
        try:
            page.set_viewport_size({"width": w, "height": h})
        except Exception:
            pass

    def max(self):
        page = self._adapter.raw_page
        try:
            page.evaluate("window.maximize && window.maximize();")
        except Exception:
            pass


class _CookieSetter:
    def __init__(self, page_adapter: CamoufoxPage):
        self._adapter = page_adapter

    def __call__(self, cookies_list: list):
        """批量设置 Cookie。"""
        formatted = []
        for c in cookies_list:
            if isinstance(c, dict):
                formatted.append({
                    "name": c.get("name", ""),
                    "value": c.get("value", ""),
                    "domain": c.get("domain", ""),
                    "path": c.get("path", "/"),
                })
            else:
                formatted.append({
                    "name": getattr(c, "name", ""),
                    "value": getattr(c, "value", ""),
                    "domain": getattr(c, "domain", ""),
                    "path": getattr(c, "path", "/"),
                })
        self._adapter.raw_context.add_cookies(formatted)


class _TabSetter:
    def __init__(self, page_adapter: CamoufoxPage):
        self._adapter = page_adapter

    def create(self, url: str = ""):
        page = self._adapter.raw_context.new_page()
        if url:
            page.goto(url)
        return CamoufoxPage(page, self._adapter.raw_context)


class _PageWaiter:
    """模拟 DrissionPage page.wait.* 命名空间。"""

    def __init__(self, page):
        self._page = page

    def doc_loaded(self, timeout: float = 30):
        try:
            self._page.wait_for_load_state("domcontentloaded", timeout=int(timeout * 1000))
        except Exception:
            pass

    def ele_displayed(self, selector: str, timeout: float = 30):
        css = _convert_dp_selector(selector)
        try:
            self._page.wait_for_selector(css, state="visible", timeout=int(timeout * 1000))
        except Exception:
            pass

    def s(self, seconds: float):
        time.sleep(seconds)


# ─── Browser 适配器 ────────────────────────────────────────────────────

class CamoufoxBrowser:
    """把 Camoufox Browser/Context 包装成 DrissionPage browser 接口。"""

    def __init__(self, browser=None, context=None, camoufox_instance=None):
        self._browser = browser
        self._context = context
        self._camoufox = camoufox_instance
        self.user_data_path = ""

    def get_tabs(self):
        """返回所有页面（模拟 DrissionPage get_tabs）。"""
        if self._context:
            pages = self._context.pages
        elif self._browser:
            pages = []
            for ctx in self._browser.contexts:
                pages.extend(ctx.pages)
        else:
            pages = []
        return [CamoufoxPage(p, p.context) for p in pages]

    def new_tab(self, url: str = ""):
        """新建标签页。"""
        if self._context:
            page = self._context.new_page()
        elif self._browser:
            ctx = self._browser.contexts[0] if self._browser.contexts else self._browser.new_context()
            page = ctx.new_page()
        else:
            raise RuntimeError("Browser not started")
        if url:
            page.goto(url)
        return CamoufoxPage(page, page.context)

    def quit(self, del_data: bool = False):
        """关闭浏览器。

        del_data 参数仅为兼容 DrissionPage 接口签名；
        persistent_context=True 时关闭 context 即清除会话数据。
        """
        # 先关 context / browser，再拆 Playwright。任何一端已死后都吞掉
        # EPIPE / TargetClosed，避免 Node 24 Unhandled 'error' 拖死整批。
        try:
            if self._context:
                self._context.close()
        except Exception:
            pass
        try:
            if self._browser:
                self._browser.close()
        except Exception:
            pass
        try:
            if self._camoufox:
                self._camoufox.__exit__(None, None, None)
        except Exception:
            pass
        self._context = None
        self._browser = None
        self._camoufox = None

    @property
    def raw(self):
        return self._browser or self._context
