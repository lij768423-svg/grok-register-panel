#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared disk cache for browser static assets (CSS/font/image).

Opt-in only. Used by run_batch_headless_static_cache.py — does not change the
default run_batch_headless / browser_session path.

Design:
  - Intercept GET static resources via Playwright context.route
  - Shared cache dir across workers (saves jump-board bandwidth)
  - Never caches document / xhr / fetch / websocket (identity & APIs stay live)
  - Does not share cookies or profiles across accounts
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
import weakref
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlsplit, urlunsplit

LogFn = Callable[[str], None]

# Resource types Playwright reports for static assets
_STATIC_RESOURCE_TYPES = frozenset({"script", "stylesheet", "image", "font"})

_STATIC_EXT = frozenset(
    {
        ".js",
        ".mjs",
        ".cjs",
        ".css",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".webp",
        ".ico",
        ".avif",
        ".map",
    }
)

# Host substrings we refuse to cache even if extension matches (challenge / auth APIs)
_SKIP_HOST_SUBSTR = (
    "challenges.cloudflare.com",
    "turnstile",
    "/cdn-cgi/challenge",
)

_META_NAME = "meta.json"
_BODY_NAME = "body.bin"
_DEFAULT_TTL_SECONDS = 3600
_MAX_TTL_SECONDS = 7 * 24 * 3600

_stats_lock = threading.Lock()
_stats = {
    "hits": 0,
    "misses": 0,
    "stores": 0,
    "bypasses": 0,
    "errors": 0,
    "bytes_served": 0,
    "bytes_stored": 0,
}

_installed_contexts: weakref.WeakSet[Any] = weakref.WeakSet()
_install_lock = threading.Lock()


def cache_enabled() -> bool:
    raw = str(os.environ.get("GROK_STATIC_ASSET_CACHE", "") or "").strip().lower()
    return raw in ("1", "true", "yes", "on")


def cache_dir() -> Path:
    raw = str(os.environ.get("GROK_STATIC_CACHE_DIR") or "").strip()
    if raw:
        root = Path(raw)
    else:
        root = Path(__file__).resolve().parent / "log" / "static-asset-cache"
    root.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    return root


def max_cache_mb() -> int:
    try:
        return max(32, int(os.environ.get("GROK_STATIC_CACHE_MAX_MB", "1024")))
    except (TypeError, ValueError):
        return 1024


def get_stats() -> dict[str, int]:
    with _stats_lock:
        return dict(_stats)


def reset_stats() -> None:
    with _stats_lock:
        for k in _stats:
            _stats[k] = 0


def _bump(key: str, amount: int = 1) -> None:
    with _stats_lock:
        _stats[key] = int(_stats.get(key, 0)) + amount


def normalize_cache_url(url: str) -> str:
    """Drop fragment; keep query (hashed assets often version via query)."""
    try:
        parts = urlsplit(url)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))
    except Exception:
        return str(url or "").split("#", 1)[0]


def cache_key(url: str) -> str:
    norm = normalize_cache_url(url)
    return hashlib.sha256(norm.encode("utf-8", "replace")).hexdigest()


def _ext_of(url: str) -> str:
    try:
        path = urlsplit(url).path.lower()
    except Exception:
        path = str(url).lower()
    # handle ".../file.js" or ".../file.js/..."
    base = path.rsplit("/", 1)[-1]
    if "." not in base:
        return ""
    return "." + base.rsplit(".", 1)[-1]


def is_static_request(url: str, resource_type: str = "", method: str = "GET") -> bool:
    if str(method or "GET").upper() != "GET":
        return False
    u = str(url or "")
    if not u.startswith("http://") and not u.startswith("https://"):
        return False
    low = u.lower()
    for skip in _SKIP_HOST_SUBSTR:
        if skip in low:
            return False
    ext = _ext_of(u)
    # Signup scripts build the Castle token. Replaying them from disk
    # correlated with HTTP 400 email-signup-unavailable; leave them live.
    if ext in {".js", ".mjs", ".cjs"}:
        return False
    rt = str(resource_type or "").lower()
    if rt == "script":
        return False
    if rt in {"stylesheet", "font"}:
        return True
    if ext in _STATIC_EXT:
        return True
    # common static path markers without clear extension
    try:
        path = urlsplit(u).path.lower()
    except Exception:
        path = low
    if "/_next/static/" in path or "/static/" in path or "/assets/" in path:
        if rt in ("", "other", "stylesheet", "image", "font"):
            return True
    return False


def _entry_dir(key: str) -> Path:
    # shard two levels to avoid huge single directory
    return cache_dir() / key[:2] / key[2:4] / key


def _read_entry(key: str) -> Optional[dict[str, Any]]:
    d = _entry_dir(key)
    meta_path = d / _META_NAME
    body_path = d / _BODY_NAME
    if not meta_path.is_file() or not body_path.is_file():
        return None
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if float(meta.get("expires_at") or 0) <= time.time():
            return None
        body = body_path.read_bytes()
        if int(meta.get("size") or -1) not in (-1, len(body)):
            # corrupt
            return None
        meta["body"] = body
        # touch for simple LRU signal
        try:
            now = time.time()
            os.utime(meta_path, (now, now))
            os.utime(body_path, (now, now))
        except OSError:
            pass
        return meta
    except Exception:
        return None


def _cache_ttl(headers: dict) -> int:
    normalized = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    cache_control = normalized.get("cache-control", "").lower()
    directives = {part.strip().split("=", 1)[0] for part in cache_control.split(",")}
    if directives.intersection({"private", "no-store", "no-cache"}):
        return 0
    if "set-cookie" in normalized or normalized.get("vary", "").strip() == "*":
        return 0
    match = re.search(r"(?:s-maxage|max-age)\s*=\s*\"?(\d+)", cache_control)
    if match:
        return min(max(0, int(match.group(1))), _MAX_TTL_SECONDS)
    return _DEFAULT_TTL_SECONDS


def _write_entry(key: str, *, url: str, status: int, headers: dict, body: bytes) -> None:
    if not body or len(body) > 15 * 1024 * 1024:
        return
    ttl = _cache_ttl(headers)
    if ttl <= 0:
        return
    d = _entry_dir(key)
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    # keep only safe response headers
    keep = {}
    for hk, hv in (headers or {}).items():
        lk = str(hk).lower()
        if lk in (
            "content-type",
            "content-encoding",
            "cache-control",
            "etag",
            "last-modified",
            "expires",
        ):
            keep[lk] = str(hv)
        elif lk == "access-control-allow-origin" and str(hv).strip() == "*":
            keep[lk] = "*"
    meta = {
        "url": normalize_cache_url(url),
        "status": int(status or 200),
        "headers": keep,
        "size": len(body),
        "stored_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "expires_at": time.time() + ttl,
    }
    body_tmp = d / ( _BODY_NAME + ".tmp")
    meta_tmp = d / (_META_NAME + ".tmp")
    lock_path = d / ".lock"
    # coarse per-entry lock via mkdir
    try:
        lock_path.mkdir()
    except FileExistsError:
        # another worker writing — skip store
        return
    try:
        body_tmp.write_bytes(body)
        meta_tmp.write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        body_tmp.replace(d / _BODY_NAME)
        meta_tmp.replace(d / _META_NAME)
        _bump("stores")
        _bump("bytes_stored", len(body))
    except Exception:
        _bump("errors")
        try:
            body_tmp.unlink(missing_ok=True)
            meta_tmp.unlink(missing_ok=True)
        except Exception:
            pass
    finally:
        try:
            lock_path.rmdir()
        except Exception:
            pass
    _maybe_evict()


def _dir_size_bytes(root: Path) -> int:
    total = 0
    try:
        for p in root.rglob(_BODY_NAME):
            try:
                total += p.stat().st_size
            except OSError:
                pass
    except OSError:
        pass
    return total


def _maybe_evict() -> None:
    """Simple size cap: delete oldest body entries until under max."""
    root = cache_dir()
    limit = max_cache_mb() * 1024 * 1024
    try:
        size = _dir_size_bytes(root)
    except Exception:
        return
    if size <= limit:
        return
    entries: list[tuple[float, Path]] = []
    try:
        for meta in root.rglob(_META_NAME):
            try:
                entries.append((meta.stat().st_mtime, meta.parent))
            except OSError:
                pass
    except OSError:
        return
    entries.sort()  # oldest first
    for _mtime, d in entries:
        if size <= limit * 0.85:
            break
        try:
            body = d / _BODY_NAME
            if body.is_file():
                size -= body.stat().st_size
            for child in d.iterdir():
                try:
                    child.unlink()
                except Exception:
                    pass
            d.rmdir()
        except Exception:
            pass


def _fulfill_headers(meta_headers: dict) -> dict:
    out = {}
    for k, v in (meta_headers or {}).items():
        # Playwright fulfill wants proper header names; lowercase is fine
        if k == "content-encoding":
            # body on disk is already decoded by route.fetch() in most cases;
            # if we stored encoded body we'd need encoding — we store decoded via fetch body()
            continue
        out[k] = v
    if "content-type" not in {k.lower() for k in out}:
        out["content-type"] = "application/octet-stream"
    # mark from our cache for debugging (harmless)
    out["x-grok-static-cache"] = "HIT"
    return out


def static_route_globs() -> tuple[str, ...]:
    """Playwright route globs for immutable assets only.

    Do not use ``**/*``. A catch-all handler also sees the signup document,
    XHR, and fetch calls; stalling those leaves ``inputs=none``.
    """
    return (
        "**/*.css",
        "**/*.woff",
        "**/*.woff2",
        "**/*.ttf",
        "**/*.otf",
        "**/*.png",
        "**/*.jpg",
        "**/*.jpeg",
        "**/*.gif",
        "**/*.svg",
        "**/*.webp",
        "**/*.ico",
        "**/*.avif",
    )


def attach_static_cache(context, log_callback: Optional[LogFn] = None) -> bool:
    """Install route handler on a Playwright/Camoufox BrowserContext.

    Safe to call multiple times; installs once per context object id.
    """
    if context is None:
        return False
    if not cache_enabled():
        return False
    with _install_lock:
        try:
            if context in _installed_contexts:
                return True
            _installed_contexts.add(context)
        except TypeError:
            if getattr(context, "_grok_static_cache_installed", False):
                return True
            try:
                setattr(context, "_grok_static_cache_installed", True)
            except Exception:
                pass

    def _handler(route, request=None):
        # Playwright may call handler(route) only; request on route.request
        try:
            req = request or route.request
            method = getattr(req, "method", "GET") or "GET"
            url = getattr(req, "url", "") or ""
            rtype = getattr(req, "resource_type", "") or ""
            if not is_static_request(url, rtype, method):
                _bump("bypasses")
                route.continue_()
                return
            key = cache_key(url)
            cached = _read_entry(key)
            if cached and cached.get("body") is not None:
                _bump("hits")
                _bump("bytes_served", len(cached["body"]))
                route.fulfill(
                    status=int(cached.get("status") or 200),
                    headers=_fulfill_headers(cached.get("headers") or {}),
                    body=cached["body"],
                )
                return
            _bump("misses")
            # fetch via browser stack (still through proxy) then store decoded body
            try:
                response = route.fetch()
            except Exception:
                _bump("errors")
                route.continue_()
                return
            try:
                body = response.body()
            except Exception:
                body = b""
            status = int(getattr(response, "status", 200) or 200)
            try:
                headers = response.headers
            except Exception:
                headers = {}
            if status == 200 and body:
                try:
                    _write_entry(key, url=url, status=status, headers=dict(headers), body=body)
                except Exception:
                    _bump("errors")
            # re-fulfill so we control content-encoding (body already decoded)
            try:
                fh = {str(k).lower(): str(v) for k, v in dict(headers).items()}
                fh.pop("content-encoding", None)
                fh.pop("content-length", None)
                fh["x-grok-static-cache"] = "MISS"
                route.fulfill(status=status, headers=fh, body=body)
            except Exception:
                try:
                    route.fulfill(response=response)
                except Exception:
                    _bump("errors")
                    try:
                        route.continue_()
                    except Exception:
                        pass
        except Exception:
            _bump("errors")
            try:
                route.continue_()
            except Exception:
                pass

    try:
        for glob in static_route_globs():
            context.route(glob, _handler)
    except Exception as exc:
        with _install_lock:
            try:
                _installed_contexts.discard(context)
            except TypeError:
                try:
                    setattr(context, "_grok_static_cache_installed", False)
                except Exception:
                    pass
        if log_callback:
            log_callback(f"[static-cache] route install failed: {exc}")
        return False

    if log_callback:
        st = get_stats()
        log_callback(
            f"[static-cache] enabled dir={cache_dir()} "
            f"hits={st['hits']} misses={st['misses']} max_mb={max_cache_mb()}"
        )
    return True


def attach_from_browser_page(browser_obj, page_obj, log_callback: Optional[LogFn] = None) -> bool:
    """Helper for CamoufoxBrowser / CamoufoxPage adapters."""
    ctx = None
    try:
        if page_obj is not None and hasattr(page_obj, "raw_context"):
            ctx = page_obj.raw_context
    except Exception:
        ctx = None
    if ctx is None and browser_obj is not None:
        try:
            ctx = getattr(browser_obj, "_context", None)
        except Exception:
            ctx = None
    return attach_static_cache(ctx, log_callback=log_callback)


def patch_browser_session(module, log_callback: Optional[LogFn] = None) -> None:
    """Wrap module.start_browser so every new browser gets the cache routes."""
    if getattr(module, "_static_asset_cache_patched", False):
        return
    original = module.start_browser

    def _wrapped(log_callback=None):
        browser_obj, page_obj = original(log_callback=log_callback)
        try:
            attach_from_browser_page(browser_obj, page_obj, log_callback=log_callback)
        except Exception as exc:
            if log_callback:
                log_callback(f"[static-cache] attach failed: {exc}")
        return browser_obj, page_obj

    module.start_browser = _wrapped  # type: ignore[assignment]
    module._static_asset_cache_patched = True
    # also patch restart_browser which calls start_browser — already covered
    if log_callback:
        log_callback("[static-cache] browser_session.start_browser patched")


def format_stats_line() -> str:
    st = get_stats()
    hit = st["hits"]
    miss = st["misses"]
    total = hit + miss
    rate = (100.0 * hit / total) if total else 0.0
    return (
        f"[static-cache] stats hits={hit} misses={miss} hit_rate={rate:.1f}% "
        f"stores={st['stores']} served_mb={st['bytes_served']/1024/1024:.2f} "
        f"stored_mb={st['bytes_stored']/1024/1024:.2f} errors={st['errors']}"
    )
