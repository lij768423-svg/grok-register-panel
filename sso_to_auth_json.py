#!/usr/bin/env python3
"""
SSO cookie → CPA / Grok2API auth.json 格式（纯 HTTP）

主路径：RFC 8628 Device Flow（对齐 CLIProxyAPI internal/auth/xai + verify/approve）
回退：Authorization Code + PKCE（referrer=grok-build + plan=generic）

写出：
  - CLIProxyAPI 扁平 xai-*.json（base_url=cli-chat-proxy.grok.com）
  - Grok2API accounts 数组格式 auth

用法:
  # 单个 / 批量 SSO，写出多个独立 auth 文件（每个可直接 cp 到 ~/.grok/auth.json）
  python3 sso_to_auth_json.py --sso sso_list.txt --out-dir ./auth_out

  # 合并到一个 json（key 带 user_id 后缀，避免覆盖）
  python3 sso_to_auth_json.py --sso sso_list.txt --out auth_merged.json --merge

  # 单行 sso
  python3 sso_to_auth_json.py --sso-cookie 'eyJ...' --out ~/.grok/auth.json

  # 只出 CPA + Grok2API
  python3 sso_to_auth_json.py --sso sso_list.txt --cpa-auth-dir /path/to/auths \\
    --grok2api-auth-dir /path/to/g2a --proxy http://127.0.0.1:7890

  # 仅批量检查 grok.com 账号风控状态（botFlagSource/risk/deny），不换 token 不入库
  # --sso-state-export 导出被标记名单 jsonl；--sso-state-clean-export 导出干净 sso 原始行 txt
  python3 sso_to_auth_json.py --check-sso-state sso_list.txt --from-config config.json \\
    --sso-state-export log/sso_flagged.jsonl \\
    --sso-state-clean-export log/sso_clean.txt \\
    --report-json log/sso_state_report.json
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from curl_cffi import CurlMime, requests
from secure_files import (
    append_private_text,
    atomic_write_json,
    atomic_write_text,
    ensure_private_dir,
    exclusive_file_lock,
)

CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
OIDC_ISSUER = "https://auth.x.ai"
AUTH_KEY = f"{OIDC_ISSUER}::{CLIENT_ID}"
# 与 CPA internal/auth/xai/types.go 的 Scope 严格一致。
# 不可加 conversations:read/write —— 该 client 未获授权，device/code 与 consent
# 均会通过，但 token 端点会以 invalid_grant "Access denied" 拒绝签发。
SCOPES = "openid profile email offline_access grok-cli:access api:access"

# --- Device Flow 常量（主路径，对齐 CPA internal/auth/xai） --------------------
DEVICE_CODE_URL = f"{OIDC_ISSUER}/oauth2/device/code"
DEVICE_VERIFY_URL = f"{OIDC_ISSUER}/oauth2/device/verify"
DEVICE_APPROVE_URL = f"{OIDC_ISSUER}/oauth2/device/approve"
DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"
DEVICE_DEFAULT_INTERVAL = 2
DEVICE_DEFAULT_EXPIRES = 1800
DEVICE_POLL_CAP_SECONDS = 10
# 浏览器点完「允许」后，服务端落库可能有延迟；协议路径 approve 多半无效，快速回退
DEVICE_GRACE_BROWSER = 8
DEVICE_GRACE_PROTOCOL = 6

# --- Authorization Code Flow 常量（回退路径） --------------------------------
# authorize 必须注入 referrer=grok-build，否则 access_token 无该 claim，
# cli-chat-proxy 会 403。实测 referrer=cli-proxy-api 会得到 referrer=None。
# plan=generic 对齐 grok-build-auth；consent.referrer 仍置空。
REDIRECT_URI = "http://127.0.0.1:56121/callback"
GROK_REFERRER = "grok-build"
GROK_PLAN = "generic"
GROK_VERSION = "0.2.93"
GROK_TOKEN_UA = f"grok-pager/{GROK_VERSION} grok-shell/{GROK_VERSION} (linux; x86_64)"
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
)
# consent 提交用的 Next.js Server Action ID（bootstrap；失效时扫 JS / 读本地缓存）
# 2026-07 实测：401b73e22a5e... 已 404；成功 ID 会写入 .next_action_id.cache 供下次快速路径
NEXT_ACTION_ID = "401b73e22a5e68737d0037e1aa449fef82cd1b35fb"
_NEXT_ACTION_CACHE_PATH = Path(__file__).resolve().parent / ".next_action_id.cache"
_NEXT_ACTION_ID_RE = re.compile(r"^[0-9a-f]{40,44}$", re.I)
_working_next_action_id = ""  # 启动时由 _load_working_next_action_id() 填充
_NEXT_ACTION_RE = re.compile(
    r'(?:\$ACTION_ID_|next-action["\']?\s*[:=]\s*["\']|["\'])([0-9a-f]{40,44})["\']',
    re.I,
)
_CREATE_SERVER_REF_RE = re.compile(
    r'createServerReference\)?\(["\']([0-9a-f]{40,44})["\']',
    re.I,
)
_CALL_SERVER_RE = re.compile(
    r'["\']([0-9a-f]{40,44})["\']\s*,\s*(?:callServer|findSourceMapURL)',
    re.I,
)
_SCRIPT_SRC_RE = re.compile(r'src=["\']([^"\']+)["\']', re.I)

# --- CLIProxyAPI (CPA) 扁平格式常量 ------------------------------------------
# CPA 的 internal/auth/xai/token.go TokenStorage 读的是扁平字段。
# Build/CLI token（scope 含 grok-cli:access）必须走 cli-chat-proxy.grok.com，
# 不能用默认 api.x.ai/v1（那是计费通道，会 402）。
# headers 对齐 @xai-official/grok CLI / grok-build-auth（无 x-authenticateresponse）
CPA_TOKEN_ENDPOINT = f"{OIDC_ISSUER}/oauth2/token"
CPA_GROK_BASE_URL = "https://cli-chat-proxy.grok.com/v1"
CPA_GROK_HEADERS = {
    "User-Agent": GROK_TOKEN_UA,
    "X-XAI-Token-Auth": "xai-grok-cli",
    "x-authenticateresponse": "authenticate-response",
    "x-grok-client-identifier": "grok-pager",
    "x-grok-client-version": GROK_VERSION,
}
CPA_PROBE_MODEL = "grok-4.5"
CPA_PROBE_URL = f"{CPA_GROK_BASE_URL}/responses"
GROK_HOME_URL = "https://grok.com/"


def _normalize_next_action_id(value: str) -> str:
    val = str(value or "").strip().lower()
    if _NEXT_ACTION_ID_RE.fullmatch(val):
        return val
    return ""


def _load_working_next_action_id() -> str:
    """优先读磁盘缓存（上次成功的 consent Next-Action），否则回落内置 bootstrap。"""
    try:
        cached = _normalize_next_action_id(
            _NEXT_ACTION_CACHE_PATH.read_text(encoding="utf-8")
        )
        if cached:
            return cached
    except Exception:
        pass
    return _normalize_next_action_id(NEXT_ACTION_ID) or NEXT_ACTION_ID.lower()


def _save_working_next_action_id(action_id: str) -> None:
    """把已验证可用的 Next-Action 持久化，避免进程重启后再次扫 JS chunks。"""
    val = _normalize_next_action_id(action_id)
    if not val:
        return
    try:
        atomic_write_text(_NEXT_ACTION_CACHE_PATH, val + "\n")
    except Exception:
        pass


def _invalidate_working_next_action_id(action_id: str = "") -> None:
    """某 ID 返回 Server action not found 时剔除，避免反复 404。"""
    global _working_next_action_id
    bad = _normalize_next_action_id(action_id)
    current = _normalize_next_action_id(_working_next_action_id)
    if bad and current and bad != current:
        return
    _working_next_action_id = ""
    try:
        if _NEXT_ACTION_CACHE_PATH.is_file():
            if not bad:
                _NEXT_ACTION_CACHE_PATH.unlink(missing_ok=True)
            else:
                cached = _normalize_next_action_id(
                    _NEXT_ACTION_CACHE_PATH.read_text(encoding="utf-8")
                )
                if not cached or cached == bad:
                    _NEXT_ACTION_CACHE_PATH.unlink(missing_ok=True)
    except Exception:
        pass


def _remember_working_next_action_id(action_id: str) -> None:
    global _working_next_action_id
    val = _normalize_next_action_id(action_id)
    if not val:
        return
    _working_next_action_id = val
    _save_working_next_action_id(val)


# 模块导入时加载缓存，保证 GUI/CLI 冷启动也能走快速路径
_working_next_action_id = _load_working_next_action_id()


def b64url_decode(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg)


def _decode_jwt_payload_with_status(token: str) -> tuple[bool, dict]:
    """Decode a JWT payload and distinguish valid empty claims from failure."""
    try:
        parts = str(token or "").split(".")
        if len(parts) < 2:
            return False, {}
        payload = json.loads(b64url_decode(parts[1]))
        if not isinstance(payload, dict):
            return False, {}
        return True, payload
    except Exception:
        return False, {}


def decode_jwt_payload(token: str) -> dict:
    """Return object claims, or an empty dict for malformed/non-object payloads."""
    _ok, payload = _decode_jwt_payload_with_status(token)
    return payload


def inspect_jwt_bfs(token: str) -> dict:
    """Detect xAI JWT risk claim ``bfs`` by key presence (not truthiness).

    Clean tokens simply omit the claim. Flagged tokens typically carry
    ``bfs: 2`` (value may vary; presence alone is the signal).
    Distinct from grok.com ``botFlagSource`` / registration policy deny.
    """
    raw = str(token or "").strip()
    if raw.startswith("sso="):
        raw = raw[4:].strip()
    # Nested JSON blob (encrypted_primary decode, or full OAuth response)
    if raw.startswith("{"):
        try:
            obj = json.loads(raw)
        except Exception:
            obj = None
        if isinstance(obj, dict):
            for key in ("access_token", "token", "sso", "id_token", "key"):
                nested = str(obj.get(key) or "").strip()
                if nested.count(".") >= 2:
                    raw = nested
                    break
    ok, claims = _decode_jwt_payload_with_status(raw) if raw.count(".") >= 2 else (False, {})
    has = ok and ("bfs" in claims)
    return {
        "ok": ok,
        "has_bfs": has,
        "bfs": claims.get("bfs") if has else None,
        "tier": claims.get("tier"),
        "sub": str(claims.get("sub") or claims.get("principal_id") or "")[:48],
        "exp": claims.get("exp"),
        "referrer": claims.get("referrer"),
        "claim_keys": sorted(str(k) for k in claims.keys()) if claims else [],
    }


def inspect_token_bundle_bfs(
    *,
    access_token: str = "",
    sso: str = "",
    id_token: str = "",
    refresh_token: str = "",
) -> dict:
    """Check OAuth / SSO bundle; prefer access_token, fall back to sso/id/refresh."""
    sources: list[tuple[str, str]] = [
        ("access_token", str(access_token or "").strip()),
        ("sso", str(sso or "").strip()),
        ("id_token", str(id_token or "").strip()),
        ("refresh_token", str(refresh_token or "").strip()),
    ]
    result = {
        "ok": False,
        "has_bfs": False,
        "bfs": None,
        "source": "",
        "tier": None,
        "sub": "",
        "exp": None,
        "referrer": None,
        "claim_keys": [],
        "checked": [],
    }
    for name, value in sources:
        if not value or value.count(".") < 2:
            continue
        info = inspect_jwt_bfs(value)
        result["checked"].append(name)
        if not info.get("ok"):
            continue
        if not result["ok"]:
            result.update(
                {
                    "ok": True,
                    "has_bfs": bool(info.get("has_bfs")),
                    "bfs": info.get("bfs"),
                    "source": name,
                    "tier": info.get("tier"),
                    "sub": info.get("sub") or "",
                    "exp": info.get("exp"),
                    "referrer": info.get("referrer"),
                    "claim_keys": list(info.get("claim_keys") or []),
                }
            )
        # Any source with bfs marks the bundle flagged (prefer reporting that source)
        if info.get("has_bfs"):
            result.update(
                {
                    "ok": True,
                    "has_bfs": True,
                    "bfs": info.get("bfs"),
                    "source": name,
                    "tier": info.get("tier"),
                    "sub": info.get("sub") or result.get("sub") or "",
                    "exp": info.get("exp") or result.get("exp"),
                    "referrer": info.get("referrer") or result.get("referrer"),
                    "claim_keys": list(info.get("claim_keys") or result.get("claim_keys") or []),
                }
            )
            break
    return result


def inspect_cpa_record_bfs(record: dict | None) -> dict:
    """Inspect a CPA xai-*.json (or similar) auth record for the bfs claim."""
    if not isinstance(record, dict):
        return {
            "ok": False,
            "has_bfs": False,
            "bfs": None,
            "source": "",
            "email": "",
            "error": "invalid record",
        }
    # Prefer the current token over cached metadata. CPA may refresh the token
    # in place while leaving custom fields untouched.
    has_token = any(
        str(record.get(key) or "").strip()
        for key in ("access_token", "key", "sso", "id_token", "refresh_token")
    )
    # A record without a token can still be classified from metadata written by
    # the register flow.
    if not has_token and "bfs" in record and record.get("bfs") is True:
        return {
            "ok": True,
            "has_bfs": True,
            "bfs": record.get("bfs_value", record.get("bfs")),
            "source": "record.bfs",
            "email": str(record.get("email") or "").strip(),
            "tier": record.get("tier"),
            "sub": str(record.get("sub") or "")[:48],
            "exp": None,
            "referrer": None,
            "claim_keys": [],
            "checked": ["record.bfs"],
        }
    if not has_token and record.get("bfs") is False and record.get("bfs_checked"):
        return {
            "ok": True,
            "has_bfs": False,
            "bfs": None,
            "source": "record.bfs",
            "email": str(record.get("email") or "").strip(),
            "tier": record.get("tier"),
            "sub": str(record.get("sub") or "")[:48],
            "exp": None,
            "referrer": None,
            "claim_keys": [],
            "checked": ["record.bfs"],
        }
    info = inspect_token_bundle_bfs(
        access_token=str(record.get("access_token") or record.get("key") or ""),
        sso=str(record.get("sso") or ""),
        id_token=str(record.get("id_token") or ""),
        refresh_token=str(record.get("refresh_token") or ""),
    )
    info["email"] = str(record.get("email") or "").strip()
    return info


def _flatten_nested_auth_entry(entry: dict) -> dict:
    """Normalize one nested Grok2API auth entry for the common scanner."""
    return {
        "access_token": entry.get("access_token") or entry.get("key") or "",
        "refresh_token": entry.get("refresh_token") or "",
        "id_token": entry.get("id_token") or "",
        "email": entry.get("email") or "",
        "sub": entry.get("user_id") or entry.get("sub") or "",
        "sso": entry.get("sso") or "",
        "disabled": entry.get("disabled"),
        "bfs": entry.get("bfs"),
        "bfs_value": entry.get("bfs_value"),
        "bfs_source": entry.get("bfs_source"),
        "bfs_checked": entry.get("bfs_checked"),
        "bfs_status": entry.get("bfs_status"),
    }


def _auth_record_candidates(data: object) -> list[tuple[str, dict]]:
    """Return direct or nested auth records from one JSON file."""
    if not isinstance(data, dict):
        return []
    auth_fields = {
        "access_token",
        "key",
        "sso",
        "id_token",
        "refresh_token",
        "bfs",
        "bfs_checked",
    }
    if auth_fields.intersection(data):
        return [("", data)]
    candidates: list[tuple[str, dict]] = []
    for key, entry in data.items():
        if not isinstance(entry, dict) or not auth_fields.intersection(entry):
            continue
        candidates.append((str(key), _flatten_nested_auth_entry(entry)))
    return candidates


def scan_cpa_auth_dir_bfs(
    auth_dir: str | Path,
    *,
    limit: int = 0,
    include_clean: bool = True,
) -> dict:
    """Batch-scan CPA auth directory for JWT bfs flags. Pure local JWT decode."""
    root = Path(auth_dir)
    summary = {
        "ok": True,
        "auth_dir": str(root),
        "total": 0,
        "bfs_count": 0,
        "clean_count": 0,
        "error_count": 0,
        "bfs_rate": 0.0,
        "bfs_value_dist": {},
        "items": [],
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if not root.is_dir():
        summary["ok"] = False
        summary["error"] = f"auth_dir not found: {root}"
        return summary

    # Auth directories can contain generated xai-/g2a- files or a merged
    # auth.json created by the CLI. Scan JSON files by content rather than
    # relying on one filename convention.
    paths = sorted(root.glob("*.json"))
    # de-dup by path
    seen: set[str] = set()
    ordered: list[Path] = []
    for path in paths:
        key = str(path.resolve()) if path.exists() else str(path)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(path)
    if limit and limit > 0:
        ordered = ordered[: int(limit)]

    value_dist: dict[str, int] = {}
    for path in ordered:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            summary["total"] += 1
            item = {
                "file": path.name,
                "email": "",
                "has_bfs": False,
                "bfs": None,
                "source": "",
                "disabled": None,
                "error": str(exc)[:120],
            }
            summary["error_count"] += 1
            summary["items"].append(item)
            continue
        candidates = _auth_record_candidates(data)
        if not candidates:
            summary["total"] += 1
            summary["error_count"] += 1
            summary["items"].append(
                {
                    "file": path.name,
                    "email": "",
                    "has_bfs": False,
                    "bfs": None,
                    "source": "",
                    "disabled": None,
                    "error": "no auth record found",
                }
            )
            continue
        for entry_key, data_record in candidates:
            summary["total"] += 1
            item = {
                "file": f"{path.name}#{entry_key}" if entry_key else path.name,
                "email": "",
                "has_bfs": False,
                "bfs": None,
                "source": "",
                "disabled": None,
                "error": "",
            }
            info = inspect_cpa_record_bfs(data_record)
            item["email"] = str(info.get("email") or data_record.get("email") or "")
            item["has_bfs"] = bool(info.get("has_bfs"))
            item["bfs"] = info.get("bfs")
            item["source"] = str(info.get("source") or "")
            item["sub"] = str(info.get("sub") or "")
            item["tier"] = info.get("tier")
            if "disabled" in data_record:
                item["disabled"] = bool(data_record.get("disabled"))
            if not info.get("ok") and not info.get("has_bfs"):
                summary["error_count"] += 1
                item["error"] = "jwt decode failed or empty token"
                summary["items"].append(item)
                continue
            if item["has_bfs"]:
                summary["bfs_count"] += 1
                key = str(item["bfs"])
                value_dist[key] = value_dist.get(key, 0) + 1
                summary["items"].append(item)
            else:
                summary["clean_count"] += 1
                if include_clean:
                    summary["items"].append(item)
    decoded = summary["bfs_count"] + summary["clean_count"]
    summary["bfs_rate"] = round(100.0 * summary["bfs_count"] / decoded, 2) if decoded else 0.0
    summary["bfs_value_dist"] = value_dist
    return summary


def apply_bfs_to_cpa_record(record: dict, bfs_info: dict | None = None) -> dict:
    """Annotate CPA record with bfs metadata; optionally disable flagged accounts."""
    if not isinstance(record, dict):
        return record
    info = bfs_info or inspect_cpa_record_bfs(record)
    if info.get("ok") is not True:
        record["bfs"] = None
        record["bfs_checked"] = False
        record["bfs_status"] = "unknown"
        record.pop("bfs_value", None)
        record.pop("bfs_source", None)
        return record
    has = bool(info.get("has_bfs"))
    record["bfs"] = has
    record["bfs_checked"] = True
    record["bfs_status"] = "flagged" if has else "clean"
    if has:
        record["bfs_value"] = info.get("bfs")
        record["bfs_source"] = str(info.get("source") or "")
    else:
        record.pop("bfs_value", None)
        record.pop("bfs_source", None)
    return record


def rfc3339_ns(ts: float | None = None) -> str:
    """2026-07-10T01:00:00.000000000Z"""
    if ts is None:
        ts = time.time()
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + ".000000000Z"


def _urlopen(req, proxy: str = "", timeout: int = 15):
    """urllib 请求，proxy 非空时走代理。"""
    if proxy:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        )
        return opener.open(req, timeout=timeout)
    return urllib.request.urlopen(req, timeout=timeout)


def _gen_pkce() -> tuple[str, str, str, str]:
    """生成 (code_verifier, code_challenge, state, nonce)。"""
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    state = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode()
    nonce = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode()
    return verifier, challenge, state, nonce


def _parse_consent_result(body: str) -> tuple[str | None, str]:
    """解析 consent 的 text/x-component 响应，返回 (code, 服务端错误)。

    服务端拒绝时回 {"success":false,"error":"Access denied"}——这是账号资质裁决，
    与 Next-Action 是否正确无关。必须把 error 透出来，否则会被误判成
    「这个 action id 不对」而去徒劳地换 ID、扫 JS chunk。
    """
    error = ""
    for line in body.split("\n"):
        start = line.find("{")
        if start < 0:
            continue
        try:
            data = json.loads(line[start:])
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        if data.get("code") and data.get("success") is not False:
            return data.get("code"), ""
        if data.get("error"):
            error = str(data.get("error"))
        elif data.get("success") is False and not error:
            error = "success=false"
    return None, error


def _parse_consent_code(body: str) -> str | None:
    """从 consent 提交的 text/x-component 响应里解析出 authorization code。"""
    return _parse_consent_result(body)[0]


def _extract_next_action_ids(html: str) -> list[str]:
    """仅从 HTML 文本抽哈希（弱信号；真正 id 多在 JS chunk）。"""
    found: list[str] = []
    seen: set[str] = set()
    text = html or ""

    def _add(val: str):
        v = (val or "").strip().lower()
        if len(v) < 40 or v in seen:
            return
        seen.add(v)
        found.append(v)

    for m in _CREATE_SERVER_REF_RE.finditer(text):
        _add(m.group(1))
    for m in _CALL_SERVER_RE.finditer(text):
        _add(m.group(1))
    for m in _NEXT_ACTION_RE.finditer(text):
        _add(m.group(1))
    if NEXT_ACTION_ID and NEXT_ACTION_ID.lower() not in seen:
        found.append(NEXT_ACTION_ID.lower())
    return found


def _discover_action_ids_from_js(session, html: str, base_url: str = "https://accounts.x.ai", log=None) -> list[str]:
    """从 consent 页引用的 /_next/static/chunks/*.js 解析 createServerReference 的 action id。

    HTML 内嵌的 40 位 hex 经常是错误候选（会 404）；真实 allow consent 在 JS 里。
    """
    found: list[str] = []
    seen: set[str] = set()
    priority: list[str] = []  # consent/oauth 相关 chunk 里的 id 优先

    def _add(val: str, prefer: bool = False):
        v = (val or "").strip().lower()
        if len(v) < 40 or v in seen:
            return
        seen.add(v)
        if prefer:
            priority.append(v)
        else:
            found.append(v)

    srcs = _SCRIPT_SRC_RE.findall(html or "")
    # 优先扫可能含 consent 逻辑的 chunk；其余也扫但限数量
    scored: list[tuple[int, str]] = []
    for src in srcs:
        low = src.lower()
        score = 0
        if "chunk" not in low and "/_next/" not in low:
            continue
        if any(k in low for k in ("consent", "oauth", "auth", "login", "sign")):
            score += 5
        scored.append((score, src))
    scored.sort(key=lambda x: (-x[0], x[1]))

    fetched = 0
    max_fetch = 40
    for score, src in scored:
        if fetched >= max_fetch:
            break
        full = src if src.startswith("http") else urllib.parse.urljoin(base_url.rstrip("/") + "/", src.lstrip("/"))
        try:
            resp = session.get(full, impersonate="chrome", timeout=15)
            text = str(resp.text or "")
        except Exception:
            continue
        fetched += 1
        prefer = score > 0 or ("consent" in text.lower() and "oauth" in text.lower())
        # 含 allow + createServerReference 的 chunk 更优先
        if "createServerReference" in text or "callServer" in text:
            prefer = True
        for m in _CREATE_SERVER_REF_RE.finditer(text):
            _add(m.group(1), prefer=prefer)
        for m in _CALL_SERVER_RE.finditer(text):
            _add(m.group(1), prefer=prefer)

    # HTML 弱信号放后
    for aid in _extract_next_action_ids(html):
        _add(aid, prefer=False)

    ordered = priority + [x for x in found if x not in priority]
    if log:
        log(f"  [*] 从 JS chunks 解析 Next-Action {len(ordered)} 个（扫 {fetched} 个脚本）")
    return ordered


def _new_sso_session(sso_cookie: str, proxy: str = ""):
    """创建带 SSO cookie 的 curl_cffi Session。"""
    proxies = {"http": proxy, "https": proxy} if proxy else None
    s = requests.Session()
    if proxies:
        s.proxies = proxies
    for domain in (".x.ai", "accounts.x.ai", "auth.x.ai", ".grok.com", "grok.com"):
        s.cookies.set("sso", sso_cookie, domain=domain)
        s.cookies.set("sso-rw", sso_cookie, domain=domain)
    return s


def _parse_grok_account_state(page_html: str) -> dict:
    """从 grok.com 首页 RSC 数据解析账号注册风控状态。"""
    raw = str(page_html or "")
    # Next.js 会把对象嵌入字符串，字段名通常表现为 \"botFlagSource\"。
    # 解开这一层即可按普通 JSON 片段稳定提取，不依赖具体 chunk 或组件名。
    normalized = raw.replace('\\"', '"')
    source_match = re.search(r'botFlagSource"\s*:\s*(null|-?\d+)', normalized)
    details_match = re.search(
        r'botFlagDetails"\s*:\s*(?:null|"([^"]*)")', normalized
    )

    source = None
    if source_match and source_match.group(1) != "null":
        try:
            source = int(source_match.group(1))
        except (TypeError, ValueError):
            source = None
    details = details_match.group(1) if details_match and details_match.group(1) else ""

    detail_fields: dict[str, str] = {}
    for item in details.split(","):
        key, sep, value = item.partition("=")
        if sep and key.strip():
            detail_fields[key.strip().lower()] = value.strip()
    risk = None
    try:
        if detail_fields.get("risk"):
            risk = float(detail_fields["risk"])
    except (TypeError, ValueError):
        risk = None
    policy = detail_fields.get("policy", "").lower()
    event = detail_fields.get("event", "")
    denied = policy == "deny"

    return {
        "found": bool(source_match or details_match),
        "bot_flag_source": source,
        "bot_flag_details": details,
        "policy": policy,
        "risk": risk,
        "event": event,
        "denied": denied,
    }


def inspect_sso_account_state(
    sso_cookie: str,
    proxy: str = "",
    log=print,
    timeout: int = 20,
) -> dict:
    """读取 grok.com 当前账号状态；诊断失败时返回 unknown，不阻断 OAuth。"""
    result = _parse_grok_account_state("")
    result.update({"status_code": 0, "url": "", "error": ""})
    token = str(sso_cookie or "").strip()
    if not token:
        result["error"] = "sso 为空"
        return result

    try:
        session = _new_sso_session(token, proxy=proxy)
        response = session.get(
            GROK_HOME_URL,
            headers={"User-Agent": DEFAULT_UA, "Accept": "text/html,application/xhtml+xml"},
            impersonate="chrome",
            timeout=timeout,
            allow_redirects=True,
        )
        result["status_code"] = int(getattr(response, "status_code", 0) or 0)
        result["url"] = str(getattr(response, "url", "") or "")
        if result["status_code"] != 200:
            suffix = "（可能是 Cloudflare/出口限制）" if result["status_code"] in (403, 429, 503) else ""
            result["error"] = f"grok.com HTTP {result['status_code']}{suffix}"
            return result
        parsed = _parse_grok_account_state(getattr(response, "text", "") or "")
        result.update(parsed)
        if parsed["denied"]:
            log(
                "  ❌ 注册风控状态: "
                f"botFlagSource={parsed['bot_flag_source']} "
                f"{parsed['bot_flag_details']}"
            )
        elif parsed["found"]:
            log(
                "  ✅ 注册风控状态可用: "
                f"botFlagSource={parsed['bot_flag_source']}"
            )
        else:
            result["error"] = "grok.com 未发现 botFlag 字段"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result


def classify_sso_account_state(state: dict) -> str:
    """Map inspect_sso_account_state() into flagged / clean / error / unknown.

    Aligns with the live risk gate:
      - botFlagSource in (1, 2)
      - policy=deny (any event, including $registration / $login)
    """
    if not isinstance(state, dict):
        return "unknown"
    bf = state.get("bot_flag_source")
    policy = str(state.get("policy") or "").strip().lower()
    if state.get("denied") or bf in (1, 2) or policy == "deny":
        return "flagged"
    if state.get("found"):
        return "clean"
    try:
        status = int(state.get("status_code") or 0)
    except (TypeError, ValueError):
        status = 0
    if status != 200 or str(state.get("error") or "").strip():
        return "error"
    return "unknown"


def run_check_sso_state(
    records: list[SsoInput],
    *,
    proxy: str = "",
    delay: float = 0,
    export: str | Path | None = None,
    clean_export: str | Path | None = None,
    log=print,
    on_item=None,
    cancel_callback=None,
) -> dict:
    """批量读取 grok.com 账号风控状态，不换 token 不入库。

    export / clean_export 边检查边逐行追加写（0600），中断不丢已检查结果；
    clean_export 写出 verdict=clean 的原始行（raw_line，每行一条），仅用于本机后续 --sso 输入。
    """
    summary: dict = {
        "ok": True,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total": 0,
        "flagged_count": 0,
        "clean_count": 0,
        "unknown_count": 0,
        "error_count": 0,
        "denied_count": 0,
        "bot_flag_dist": {},
        "items": [],
        "export_path": "",
        "export_count": 0,
        "clean_export_path": "",
        "clean_export_count": 0,
        "cancelled": False,
    }
    dist: dict[str, int] = {}
    export_path = None
    clean_path = None
    if export:
        export_path = Path(export)
        export_path.unlink(missing_ok=True)
    if clean_export:
        clean_path = Path(clean_export)
        clean_path.unlink(missing_ok=True)

    total = len(records)
    for i, record in enumerate(records, 1):
        if cancel_callback and cancel_callback():
            summary["cancelled"] = True
            break
        email = str(record.email or "").strip()

        def _check_log(message, _i=i):
            log(f"  [{_i}] {str(message).strip()}")

        state = inspect_sso_account_state(record.sso, proxy=proxy, log=_check_log)
        verdict = classify_sso_account_state(state)
        bf = state.get("bot_flag_source")
        summary["total"] += 1
        dist_key = str(bf) if bf is not None else "none"
        dist[dist_key] = dist.get(dist_key, 0) + 1
        row = {
            "index": i,
            "email": email,
            "bot_flag_source": bf,
            "bot_flag_details": state.get("bot_flag_details") or "",
            "risk": state.get("risk"),
            "policy": state.get("policy") or "",
            "event": state.get("event") or "",
            "denied": bool(state.get("denied")),
            "found": bool(state.get("found")),
            "status_code": state.get("status_code"),
            "verdict": verdict,
            "error": state.get("error") or "",
        }
        summary["items"].append(row)
        if verdict == "flagged":
            summary["flagged_count"] += 1
            if row["denied"]:
                summary["denied_count"] += 1
            if export_path:
                append_private_text(export_path, json.dumps(row, ensure_ascii=False) + "\n")
        elif verdict == "clean":
            summary["clean_count"] += 1
            if clean_path:
                append_private_text(clean_path, record.raw_line + "\n")
        elif verdict == "unknown":
            summary["unknown_count"] += 1
        else:
            summary["error_count"] += 1

        tag = "❌" if verdict == "flagged" else ("✅" if verdict == "clean" else "⚠️")
        log(
            f"{tag} [{i}/{total}] {email or '(no email)'} "
            f"botFlagSource={bf} details={row['bot_flag_details'] or '-'} "
            f"status={state.get('status_code')} -> {verdict}"
        )
        if on_item:
            on_item(row, record, summary)
        if delay and i < total:
            if cancel_callback and cancel_callback():
                summary["cancelled"] = True
                break
            time.sleep(float(delay))

    summary["export_path"] = str(export_path) if export_path else ""
    summary["export_count"] = summary["flagged_count"]
    summary["clean_export_path"] = str(clean_path) if clean_path else ""
    summary["clean_export_count"] = summary["clean_count"]
    summary["bot_flag_dist"] = dist
    if (
        summary["total"]
        and summary["flagged_count"] + summary["clean_count"] + summary["unknown_count"] == 0
    ):
        summary["ok"] = False
    return summary


def _normalize_token_payload(token: dict) -> dict | None:
    if not isinstance(token, dict) or not token.get("access_token"):
        return None
    if not token.get("expires_in"):
        token["expires_in"] = 21600
    if not token.get("token_type"):
        token["token_type"] = "Bearer"
    return token


def _is_trusted_xai_url(raw: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(str(raw or "").strip())
    except Exception:
        return False
    if parsed.scheme != "https" or not parsed.hostname:
        return False
    host = parsed.hostname.lower()
    return host == "x.ai" or host.endswith(".x.ai")


def _sso_principal_id(sso_cookie: str) -> str:
    claims = decode_jwt_payload(sso_cookie)
    for key in ("sub", "principal_id", "user_id", "uid", "id"):
        val = str(claims.get(key) or "").strip()
        if val:
            return val
    return ""


def _device_authorized(url: str = "", body: str = "") -> bool:
    u = str(url or "").lower()
    b = str(body or "").lower()
    if "/oauth2/device/done" in u or u.rstrip("/").endswith("/device/done"):
        return True
    markers = (
        "device authorized",
        "you have authorized",
        "device is authorized",
        "authorization complete",
        "设备已授权",
        "已授权此设备",
    )
    return any(m in b for m in markers)


def request_device_code(proxy: str = "", log=print, session=None) -> dict | None:
    """申请 device_code / user_code（对齐 CPA；可不带 SSO）。"""
    s = session
    own = False
    if s is None:
        own = True
        proxies = {"http": proxy, "https": proxy} if proxy else None
        s = requests.Session()
        if proxies:
            s.proxies = proxies
    try:
        log("  🔑 Device Flow: 申请 device_code / user_code ...")
        try:
            r = s.post(
                DEVICE_CODE_URL,
                data={"client_id": CLIENT_ID, "scope": SCOPES},
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                    "User-Agent": DEFAULT_UA,
                },
                impersonate="chrome",
                timeout=20,
            )
        except Exception as e:
            log(f"  ❌ device/code 异常: {e}")
            return None
        if r.status_code < 200 or r.status_code >= 300:
            log(f"  ❌ device/code HTTP {r.status_code}: {str(r.text)[:200]}")
            return None
        try:
            device = r.json()
        except Exception:
            log(f"  ❌ device/code 非 JSON: {str(r.text)[:200]}")
            return None
        device_code = str(device.get("device_code") or "").strip()
        user_code = str(device.get("user_code") or "").strip()
        if not device_code or not user_code:
            log(f"  ❌ device/code 响应缺字段: {device}")
            return None
        try:
            interval = max(1, int(device.get("interval") or DEVICE_DEFAULT_INTERVAL))
        except Exception:
            interval = DEVICE_DEFAULT_INTERVAL
        try:
            expires_in = max(30, int(device.get("expires_in") or DEVICE_DEFAULT_EXPIRES))
        except Exception:
            expires_in = DEVICE_DEFAULT_EXPIRES
        verification_complete = str(
            device.get("verification_uri_complete")
            or device.get("verification_url_complete")
            or ""
        ).strip()
        verification_uri = str(
            device.get("verification_uri") or device.get("verification_url") or ""
        ).strip()
        open_url = verification_complete or (
            f"{verification_uri}?user_code={urllib.parse.quote(user_code)}"
            if verification_uri
            else f"https://accounts.x.ai/oauth2/device?user_code={urllib.parse.quote(user_code)}"
        )
        log(f"  [*] user_code={user_code} interval={interval}s expires_in={expires_in}s")
        return {
            "device_code": device_code,
            "user_code": user_code,
            "interval": interval,
            "expires_in": expires_in,
            "verification_uri": verification_uri,
            "verification_uri_complete": verification_complete,
            "open_url": open_url,
        }
    finally:
        if own:
            try:
                s.close()
            except Exception:
                pass


def poll_device_token(
    device_code: str,
    interval: int = DEVICE_DEFAULT_INTERVAL,
    expires_in: int = DEVICE_DEFAULT_EXPIRES,
    proxy: str = "",
    log=print,
    session=None,
    grace_invalid_grant: float = 0.0,
) -> dict | None:
    """轮询 device_code → access/refresh token。

    grace_invalid_grant: x.ai 在设备尚未授权时返回 invalid_grant（而非 RFC 8628
    的 authorization_pending）。该秒数内把 invalid_grant 当作 pending 继续轮询，
    超出后才判为终态。浏览器授权路径应传较大值，纯协议路径传较小值以快速回退。
    """
    device_code = str(device_code or "").strip()
    if not device_code:
        log("  ❌ device_code 为空")
        return None
    s = session
    own = False
    if s is None:
        own = True
        proxies = {"http": proxy, "https": proxy} if proxy else None
        s = requests.Session()
        if proxies:
            s.proxies = proxies
    try:
        interval = max(1, min(2, int(interval or DEVICE_DEFAULT_INTERVAL)))
        expires_in = max(30, int(expires_in or DEVICE_DEFAULT_EXPIRES))
        log("  [*] Device Flow: 轮询 access/refresh token ...")
        started_at = time.time()
        poll_deadline = started_at + min(expires_in, DEVICE_POLL_CAP_SECONDS)
        try:
            grace_deadline = started_at + max(0.0, float(grace_invalid_grant or 0.0))
        except Exception:
            grace_deadline = started_at
        last_err = ""
        while time.time() < poll_deadline:
            try:
                r = s.post(
                    f"{OIDC_ISSUER}/oauth2/token",
                    data={
                        "grant_type": DEVICE_CODE_GRANT_TYPE,
                        "device_code": device_code,
                        "client_id": CLIENT_ID,
                    },
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Accept": "application/json",
                        "User-Agent": GROK_TOKEN_UA,
                        "X-Grok-Client-Version": GROK_VERSION,
                    },
                    impersonate="chrome",
                    timeout=8,
                )
            except Exception as e:
                last_err = f"token 异常: {e}"
                log(f"  ⚠️ {last_err}")
                time.sleep(interval)
                continue
            payload = {}
            try:
                payload = r.json()
            except Exception:
                payload = {}
            if not isinstance(payload, dict):
                payload = {}
            err = str(payload.get("error") or "").strip()
            if r.status_code >= 200 and r.status_code < 300 and payload.get("access_token"):
                token = _normalize_token_payload(payload)
                if not token:
                    last_err = "token 缺 access_token"
                    break
                ap = decode_jwt_payload(token["access_token"])
                ref = ap.get("referrer")
                if ref:
                    log(f"  ✅ access_token referrer={ref!r}")
                log(
                    f"  ✅ access_token (expires_in={token.get('expires_in')}s)"
                    + (" + refresh_token" if token.get("refresh_token") else "")
                )
                return token
            if err == "authorization_pending":
                last_err = err
                time.sleep(interval)
                continue
            if err == "slow_down":
                interval = min(interval + 5, 30)
                last_err = err
                time.sleep(interval)
                continue
            if err == "invalid_grant" and time.time() < grace_deadline:
                # 授权刚提交时服务端可能尚未落库，宽限期内按 pending 处理
                last_err = "invalid_grant(宽限期内重试)"
                time.sleep(interval)
                continue
            if err in ("expired_token", "access_denied", "invalid_grant"):
                desc = str(payload.get("error_description") or "").strip()
                log(f"  ❌ device token 终态: {err} {desc}")
                return None
            last_err = f"HTTP {r.status_code} err={err or str(r.text)[:120]}"
            log(f"  ⚠️ token 轮询: {last_err}")
            time.sleep(interval)
        log(f"  ❌ device-flow 轮询超时/失败: {last_err}")
        return None
    finally:
        if own:
            try:
                s.close()
            except Exception:
                pass


def sso_to_token_device_browser(
    sso_cookie: str,
    browser_approve,
    proxy: str = "",
    log=print,
) -> dict | None:
    """Device Flow：HTTP 申请 code + 浏览器点「继续/允许」+ HTTP 轮询 token。

    browser_approve(user_code, open_url) -> bool
    """
    sso_cookie = str(sso_cookie or "").strip()
    if not sso_cookie:
        log("  ❌ sso 为空")
        return None
    if not callable(browser_approve):
        log("  ❌ browser_approve 回调不可用")
        return None

    # 轻量校验 SSO（带 cookie 的独立会话）
    s_check = _new_sso_session(sso_cookie, proxy=proxy)
    try:
        r = s_check.get("https://accounts.x.ai/", impersonate="chrome", timeout=15)
        final = str(getattr(r, "url", "") or "")
        if "sign-in" in final or "sign-up" in final or int(getattr(r, "status_code", 0) or 0) == 401:
            log("  ❌ sso 无效")
            return None
        log("  ✅ sso 有效（浏览器 Device 授权路径）")
    except Exception as e:
        log(f"  ❌ 网络错误: {e}")
        return None
    finally:
        try:
            s_check.close()
        except Exception:
            pass

    # device_code 申请不强制绑 SSO，对齐 CPA 服务端角色
    device = request_device_code(proxy=proxy, log=log, session=None)
    if not device:
        return None
    open_url = str(device.get("open_url") or "").strip()
    if open_url and not _is_trusted_xai_url(open_url):
        log(f"  ❌ verification URL 不受信: {open_url[:120]}")
        return None
    log(f"  [*] 浏览器授权: {open_url[:120]}")
    try:
        ok = bool(browser_approve(device["user_code"], open_url))
    except Exception as e:
        log(f"  ❌ 浏览器授权异常: {e}")
        return None
    if not ok:
        log("  ❌ 浏览器未完成 继续/允许")
        return None
    log("  ✅ 浏览器已提交「允许」，由 token 端点裁决结果")
    return poll_device_token(
        device["device_code"],
        interval=device.get("interval", DEVICE_DEFAULT_INTERVAL),
        expires_in=device.get("expires_in", DEVICE_DEFAULT_EXPIRES),
        proxy=proxy,
        log=log,
        session=None,
        grace_invalid_grant=DEVICE_GRACE_BROWSER,
    )


def sso_to_token_device_flow(sso_cookie: str, proxy: str = "", log=print) -> dict | None:
    """SSO cookie → token（纯协议 Device Flow + verify/approve，回退路径）。

    对齐 sub2api/gptGrok2api 的 /oauth2/device/verify + approve。
    主路径优先用 sso_to_token_device_browser（复用注册浏览器点允许）。
    """
    sso_cookie = str(sso_cookie or "").strip()
    if not sso_cookie:
        log("  ❌ sso 为空")
        return None

    principal_id = _sso_principal_id(sso_cookie)
    s = _new_sso_session(sso_cookie, proxy=proxy)
    try:
        r = s.get("https://accounts.x.ai/", impersonate="chrome", timeout=15)
    except Exception as e:
        log(f"  ❌ 网络错误: {e}")
        return None
    final = str(getattr(r, "url", "") or "")
    if "sign-in" in final or "sign-up" in final or int(getattr(r, "status_code", 0) or 0) == 401:
        log("  ❌ sso 无效")
        return None
    log("  ✅ sso 有效" + (f" principal_id={principal_id[:12]}..." if principal_id else "（协议路径）"))

    device = request_device_code(proxy=proxy, log=log, session=s)
    if not device:
        return None
    user_code = device["user_code"]
    open_url = str(device.get("open_url") or "")
    if open_url and _is_trusted_xai_url(open_url):
        try:
            s.get(open_url, impersonate="chrome", timeout=15, allow_redirects=True)
        except Exception as e:
            log(f"  ⚠️ 打开 verification URL 失败（继续 verify）: {e}")

    log("  [*] Device Flow: verify user_code ...")
    try:
        r = s.post(
            DEVICE_VERIFY_URL,
            data={"user_code": user_code},
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
                "Origin": "https://accounts.x.ai",
                "Referer": open_url or "https://accounts.x.ai/",
                "User-Agent": DEFAULT_UA,
            },
            impersonate="chrome",
            timeout=20,
            allow_redirects=True,
        )
    except Exception as e:
        log(f"  ❌ device/verify 异常: {e}")
        return None
    verify_url = str(getattr(r, "url", "") or "")
    verify_body = str(getattr(r, "text", "") or "")
    if r.status_code in (401, 403) or "sign-in" in verify_url or "sign-up" in verify_url:
        log(f"  ❌ device/verify 会话无效 HTTP {r.status_code} url={verify_url[:120]}")
        return None
    if r.status_code < 200 or r.status_code >= 400:
        log(f"  ❌ device/verify HTTP {r.status_code}: {verify_body[:180]}")
        return None
    # 只认 URL：consent 页的 JS bundle / i18n 字典里含有「设备已授权」等全站文案，
    # 用 body 文本判定会误判成已授权而跳过 approve，导致一直 authorization_pending。
    if "/oauth2/device/done" in verify_url.lower():
        log("  ✅ device/verify 已直接授权")
    else:
        log(f"  ✅ device/verify OK → {verify_url[:120]}")
        log(
            "  [*] Device Flow: approve allow"
            + (f" principal_id={principal_id[:12]}..." if principal_id else " principal_id=(empty)")
            + " ..."
        )
        try:
            r = s.post(
                DEVICE_APPROVE_URL,
                data={
                    "user_code": user_code,
                    "action": "allow",
                    "principal_type": "User",
                    "principal_id": principal_id,
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
                    "Origin": "https://accounts.x.ai",
                    "Referer": verify_url or "https://accounts.x.ai/",
                    "User-Agent": DEFAULT_UA,
                },
                impersonate="chrome",
                timeout=20,
                allow_redirects=True,
            )
        except Exception as e:
            log(f"  ❌ device/approve 异常: {e}")
            return None
        approve_url = str(getattr(r, "url", "") or "")
        approve_body = str(r.text or "")
        if r.status_code in (401, 403) or "sign-in" in approve_url:
            log(f"  ❌ device/approve 被拒 HTTP {r.status_code}")
            return None
        if r.status_code < 200 or r.status_code >= 400:
            log(f"  ❌ device/approve HTTP {r.status_code}: {approve_body[:180]}")
            return None
        if _device_authorized(approve_url, approve_body):
            log("  ✅ device/approve 已允许")
        else:
            # 不再把任意 HTTP 200 当成功；未到 done 直接失败，交给外层回退
            log(f"  ❌ device/approve 未到 done: {approve_url[:120]}")
            return None

    return poll_device_token(
        device["device_code"],
        interval=device.get("interval", DEVICE_DEFAULT_INTERVAL),
        expires_in=device.get("expires_in", DEVICE_DEFAULT_EXPIRES),
        proxy=proxy,
        log=log,
        session=s,
        grace_invalid_grant=DEVICE_GRACE_PROTOCOL,
    )


def sso_to_token_auth_code(sso_cookie: str, proxy: str = "", log=print) -> dict | None:
    """SSO cookie → token（Authorization Code + PKCE，回退路径）。

    authorize 注入 referrer=grok-build + plan=generic，
    consent 优先复用已成功的 Next-Action，失效时才扫描页面 JS 并重试。
    """
    global _working_next_action_id

    s = _new_sso_session(sso_cookie, proxy=proxy)
    try:
        r = s.get("https://accounts.x.ai/", impersonate="chrome", timeout=15)
    except Exception as e:
        log(f"  ❌ 网络错误: {e}")
        return None
    if "sign-in" in r.url or "sign-up" in r.url:
        log("  ❌ sso 无效")
        return None
    log("  ✅ sso 有效")

    verifier, challenge, state, nonce = _gen_pkce()

    # 1) 打开 authorize 页，跟随重定向进入 consent
    log(f"  🔑 Authorization Code Flow (referrer={GROK_REFERRER}, plan={GROK_PLAN})...")
    authorize_params = urllib.parse.urlencode({
        "client_id": CLIENT_ID,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "nonce": nonce,
        "plan": GROK_PLAN,
        "redirect_uri": REDIRECT_URI,
        "referrer": GROK_REFERRER,
        "response_type": "code",
        "scope": SCOPES,
        "state": state,
    })
    authorize_url = f"{OIDC_ISSUER}/oauth2/authorize?{authorize_params}"

    def _open_consent(discover_actions=False):
        try:
            resp = s.get(
                authorize_url,
                impersonate="chrome",
                timeout=15,
                allow_redirects=True,
            )
        except Exception as e:
            log(f"  ❌ authorize 异常: {e}")
            return None, "", []
        url = str(resp.url)
        if "sign-in" in url or "sign-up" in url:
            log("  ❌ sso 无效")
            return None, url, []
        if "/oauth2/consent" not in url:
            log(f"  ❌ authorize 未进入 consent: {url}")
            return None, url, []
        html = str(resp.text or "")
        # consent 实际在 accounts.x.ai（从 auth.x.ai authorize 重定向）
        base = "https://accounts.x.ai"
        if "auth.x.ai" in url and "accounts.x.ai" not in url:
            base = "https://auth.x.ai"
        if discover_actions:
            action_ids = _discover_action_ids_from_js(s, html, base_url=base, log=log)
        else:
            action_ids = []
            # 磁盘/内存中上次成功的 ID 优先；无缓存时再试 bootstrap
            for candidate in (
                _normalize_next_action_id(_working_next_action_id),
                _normalize_next_action_id(NEXT_ACTION_ID),
            ):
                if candidate and candidate not in action_ids:
                    action_ids.append(candidate)
            for action_id in _extract_next_action_ids(html):
                aid = _normalize_next_action_id(action_id) or str(action_id or "").strip().lower()
                if aid and aid not in action_ids:
                    action_ids.append(aid)
            log(f"  [*] consent 快速路径 Next-Action {len(action_ids)} 个（跳过 JS chunks 扫描）")
        return resp, url, action_ids

    r, final_url, action_ids = _open_consent()
    if r is None:
        return None
    if not action_ids:
        action_ids = [NEXT_ACTION_ID]
        log(f"  ⚠️ 未解析到 Next-Action，使用 fallback {NEXT_ACTION_ID[:12]}...")
    else:
        log(f"  [*] consent Next-Action 候选 {len(action_ids)} 个（首个 {action_ids[0][:12]}...）")

    # 2) 提交 consent（allow），拿 authorization code
    # consent 也必须带 referrer=grok-build，否则 JWT claim 为 None
    consent_payload = json.dumps([{
        "action": "allow",
        "clientId": CLIENT_ID,
        "redirectUri": REDIRECT_URI,
        "scope": SCOPES,
        "state": state,
        "codeChallenge": challenge,
        "codeChallengeMethod": "S256",
        "nonce": nonce,
        "principalType": "User",
        "principalId": "",
        "referrer": GROK_REFERRER,
    }])

    code = None
    last_err = ""
    tried: set[str] = set()
    # 最多 2 轮：第一轮优先试上次成功/内置 id；失败再重开 consent 扫 JS chunks。
    for round_i in range(2):
        if round_i > 0:
            log("  [*] consent 失败，重新进入 authorize/consent 并解析 Next-Action...")
            r, final_url, action_ids = _open_consent(discover_actions=True)
            if r is None:
                return None
            if not action_ids:
                action_ids = [NEXT_ACTION_ID]

        for action_id in action_ids[:8]:
            if action_id in tried:
                continue
            tried.add(action_id)
            try:
                r = s.post(
                    final_url,
                    data=consent_payload,
                    headers={
                        "Content-Type": "text/plain;charset=UTF-8",
                        "Accept": "text/x-component",
                        "Origin": "https://accounts.x.ai",
                        "Referer": final_url,
                        "Next-Action": action_id,
                    },
                    impersonate="chrome",
                    timeout=15,
                    allow_redirects=True,
                )
            except Exception as e:
                last_err = f"consent 异常: {e}"
                log(f"  ❌ {last_err}")
                continue
            body = str(r.text or "")
            if r.status_code == 404 or "server action not found" in body.lower():
                last_err = f"consent HTTP {r.status_code}: {body[:160]}"
                log(f"  ⚠️ Next-Action {action_id[:12]}... 无效: {last_err}")
                # 剔除失效 ID，避免下次冷启动仍优先打 404
                _invalidate_working_next_action_id(action_id)
                continue
            if r.status_code < 200 or r.status_code >= 300:
                last_err = f"consent HTTP {r.status_code}: {body[:200]}"
                log(f"  ⚠️ {last_err}")
                continue
            code, server_err = _parse_consent_result(body)
            if code:
                _remember_working_next_action_id(action_id)
                log(f"  [*] Next-Action {action_id[:12]}... 返回 authorization code")
                break
            if server_err:
                # 服务端已受理并明确裁决（如 Access denied）：说明这个 action id
                # 是对的，问题在账号资质。再换 ID 或扫 JS chunk 都是白费。
                _remember_working_next_action_id(action_id)
                log(f"  ❌ consent 被服务端拒绝: {server_err}")
                log("     （Next-Action 有效，属账号资质裁决，换 ID 重试无意义）")
                return None
            # 200 但无 code 也无裁决：多半是别的 server action（如读用户信息）
            last_err = f"consent 未返回 code: {body[:180]}"
            log(f"  ⚠️ Next-Action {action_id[:12]}... 非 allow 响应，继续试")
        if code:
            break

    if not code:
        log(f"  ❌ consent 失败（已试 {len(tried)} 个 Next-Action）: {last_err}")
        return None
    log("  ✅ 授权确认")

    # 3) 用 authorization code 换 token
    token_data = urllib.parse.urlencode({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "code_verifier": verifier,
    })
    try:
        r = s.post(
            f"{OIDC_ISSUER}/oauth2/token",
            data=token_data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": GROK_TOKEN_UA,
                "X-Grok-Client-Version": GROK_VERSION,
                "Accept": "*/*",
            },
            impersonate="chrome",
            timeout=15,
        )
    except Exception as e:
        log(f"  ❌ token 异常: {e}")
        return None
    if r.status_code < 200 or r.status_code >= 300:
        log(f"  ❌ token HTTP {r.status_code}: {str(r.text)[:200]}")
        return None
    try:
        token = r.json()
    except Exception:
        log(f"  ❌ token 返回非 JSON: {str(r.text)[:200]}")
        return None
    token = _normalize_token_payload(token or {})
    if not token:
        log("  ❌ token 缺少 access_token")
        return None

    # 校验 referrer claim（authorize 注入 grok-build 后应写入 JWT）
    ap = decode_jwt_payload(token["access_token"])
    ref = ap.get("referrer")
    if ref not in (GROK_REFERRER, "grok-build", "cli-proxy-api"):
        log(f"  ⚠️ access_token referrer={ref!r}（预期 {GROK_REFERRER!r} 或 grok-build）")
    else:
        log(f"  ✅ access_token referrer={ref!r}")
    log(
        f"  ✅ access_token (expires_in={token.get('expires_in')}s)"
        + (" + refresh_token" if token.get("refresh_token") else "")
    )
    return token


def sso_to_token(
    sso_cookie: str,
    proxy: str = "",
    log=print,
    prefer: str = "device",
    allow_fallback: bool = True,
    browser_approve=None,
) -> dict | None:
    """SSO cookie → token dict。

    默认顺序：
      1) 浏览器 Device（有 browser_approve 时）
      2) 纯协议 Device verify/approve
      3) Authorization Code（allow_fallback）
    prefer: "device" | "auth_code"
    """
    sso_cookie = str(sso_cookie or "").strip()
    if not sso_cookie:
        log("  ❌ sso 为空")
        return None

    order: list[str] = []
    if prefer == "auth_code":
        order = ["auth_code"]
        if allow_fallback:
            if callable(browser_approve):
                order.append("device_browser")
            order.append("device_protocol")
    else:
        if callable(browser_approve):
            order.append("device_browser")
        order.append("device_protocol")
        if allow_fallback:
            order.append("auth_code")
    if not allow_fallback and prefer == "device":
        # 已按上面构造；若只要单路径且无 browser，仅 protocol
        pass

    last_label = ""
    for method in order:
        last_label = method
        if method == "device_browser":
            log("  [*] 尝试浏览器 Device Flow（继续/允许）...")
            token = sso_to_token_device_browser(
                sso_cookie, browser_approve, proxy=proxy, log=log
            )
        elif method == "device_protocol":
            log("  [*] 尝试协议 Device Flow 换 token ...")
            token = sso_to_token_device_flow(sso_cookie, proxy=proxy, log=log)
        else:
            log("  [*] 尝试 Authorization Code 换 token ...")
            token = sso_to_token_auth_code(sso_cookie, proxy=proxy, log=log)
        if token and token.get("access_token"):
            if method != order[0]:
                log(f"  ✅ 回退路径 {method} 成功")
            return token
        if method != order[-1]:
            log(f"  ⚠️ {method} 失败，回退下一路径 ...")
    log(f"  ❌ 全部换 token 路径失败（最后尝试 {last_label}）")
    return None


def token_to_auth_entry(token: dict, email: str = "") -> tuple[str, dict]:
    """
    返回 (top_level_key, entry)
    top_level_key 固定为 issuer::client_id（与 ~/.grok/auth.json 一致）
    """
    access = token.get("access_token") or token.get("key") or ""
    refresh = token.get("refresh_token") or ""
    payload = decode_jwt_payload(access)

    user_id = payload.get("sub") or payload.get("principal_id") or ""
    principal_id = payload.get("principal_id") or user_id
    principal_type = payload.get("principal_type") or "User"

    expires_in = int(token.get("expires_in") or 21600)
    # 优先用 JWT exp
    if "exp" in payload:
        expires_at = rfc3339_ns(float(payload["exp"]))
    else:
        expires_at = rfc3339_ns(time.time() + expires_in)

    iat = payload.get("iat")
    create_time = rfc3339_ns(float(iat) if iat else time.time())

    entry = {
        "key": access,
        "auth_mode": "oidc",
        "create_time": create_time,
        "user_id": user_id,
        "email": email or "",
        "principal_type": principal_type,
        "principal_id": principal_id,
        "refresh_token": refresh,
        "expires_at": expires_at,
        "oidc_issuer": OIDC_ISSUER,
        "oidc_client_id": CLIENT_ID,
    }
    return AUTH_KEY, entry


def _iso_utc_from_unix(ts) -> str:
    """unix 秒 → CPA 认的 RFC3339（秒级，带 Z）。"""
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return ""


def _safe_email_for_filename(email: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "._-@" else "_" for ch in email)
    return safe or "unknown"


def token_to_cpa_record(
    token: dict,
    email: str = "",
    sso: str = "",
    *,
    bfs_info: dict | None = None,
    check_bfs: bool = True,
) -> dict:
    """token dict → CLIProxyAPI 扁平 xai auth 记录。

    对齐 CPA internal/auth/xai/token.go 的 TokenStorage 字段，以及
    grok-build-auth build_cliproxyapi_auth_record 的输出。
    """
    access = token.get("access_token") or token.get("key") or ""
    refresh = token.get("refresh_token") or ""
    id_token = token.get("id_token") or ""
    payload = decode_jwt_payload(access)
    id_payload = decode_jwt_payload(id_token) if id_token else {}

    if not email:
        email = id_payload.get("email") or payload.get("email") or ""
    sub = payload.get("sub") or id_payload.get("sub") or ""

    # expired: 优先 access token 的 exp，其次 expires_in 推算
    expired = ""
    if "exp" in payload:
        expired = _iso_utc_from_unix(payload["exp"])
    elif token.get("expires_in") is not None:
        try:
            expired = _iso_utc_from_unix(int(time.time()) + int(token["expires_in"]))
        except Exception:
            expired = ""

    record = {
        "type": "xai",
        "auth_kind": "oauth",
        "email": email or "",
        "sub": sub,
        "access_token": access,
        "refresh_token": refresh,
        "id_token": id_token,
        "token_type": token.get("token_type", "Bearer"),
        "expires_in": token.get("expires_in", None),
        "expired": expired,
        "last_refresh": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "redirect_uri": REDIRECT_URI,
        "token_endpoint": CPA_TOKEN_ENDPOINT,
        "base_url": CPA_GROK_BASE_URL,
        "disabled": False,
        "headers": dict(CPA_GROK_HEADERS),
    }
    sso_val = str(sso or "").strip()
    if sso_val:
        record["sso"] = sso_val
    if check_bfs:
        info = bfs_info or inspect_token_bundle_bfs(
            access_token=access,
            sso=sso_val,
            id_token=id_token,
            refresh_token=refresh,
        )
        apply_bfs_to_cpa_record(record, info)
    else:
        record["bfs"] = None
        record["bfs_checked"] = False
        record["bfs_status"] = "disabled"
    return record


def cpa_auth_filename(record: dict) -> str:
    """生成 CPA auth 文件名：xai-<email>.json。"""
    ident = str(record.get("email") or "").strip() or str(record.get("sub") or "").strip()
    safe = _safe_email_for_filename(ident)
    # 避免 email 本地部分已是 xai 时出现 "xai-xai..."
    fname = safe if safe.lower().startswith("xai") else f"xai-{safe}"
    return f"{fname}.json"


def probe_cpa_record(
    record: dict,
    proxy: str = "",
    timeout: int = 30,
    model: str = CPA_PROBE_MODEL,
) -> tuple[int | None, str]:
    """直连 CLI chat proxy 自测，返回 (HTTP 状态码, 响应摘要)。"""
    access = str(record.get("access_token") or "").strip()
    if not access:
        return None, "missing access_token"

    headers = dict(record.get("headers") or {})
    headers["Authorization"] = f"Bearer {access}"
    headers["Content-Type"] = "application/json"
    kwargs = {
        "headers": headers,
        "json": {
            "model": model,
            "input": "ping",
            "max_output_tokens": 2,
            "stream": False,
        },
        "impersonate": "chrome",
        "timeout": timeout,
    }
    if proxy:
        kwargs["proxy"] = proxy
    try:
        resp = requests.post(CPA_PROBE_URL, **kwargs)
        summary = str(resp.text or "").replace("\n", " ").strip()
        return int(resp.status_code), summary[:300]
    except Exception as exc:
        return None, str(exc)[:300]


def write_cpa_auth(auth_dir: Path, record: dict) -> Path:
    """写出 CPA 可热加载的 xai-<email>.json（原子替换）。

    无 email 时用 sub(user_id) 命名，避免多个无 email 账号写成同一个
    xai-unknown.json 互相覆盖。
    """
    ensure_private_dir(auth_dir)
    path = auth_dir / cpa_auth_filename(record)
    atomic_write_json(path, record)
    return path


def grok2api_auth_filename(entry: dict, email: str = "") -> str:
    """Grok2API / 官方 grok 风格文件名。"""
    ident = (
        str(email or "").strip()
        or str(entry.get("email") or "").strip()
        or str(entry.get("user_id") or "").strip()
        or secrets.token_hex(4)
    )
    safe = _safe_email_for_filename(ident)
    return f"g2a-{safe}.json"


def token_to_grok2api_account(token: dict, email: str = "") -> dict:
    """把 OAuth token 转成 Grok2API 的 ``{"accounts": [...]}`` 单账号格式."""
    access = str(token.get("access_token") or token.get("key") or "").strip()
    refresh = str(token.get("refresh_token") or "").strip()
    id_token = str(token.get("id_token") or "").strip()
    payload = decode_jwt_payload(access)
    id_payload = decode_jwt_payload(id_token) if id_token else {}

    resolved_email = str(
        email
        or id_payload.get("email")
        or payload.get("email")
        or ""
    ).strip()
    subject = str(
        payload.get("sub")
        or payload.get("user_id")
        or id_payload.get("sub")
        or ""
    ).strip()
    principal_id = str(
        payload.get("principal_id")
        or payload.get("user_id")
        or subject
    ).strip()
    client_id = str(payload.get("client_id") or CLIENT_ID).strip()
    team_id = str(payload.get("team_id") or "").strip()

    expires_at = ""
    if payload.get("exp") is not None:
        try:
            expires_at = rfc3339_ns(float(payload["exp"]))
        except (TypeError, ValueError, OverflowError):
            expires_at = ""
    if not expires_at:
        try:
            expires_at = rfc3339_ns(
                time.time() + int(token.get("expires_in") or 21600)
            )
        except (TypeError, ValueError, OverflowError):
            expires_at = ""

    return {
        "provider": "grok_build",
        "name": resolved_email,
        "client_id": client_id,
        "access_token": access,
        "refresh_token": refresh,
        "id_token": id_token,
        "token_type": token.get("token_type") or "Bearer",
        "scope": token.get("scope") or "",
        "expires_at": expires_at,
        # Grok2API uses expires_at as the source of truth for this format.
        "expires_in": 0,
        "email": resolved_email,
        "sub": subject,
        "user_id": subject,
        "principal_id": principal_id,
        "team_id": team_id,
    }


def _normalize_bearer_token(value: object) -> str:
    """接受裸 token、Bearer token 或完整 Authorization 头。"""
    key = str(value or "").strip().strip("`\"'")
    if key.lower().startswith("authorization:"):
        key = key.split(":", 1)[1].strip()
    if key.lower().startswith("bearer "):
        key = key[7:].strip()
    return key.strip("`\"'")


_GROK2API_DIRECT_PROXIES = {"http": "", "https": "", "all": ""}
_GROK2API_ADMIN_SUFFIXES = (
    "/api/admin/v1/accounts/import",
    "/api/admin/v1",
    "/admin/api/v1",
    "/api/admin",
    "/admin/api",
    "/admin",
)


def _grok2api_admin_root(base_url: str) -> str:
    """Normalize a Grok2API origin; strip admin/import suffixes if pasted."""
    base = str(base_url or "").strip().rstrip("/")
    for suffix in _GROK2API_ADMIN_SUFFIXES:
        if base.endswith(suffix):
            return base[: -len(suffix)].rstrip("/")
    return base


def _grok2api_http_session(state: dict | None = None):
    """Reuse one curl_cffi session so login Set-Cookie can refresh later."""
    bag = state if isinstance(state, dict) else {}
    session = bag.get("session")
    if session is not None:
        return session
    try:
        session = requests.Session(trust_env=False)
    except TypeError:
        session = requests.Session()
    if isinstance(state, dict):
        state["session"] = session
    return session


def _grok2api_access_token_usable(value: object) -> bool:
    """Reject empty or expired JWTs. Opaque keys are treated as still usable."""
    token = _normalize_bearer_token(value)
    if not token:
        return False
    claims = decode_jwt_payload(token)
    exp = claims.get("exp")
    if exp is None:
        return True
    try:
        return int(exp) > int(time.time()) + 30
    except (TypeError, ValueError):
        return True


def write_grok2api_auth(auth_dir: Path, token: dict, email: str = "") -> Path:
    """写出 Grok2API ``{"accounts": [{...}]}`` auth 文件。"""
    ensure_private_dir(auth_dir)
    account = token_to_grok2api_account(token, email=email)
    path = auth_dir / grok2api_auth_filename(account, email=email)
    atomic_write_json(path, {"accounts": [account]})
    return path


def _grok2api_response_detail(resp) -> str:
    """提取远端错误文本，并过滤可能意外回显的敏感字段。"""
    body = str(getattr(resp, "text", "") or "").strip()
    try:
        from webui.security_utils import redact_log_line

        body = redact_log_line(body)
    except Exception:
        body = body[:240]
    return body[:240]


def login_grok2api(
    base_url: str,
    username: str,
    password: str,
    timeout: int = 30,
    proxy: str = "",
    session=None,
    auth_state: dict | None = None,
) -> str:
    """通过 Grok2API 管理登录接口取得短期 access token。

    Grok2API 的 access JWT 约 15 分钟过期；refresh token 只在
    ``grok2api_admin_refresh`` Cookie 里，不在 JSON 响应中。
    管理接口直连目标实例，忽略注册用住宅代理（``proxy`` 保留兼容）。
    """
    del proxy
    base = _grok2api_admin_root(base_url)
    user = str(username or "").strip()
    secret = str(password or "")
    if not base:
        raise ValueError("grok2api_remote_url 为空")
    if not user or not secret:
        raise ValueError("Grok2API 登录需要同时填写用户名和密码")

    sess = session or _grok2api_http_session(auth_state)
    resp = sess.post(
        f"{base}/api/admin/v1/auth/login",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        json={"username": user, "password": secret},
        timeout=timeout,
        proxies=_GROK2API_DIRECT_PROXIES,
    )
    if resp.status_code >= 400:
        detail = _grok2api_response_detail(resp) or "用户名或密码错误"
        raise RuntimeError(f"Grok2API 登录失败 HTTP {resp.status_code}: {detail}")
    try:
        payload = resp.json()
    except Exception as exc:
        raise RuntimeError("Grok2API 登录响应不是有效 JSON") from exc
    try:
        access_token = str(payload["data"]["tokens"]["accessToken"] or "").strip()
    except (AttributeError, KeyError, TypeError):
        access_token = ""
    if not access_token:
        raise RuntimeError("Grok2API 登录响应缺少 data.tokens.accessToken")
    if isinstance(auth_state, dict):
        auth_state["access_token"] = access_token
        auth_state["session"] = sess
    return access_token


def _refresh_grok2api_access_token(
    base_url: str,
    session,
    timeout: int = 30,
) -> str:
    """Use the login refresh cookie to mint a new access JWT."""
    base = _grok2api_admin_root(base_url)
    resp = session.post(
        f"{base}/api/admin/v1/auth/refresh",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        json={},
        timeout=timeout,
        proxies=_GROK2API_DIRECT_PROXIES,
    )
    if resp.status_code >= 400:
        return ""
    try:
        payload = resp.json()
    except Exception:
        return ""
    if not isinstance(payload, dict):
        return ""
    data = payload.get("data")
    if not isinstance(data, dict):
        return ""
    token = str(data.get("accessToken") or "").strip()
    if token:
        return token
    tokens = data.get("tokens")
    if isinstance(tokens, dict):
        return str(tokens.get("accessToken") or "").strip()
    return ""


def _resolve_grok2api_access_token(
    base: str,
    username: str,
    password: str,
    state: dict,
    timeout: int,
    session,
) -> str:
    """Login for an access JWT; reuse a still-valid in-memory login token."""
    cached = _normalize_bearer_token(state.get("access_token"))
    if _grok2api_access_token_usable(cached):
        return cached
    user = str(username or "").strip()
    secret = str(password or "")
    if not user or not secret:
        raise ValueError("Grok2API 登录需要同时填写用户名和密码")
    return login_grok2api(
        base,
        user,
        secret,
        timeout=timeout,
        session=session,
        auth_state=state,
    )


def upload_grok2api_auth_remote(
    base_url: str,
    account: dict,
    timeout: int = 30,
    proxy: str = "",
    username: str = "",
    password: str = "",
    auth_state: dict | None = None,
) -> str:
    """通过 Grok2API 管理接口以 multipart 文件方式导入单个账号。

    每次用管理员账号登录拿 access JWT，并在 401 时刷新/重登。不要把注册
    代理带到这个管理接口，否则 multipart 的 Authorization 可能被中间代理丢掉。
    """
    del proxy
    base = _grok2api_admin_root(base_url)
    if not base:
        raise ValueError("grok2api_remote_url 为空")
    state = auth_state if isinstance(auth_state, dict) else {}
    session = _grok2api_http_session(state)
    key = _resolve_grok2api_access_token(
        base,
        username,
        password,
        state,
        timeout,
        session,
    )

    url = f"{base}/api/admin/v1/accounts/import"
    name = grok2api_auth_filename(account)
    payload = json.dumps(
        {"accounts": [account]}, ensure_ascii=False, indent=2
    ).encode("utf-8")

    def _upload_once(access_token: str):
        multipart = CurlMime()
        try:
            multipart.addpart(
                name="files",
                filename=name,
                content_type="application/json",
                data=payload,
            )
            return session.post(
                url,
                headers={
                    "Accept": "text/event-stream",
                    "Authorization": f"Bearer {access_token}",
                },
                multipart=multipart,
                timeout=timeout,
                proxies=_GROK2API_DIRECT_PROXIES,
            )
        finally:
            multipart.close()

    resp = _upload_once(key)
    if resp.status_code == 401 and str(username or "").strip() and str(password or ""):
        refreshed = _refresh_grok2api_access_token(base, session, timeout=timeout)
        if _grok2api_access_token_usable(refreshed):
            key = refreshed
        else:
            key = login_grok2api(
                base,
                username,
                password,
                timeout=timeout,
                session=session,
                auth_state=state,
            )
        state["access_token"] = key
        resp = _upload_once(key)
    if resp.status_code >= 400:
        body = _grok2api_response_detail(resp)
        detail = body or str(
            getattr(resp, "reason", "") or "remote rejected the request"
        ).strip()
        raise RuntimeError(
            f"Grok2API 远程上传失败 HTTP {resp.status_code}: {detail}"
        )
    return name


def _public_grok2api_account(item: dict) -> dict:
    email = str(item.get("email") or item.get("name") or "").strip().lower()
    quota = item.get("quota") if isinstance(item.get("quota"), dict) else {}
    try:
        refresh_failures = int(item.get("refreshFailureCount") or 0)
    except (TypeError, ValueError):
        refresh_failures = 0
    return {
        "email": email,
        "auth_status": str(item.get("authStatus") or ""),
        "enabled": bool(item.get("enabled")),
        "expires_at": str(item.get("expiresAt") or ""),
        "quota_status": str(quota.get("status") or ""),
        "refresh_failure_count": refresh_failures,
    }


def list_grok2api_accounts(
    base_url: str,
    username: str = "",
    password: str = "",
    *,
    provider: str = "grok_build",
    page_size: int = 100,
    timeout: int = 30,
    proxy: str = "",
    auth_state: dict | None = None,
) -> list[dict]:
    """Page through GET /api/admin/v1/accounts. Returns redacted account rows."""
    del proxy
    base = _grok2api_admin_root(base_url)
    if not base:
        raise ValueError("grok2api_remote_url 为空")
    state = auth_state if isinstance(auth_state, dict) else {}
    session = _grok2api_http_session(state)
    key = _resolve_grok2api_access_token(
        base,
        username,
        password,
        state,
        timeout,
        session,
    )
    size = max(1, min(int(page_size or 100), 1000))
    kind = str(provider or "grok_build").strip() or "grok_build"

    def _fetch(page: int, access_token: str):
        return session.get(
            f"{base}/api/admin/v1/accounts",
            params={
                "page": page,
                "pageSize": size,
                "sortBy": "createdAt",
                "sortOrder": "desc",
                "provider": kind,
            },
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {access_token}",
            },
            timeout=timeout,
            proxies=_GROK2API_DIRECT_PROXIES,
        )

    rows: list[dict] = []
    seen: set[str] = set()
    page = 1
    total = 0
    while page <= 50:
        resp = _fetch(page, key)
        if resp.status_code == 401 and str(username or "").strip() and str(password or ""):
            refreshed = _refresh_grok2api_access_token(base, session, timeout=timeout)
            if _grok2api_access_token_usable(refreshed):
                key = refreshed
            else:
                key = login_grok2api(
                    base,
                    username,
                    password,
                    timeout=timeout,
                    session=session,
                    auth_state=state,
                )
            state["access_token"] = key
            resp = _fetch(page, key)
        if resp.status_code >= 400:
            detail = _grok2api_response_detail(resp) or "remote rejected the request"
            raise RuntimeError(
                f"Grok2API 账号列表失败 HTTP {resp.status_code}: {detail}"
            )
        try:
            payload = resp.json()
        except Exception as exc:
            raise RuntimeError("Grok2API 账号列表不是有效 JSON") from exc
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, dict):
            raise RuntimeError("Grok2API 账号列表缺少 data")
        try:
            total = int(data.get("total") or 0)
        except (TypeError, ValueError):
            total = 0
        items = data.get("items")
        if not isinstance(items, list) or not items:
            break
        for item in items:
            if not isinstance(item, dict):
                continue
            row = _public_grok2api_account(item)
            email = row["email"]
            if not email or email in seen:
                continue
            seen.add(email)
            rows.append(row)
        if total and len(rows) >= total:
            break
        if len(items) < size:
            break
        page += 1
    return rows


def upload_cpa_auth_remote(
    base_url: str,
    management_key: str,
    record: dict,
    timeout: int = 30,
    proxy: str = "",
) -> str:
    """通过 CPA Management API 上传 auth 文件到远程实例。

    POST /v0/management/auth-files?name=<file.json>
    Header: Authorization: Bearer <management_key>
    Body: raw JSON auth record

    使用 curl_cffi（Chrome TLS 指纹）替代标准 requests，
    避免 CPA 服务端 Cloudflare 将裸 TLS 识别为非浏览器流量返回 403。
    """
    base = str(base_url or "").strip().rstrip("/")
    key = str(management_key or "").strip()
    if not base:
        raise ValueError("cpa_remote_url 为空")
    if not key:
        raise ValueError("cpa_management_key 为空")

    name = cpa_auth_filename(record)
    url = f"{base}/v0/management/auth-files"
    proxies = {"http": proxy, "https": proxy} if proxy else None
    resp = requests.post(
        url,
        params={"name": name},
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
        data=json.dumps(record, ensure_ascii=False).encode("utf-8"),
        timeout=timeout,
        proxies=proxies,
        impersonate="chrome",
    )
    if resp.status_code >= 400:
        body = (resp.text or "").strip()
        if len(body) > 300:
            body = body[:300] + "..."
        raise RuntimeError(f"远程上传失败 HTTP {resp.status_code}: {body or resp.reason}")
    return name


def write_auth_json(path: Path, auth_key: str, entry: dict) -> None:
    ensure_private_dir(path.parent)
    data = {auth_key: entry}
    atomic_write_json(path, data)


def merge_auth_json(path: Path, auth_key: str, entry: dict, unique: bool = True) -> None:
    """
    合并写入。unique=True 时 key 变成 issuer::client_id::user_id，避免多账号互相覆盖。
    """
    ensure_private_dir(path.parent)
    existing: dict = {}
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            existing = {}
    key = auth_key
    if unique and entry.get("user_id"):
        key = f"{auth_key}::{entry['user_id']}"
    existing[key] = entry
    atomic_write_json(path, existing)


@dataclass(frozen=True)
class SsoInput:
    sso: str
    email: str = ""
    password: str = ""
    source: str = ""
    raw_line: str = ""


def parse_sso_line(line: str, source: str = "") -> SsoInput | None:
    raw = str(line or "").strip()
    if not raw or raw.startswith("#"):
        return None
    email = ""
    password = ""
    sso = raw
    if "----" in raw:
        parts = [part.strip() for part in raw.split("----")]
        if len(parts) >= 3:
            email = parts[0]
            password = "----".join(parts[1:-1])
            sso = parts[-1]
        elif len(parts) == 2:
            email, sso = parts
    if sso.startswith("sso="):
        sso = sso[4:].strip()
    if len(sso) < 24 or any(ch.isspace() for ch in sso):
        return None
    return SsoInput(
        sso=sso,
        email=email,
        password=password,
        source=source,
        raw_line=raw,
    )


def _dedupe_sso_inputs(records: list[SsoInput]) -> list[SsoInput]:
    by_sso: dict[str, SsoInput] = {}
    order: list[str] = []
    for record in records:
        previous = by_sso.get(record.sso)
        if previous is None:
            order.append(record.sso)
            by_sso[record.sso] = record
            continue
        by_sso[record.sso] = SsoInput(
            sso=record.sso,
            email=previous.email or record.email,
            password=previous.password or record.password,
            source=previous.source or record.source,
            raw_line=previous.raw_line or record.raw_line,
        )
    return [by_sso[sso] for sso in order]


def load_sso_records(
    path: str | None = None,
    single: str | None = None,
    accounts_dir: str | None = None,
) -> list[SsoInput]:
    records: list[SsoInput] = []
    if single:
        parsed = parse_sso_line(single, source="command-line")
        return [parsed] if parsed else []
    paths: list[Path] = []
    locked_paths: set[Path] = set()
    if path:
        explicit_path = Path(path)
        paths.append(explicit_path)
        locked_paths.add(explicit_path.resolve())
    if accounts_dir:
        account_root = Path(accounts_dir)
        if account_root.is_dir():
            for candidate in sorted(account_root.glob("*.txt")):
                if candidate.name in {
                    "mail_credentials.txt",
                    "sso_risk_rejected.txt",
                    "sso_bfs_flagged.txt",
                }:
                    continue
                paths.append(candidate)
    for input_path in paths:
        try:
            if input_path.resolve() in locked_paths or input_path.name == "sso_pending.txt":
                with exclusive_file_lock(input_path.with_suffix(input_path.suffix + ".lock")):
                    lines = input_path.read_text(encoding="utf-8").splitlines()
            else:
                lines = input_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            parsed = parse_sso_line(line, source=str(input_path))
            if parsed:
                records.append(parsed)
    return _dedupe_sso_inputs(records)


def load_sso_list(path: str | None, single: str | None) -> list[str]:
    """Backward-compatible SSO-only loader."""
    return [record.sso for record in load_sso_records(path=path, single=single)]


def consume_successful_records(path: str | Path, succeeded_ssos: set[str]) -> int:
    queue_path = Path(path)
    if not queue_path.exists():
        return 0
    with exclusive_file_lock(queue_path.with_suffix(queue_path.suffix + ".lock")):
        if not succeeded_ssos:
            lines = queue_path.read_text(encoding="utf-8").splitlines()
            return sum(1 for line in lines if parse_sso_line(line, source=str(queue_path)))
        kept: list[str] = []
        for line in queue_path.read_text(encoding="utf-8").splitlines():
            parsed = parse_sso_line(line, source=str(queue_path))
            if parsed and parsed.sso in succeeded_ssos:
                continue
            kept.append(line)
        body = "\n".join(kept)
        if body:
            body += "\n"
        atomic_write_text(queue_path, body)
    return len(load_sso_records(path=str(queue_path)))


def _resolve_config_path(base: Path, value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    path = Path(text).expanduser()
    if not path.is_absolute():
        path = base / path
    return str(path.resolve())


def _config_bool(value: object, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().lower() not in ("", "0", "false", "no", "off")
    return bool(value)


def apply_config_defaults(args) -> None:
    if not args.from_config:
        if getattr(args, "bfs_check", None) is None:
            args.bfs_check = True
        if getattr(args, "bfs_skip_write", None) is None:
            args.bfs_skip_write = False
        if getattr(args, "bfs_disable", None) is None:
            args.bfs_disable = False
        args.prefer = args.prefer or "device"
        return
    config_path = Path(args.from_config).expanduser().resolve()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    base = config_path.parent
    if not args.cpa_auth_dir:
        args.cpa_auth_dir = _resolve_config_path(base, config.get("cpa_auth_dir"))
    if not args.grok2api_auth_dir:
        args.grok2api_auth_dir = _resolve_config_path(base, config.get("grok2api_auth_dir"))
    args.cpa_remote_url = args.cpa_remote_url or str(config.get("cpa_remote_url") or "").strip()
    args.cpa_management_key = args.cpa_management_key or str(config.get("cpa_management_key") or "").strip()
    args.grok2api_remote_url = getattr(args, "grok2api_remote_url", None) or str(
        config.get("grok2api_remote_url") or ""
    ).strip()
    args.grok2api_username = getattr(args, "grok2api_username", None) or str(
        config.get("grok2api_username") or ""
    ).strip()
    args.grok2api_password = getattr(args, "grok2api_password", None) or str(
        config.get("grok2api_password") or ""
    )
    args.proxy = args.proxy or str(config.get("proxy") or "").strip()
    if getattr(args, "bfs_check", None) is None:
        args.bfs_check = _config_bool(config.get("bfs_check"), True)
    if getattr(args, "bfs_skip_write", None) is None:
        args.bfs_skip_write = _config_bool(config.get("bfs_skip_cpa"), False)
    if getattr(args, "bfs_disable", None) is None:
        args.bfs_disable = _config_bool(config.get("bfs_disable_cpa"), False)
    if not args.prefer:
        mode = str(config.get("cpa_token_mode") or "device_protocol")
        args.prefer = "auth_code" if mode == "auth_code" else "device"


def should_create_default_out_dir(args, record_count: int) -> bool:
    has_target = any(
        (
            args.out,
            args.out_dir,
            args.cpa_auth_dir,
            args.cpa_remote_url,
            args.grok2api_auth_dir,
            getattr(args, "grok2api_remote_url", ""),
        )
    )
    return record_count > 1 and not has_target and not args.merge


def _mask_report_email(email: str) -> str:
    value = str(email or "").strip()
    if "@" not in value:
        return ""
    local, _, domain = value.partition("@")
    return f"{local[:2]}***@{domain}" if local else f"***@{domain}"


def existing_cpa_emails(auth_dir: str | Path | None) -> set[str]:
    if not auth_dir:
        return set()
    root = Path(auth_dir)
    if not root.is_dir():
        return set()
    emails: set[str] = set()
    for path in root.glob("xai-*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        email = str(data.get("email") or "").strip().lower()
        if email:
            emails.add(email)
    return emails


def main() -> int:
    ap = argparse.ArgumentParser(description="SSO cookie → grok auth.json (纯 HTTP)")
    ap.add_argument("--sso", metavar="FILE", help="sso 列表文件（一行一个 JWT，或 邮箱----密码----sso）")
    ap.add_argument("--sso-cookie", metavar="JWT", help="单个 sso cookie")
    ap.add_argument("--accounts-dir", metavar="DIR", help="扫描 accounts 目录内可恢复的 txt 账号")
    ap.add_argument("--from-config", metavar="FILE", help="从 config.json 读取 CPA、Grok2API 和代理默认值")
    ap.add_argument("--out", default=None, help="输出 auth.json 路径（单账号或 --merge）")
    ap.add_argument(
        "--out-dir",
        default=None,
        help="批量时每个账号写一个 {user_id}.json（可直接 cp 到 ~/.grok/auth.json）",
    )
    ap.add_argument(
        "--merge",
        action="store_true",
        help="合并到 --out，key 用 issuer::client_id::user_id",
    )
    ap.add_argument("--delay", type=int, default=0, help="每个间隔秒数")
    ap.add_argument("--email", default="", help="写入 entry.email（可选）")
    ap.add_argument(
        "--cpa-auth-dir",
        default=None,
        help="额外写出 CLIProxyAPI 扁平格式 xai-<email>.json 到该目录（CPA 热加载）",
    )
    ap.add_argument(
        "--cpa-remote-url",
        default=None,
        help="远程 CPA 地址，如 http://你的CPA地址:8317；配合 --cpa-management-key 通过 Management API 上传",
    )
    ap.add_argument(
        "--cpa-management-key",
        default=None,
        help="远程 CPA 管理密钥（remote-management.secret-key 明文）",
    )
    ap.add_argument(
        "--grok2api-auth-dir",
        default=None,
        help="额外写出 Grok2API / ~/.grok 风格 g2a-<email>.json 到该目录",
    )
    ap.add_argument(
        "--grok2api-remote-url",
        default=None,
        help="Grok2API 服务根地址；配合管理员用户名/密码登录后上传到 accounts/import",
    )
    ap.add_argument(
        "--grok2api-username",
        default=None,
        help="Grok2API 管理员用户名；用于 /api/admin/v1/auth/login",
    )
    ap.add_argument(
        "--grok2api-password",
        default=None,
        help="Grok2API 管理员密码；用于 /api/admin/v1/auth/login",
    )
    ap.add_argument(
        "--prefer",
        choices=("device", "auth_code"),
        default=None,
        help="换 token 优先路径：device（默认）或 auth_code",
    )
    ap.add_argument(
        "--no-fallback",
        action="store_true",
        help="禁用换 token 回退（仅用 --prefer 指定路径）",
    )
    ap.add_argument("--proxy", default="", help="OAuth 请求走代理，如 http://127.0.0.1:7890")
    ap.add_argument("--consume-success", action="store_true", help="成功后从 --sso 队列原子移除对应记录")
    ap.add_argument(
        "--no-skip-existing",
        action="store_true",
        help="即使本地 CPA 已有同邮箱也继续换 token 并写入 Grok2API",
    )
    ap.add_argument("--report-json", default=None, help="写入不含 token 的运行摘要 JSON")
    ap.add_argument(
        "--check-bfs-dir",
        metavar="DIR",
        default=None,
        help="仅扫描 CPA/Grok2API auth 目录中 JWT 的 bfs 标记（不换 token）",
    )
    ap.add_argument(
        "--bfs-export",
        metavar="FILE",
        default=None,
        help="与 --check-bfs-dir 联用：导出 has_bfs 列表（jsonl，不含 token）",
    )
    ap.add_argument(
        "--bfs-skip-write",
        dest="bfs_skip_write",
        action="store_true",
        default=None,
        help="换 token 后若 access_token/sso 含 bfs claim，跳过 CPA/Grok2API 写入",
    )
    ap.add_argument(
        "--bfs-check",
        dest="bfs_check",
        action="store_true",
        default=None,
        help="启用 JWT bfs claim 检测（默认开启，可由 config.json 覆盖）",
    )
    ap.add_argument(
        "--no-bfs-check",
        dest="bfs_check",
        action="store_false",
        default=None,
        help="禁用 JWT bfs claim 检测",
    )
    ap.add_argument(
        "--bfs-disable",
        dest="bfs_disable",
        action="store_true",
        default=None,
        help="换 token 后若含 bfs，仍写入 CPA 但 disabled=true",
    )
    ap.add_argument(
        "--check-sso-state",
        metavar="FILE",
        default=None,
        help="仅批量检查 sso 列表的 grok.com 账号风控状态（botFlagSource/risk/policy deny），不换 token 不入库",
    )
    ap.add_argument(
        "--sso-state-export",
        metavar="FILE",
        default=None,
        help="与 --check-sso-state 联用：导出被标记（botFlagSource=1/2 或 policy deny）名单 jsonl，不含 token",
    )
    ap.add_argument(
        "--sso-state-clean-export",
        metavar="FILE",
        default=None,
        help="与 --check-sso-state 联用：导出干净 sso 原始行 txt，每行一条，可直接复用为 --sso 输入",
    )
    args = ap.parse_args()

    # Standalone batch bfs scan (no SSO conversion)
    if args.check_bfs_dir:
        summary = scan_cpa_auth_dir_bfs(args.check_bfs_dir, include_clean=True)
        if args.bfs_export:
            export_path = Path(args.bfs_export)
            ensure_private_dir(export_path.parent)
            lines = []
            for item in summary.get("items") or []:
                if not item.get("has_bfs"):
                    continue
                lines.append(json.dumps(item, ensure_ascii=False))
            atomic_write_text(export_path, ("\n".join(lines) + ("\n" if lines else "")))
            print(f"导出 bfs 列表 → {export_path} ({len(lines)} 条)")
        print(
            f"bfs 扫描: total={summary.get('total')} bfs={summary.get('bfs_count')} "
            f"clean={summary.get('clean_count')} err={summary.get('error_count')} "
            f"rate={summary.get('bfs_rate')}% dist={summary.get('bfs_value_dist')}"
        )
        if args.report_json:
            # strip full items if huge? keep summary with items for offline review
            atomic_write_json(args.report_json, summary)
            print(f"报告 → {args.report_json}")
        return 0 if summary.get("ok") else 1

    apply_config_defaults(args)

    # Standalone batch grok.com account-state check (no token conversion)
    if args.check_sso_state:
        records = load_sso_records(path=args.check_sso_state)
        if not records:
            ap.error(f"--check-sso-state: {args.check_sso_state} 中没有可用 sso")
        summary = run_check_sso_state(
            records,
            proxy=args.proxy,
            delay=args.delay,
            export=args.sso_state_export,
            clean_export=args.sso_state_clean_export,
        )
        if args.report_json:
            atomic_write_json(args.report_json, summary)
            print(f"报告 → {args.report_json}")
        print(
            f"sso 状态检查: total={summary['total']} "
            f"flagged={summary['flagged_count']} clean={summary['clean_count']} "
            f"unknown={summary['unknown_count']} err={summary['error_count']} "
            f"botFlagDist={summary['bot_flag_dist']}"
        )
        return 0 if summary.get("ok") else 1

    records = load_sso_records(
        path=args.sso,
        single=args.sso_cookie,
        accounts_dir=args.accounts_dir,
    )
    if not records:
        ap.error("需要有效的 --sso、--sso-cookie、--accounts-dir 或 --check-bfs-dir")
    if args.consume_success and not args.sso:
        ap.error("--consume-success 只能与 --sso FILE 一起使用")
    if args.merge and not args.out:
        ap.error("--merge 必须同时指定 --out")

    if args.cpa_remote_url and not args.cpa_management_key:
        ap.error("使用 --cpa-remote-url 时必须同时提供 --cpa-management-key")
    if args.cpa_management_key and not args.cpa_remote_url:
        ap.error("使用 --cpa-management-key 时必须同时提供 --cpa-remote-url")
    if args.grok2api_remote_url and not (args.grok2api_username and args.grok2api_password):
        ap.error("使用 --grok2api-remote-url 时必须同时提供 --grok2api-username 和 --grok2api-password")
    if (args.grok2api_username or args.grok2api_password) and not args.grok2api_remote_url:
        ap.error("使用 Grok2API 用户名/密码时必须同时提供 --grok2api-remote-url")

    input_count = len(records)
    existing_emails = existing_cpa_emails(args.cpa_auth_dir)
    already_present = [
        record
        for record in records
        if record.email and record.email.strip().lower() in existing_emails
    ]
    if already_present and not getattr(args, "no_skip_existing", False):
        existing_ssos = {record.sso for record in already_present}
        records = [record for record in records if record.sso not in existing_ssos]
        if args.consume_success and args.sso:
            consume_successful_records(args.sso, existing_ssos)
        print(f"跳过已存在 CPA 的记录: {len(already_present)}")

    if should_create_default_out_dir(args, len(records)):
        args.out_dir = "./auth_out"
        print(f"批量模式默认 --out-dir {args.out_dir}")

    # 只指定 CPA 目标时不再默认写官方 ~/.grok/auth.json
    if (
        args.out is None
        and args.out_dir is None
        and not args.cpa_auth_dir
        and not args.cpa_remote_url
        and not args.grok2api_auth_dir
        and not args.grok2api_remote_url
        and len(records) == 1
    ):
        args.out = str(Path.home() / ".grok" / "auth.json")

    args.prefer = args.prefer or "device"
    print(
        f"🚀 SSO → auth.json: {len(records)} 个待处理, delay={args.delay}s, "
        f"prefer={args.prefer}, fallback={not args.no_fallback}"
    )
    ok = 0
    fail = 0
    bfs_flagged = 0
    bfs_unknown = 0
    succeeded_ssos: set[str] = set()
    failures: list[dict] = []
    grok2api_auth_state: dict = {}

    for i, record in enumerate(records, 1):
        sso = record.sso
        email = str(args.email or record.email or "").strip()
        print(f"\n{'=' * 60}\n[{i}/{len(records)}] ...\n{'=' * 60}")
        try:
            state = inspect_sso_account_state(
                sso,
                proxy=args.proxy,
                log=lambda message: print(f"  {str(message).strip()}"),
            )
            if state.get("denied"):
                fail += 1
                failures.append({"index": i, "email": _mask_report_email(email), "reason": "registration-risk"})
                print(
                    "  ❌ 注册风控拒绝，跳过三条 OAuth 路径: "
                    f"{state.get('bot_flag_details') or 'policy=deny,event=$registration'}"
                )
                continue
            token = sso_to_token(
                sso,
                proxy=args.proxy,
                prefer=args.prefer,
                allow_fallback=not args.no_fallback,
            )
            if not token:
                fail += 1
                failures.append({"index": i, "email": _mask_report_email(email), "reason": "token-conversion"})
                print(f"  ❌ [{i}] 失败")
                continue

            bfs_info = {
                "ok": False,
                "has_bfs": False,
                "bfs": None,
                "source": "",
            }
            if args.bfs_check:
                bfs_info = inspect_token_bundle_bfs(
                    access_token=str(token.get("access_token") or ""),
                    sso=sso,
                    id_token=str(token.get("id_token") or ""),
                    refresh_token=str(token.get("refresh_token") or ""),
                )
                if not bfs_info.get("ok"):
                    bfs_unknown += 1
                    print("  ⚠️ JWT bfs 检测: unknown（无法解码 token）")
                    if args.bfs_skip_write:
                        fail += 1
                        failures.append(
                            {
                                "index": i,
                                "email": _mask_report_email(email),
                                "reason": "bfs-unknown",
                            }
                        )
                        print(f"  ❌ [{i}] bfs 状态未知，已按 --bfs-skip-write 跳过写入")
                        continue
                elif bfs_info.get("has_bfs"):
                    bfs_flagged += 1
                    print(
                        f"  ⚠️ JWT bfs 标记: value={bfs_info.get('bfs')!r} "
                        f"source={bfs_info.get('source') or '-'}"
                    )
                    if args.bfs_skip_write:
                        fail += 1
                        failures.append(
                            {
                                "index": i,
                                "email": _mask_report_email(email),
                                "reason": "bfs-flagged",
                                "bfs": bfs_info.get("bfs"),
                            }
                        )
                        print(f"  ❌ [{i}] bfs 标记，已按 --bfs-skip-write 跳过写入")
                        continue
                else:
                    print("  ✅ JWT bfs 检测: clean（无 bfs claim）")
            else:
                print("  ⏭️ JWT bfs 检测已禁用")

            key, entry = token_to_auth_entry(token, email=email)
            uid = entry.get("user_id") or secrets.token_hex(4)

            if args.out_dir:
                p = Path(args.out_dir) / f"{uid}.json"
                write_auth_json(p, key, entry)
                print(f"  💾 {p}")
            if args.out:
                if args.merge or len(records) > 1:
                    merge_auth_json(Path(args.out), key, entry, unique=True)
                    print(f"  💾 merge → {args.out}")
                else:
                    write_auth_json(Path(args.out), key, entry)
                    print(f"  💾 {args.out}")

            if args.grok2api_auth_dir:
                gp = write_grok2api_auth(Path(args.grok2api_auth_dir), token, email=email)
                print(f"  💾 Grok2API → {gp}")
            if args.grok2api_remote_url:
                grok_account = token_to_grok2api_account(token, email=email)
                name = upload_grok2api_auth_remote(
                    args.grok2api_remote_url,
                    grok_account,
                    username=args.grok2api_username,
                    password=args.grok2api_password,
                    auth_state=grok2api_auth_state,
                )
                print(
                    f"  💾 Grok2API 远程 → "
                    f"{args.grok2api_remote_url.rstrip('/')}/.../{name}"
                )

            if args.cpa_auth_dir or args.cpa_remote_url:
                cpa_record = token_to_cpa_record(
                    token,
                    email=email,
                    sso=sso,
                    bfs_info=bfs_info if args.bfs_check else None,
                    check_bfs=args.bfs_check,
                )
                if args.bfs_disable and cpa_record.get("bfs") is True:
                    cpa_record["disabled"] = True
                    print("  ⚠️ bfs 账号已标记 disabled=true")
                if args.cpa_auth_dir:
                    cp = write_cpa_auth(Path(args.cpa_auth_dir), cpa_record)
                    print(f"  💾 CPA 本地 → {cp}")
                if args.cpa_remote_url:
                    name = upload_cpa_auth_remote(
                        args.cpa_remote_url,
                        args.cpa_management_key,
                        cpa_record,
                        proxy=args.proxy,
                    )
                    print(f"  💾 CPA 远程 → {args.cpa_remote_url.rstrip('/')}/.../{name}")

            ok += 1
            succeeded_ssos.add(sso)
            if args.consume_success and args.sso:
                consume_successful_records(args.sso, {sso})
            print(f"  ✅ [{i}] 完成 user_id={uid[:12]}...")
        except Exception as e:
            fail += 1
            try:
                from webui.security_utils import redact_log_line

                reason = redact_log_line(str(e))[:240]
            except Exception:
                reason = type(e).__name__
            failures.append({"index": i, "email": _mask_report_email(email), "reason": reason})
            print(f"  ❌ [{i}] 异常: {e}")

        if args.delay > 0 and i < len(records):
            time.sleep(args.delay)

    remaining = None
    if args.consume_success and args.sso:
        remaining = consume_successful_records(args.sso, succeeded_ssos)
        print(f"  队列剩余 {remaining} 条")
    report = {
        "version": 1,
        "finished_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "input_count": input_count,
        "skipped_existing_count": len(already_present),
        "success_count": ok,
        "failure_count": fail,
        "bfs_flagged_count": bfs_flagged,
        "bfs_unknown_count": bfs_unknown,
        "remaining_count": remaining,
        "failures": failures,
    }
    if args.report_json:
        atomic_write_json(args.report_json, report)
    print(
        f"\n{'=' * 60}\n📊 完成: {ok}/{len(records)} 成功, {fail} 失败, "
        f"bfs={bfs_flagged}, unknown={bfs_unknown}"
    )
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
