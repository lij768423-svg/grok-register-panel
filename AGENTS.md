# AGENTS.md

This file is the working contract for AI coding agents in this repository. Keep
changes narrow, preserve existing runtime behavior, and never use real operator
credentials as fixtures or examples.

## Project Scope

Grok Register + Live Panel is a Camoufox-based registration workflow with a
local operations panel. It is intended for authorized research, integration,
and personal environments. Do not add features intended to evade access
controls, scrape or distribute third-party proxies, or conceal unauthorized
bulk abuse.

## Architecture And Ownership

- `register_flow.py`, `browser_session.py`, and `camoufox_adapter.py` own the
  browser registration flow, session lifecycle, exit checks, and Camoufox
  integration.
- `run_batch_headless.py` starts a batch. `batch_supervisor.py` supervises its
  child process, restarts driver crashes or idle runs, and resumes only the
  remaining slots through an atomic progress file.
- `run_until_100.py` owns multi-batch orchestration and runtime control state.
- `sso_to_auth_json.py` owns SSO/device OAuth conversion and CPA/Grok2API auth
  output. Successful output is not rolled back when a later slot fails.
- `email_providers/` contains provider adapters. Keep provider-specific API
  behavior there instead of branching throughout the registration flow.
- `webui/monitor.py` owns the HTTP server and embedded UI. Its focused stores
  and operations live in `webui/*_store.py` and `webui/*_ops.py`.
- `webui/sso_state_ops.py` owns the deprecated SSO botFlag / policy scan job.
  Reports must not include raw SSO tokens; clean exports stay in
  `log/sso_clean.txt`. Do not use this scan as a live risk gate.
- `quality_probe.py` and `webui/quality_ops.py` own the 降智测试: short streamed
  chat replies over 家宽/proxy pool (early-stop after thinking). Registration
  stamps `quality_*` onto CPA/Grok2API auth only when `quality_probe_on_register`
  is on (default off). Panel exports must not include access tokens. Prefer home
  proxies from `proxy_store.worker_proxy_details()`.
- `webui/proxy_store.py` owns proxy import, normalization, health, cooldown, and
  redacted API views. `webui/email_provider_store.py` owns provider config and
  secret-preserving updates. `webui/email_domain_store.py` owns domain rotation
  and rejection state.
- `runtime_platform.py` owns interpreter discovery, Xvfb selection, and process
  group flags. `webui/process_utils.py` owns project-scoped process discovery
  and termination.
- `static_asset_cache.py` is opt-in infrastructure. Its default-off behavior and
  request exclusions are security boundaries, not implementation details.
- `batch_traffic.py` owns the per-batch loopback proxy meter and aggregate byte
  state. It must never persist upstream proxy URLs, credentials, or content.

## Runtime Flows

1. A CLI or the panel starts `run_batch_headless.py` directly, or starts
   `run_until_100.py` for multiple rounds.
2. The supervisor isolates each browser batch and resumes incomplete work after
   a recoverable driver crash or idle timeout.
3. A worker selects an enabled, healthy proxy and keeps that same proxy for one
   account across registration, SSO, and OAuth.
4. Email provider/domain selection occurs before the registration form. Only an
   explicit xAI domain rejection increments domain rejection state.
5. Successful SSO can be converted to CPA/Grok2API auth. BFS detection is a JWT
   claim check separate from the deprecated grok.com `botFlagSource` page field.
   Account chat quality / 风控 is judged by `quality_probe` (short real replies),
   not SSO homepage scraping. New accounts are probed after OAuth write only when
   `quality_probe_on_register` is enabled.
6. The panel reads JSON/runtime state and controls only processes whose command
   line resolves to this project root.

## Setup And Run

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m camoufox fetch
cp config.example.json config.json

MONITOR_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')" \
MONITOR_HOST=127.0.0.1 \
PANEL_INCLUDE_TAIL=0 \
  .venv/bin/python -u webui/monitor.py
```

For a headless Linux batch use:

```bash
xvfb-run -a .venv/bin/python -u run_batch_headless.py 20 3
```

Linux graphical sessions and macOS run the Python entry point directly.
Windows runs the same Python entry point without Xvfb. Pin Playwright Node
through `apply_playwright_node_env()`; never point `PLAYWRIGHT_NODEJS_PATH`
at the POSIX `scripts/playwright-node` wrapper on Windows. Default Windows
batches to `GROK_HEADLESS=1`. Proxy URLs must be reachable from the Windows
process itself (remote HTTP/SOCKS), not Linux-only loopback mixed ports.

## Required Verification

Run the full repository check for every code or UI change:

```bash
PYTHON_BIN=.venv/bin/python scripts/run_tests.sh
git diff --check
```

Before deployment also run:

```bash
.venv/bin/python -m pip check
.venv/bin/python -m camoufox version
.venv/bin/python scripts/harden_runtime_permissions.py .
```

Add or update a focused test under `tests/` when behavior changes. The release
script intentionally uses direct Python test files, `compileall`, shell syntax
checks, and `git diff --check`; do not assume pytest is required. Test files are
plain `test_*` functions with a `__main__` block, so `python -m unittest` finds
nothing — run them as scripts or with `python -m pytest tests`. Tests that import
`grok_register_ttk` need a Python with tkinter and skip themselves otherwise.

For UI changes, review desktop and mobile layouts in light and dark themes.
Verify that operational API calls still require authentication and that no
credential appears in rendered HTML, JSON responses, console output, or
screenshots.

## Authentication And HTTP Rules

- `GET /` and `GET /api/health` are anonymous and must not expose runtime data.
- Operational GET endpoints require a token when `MONITOR_TOKEN` is configured.
- Every POST, PATCH, and DELETE operation requires `MONITOR_TOKEN`; an unset
  token does not make write operations public.
- Accept tokens through `Authorization: Bearer` or `X-Monitor-Token`. Never add
  token query parameters, include tokens in URLs, or log request headers.
- A non-loopback panel bind requires a strong token. Prefer an exact loopback,
  LAN, or Tailscale address over `0.0.0.0`.
- Keep CSP, frame denial, referrer policy, request-size limits, and the absence
  of wildcard CORS intact unless a reviewed design explicitly replaces them.
- `PANEL_INCLUDE_TAIL` defaults to `0`. Raw log tails can contain sensitive
  runtime material and must stay opt-in.

## Secrets And Runtime Files

Never commit or paste real values from:

- `config.json`, `.env.monitor`, `proxies*.txt`, or `stickies*.txt`
- `accounts/`, `cpa_auth/`, `grok2api_auth/`, or any exported auth file
- `log/`, including proxy pool, email domain pool, monitor token, reports, and
  static cache data
- API keys, JWTs, passwords, proxy userinfo, OTP/device codes, or bearer tokens

Runtime directories are owner-only (`0700`) and sensitive files are `0600`.
Preserve atomic writes and permission hardening when changing a store. Public
fixtures must use reserved/example values such as `example.test`,
`proxy.example`, `192.0.2.0/24`, `198.51.100.0/24`, and documentation ASNs.

Proxy GET responses and UI state must expose only redacted endpoints and
`has_auth`; never return stored userinfo. Email provider GET responses must
return only whether a secret is configured. Blank secret inputs preserve the
stored value, explicit clear removes it, and connection tests must not mutate
`config.json`.

## Proxy And Email Conventions

- Keep one proxy fixed for the full lifecycle of one account. Do not rotate an
  active account mid-flow.
- Network failures may cool down a proxy; email API, OTP, or domain failures
  must not penalize it. Risk failures use the longer cooldown.
- When a configured panel pool has no healthy enabled proxy, fail clearly. Do
  not silently fall back to legacy files or `config.proxy`.
- Only an explicit upstream domain rejection increments domain failures. Email
  API errors, OTP timeouts, and network failures do not blacklist a domain.
- When a configured provider domain pool is exhausted, fail clearly instead of
  falling back to disabled, blocked, or legacy domains.
- Preserve all supported provider adapters and secret-preserving save/test
  semantics when changing the email UI or config schema. Recommend Outlook-class
  mailboxes and 家宽 exits; do not present custom domain mail as the default.

## Static Cache Rules

The shared cache remains disabled unless `GROK_STATIC_ASSET_CACHE=1`; the panel
sets that variable for jobs it launches, while direct CLI runs remain opt-in.
Cache only eligible GET static resources such as scripts, styles, fonts, and images. Never
cache documents, XHR/fetch, WebSockets, Turnstile/challenge traffic, responses
with private/no-store/no-cache semantics, cookies, or per-account state. Do not
share browser profiles, cookies, or authentication state between accounts.

## Cross-Platform Rules

- `GROK_PYTHON_BIN` may select an external interpreter. Preserve `.venv/bin`
  and `.venv/Scripts` discovery.
- `GROK_USE_XVFB=auto` adds Xvfb only on Linux without `DISPLAY` or
  `WAYLAND_DISPLAY`. Do not add Xvfb on macOS or Windows.
- Windows subprocess output uses a pipe-reader thread rather than
  `selectors.DefaultSelector`, and stop paths terminate the full browser tree.
- Linux containers must expose readable procfs at `/proc`. Process discovery
  fails closed when it cannot safely inspect the process table.
- Stop only exact project-owned orchestration and batch processes. Never add a
  fuzzy global kill pattern.
- During a release-directory switch, `GROK_COMPAT_PROCESS_ROOTS` may list
  explicit previous release roots so the new panel still detects in-flight
  jobs. New jobs must continue to launch from the current project root.

## Pull Request And Release Checklist

- Keep the working tree limited to intended files and preserve unrelated user
  changes.
- Update README, deployment docs, examples, and changelog when a public contract
  changes.
- Run the required checks above and inspect `RELEASE_CHECKLIST.md`.
- Verify anonymous `/api/health` returns 200, anonymous operational endpoints
  return 401 when configured, and authenticated endpoints work.
- Scan the diff and new images for secrets, real hostnames, private endpoints,
  account data, and live proxy credentials.
- Do not synchronize or restart a deployed instance while registration or
  recovery jobs are active.
- Use `UMask=0077`, `PANEL_INCLUDE_TAIL=0`, a strong token, and an exact bind
  address for production service units.
