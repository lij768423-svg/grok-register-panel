# Changelog

## Unreleased

## 0.4.1 - 2026-08-11

### Fixed

- Fix Windows state, progress, proxy, email, panel, orchestrator, and recovery file writes when `os.fchmod` is unavailable; use `msvcrt` byte-range locks for cross-process state protection.
- Add `GROK_HEADLESS` / `GROK_HEADED` controls and software-rendering preferences for Windows sessions where headed Camoufox GPU processes fail.
- Preserve configured virtual-environment Python symlink paths so panel-launched jobs keep their installed dependencies.
- Ship `tzdata` in both direct and locked dependency manifests for Windows Beijing-time support.

## 0.4.0 - 2026-08-11

### Added

- Add post-registration sign-in recovery so workers can rebuild an SSO session with the account credentials when the normal redirect loses the cookie.
- Add bounded Cloudflare address-collision retries and a configurable random-subdomain mode for wildcard mail routing.
- Add per-batch HTTP/HTTPS proxy byte metering with authenticated upstream forwarding and a live upload/download KPI in the panel.
- Add Windows-safe supervisor pipe streaming, recursive Camoufox process-tree shutdown, and user-local browser profiles.

### Changed

- Display panel, proxy, blacklist, and worker timestamps in Beijing time regardless of the server timezone.
- Keep up to 80 recent success/failure records and paginate them in the panel while refreshing full statistics every 30 seconds.
- Enable the guarded static-asset cache for panel-launched batches and reduce browser, proxy-rotation, slot, and supervisor retry defaults.
- Stop the batch and orchestrator without retrying when the xAI registration-page precheck fails.

### Fixed

- Preserve BFS `unknown` handling and `bfs_skip_cpa` behavior instead of treating undecodable tokens as clean.
- Redact Cloudflare fallback errors, avoid retrying unrelated HTTP 400 responses, and fall back to fixed UTC+8 when system tzdata is unavailable.
- Remove the narrow-layout horizontal overflow in the panel's proxy and email views.
- Bound Windows proxy exit-IP probes by a total timeout and reject malformed or stale cached IP candidates.

## 0.3.0 - 2026-08-09

### Added

- Add a managed external proxy pool with single/bulk HTTP proxy import, enable/disable controls, health tests, cooldown state, and panel APIs.
- Add configurable email providers, including MoeMail, plus an authenticated provider editor and connection test in the panel.
- Add a managed email-domain pool with rotation rules, failure thresholds, reset controls, and worker integration.
- Add **JWT `bfs` claim detection** to registration and OAuth output. Flagged accounts are recorded in `accounts/sso_bfs_flagged.txt`, and CPA records receive `bfs` metadata.
- Add the panel **BFS 检测** card, `/api/bfs` endpoints, `scripts/check_bfs.py`, and the `bfs_check`, `bfs_skip_cpa`, and `bfs_disable_cpa` settings.
- Add an opt-in shared browser static-asset cache for scripts, stylesheets, fonts, and public images, with size limits, TTL handling, and private-response safeguards.
- Add a self-updating GitHub Star History chart to the project documentation.

### Changed

- Supervise headless batches and atomically persist completed slots so Playwright/Camoufox driver crashes or stalls resume only the remaining work.
- Make process discovery and batch launch platform-aware with `psutil`, Linux auto-Xvfb, macOS direct launch, Windows virtualenv paths, and actionable missing-procfs errors.
- Support external runtime roots while keeping process control scoped to the configured project.
- Move GitHub Actions to Node.js 24-compatible action versions and expand release checks for proxy, email, BFS, cache, platform, and supervisor behavior.
- Document deployment guidance, the LINUX DO community link, and the related Grok2API egress project.

### Fixed

- Fix BFS unknown-token handling, stale metadata precedence, merged auth scanning, CLI config loading, and configured relative/absolute auth-directory resolution.
- Detect buffered Playwright crash markers immediately instead of waiting for the supervisor idle timeout.
- Avoid false Cloudflare email preflight failures when `/admin/new_address` uses `x-admin-auth` but `/api/domains` expects mailbox authentication.
- Preserve full success statistics and per-day jsonl results across the panel's two-second status polling.

## 0.2.0 - 2026-07-30

- Redesign the live panel with responsive light and dark themes.
- Add a dedicated usage and troubleshooting view.
- Add pending SSO and account-file recovery with success dequeue.
- Move learned ASN rules from Python source into locked JSON state.
- Scope process discovery and termination to one project root.
- Require monitor authentication for operational read and write APIs.
- Add security headers, bounded request bodies, and redacted log output.
- Create runtime credentials, account data, logs, state, and PID files owner-only.
- Add release tests, CI, a systemd service template, and deployment checks.
