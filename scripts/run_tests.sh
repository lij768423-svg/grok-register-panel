#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PYTHON_BIN="${PYTHON_BIN:-python3}"

tests=(
  tests/test_security_utils.py
  tests/test_extract_code.py
  tests/test_moemail.py
  tests/test_cloudflare_provider.py
  tests/test_runtime_security.py
  tests/test_runtime_platform.py
  tests/test_windows_runtime.py
  tests/test_sso_recovery.py
  tests/test_registration_risk_gate.py
  tests/test_bfs_detect.py
  tests/test_bfs_ops.py
  tests/test_bfs_worker_integration.py
  tests/test_static_asset_cache.py
  tests/test_batch_traffic.py
  tests/test_retry_policy.py
  tests/test_monitor_http.py
  tests/test_proxy_store.py
  tests/test_proxy_worker_integration.py
  tests/test_email_provider_store.py
  tests/test_email_domain_store.py
  tests/test_email_domain_worker_integration.py
  tests/test_star_history.py
  tests/test_panel_structure.py
  tests/test_no_live_hardcode.py
  tests/test_batch_chdir_import.py
  tests/test_batch_supervisor.py
  tests/test_orchestrator_policy.py
)

for test_file in "${tests[@]}"; do
  "$PYTHON_BIN" "$test_file"
done

"$PYTHON_BIN" -m compileall -q \
  secure_files.py \
  webui \
  email_providers \
  browser_session.py \
  connectivity.py \
  grok_register_ttk.py \
  register_flow.py \
  runtime_platform.py \
  batch_supervisor.py \
  run_batch_headless.py \
  run_until_100.py \
  sso_to_auth_json.py \
  scripts/check_bfs.py \
  webui/bfs_ops.py \
  static_asset_cache.py \
  batch_traffic.py \
  retry_policy.py \
  run_batch_headless_static_cache.py \
  run_until_100_static_cache.py

bash -n scripts/*.sh
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git diff --check
else
  echo "SKIP git diff --check (not a Git work tree)"
fi
echo "OK release tests"
