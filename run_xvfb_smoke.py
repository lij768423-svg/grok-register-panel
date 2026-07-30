#!/usr/bin/env python3
from __future__ import annotations
import importlib.util
import os, sys, time, json
from pathlib import Path
ROOT = Path(__file__).resolve().parent
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))
_spec = importlib.util.spec_from_file_location("_project_init", ROOT / "__init__.py")
if _spec and _spec.loader:
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
for k in ("http_proxy","https_proxy","HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","all_proxy"):
    os.environ.pop(k, None)
print(f"[env] DISPLAY={os.environ.get('DISPLAY')!r}", flush=True)
print(f"[env] time={time.strftime('%F %T')}", flush=True)
import connectivity
import grok_register_ttk as app
connectivity.has_blocking_xai_failure = lambda results: False
count = int(sys.argv[1]) if len(sys.argv) > 1 else 1
workers = int(sys.argv[2]) if len(sys.argv) > 2 else int(os.environ.get("REGISTER_WORKERS", "2") or 2)
workers = max(1, min(workers, 8, count))
cfg_path = ROOT / "config.json"
cfg = json.loads(cfg_path.read_text())
cfg["register_count"] = count
cfg["register_workers"] = workers
cfg_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n")
app.load_config()
app._wire_runtime_modules()
print(f"[smoke] count={count} workers={workers} proxy={app.config.get('proxy')} cpa={app.config.get('cpa_auth_dir')}", flush=True)
app.run_registration_cli(count)
print("[smoke] finished", flush=True)
