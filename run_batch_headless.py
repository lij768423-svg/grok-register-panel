#!/usr/bin/env python3
from pathlib import Path
import importlib.util
import os
import sys

_ROOT = Path(__file__).resolve().parent
os.chdir(str(_ROOT))
sys.path.insert(0, str(_ROOT))

# 加载根目录 __init__.py → 自动读 .env（不覆盖已有环境变量）
_spec = importlib.util.spec_from_file_location("_project_init", _ROOT / "__init__.py")
if _spec and _spec.loader:
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)

import types
# stub tkinter for headless server
try:
    import tkinter
except ImportError:
    tk = types.ModuleType("tkinter")
    class _N: 
        def __init__(self,*a,**k): pass
        def __getattr__(self,n):
            return lambda *a,**k: None
    tk.Tk=_N; tk.StringVar=_N; tk.IntVar=_N; tk.BooleanVar=_N
    tk.END="end"; tk.DISABLED="disabled"; tk.NORMAL="normal"; tk.LEFT="left"; tk.RIGHT="right"; tk.BOTH="both"; tk.X="x"; tk.Y="y"; tk.W="w"; tk.E="e"; tk.N="n"; tk.S="s"
    ttk_m=types.ModuleType("tkinter.ttk")
    class _T: 
        def __init__(self,*a,**k): pass
        def __getattr__(self,n): return lambda *a,**k: None
    for name in ("Frame","Label","Button","Entry","Combobox","Spinbox","Checkbutton","Notebook","Style","Scrollbar","Treeview"):
        setattr(ttk_m, name, _T)
    sc=types.ModuleType("tkinter.scrolledtext")
    sc.ScrolledText=_T
    mb=types.ModuleType("tkinter.messagebox")
    mb.showinfo=mb.showerror=mb.showwarning=mb.askyesno=lambda *a,**k: None
    sys.modules["tkinter"]=tk
    sys.modules["tkinter.ttk"]=ttk_m
    sys.modules["tkinter.scrolledtext"]=sc
    sys.modules["tkinter.messagebox"]=mb

for k in ("http_proxy","https_proxy","HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","all_proxy"):
    os.environ.pop(k, None)

import json, time
from pathlib import Path
import connectivity
import grok_register_ttk as app
connectivity.has_blocking_xai_failure = lambda r: False
count=int(sys.argv[1]) if len(sys.argv)>1 else 9
workers=int(sys.argv[2]) if len(sys.argv)>2 else 3
workers=max(1,min(workers,24,count))
cfg=json.loads(Path("config.json").read_text())
cfg["register_count"]=count
cfg["register_workers"]=workers
Path("config.json").write_text(json.dumps(cfg,ensure_ascii=False,indent=2)+"\n")
print(f"[env] DISPLAY={os.environ.get('DISPLAY')!r} time={time.strftime('%F %T')}", flush=True)
app.load_config()
app._wire_runtime_modules()
def _rp(u):
    s=str(u or "")
    if "://" in s and "@" in s.split("://",1)[-1]:
        sch,rest=s.split("://",1); cred,host=rest.rsplit("@",1); return f"{sch}://***@{host}"
    return s
print(f"[batch] count={count} workers={workers} proxy={_rp(app.config.get('proxy'))}", flush=True)
app.run_registration_cli(count)
print("[batch] finished", flush=True)
