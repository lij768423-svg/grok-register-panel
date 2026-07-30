# -*- coding: utf-8 -*-
"""项目根包初始化：自动加载根目录 `.env` 到 os.environ。

说明：
- 不覆盖进程里已经存在的环境变量（export / 系统变量优先）
- 支持 KEY=VAL、export KEY=VAL、# 注释、简单引号
- 入口脚本通过 importlib 加载本文件即可，无需每个业务模块各自写 load 逻辑
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional, Union

_ROOT = Path(__file__).resolve().parent
_LOADED = False

_LINE_RE = re.compile(
    r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$"
)


def _strip_value(raw: str) -> str:
    value = raw.strip()
    if not value:
        return ""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    # 行内注释：KEY=val # comment（无引号时）
    if " #" in value:
        value = value.split(" #", 1)[0].rstrip()
    elif "\t#" in value:
        value = value.split("\t#", 1)[0].rstrip()
    return value


def load_dotenv(
    dotenv_path: Optional[Union[str, Path]] = None,
    *,
    override: bool = False,
) -> bool:
    """读取 `.env` 写入 os.environ。成功读取返回 True（文件不存在返回 False）。"""
    global _LOADED
    path = Path(dotenv_path) if dotenv_path else (_ROOT / ".env")
    if not path.is_file():
        return False
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        m = _LINE_RE.match(line)
        if not m:
            continue
        key, raw_val = m.group(1), m.group(2)
        if not override and key in os.environ:
            continue
        os.environ[key] = _strip_value(raw_val)

    _LOADED = True
    return True


def ensure_env(*, override: bool = False) -> bool:
    """幂等加载；供入口脚本显式调用。"""
    if _LOADED and not override:
        return True
    return load_dotenv(override=override)


# 作为包被 import 时自动加载
load_dotenv()
