# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from datetime import timedelta
from pathlib import Path
from zoneinfo import ZoneInfoNotFoundError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from runtime_platform import (
    RuntimePlatformError,
    _load_beijing_timezone,
    batch_launch_command,
    batch_runtime_error,
    popen_group_kwargs,
    runtime_python,
)


def test_beijing_timezone_falls_back_without_system_tzdata():
    def missing_timezone(_name):
        raise ZoneInfoNotFoundError("missing test timezone")

    fallback = _load_beijing_timezone(missing_timezone)
    assert fallback.utcoffset(None) == timedelta(hours=8)
    assert str(fallback) == "Asia/Shanghai"


def _touch(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch()
    return path


def test_runtime_python_uses_platform_virtualenv_layout():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        posix_python = _touch(root / ".venv" / "bin" / "python")
        windows_python = _touch(root / ".venv" / "Scripts" / "python.exe")
        assert runtime_python(root, platform_name="linux") == posix_python.resolve()
        assert runtime_python(root, platform_name="darwin") == posix_python.resolve()
        assert runtime_python(root, platform_name="win32") == windows_python.resolve()


def test_runtime_python_falls_back_to_active_interpreter():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        windows_python = _touch(root / ".venv" / "Scripts" / "python.exe")
        active_python = _touch(root / "shared-venv" / "bin" / "python")
        assert windows_python.is_file()
        assert runtime_python(
            root,
            platform_name="linux",
            environ={},
            current_executable=active_python,
        ) == active_python


def test_runtime_python_supports_explicit_override():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        configured = _touch(root / "shared" / "python")
        assert runtime_python(
            root,
            platform_name="linux",
            environ={"GROK_PYTHON_BIN": "shared/python"},
            current_executable=root / "unused" / "python",
        ) == configured.resolve()


def test_runtime_python_preserves_virtualenv_symlink_override():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        base_python = _touch(root / "base" / "python")
        venv_python = root / "shared-venv" / "bin" / "python"
        venv_python.parent.mkdir(parents=True)
        venv_python.symlink_to(base_python)

        selected = runtime_python(
            root,
            platform_name="linux",
            environ={"GROK_PYTHON_BIN": str(venv_python)},
            current_executable=root / "unused" / "python",
        )

        assert selected == venv_python
        assert selected != base_python.resolve()


def test_linux_headless_launch_uses_xvfb_automatically():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        python = _touch(root / ".venv" / "bin" / "python")
        command = batch_launch_command(
            root,
            5,
            2,
            platform_name="linux",
            environ={},
            which=lambda name: "/usr/bin/xvfb-run" if name == "xvfb-run" else None,
        )
        assert command[:5] == [
            "/usr/bin/xvfb-run",
            "-a",
            "-s",
            "-screen 0 1920x1080x24",
            str(python),
        ]
        assert command[-2:] == ["5", "2"]


def test_linux_display_and_disabled_mode_launch_directly():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        python = _touch(root / ".venv" / "bin" / "python")
        with_display = batch_launch_command(
            root,
            3,
            1,
            platform_name="linux",
            environ={"DISPLAY": ":0"},
            which=lambda _name: None,
        )
        explicitly_disabled = batch_launch_command(
            root,
            3,
            1,
            platform_name="linux",
            environ={"GROK_USE_XVFB": "0"},
            which=lambda _name: None,
        )
        assert with_display[0] == str(python)
        assert explicitly_disabled[0] == str(python)


def test_missing_xvfb_returns_actionable_error():
    error = batch_runtime_error(
        platform_name="linux",
        environ={},
        which=lambda _name: None,
    )
    assert error and "xvfb-run" in error and "GROK_USE_XVFB=0" in error


def test_macos_and_windows_launch_without_xvfb():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        mac_python = _touch(root / ".venv" / "bin" / "python")
        windows_python = _touch(root / ".venv" / "Scripts" / "python.exe")
        mac_command = batch_launch_command(
            root,
            2,
            1,
            platform_name="darwin",
            environ={},
            which=lambda _name: None,
        )
        windows_command = batch_launch_command(
            root,
            2,
            1,
            platform_name="win32",
            environ={},
            which=lambda _name: None,
        )
        assert mac_command[0] == str(mac_python)
        assert windows_command[0] == str(windows_python)
        assert "xvfb-run" not in mac_command
        assert "xvfb-run" not in windows_command


def test_xvfb_force_is_rejected_off_linux():
    error = batch_runtime_error(
        platform_name="darwin",
        environ={"GROK_USE_XVFB": "1"},
        which=lambda _name: "/usr/bin/xvfb-run",
    )
    assert error == "GROK_USE_XVFB=1 仅支持 Linux"


def test_invalid_xvfb_mode_is_rejected():
    try:
        batch_launch_command(
            ROOT,
            1,
            1,
            platform_name="linux",
            environ={"GROK_USE_XVFB": "sometimes"},
        )
    except RuntimePlatformError as exc:
        assert "auto、1 或 0" in str(exc)
    else:
        raise AssertionError("invalid GROK_USE_XVFB must be rejected")


def test_process_group_settings_follow_platform():
    assert popen_group_kwargs(platform_name="linux") == {"start_new_session": True}
    assert popen_group_kwargs(platform_name="darwin") == {"start_new_session": True}
    assert popen_group_kwargs(platform_name="win32") == {
        "creationflags": int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
    }


def test_recovery_module_can_run_from_webui_directory():
    env = {**os.environ, "PYTHONPATH": ""}
    result = subprocess.run(
        [sys.executable, str(ROOT / "webui" / "recovery_ops.py")],
        cwd=str(ROOT / "webui"),
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr


if __name__ == "__main__":
    test_beijing_timezone_falls_back_without_system_tzdata()
    test_runtime_python_uses_platform_virtualenv_layout()
    test_runtime_python_falls_back_to_active_interpreter()
    test_runtime_python_supports_explicit_override()
    test_runtime_python_preserves_virtualenv_symlink_override()
    test_linux_headless_launch_uses_xvfb_automatically()
    test_linux_display_and_disabled_mode_launch_directly()
    test_missing_xvfb_returns_actionable_error()
    test_macos_and_windows_launch_without_xvfb()
    test_xvfb_force_is_rejected_off_linux()
    test_invalid_xvfb_mode_is_rejected()
    test_process_group_settings_follow_platform()
    test_recovery_module_can_run_from_webui_directory()
    print("OK runtime platform")
