"""Owner-only file helpers for runtime state and credential material."""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None

try:
    import msvcrt
except ImportError:  # pragma: no cover - POSIX
    msvcrt = None


PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
_THREAD_LOCKS: dict[str, threading.RLock] = {}
_THREAD_LOCKS_GUARD = threading.Lock()
_LOCK_CHUNK = 1


def best_effort_fchmod(fd: int, mode: int) -> None:
    """Best-effort fchmod; missing on Windows."""
    fn = getattr(os, "fchmod", None)
    if fn is None:
        return
    try:
        fn(fd, mode)
    except OSError:
        pass


def ensure_private_dir(path: str | os.PathLike[str]) -> Path:
    target = Path(path)
    target.mkdir(parents=True, exist_ok=True, mode=PRIVATE_DIR_MODE)
    try:
        target.chmod(PRIVATE_DIR_MODE)
    except OSError:
        pass
    return target


def ensure_private_file(path: str | os.PathLike[str]) -> Path:
    target = Path(path)
    if target.exists():
        try:
            target.chmod(PRIVATE_FILE_MODE)
        except OSError:
            pass
    return target


def append_private_text(
    path: str | os.PathLike[str],
    text: str,
    *,
    encoding: str = "utf-8",
) -> Path:
    target = Path(path)
    ensure_private_dir(target.parent)
    fd = os.open(
        target,
        os.O_WRONLY | os.O_CREAT | os.O_APPEND,
        PRIVATE_FILE_MODE,
    )
    try:
        best_effort_fchmod(fd, PRIVATE_FILE_MODE)
        with os.fdopen(fd, "a", encoding=encoding, newline="\n") as handle:
            fd = -1
            handle.write(text)
            handle.flush()
    finally:
        if fd >= 0:
            os.close(fd)
    return target


def create_private_text(
    path: str | os.PathLike[str],
    text: str = "",
    *,
    encoding: str = "utf-8",
) -> Path:
    target = Path(path)
    ensure_private_dir(target.parent)
    fd = os.open(
        target,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        PRIVATE_FILE_MODE,
    )
    try:
        best_effort_fchmod(fd, PRIVATE_FILE_MODE)
        with os.fdopen(fd, "w", encoding=encoding, newline="\n") as handle:
            fd = -1
            handle.write(text)
    finally:
        if fd >= 0:
            os.close(fd)
    return target


def atomic_write_text(
    path: str | os.PathLike[str],
    text: str,
    *,
    encoding: str = "utf-8",
) -> Path:
    target = Path(path)
    ensure_private_dir(target.parent)
    fd, temp_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=str(target.parent),
        text=True,
    )
    temp_path = Path(temp_name)
    try:
        best_effort_fchmod(fd, PRIVATE_FILE_MODE)
        with os.fdopen(fd, "w", encoding=encoding, newline="\n") as handle:
            fd = -1
            handle.write(text)
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:
                pass
        os.replace(temp_path, target)
        ensure_private_file(target)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            if temp_path.exists():
                temp_path.unlink()
        except OSError:
            pass
    return target


def atomic_write_json(path: str | os.PathLike[str], data: object) -> Path:
    return atomic_write_text(
        path,
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
    )


def _thread_lock_for(path: Path) -> threading.RLock:
    key = str(path.resolve())
    with _THREAD_LOCKS_GUARD:
        return _THREAD_LOCKS.setdefault(key, threading.RLock())


def _acquire_os_lock(fd: int) -> None:
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_EX)
        return
    if msvcrt is not None:
        # Ensure the lock region exists; msvcrt locks by byte range.
        try:
            size = os.fstat(fd).st_size
        except OSError:
            size = 0
        if size < _LOCK_CHUNK:
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, b"\0" * _LOCK_CHUNK)
        os.lseek(fd, 0, os.SEEK_SET)
        while True:
            try:
                msvcrt.locking(fd, msvcrt.LK_LOCK, _LOCK_CHUNK)
                return
            except OSError:
                # LK_LOCK retries internally; still guard against transient errors.
                time.sleep(0.05)


def _release_os_lock(fd: int) -> None:
    if fcntl is not None:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        return
    if msvcrt is not None:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, _LOCK_CHUNK)
        except OSError:
            pass


@contextmanager
def exclusive_file_lock(path: str | os.PathLike[str]) -> Iterator[None]:
    lock_path = Path(path)
    ensure_private_dir(lock_path.parent)
    thread_lock = _thread_lock_for(lock_path)
    with thread_lock:
        fd = os.open(
            lock_path,
            os.O_RDWR | os.O_CREAT,
            PRIVATE_FILE_MODE,
        )
        try:
            best_effort_fchmod(fd, PRIVATE_FILE_MODE)
            _acquire_os_lock(fd)
            yield
        finally:
            _release_os_lock(fd)
            os.close(fd)
