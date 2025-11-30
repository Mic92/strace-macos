"""Fork interposition library for following child processes."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

# Environment variable that signals children to stop
CHILD_STOP_ENV = "STRACE_MACOS_CHILD_STOP"

# Cached path to compiled library
_dylib_path: Path | None = None


def get_interpose_source() -> Path:
    """Get path to the interposition library source."""
    return Path(__file__).parent / "fork_interpose.c"


def get_dylib_path() -> Path:
    """Get path to compiled interposition library, building if needed."""
    global _dylib_path  # noqa: PLW0603

    if _dylib_path is not None and _dylib_path.exists():
        return _dylib_path

    # Build the library
    source = get_interpose_source()
    if not source.exists():
        msg = f"Interposition library source not found: {source}"
        raise FileNotFoundError(msg)

    # Create in a temp directory that persists for the session
    cache_dir = Path(tempfile.gettempdir()) / "strace_macos_cache"
    cache_dir.mkdir(exist_ok=True)

    dylib = cache_dir / "libfork_interpose.dylib"

    # Check if source is newer than dylib
    if dylib.exists() and dylib.stat().st_mtime >= source.stat().st_mtime:
        _dylib_path = dylib
        return dylib

    # Compile the library
    cc = os.environ.get("CC", "clang")
    cmd = [
        cc,
        "-dynamiclib",
        "-arch", "arm64",
        "-arch", "x86_64",
        "-o", str(dylib),
        str(source),
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        msg = f"Failed to compile interposition library: {result.stderr}"
        raise RuntimeError(msg)

    _dylib_path = dylib
    return dylib


def get_child_stop_env() -> dict[str, str]:
    """Get environment variables to set for enabling child stop."""
    dylib = get_dylib_path()
    return {
        "DYLD_INSERT_LIBRARIES": str(dylib),
        CHILD_STOP_ENV: "1",
    }
