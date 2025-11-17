"""Dynamic LLDB module loading."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from strace_macos.exceptions import LLDBLoadError

if TYPE_CHECKING:
    from types import ModuleType


def _iter_lldb_pythonpaths() -> list[str]:
    """Iterate possible LLDB Python paths in priority order.

    Returns:
        List of paths to try for importing LLDB
    """
    paths: list[str] = []

    # Try to get lldb-python path from lldb command
    try:
        result = subprocess.run(
            ["xcrun", "lldb", "-P"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            lldb_path = result.stdout.strip()
            if lldb_path:
                paths.append(lldb_path)
    except FileNotFoundError:
        pass

    # Common macOS LLDB locations
    common_paths = [
        "/Library/Developer/CommandLineTools/Library/PrivateFrameworks/LLDB.framework/Resources/Python",
        "/Applications/Xcode.app/Contents/SharedFrameworks/LLDB.framework/Resources/Python",
    ]

    for path_str in common_paths:
        path = Path(path_str)
        if path.exists():
            paths.append(str(path))

    return paths


def load_lldb_module() -> ModuleType:
    """Load the LLDB Python module, trying multiple methods.

    Returns:
        The imported lldb module

    Raises:
        RuntimeError: If LLDB module cannot be loaded
    """
    # Try importing directly first
    try:
        import lldb  # noqa: PLC0415
    except ImportError:
        pass
    else:
        return lldb  # type: ignore[no-any-return]

    # Try each path in priority order
    for lldb_path in _iter_lldb_pythonpaths():
        if lldb_path not in sys.path:
            sys.path.insert(0, lldb_path)
        try:
            import lldb  # noqa: PLC0415
        except ImportError:
            continue
        else:
            return lldb  # type: ignore[no-any-return]

    # Failed to load LLDB
    msg = (
        "Failed to load LLDB Python module.\n"
        "Make sure you're running with system Python (/usr/bin/python3) "
        "and have Xcode Command Line Tools installed.\n"
        "\nTo install Xcode Command Line Tools:\n"
        "  xcode-select --install"
    )
    raise LLDBLoadError(msg)
