"""Struct-based parameter decoder for struct winsize (terminal window size)."""

from __future__ import annotations

import ctypes
from typing import ClassVar

from strace_macos.syscalls.definitions import ParamDirection, StructParamBase


class Winsize(ctypes.Structure):
    """Terminal window size structure (struct winsize)."""

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("ws_row", ctypes.c_ushort),  # Rows, in characters
        ("ws_col", ctypes.c_ushort),  # Columns, in characters
        ("ws_xpixel", ctypes.c_ushort),  # Horizontal size, pixels
        ("ws_ypixel", ctypes.c_ushort),  # Vertical size, pixels
    ]


class WinsizeParam(StructParamBase):
    """Parameter decoder for struct winsize.

    Decodes terminal window size including rows, columns, and pixel dimensions.
    No custom formatters needed - all fields are simple unsigned shorts.

    Usage:
        WinsizeParam(ParamDirection.IN)   # For TIOCSWINSZ (set window size)
        WinsizeParam(ParamDirection.OUT)  # For TIOCGWINSZ (get window size)
    """

    struct_type = Winsize

    def __init__(self, direction: ParamDirection) -> None:
        """Initialize WinsizeParam with direction."""
        self.direction = direction


__all__ = [
    "WinsizeParam",
]
