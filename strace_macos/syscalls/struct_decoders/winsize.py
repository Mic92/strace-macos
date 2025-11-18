"""Decoder for struct winsize (terminal window size)."""

from __future__ import annotations

import ctypes
from typing import TYPE_CHECKING, ClassVar

from strace_macos.lldb_loader import load_lldb_module
from strace_macos.syscalls.struct_decoders import StructDecoder

if TYPE_CHECKING:
    import lldb


class Winsize(ctypes.Structure):
    """Terminal window size structure (struct winsize)."""

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("ws_row", ctypes.c_ushort),  # Rows, in characters
        ("ws_col", ctypes.c_ushort),  # Columns, in characters
        ("ws_xpixel", ctypes.c_ushort),  # Horizontal size, pixels
        ("ws_ypixel", ctypes.c_ushort),  # Vertical size, pixels
    ]


class WinsizeDecoder(StructDecoder):
    """Decoder for struct winsize."""

    struct_type = Winsize

    def decode(
        self, process: lldb.SBProcess, address: int, *, no_abbrev: bool = False
    ) -> dict[str, str | int | list] | None:
        """Decode a struct winsize from process memory.

        Args:
            process: LLDB process to read memory from
            address: Memory address of the winsize structure
            no_abbrev: If True, disable symbolic decoding (unused)

        Returns:
            Dictionary with ws_row, ws_col, ws_xpixel, ws_ypixel, or None if failed
        """
        _ = no_abbrev  # Unused

        if address == 0:
            return None

        lldb = load_lldb_module()
        error = lldb.SBError()
        size = ctypes.sizeof(Winsize)

        data = process.ReadMemory(address, size, error)
        if error.Fail() or not data:
            return None

        try:
            winsize = Winsize.from_buffer_copy(data)
        except (ValueError, TypeError):
            return None
        else:
            return {
                "ws_row": winsize.ws_row,
                "ws_col": winsize.ws_col,
                "ws_xpixel": winsize.ws_xpixel,
                "ws_ypixel": winsize.ws_ypixel,
            }
