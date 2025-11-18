"""Decoder for int* (used by FIONREAD and similar ioctls)."""

from __future__ import annotations

import ctypes
from typing import TYPE_CHECKING, ClassVar

from strace_macos.lldb_loader import load_lldb_module
from strace_macos.syscalls.struct_decoders import StructDecoder

if TYPE_CHECKING:
    import lldb


class IntPtr(ctypes.Structure):
    """Wrapper for int* pointer."""

    _fields_: ClassVar = [
        ("value", ctypes.c_int),
    ]


class IntPtrDecoder(StructDecoder):
    """Decoder for int* pointer (reads single int value)."""

    struct_type = IntPtr

    def decode(
        self, process: lldb.SBProcess, address: int, *, no_abbrev: bool = False
    ) -> dict[str, str | int | list] | None:
        """Decode an int* from process memory.

        Args:
            process: LLDB process to read memory from
            address: Memory address of the int pointer
            no_abbrev: If True, disable symbolic decoding (unused)

        Returns:
            Dictionary with "value" key, or None if failed
        """
        _ = no_abbrev  # Unused

        if address == 0:
            return None

        lldb = load_lldb_module()
        error = lldb.SBError()
        size = ctypes.sizeof(IntPtr)

        data = process.ReadMemory(address, size, error)
        if error.Fail() or not data:
            return None

        try:
            int_val = IntPtr.from_buffer_copy(data)
        except (ValueError, TypeError):
            return None
        else:
            # Return as a list with single value for consistency with strace format [N]
            return {"value": int_val.value}
