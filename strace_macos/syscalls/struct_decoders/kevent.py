"""Decoder for struct kevent on macOS.

From /usr/include/sys/event.h
"""

from __future__ import annotations

import ctypes
from typing import ClassVar

from strace_macos.syscalls.struct_decoders import StructDecoder
from strace_macos.syscalls.symbols.kqueue import (
    decode_ev_flags,
    decode_evfilt,
)


class KeventStruct(ctypes.Structure):
    """ctypes definition for struct kevent on macOS.

    This matches the Darwin kevent structure layout.
    Size varies by architecture (uintptr_t/intptr_t):
    - ARM64: 48 bytes
    - x86_64: 48 bytes
    """

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("ident", ctypes.c_uint64),  # identifier for this event
        ("filter", ctypes.c_int16),  # filter for event
        ("flags", ctypes.c_uint16),  # general flags
        ("fflags", ctypes.c_uint32),  # filter-specific flags
        ("data", ctypes.c_int64),  # filter-specific data
        ("udata", ctypes.c_void_p),  # opaque user data identifier
    ]


class Kevent64Struct(ctypes.Structure):
    """ctypes definition for struct kevent64_s on macOS.

    This is the 64-bit extended kevent structure.
    Total size: 48 bytes
    """

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("ident", ctypes.c_uint64),  # identifier for this event
        ("filter", ctypes.c_int16),  # filter for event
        ("flags", ctypes.c_uint16),  # general flags
        ("fflags", ctypes.c_uint32),  # filter-specific flags
        ("data", ctypes.c_int64),  # filter-specific data
        ("udata", ctypes.c_uint64),  # opaque user data identifier
        ("ext_0", ctypes.c_uint64),  # filter-specific extensions
        ("ext_1", ctypes.c_uint64),  # filter-specific extensions
    ]


class KeventDecoder(StructDecoder):
    """Decoder for struct kevent on macOS.

    Provides symbolic decoding for filter and flags fields.
    """

    struct_type = KeventStruct

    # Custom formatters for specific fields
    field_formatters: ClassVar[dict[str, str]] = {
        "filter": "_decode_filter",
        "flags": "_decode_flags",
    }

    def _decode_filter(self, filter_val: int, *, no_abbrev: bool) -> str:
        """Decode filter field.

        Args:
            filter_val: filter value
            no_abbrev: If True, show raw value

        Returns:
            String like "EVFILT_READ" or "-1"
        """
        if no_abbrev:
            return str(filter_val)
        return decode_evfilt(filter_val)

    def _decode_flags(self, flags: int, *, no_abbrev: bool) -> str:
        """Decode flags field.

        Args:
            flags: flags value
            no_abbrev: If True, show raw hex

        Returns:
            String like "EV_ADD|EV_ENABLE" or "0x5"
        """
        if no_abbrev:
            return hex(flags)
        return decode_ev_flags(flags)


class Kevent64Decoder(StructDecoder):
    """Decoder for struct kevent64_s on macOS.

    Provides symbolic decoding for filter and flags fields.
    """

    struct_type = Kevent64Struct

    # Custom formatters for specific fields
    field_formatters: ClassVar[dict[str, str]] = {
        "filter": "_decode_filter",
        "flags": "_decode_flags",
    }

    def _decode_filter(self, filter_val: int, *, no_abbrev: bool) -> str:
        """Decode filter field.

        Args:
            filter_val: filter value
            no_abbrev: If True, show raw value

        Returns:
            String like "EVFILT_READ" or "-1"
        """
        if no_abbrev:
            return str(filter_val)
        return decode_evfilt(filter_val)

    def _decode_flags(self, flags: int, *, no_abbrev: bool) -> str:
        """Decode flags field.

        Args:
            flags: flags value
            no_abbrev: If True, show raw hex

        Returns:
            String like "EV_ADD|EV_ENABLE" or "0x5"
        """
        if no_abbrev:
            return hex(flags)
        return decode_ev_flags(flags)
