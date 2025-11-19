"""Struct sigevent parameter decoder.

This module contains the SigeventParam class for decoding syscall arguments that
point to struct sigevent (signal event notification).
"""

from __future__ import annotations

import ctypes
from typing import ClassVar

from strace_macos.syscalls.definitions import ParamDirection, StructParamBase

# Signal event notification types
SIGEV_NOTIFY: dict[int, str] = {
    0: "SIGEV_NONE",
    1: "SIGEV_SIGNAL",
    3: "SIGEV_THREAD",
}


class SigeventStruct(ctypes.Structure):
    """ctypes definition for struct sigevent on macOS.

    This matches the Darwin sigevent structure layout.
    Note: This is a simplified version - the actual structure has
    function pointers and pthread_attr_t which we skip for decoding.
    """

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("sigev_notify", ctypes.c_int),  # Notification type
        ("sigev_signo", ctypes.c_int),  # Signal number
        ("sigev_value_int", ctypes.c_int),  # Union sigval (as int)
        ("sigev_value_ptr", ctypes.c_void_p),  # Union sigval (as ptr) - overlaps
        ("sigev_notify_function", ctypes.c_void_p),  # Function pointer
        ("sigev_notify_attributes", ctypes.c_void_p),  # pthread_attr_t*
    ]


class SigeventParam(StructParamBase):
    """Parameter decoder for struct sigevent on macOS.

    Decodes signal event notification structure showing notification type
    and signal number if applicable.

    Usage:
        SigeventParam(ParamDirection.IN)   # For lio_listio
    """

    struct_type = SigeventStruct

    # Exclude function pointer and attributes (not very useful to display)
    excluded_fields: ClassVar[set[str]] = {
        "sigev_notify_function",
        "sigev_notify_attributes",
        "sigev_value_int",  # Show ptr version instead
    }

    # Custom formatters for specific fields
    field_formatters: ClassVar[dict[str, str]] = {
        "sigev_notify": "_decode_notify",
    }

    def __init__(self, direction: ParamDirection) -> None:
        """Initialize SigeventParam with direction."""
        self.direction = direction

    def _decode_notify(self, notify: int, *, no_abbrev: bool) -> str:
        """Decode sigev_notify into symbolic constant.

        Args:
            notify: sigev_notify value
            no_abbrev: If True, show raw value instead of symbolic

        Returns:
            String like "SIGEV_SIGNAL" or raw value
        """
        if no_abbrev:
            return str(notify)

        return SIGEV_NOTIFY.get(notify, str(notify))


__all__ = [
    "SigeventParam",
]
