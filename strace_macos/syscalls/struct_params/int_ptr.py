"""Param for int* (used by FIONREAD and similar ioctls)."""

from __future__ import annotations

import ctypes
from typing import TYPE_CHECKING, Any, ClassVar

from strace_macos.syscalls.args import IntPtrArg, PointerArg
from strace_macos.syscalls.definitions import ParamDirection, StructParamBase

if TYPE_CHECKING:
    from strace_macos.syscalls.args import SyscallArg


class IntPtr(ctypes.Structure):
    """Wrapper for int* pointer."""

    _fields_: ClassVar = [
        ("value", ctypes.c_int),
    ]


class IntPtrParam(StructParamBase):
    """Parameter decoder for int* pointer (reads single int value).

    This is a special case that returns IntPtrArg instead of StructArg
    to format the output as [value] instead of {value=N}.

    Used for ioctl commands like FIONREAD that take an int* output parameter.

    Usage:
        IntPtrParam(ParamDirection.OUT)  # For ioctl FIONREAD, etc.
    """

    struct_type = IntPtr

    def __init__(self, direction: ParamDirection) -> None:
        """Initialize IntPtrParam with direction."""
        self.direction = direction

    def decode(
        self,
        tracer: Any,
        process: Any,
        raw_value: int,
        all_args: list[int],  # noqa: ARG002
        *,
        at_entry: bool,
    ) -> SyscallArg | None:
        """Decode int* pointer to IntPtrArg.

        Overrides StructParamBase.decode() to return IntPtrArg instead of StructArg.
        """

        # Direction filtering: only decode at appropriate time
        if at_entry and self.direction != ParamDirection.IN:
            return PointerArg(raw_value)  # Return as pointer for now
        if not at_entry and self.direction != ParamDirection.OUT:
            return None  # Already decoded at entry

        # Skip NULL pointers
        if raw_value == 0:
            return PointerArg(0)

        # Decode the struct
        decoded_fields = self.decode_struct(process, raw_value, no_abbrev=tracer.no_abbrev)
        if decoded_fields and "value" in decoded_fields:
            value = decoded_fields["value"]
            if isinstance(value, int):
                return IntPtrArg(value)

        return PointerArg(raw_value)


__all__ = [
    "IntPtrParam",
]
