"""Param for int* and int[2] (used by FIONREAD, socketpair, and similar syscalls)."""

from __future__ import annotations

import ctypes
from typing import TYPE_CHECKING, Any, ClassVar

from strace_macos.lldb_loader import load_lldb_module
from strace_macos.syscalls.args import IntPtrArg, PointerArg, StringArg
from strace_macos.syscalls.definitions import DecodeContext, Param, ParamDirection, StructParamBase

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

    def decode(self, ctx: DecodeContext) -> SyscallArg | None:
        """Decode int* pointer to IntPtrArg.

        Overrides StructParamBase.decode() to return IntPtrArg instead of StructArg.
        """

        # Direction filtering: only decode at appropriate time
        if ctx.at_entry and self.direction != ParamDirection.IN:
            return PointerArg(ctx.raw_value)  # Return as pointer for now
        if not ctx.at_entry and self.direction != ParamDirection.OUT:
            return None  # Already decoded at entry

        # Skip NULL pointers
        if ctx.raw_value == 0:
            return PointerArg(0)

        # Decode the struct
        decoded_fields = self.decode_struct(
            ctx.process, ctx.raw_value, no_abbrev=ctx.tracer.no_abbrev
        )
        if decoded_fields and "value" in decoded_fields:
            value = decoded_fields["value"]
            if isinstance(value, int):
                return IntPtrArg(value)

        return PointerArg(ctx.raw_value)


class IntArrayParam(Param):
    """Parameter decoder for integer arrays (int[], gid_t[], etc.).

    Decodes a fixed-size or variable-size array of integers and returns them as [val1, val2, ...].

    Usage:
        IntArrayParam(count=2)                              # Fixed size: int[2] for socketpair
        IntArrayParam(count_arg_index=0, direction=OUT)     # Variable size: getgroups(ngroups, gid_t[])
    """

    def __init__(
        self,
        count: int | None = None,
        count_arg_index: int | None = None,
        direction: ParamDirection = ParamDirection.OUT,
        element_size: int = 4,
    ) -> None:
        """Initialize IntArrayParam.

        Args:
            count: Fixed number of elements (for socketpair: count=2)
            count_arg_index: Index of argument containing count (for getgroups)
            direction: When to decode (IN/OUT/INOUT)
            element_size: Size of each element in bytes (default 4 for int32/gid_t)
        """
        if count is None and count_arg_index is None:
            msg = "Must specify either count or count_arg_index"
            raise ValueError(msg)
        self.fixed_count = count
        self.count_arg_index = count_arg_index
        self.direction = direction
        self.element_size = element_size

    def decode(self, ctx: DecodeContext) -> SyscallArg | None:
        """Decode integer array to StringArg formatted as [val1, val2, ...]."""
        # Direction filtering
        if ctx.at_entry and self.direction != ParamDirection.IN:
            return PointerArg(ctx.raw_value)
        if not ctx.at_entry and self.direction != ParamDirection.OUT:
            return None

        # Skip NULL pointers
        if ctx.raw_value == 0:
            return PointerArg(0)

        # Determine count
        count = self._get_count(ctx)
        if count is None:
            return PointerArg(ctx.raw_value)

        # Safety limits
        if count <= 0 or count > 1024:
            return PointerArg(ctx.raw_value)

        # Read and parse the array
        values = self._read_array(ctx.process, ctx.raw_value, count)
        if values is None:
            return PointerArg(ctx.raw_value)

        return StringArg(f"[{', '.join(values)}]")

    def _get_count(self, ctx: DecodeContext) -> int | None:
        """Determine the array count from fixed count or argument."""
        if self.fixed_count is not None:
            return self.fixed_count

        if self.count_arg_index is None:
            return None

        if self.count_arg_index >= len(ctx.all_args):
            return None

        count = ctx.all_args[self.count_arg_index]

        # For OUT direction, use return value if it's smaller than requested count
        if not ctx.at_entry and isinstance(ctx.return_value, int) and 0 < ctx.return_value < count:
            return ctx.return_value

        return count

    def _read_array(self, process: Any, address: int, count: int) -> list[str] | None:
        """Read and parse integer array from memory."""
        lldb = load_lldb_module()
        error = lldb.SBError()
        total_size = self.element_size * count
        data = process.ReadMemory(address, total_size, error)

        if error.Fail() or not data or len(data) < total_size:
            return None

        # Parse integers
        values = []
        for i in range(count):
            offset = i * self.element_size
            if offset + self.element_size > len(data):
                break
            val = int.from_bytes(
                data[offset : offset + self.element_size],
                byteorder="little",
                signed=True,
            )
            values.append(str(val))

        return values


class FdPairParam(IntArrayParam):
    """Parameter decoder for int sv[2] used by socketpair().

    Decodes an array of 2 file descriptors and returns them as [fd1, fd2].
    This is an output parameter that's only decoded at syscall exit.
    """

    def __init__(self) -> None:
        """Initialize FdPairParam as a fixed-size array of 2 integers."""
        super().__init__(count=2, direction=ParamDirection.OUT, element_size=4)


__all__ = [
    "FdPairParam",
    "IntArrayParam",
    "IntPtrParam",
]
