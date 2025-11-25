"""Struct parameter decoders for signal-related structures."""

from __future__ import annotations

import ctypes
from typing import TYPE_CHECKING, ClassVar

from strace_macos.syscalls.args import PointerArg, StringArg
from strace_macos.syscalls.definitions import DecodeContext, ParamDirection, StructParamBase
from strace_macos.syscalls.symbols.signal import SA_FLAGS, SIGNAL_NUMBERS, SS_FLAGS

if TYPE_CHECKING:
    from strace_macos.syscalls.args import SyscallArg


class SigactionStruct(ctypes.Structure):
    """ctypes definition for struct sigaction on macOS.

    struct sigaction {
        union {
            void (*sa_handler)(int);
            void (*sa_sigaction)(int, siginfo_t *, void *);
        };
        sigset_t sa_mask;      // 32-bit bitmask on macOS (4 bytes)
        int sa_flags;
    };

    Note: We simplify the union as a single pointer since we only care about
    whether it's SIG_DFL (0), SIG_IGN (1), or a custom handler.
    """

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("sa_handler", ctypes.c_void_p),  # Function pointer (8 bytes on 64-bit)
        ("sa_mask", ctypes.c_uint32),  # sigset_t is 32-bit on macOS
        ("sa_flags", ctypes.c_int),  # int (4 bytes)
    ]


class SigactionParam(StructParamBase):
    """Parameter decoder for struct sigaction.

    Usage:
        SigactionParam(ParamDirection.OUT)  # old_action (output)
        SigactionParam(ParamDirection.IN)   # new_action (input)
    """

    struct_type = SigactionStruct
    excluded_fields: ClassVar[set[str]] = set()
    field_formatters: ClassVar[dict[str, str]] = {
        "sa_handler": "_decode_handler",
        "sa_mask": "_decode_sigset",
        "sa_flags": "_decode_sa_flags",
    }

    def __init__(self, direction: ParamDirection) -> None:
        """Initialize SigactionParam with direction."""
        self.direction = direction

    def _decode_handler(self, value: int | None, *, no_abbrev: bool) -> str:  # noqa: ARG002
        """Decode signal handler pointer."""
        if value is None or value == 0:
            return "SIG_DFL"
        if value == 1:
            return "SIG_IGN"
        return f"0x{value:x}"

    def _decode_sigset(self, value: int | None, *, no_abbrev: bool) -> str:  # noqa: ARG002
        """Decode sigset_t bitmask to list of signal names."""
        if value is None or value == 0:
            return "[]"

        signals = []
        for signum, signame in sorted(SIGNAL_NUMBERS.items()):
            if value & (1 << (signum - 1)):
                signals.append(signame)

        if signals:
            return "[" + "|".join(signals) + "]"
        return f"0x{value:x}"

    def _decode_sa_flags(self, value: int | None, *, no_abbrev: bool) -> str:  # noqa: ARG002
        """Decode sa_flags bitfield."""
        if value is None or value == 0:
            return "0"

        flags = []
        for flag_val, flag_name in sorted(SA_FLAGS.items()):
            if value & flag_val:
                flags.append(flag_name)

        if flags:
            return "|".join(flags)
        return f"0x{value:x}"


class StackStruct(ctypes.Structure):
    """ctypes definition for stack_t (alternate signal stack) on macOS.

    typedef struct sigaltstack {
        void *ss_sp;       // signal stack base
        size_t ss_size;    // signal stack length
        int ss_flags;      // SS_DISABLE and/or SS_ONSTACK
    } stack_t;
    """

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("ss_sp", ctypes.c_void_p),  # void* (8 bytes on 64-bit)
        ("ss_size", ctypes.c_size_t),  # size_t (8 bytes on 64-bit)
        ("ss_flags", ctypes.c_int),  # int (4 bytes)
    ]


class StackParam(StructParamBase):
    """Parameter decoder for stack_t (alternate signal stack).

    Usage:
        StackParam(ParamDirection.OUT)  # old_stack (output)
        StackParam(ParamDirection.IN)   # new_stack (input)
    """

    struct_type = StackStruct
    excluded_fields: ClassVar[set[str]] = set()
    field_formatters: ClassVar[dict[str, str]] = {
        "ss_sp": "_decode_pointer",
        "ss_size": "_decode_size",
        "ss_flags": "_decode_ss_flags",
    }

    def __init__(self, direction: ParamDirection) -> None:
        """Initialize StackParam with direction."""
        self.direction = direction

    def _decode_pointer(self, value: int | None, *, no_abbrev: bool) -> str:  # noqa: ARG002
        """Decode stack pointer."""
        if value is None or value == 0:
            return "NULL"
        return f"0x{value:x}"

    def _decode_size(self, value: int | None, *, no_abbrev: bool) -> str:  # noqa: ARG002
        """Decode stack size, showing SIGSTKSZ constant if applicable."""
        if value is None:
            return "0"
        # SIGSTKSZ is typically 131072 (128KB) on macOS
        if value == 131072:
            return "SIGSTKSZ"
        return str(value)

    def _decode_ss_flags(self, value: int | None, *, no_abbrev: bool) -> str:  # noqa: ARG002
        """Decode ss_flags bitfield."""
        if value is None or value == 0:
            return "0"

        flags = []
        for flag_val, flag_name in sorted(SS_FLAGS.items()):
            if value & flag_val:
                flags.append(flag_name)

        if flags:
            return "|".join(flags)
        return f"0x{value:x}"


class SigsetParam(StructParamBase):
    """Parameter decoder for sigset_t pointer.

    sigset_t on macOS is a 32-bit bitmask (not a struct).

    Usage:
        SigsetParam(ParamDirection.OUT)  # oldset (output)
        SigsetParam(ParamDirection.IN)   # newset (input)
    """

    struct_type = None  # Not a struct, custom decode() reads uint32 directly
    excluded_fields: ClassVar[set[str]] = set()
    field_formatters: ClassVar[dict[str, str]] = {}

    def __init__(self, direction: ParamDirection) -> None:
        """Initialize SigsetParam with direction."""
        self.direction = direction

    def decode(self, ctx: DecodeContext) -> SyscallArg | None:
        """Decode sigset_t* to show signal names."""

        # Direction filtering
        if ctx.at_entry and self.direction != ParamDirection.IN:
            return PointerArg(ctx.raw_value)
        if not ctx.at_entry and self.direction != ParamDirection.OUT:
            return None

        # If NULL pointer
        if ctx.raw_value == 0:
            return PointerArg(0)

        # Read the sigset_t (32-bit value) from memory
        try:
            import lldb  # noqa: PLC0415

            error = lldb.SBError()
            value = ctx.process.ReadUnsignedFromMemory(ctx.raw_value, 4, error)
            if error.Fail():
                return PointerArg(ctx.raw_value)

            # Decode the bitmask
            if value == 0:
                signals_str = "[]"
            else:
                signals = []
                for signum, signame in sorted(SIGNAL_NUMBERS.items()):
                    if value & (1 << (signum - 1)):
                        signals.append(signame)

                signals_str = "[" + "|".join(signals) + "]" if signals else f"[0x{value:x}]"

            return StringArg(signals_str)

        except (ValueError, TypeError, AttributeError):
            return PointerArg(ctx.raw_value)
