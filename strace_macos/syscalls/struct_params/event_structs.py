"""Struct parameter decoders for kqueue/kevent/select/poll structures."""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Any, ClassVar

from strace_macos.lldb_loader import load_lldb_module
from strace_macos.syscalls.args import PointerArg, StringArg, StructArrayArg
from strace_macos.syscalls.definitions import (
    DecodeContext,
    Param,
    ParamDirection,
    StructParamBase,
    SyscallArg,
)
from strace_macos.syscalls.symbols.ipc import POLL_EVENTS
from strace_macos.syscalls.symbols.kqueue import (
    EV_FLAGS,
    EVFILT_CONSTANTS,
    NOTE_PROC_FLAGS,
    NOTE_TIMER_FLAGS,
    NOTE_USER_FLAGS,
    NOTE_VNODE_FLAGS,
)

# Filter type constants for fflags decoding
EVFILT_VNODE = -4
EVFILT_PROC = -5
EVFILT_TIMER = -7
EVFILT_USER = -10


class KeventStruct(ctypes.Structure):
    """ctypes definition for struct kevent on macOS.

    struct kevent {
        uintptr_t ident;        // identifier (e.g., fd, pid, signal)
        int16_t   filter;       // filter type (EVFILT_*)
        uint16_t  flags;        // action flags (EV_ADD, EV_ENABLE, etc.)
        uint32_t  fflags;       // filter-specific flags
        intptr_t  data;         // filter-specific data
        void      *udata;       // user-defined data
    };
    """

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("ident", ctypes.c_uint64),  # uintptr_t
        ("filter", ctypes.c_int16),
        ("flags", ctypes.c_uint16),
        ("fflags", ctypes.c_uint32),
        ("data", ctypes.c_int64),  # intptr_t
        ("udata", ctypes.c_void_p),
    ]


@dataclass
class KeventParam(Param):
    """Parameter decoder for struct kevent array.

    Usage:
        KeventParam(count_arg_index=2, direction=ParamDirection.IN)   # changelist
        KeventParam(count_arg_index=4, direction=ParamDirection.OUT)  # eventlist
    """

    count_arg_index: int
    direction: ParamDirection

    def decode(self, ctx: DecodeContext) -> SyscallArg | None:
        """Decode kevent array parameter."""
        # Direction filtering
        if ctx.at_entry and self.direction != ParamDirection.IN:
            return PointerArg(ctx.raw_value)
        if not ctx.at_entry and self.direction != ParamDirection.OUT:
            return None

        if ctx.raw_value == 0:
            return PointerArg(0)

        # Get count from specified argument
        if self.count_arg_index >= len(ctx.all_args):
            return PointerArg(ctx.raw_value)

        count = ctx.all_args[self.count_arg_index]

        # For OUT direction at exit, use return value as count if available
        # (kevent returns the actual number of events filled in)
        if (
            not ctx.at_entry
            and self.direction == ParamDirection.OUT
            and isinstance(ctx.return_value, int)
            and 0 < ctx.return_value < count
        ):
            count = ctx.return_value

        if count <= 0 or count > 1000:  # Safety limit
            return PointerArg(ctx.raw_value)

        # Decode the kevent array
        kevent_list = self._decode_array(ctx.process, ctx.raw_value, count)
        if kevent_list:
            return StructArrayArg(kevent_list)

        return PointerArg(ctx.raw_value)

    def _decode_array(
        self,
        process: Any,
        address: int,
        count: int,
    ) -> list[dict[str, str | int]] | None:
        """Decode an array of kevent structures."""
        if count <= 0 or count > 1000:
            return None

        lldb = load_lldb_module()
        error = lldb.SBError()
        kevent_size = ctypes.sizeof(KeventStruct)
        total_size = kevent_size * count

        data = process.ReadMemory(address, total_size, error)
        if error.Fail() or not data:
            return None

        kevent_list = []
        for i in range(count):
            offset = i * kevent_size
            try:
                kev = KeventStruct.from_buffer_copy(data[offset : offset + kevent_size])
            except (ValueError, TypeError):
                continue

            # Build entry with essential fields
            entry: dict[str, str | int] = {
                "ident": kev.ident,
                "filter": decode_kevent_filter(kev.filter),
                "flags": decode_kevent_flags(kev.flags),
            }

            # Only show fflags if non-zero
            if kev.fflags != 0:
                entry["fflags"] = decode_kevent_fflags(kev.fflags, kev.filter)

            # For IN direction (changelist), skip data/udata to reduce noise
            # For OUT direction (eventlist), show data if non-zero
            if self.direction == ParamDirection.OUT and kev.data != 0:
                entry["data"] = kev.data

            kevent_list.append(entry)

        return kevent_list if kevent_list else None


def decode_kevent_filter(value: int) -> str:
    """Decode kevent filter type constant."""
    return EVFILT_CONSTANTS.get(value, str(value))


def decode_kevent_flags(value: int) -> str:
    """Decode kevent event flags bitfield."""
    if value == 0:
        return "0"

    flags = []
    for flag_val, flag_name in sorted(EV_FLAGS.items()):
        if value & flag_val:
            flags.append(flag_name)

    return "|".join(flags) if flags else f"0x{value:x}"


def decode_kevent_fflags(value: int, filter_value: int) -> str:
    """Decode kevent filter-specific flags based on filter type.

    Args:
        value: The fflags value to decode
        filter_value: The filter type (determines which flag map to use)

    Returns:
        Symbolic representation of fflags or raw value if unknown
    """
    if value == 0:
        return "0"

    # Select flag map based on filter type
    flag_map = None
    if filter_value == EVFILT_VNODE:  # -4
        flag_map = NOTE_VNODE_FLAGS
    elif filter_value == EVFILT_PROC:  # -5
        flag_map = NOTE_PROC_FLAGS
    elif filter_value == EVFILT_TIMER:  # -7
        flag_map = NOTE_TIMER_FLAGS
    elif filter_value == EVFILT_USER:  # -10
        flag_map = NOTE_USER_FLAGS

    if flag_map is None:
        # Unknown filter type, show raw value
        return str(value)

    # Decode flags using the appropriate map
    flags = []
    remaining = value
    for flag_val, flag_name in sorted(flag_map.items()):
        if value & flag_val:
            flags.append(flag_name)
            remaining &= ~flag_val

    if flags and remaining == 0:
        return "|".join(flags)

    # If there are unrecognized bits, show everything as raw value
    return str(value)


class Kevent64Struct(ctypes.Structure):
    """ctypes definition for struct kevent64_s on macOS.

    struct kevent64_s {
        uint64_t  ident;
        int16_t   filter;
        uint16_t  flags;
        uint32_t  fflags;
        int64_t   data;
        uint64_t  udata;
        uint64_t  ext[2];
    };
    """

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("ident", ctypes.c_uint64),
        ("filter", ctypes.c_int16),
        ("flags", ctypes.c_uint16),
        ("fflags", ctypes.c_uint32),
        ("data", ctypes.c_int64),
        ("udata", ctypes.c_uint64),
        ("ext0", ctypes.c_uint64),
        ("ext1", ctypes.c_uint64),
    ]


@dataclass
class Kevent64Param(Param):
    """Parameter decoder for struct kevent64_s array.

    Usage:
        Kevent64Param(count_arg_index=2, direction=ParamDirection.IN)   # changelist
        Kevent64Param(count_arg_index=4, direction=ParamDirection.OUT)  # eventlist
    """

    count_arg_index: int
    direction: ParamDirection

    def decode(self, ctx: DecodeContext) -> SyscallArg | None:
        """Decode kevent64 array parameter."""
        # Direction filtering
        if ctx.at_entry and self.direction != ParamDirection.IN:
            return PointerArg(ctx.raw_value)
        if not ctx.at_entry and self.direction != ParamDirection.OUT:
            return None

        if ctx.raw_value == 0:
            return PointerArg(0)

        # Get count from specified argument
        if self.count_arg_index >= len(ctx.all_args):
            return PointerArg(ctx.raw_value)

        count = ctx.all_args[self.count_arg_index]

        # For OUT direction at exit, use return value as count if available
        # (kevent64 returns the actual number of events filled in)
        if (
            not ctx.at_entry
            and self.direction == ParamDirection.OUT
            and isinstance(ctx.return_value, int)
            and 0 < ctx.return_value < count
        ):
            count = ctx.return_value

        if count <= 0 or count > 1000:
            return PointerArg(ctx.raw_value)

        # Decode the kevent64 array
        kevent_list = self._decode_array(ctx.process, ctx.raw_value, count)
        if kevent_list:
            return StructArrayArg(kevent_list)

        return PointerArg(ctx.raw_value)

    def _decode_array(
        self,
        process: Any,
        address: int,
        count: int,
    ) -> list[dict[str, str | int]] | None:
        """Decode an array of kevent64_s structures."""
        if count <= 0 or count > 1000:
            return None

        lldb = load_lldb_module()
        error = lldb.SBError()
        kevent_size = ctypes.sizeof(Kevent64Struct)
        total_size = kevent_size * count

        data = process.ReadMemory(address, total_size, error)
        if error.Fail() or not data:
            return None

        kevent_list = []
        for i in range(count):
            offset = i * kevent_size
            try:
                kev = Kevent64Struct.from_buffer_copy(data[offset : offset + kevent_size])
            except (ValueError, TypeError):
                continue

            # Build entry with essential fields
            entry: dict[str, str | int] = {
                "ident": kev.ident,
                "filter": decode_kevent_filter(kev.filter),
                "flags": decode_kevent_flags(kev.flags),
            }

            # Only show fflags if non-zero
            if kev.fflags != 0:
                entry["fflags"] = decode_kevent_fflags(kev.fflags, kev.filter)

            # For OUT direction (eventlist), show data if non-zero
            if self.direction == ParamDirection.OUT and kev.data != 0:
                entry["data"] = kev.data

            kevent_list.append(entry)

        return kevent_list if kevent_list else None


class PollfdStruct(ctypes.Structure):
    """ctypes definition for struct pollfd on macOS.

    struct pollfd {
        int   fd;       // file descriptor
        short events;   // requested events
        short revents;  // returned events
    };
    """

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("fd", ctypes.c_int),
        ("events", ctypes.c_short),
        ("revents", ctypes.c_short),
    ]


@dataclass
class PollfdParam(Param):
    """Parameter decoder for struct pollfd array.

    Usage:
        PollfdParam(count_arg_index=1)  # nfds is second argument
    """

    count_arg_index: int

    def decode(self, ctx: DecodeContext) -> SyscallArg | None:
        """Decode pollfd array parameter."""
        # Decode at entry (for events field)
        if not ctx.at_entry:
            return None

        if ctx.raw_value == 0:
            return PointerArg(0)

        # Get count from specified argument
        if self.count_arg_index >= len(ctx.all_args):
            return PointerArg(ctx.raw_value)

        count = ctx.all_args[self.count_arg_index]
        if count <= 0 or count > 1000:
            return PointerArg(ctx.raw_value)

        # Decode the pollfd array
        pollfd_list = self._decode_array(ctx.process, ctx.raw_value, count)
        if pollfd_list:
            return StructArrayArg(pollfd_list)

        return PointerArg(ctx.raw_value)

    def _decode_array(
        self,
        process: Any,
        address: int,
        count: int,
    ) -> list[dict[str, str | int]] | None:
        """Decode an array of pollfd structures."""
        if count <= 0 or count > 1000:
            return None

        lldb = load_lldb_module()
        error = lldb.SBError()
        pollfd_size = ctypes.sizeof(PollfdStruct)
        total_size = pollfd_size * count

        data = process.ReadMemory(address, total_size, error)
        if error.Fail() or not data:
            return None

        pollfd_list = []
        for i in range(count):
            offset = i * pollfd_size
            try:
                pfd = PollfdStruct.from_buffer_copy(data[offset : offset + pollfd_size])
            except (ValueError, TypeError):
                continue

            pollfd_list.append(
                {
                    "fd": pfd.fd,
                    "events": self._decode_events(pfd.events),
                }
            )

        return pollfd_list if pollfd_list else None

    @staticmethod
    def _decode_events(value: int) -> str:
        """Decode poll event flags."""
        if value == 0:
            return "0"

        flags = []
        for flag_val, flag_name in sorted(POLL_EVENTS.items()):
            if value & flag_val:
                flags.append(flag_name)

        return "|".join(flags) if flags else f"0x{value:x}"


class TimespecStruct(ctypes.Structure):
    """ctypes definition for struct timespec.

    struct timespec {
        time_t  tv_sec;   // seconds
        long    tv_nsec;  // nanoseconds
    };
    """

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("tv_sec", ctypes.c_int64),  # time_t
        ("tv_nsec", ctypes.c_long),  # long
    ]


class TimespecParam(StructParamBase):
    """Parameter decoder for struct timespec."""

    struct_type = TimespecStruct
    excluded_fields: ClassVar[set[str]] = set()
    field_formatters: ClassVar[dict[str, str]] = {}

    def __init__(self) -> None:
        """Initialize TimespecParam."""
        self.direction = ParamDirection.IN


class TimevalStruct(ctypes.Structure):
    """ctypes definition for struct timeval.

    struct timeval {
        time_t       tv_sec;   // seconds
        suseconds_t  tv_usec;  // microseconds
    };
    """

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("tv_sec", ctypes.c_int64),  # time_t
        ("tv_usec", ctypes.c_int32),  # suseconds_t (int32 on macOS)
    ]


class TimevalParam(StructParamBase):
    """Parameter decoder for struct timeval."""

    struct_type = TimevalStruct
    excluded_fields: ClassVar[set[str]] = set()
    field_formatters: ClassVar[dict[str, str]] = {}

    def __init__(self) -> None:
        """Initialize TimevalParam."""
        self.direction = ParamDirection.IN


@dataclass
class FdSetParam(Param):
    """Parameter decoder for fd_set (file descriptor set).

    fd_set is a bitmap of file descriptors, implemented as an array of 32 int32_t values
    (1024 bits total on macOS). Each bit represents whether that fd is in the set.
    """

    FD_SETSIZE = 1024
    NFDBITS = 32  # bits per int32_t
    ARRAY_SIZE = FD_SETSIZE // NFDBITS  # 32 int32_t values

    def decode(self, ctx: DecodeContext) -> SyscallArg | None:
        """Decode fd_set bitmap to list of file descriptors."""
        # Only decode at entry (input fd_sets)
        if not ctx.at_entry:
            return None

        if ctx.raw_value == 0:
            return PointerArg(0)

        # Read the fd_set bitmap (32 * 4 bytes = 128 bytes)
        lldb = load_lldb_module()
        error = lldb.SBError()
        data = ctx.process.ReadMemory(ctx.raw_value, self.ARRAY_SIZE * 4, error)

        if error.Fail():
            return PointerArg(ctx.raw_value)

        # Parse bitmap to find which fds are set
        fds = []
        for i in range(self.ARRAY_SIZE):
            # Extract each 32-bit int from the data
            offset = i * 4
            if offset + 4 > len(data):
                break
            bitmap = int.from_bytes(data[offset : offset + 4], byteorder="little", signed=False)

            # Check each bit in this int
            for bit in range(self.NFDBITS):
                if bitmap & (1 << bit):
                    fd = i * self.NFDBITS + bit
                    fds.append(fd)

        if not fds:
            return StringArg("[]")

        # Format as [3 4 5]
        fd_list = " ".join(str(fd) for fd in fds)
        return StringArg(f"[{fd_list}]")


__all__ = [
    "FdSetParam",
    "Kevent64Param",
    "KeventParam",
    "PollfdParam",
    "TimespecParam",
    "TimevalParam",
]
