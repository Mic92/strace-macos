"""Struct parameter decoders for process-related structures."""

from __future__ import annotations

import ctypes
from typing import ClassVar

from strace_macos.syscalls.definitions import ParamDirection, StructParamBase

# RLIM_INFINITY from sys/resource.h: (((__uint64_t)1 << 63) - 1)
RLIM_INFINITY = (1 << 63) - 1  # 0x7fffffffffffffff


class RlimitStruct(ctypes.Structure):
    """ctypes definition for struct rlimit on macOS.

    struct rlimit {
        rlim_t rlim_cur;  // current (soft) limit
        rlim_t rlim_max;  // maximum value for rlim_cur (hard limit)
    };

    rlim_t is uint64_t on macOS
    """

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("rlim_cur", ctypes.c_uint64),
        ("rlim_max", ctypes.c_uint64),
    ]


class RlimitParam(StructParamBase):
    """Parameter decoder for struct rlimit.

    Usage:
        RlimitParam(ParamDirection.OUT)  # For getrlimit
        RlimitParam(ParamDirection.IN)   # For setrlimit
    """

    struct_type = RlimitStruct
    excluded_fields: ClassVar[set[str]] = set()
    field_formatters: ClassVar[dict[str, str]] = {
        "rlim_cur": "_decode_rlim",
        "rlim_max": "_decode_rlim",
    }

    def __init__(self, direction: ParamDirection) -> None:
        """Initialize RlimitParam with direction."""
        self.direction = direction

    def _decode_rlim(self, value: int, *, no_abbrev: bool) -> str:  # noqa: ARG002
        """Decode resource limit value, showing RLIM_INFINITY as symbolic constant."""
        if value == RLIM_INFINITY:
            return "RLIM_INFINITY"
        return str(value)


class RusageStruct(ctypes.Structure):
    """ctypes definition for struct rusage on macOS.

    struct rusage {
        struct timeval ru_utime;     // user time used
        struct timeval ru_stime;     // system time used
        long ru_maxrss;              // max resident set size
        long ru_ixrss;               // integral shared memory size
        long ru_idrss;               // integral unshared data size
        long ru_isrss;               // integral unshared stack size
        long ru_minflt;              // page reclaims
        long ru_majflt;              // page faults
        long ru_nswap;               // swaps
        long ru_inblock;             // block input operations
        long ru_oublock;             // block output operations
        long ru_msgsnd;              // messages sent
        long ru_msgrcv;              // messages received
        long ru_nsignals;            // signals received
        long ru_nvcsw;               // voluntary context switches
        long ru_nivcsw;              // involuntary context switches
    };

    struct timeval {
        time_t      tv_sec;   // seconds (64-bit on macOS)
        suseconds_t tv_usec;  // microseconds (32-bit on macOS)
    };
    """

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("ru_utime_sec", ctypes.c_int64),
        ("ru_utime_usec", ctypes.c_int32),
        ("_padding1", ctypes.c_int32),  # padding for alignment
        ("ru_stime_sec", ctypes.c_int64),
        ("ru_stime_usec", ctypes.c_int32),
        ("_padding2", ctypes.c_int32),  # padding for alignment
        ("ru_maxrss", ctypes.c_long),
        ("ru_ixrss", ctypes.c_long),
        ("ru_idrss", ctypes.c_long),
        ("ru_isrss", ctypes.c_long),
        ("ru_minflt", ctypes.c_long),
        ("ru_majflt", ctypes.c_long),
        ("ru_nswap", ctypes.c_long),
        ("ru_inblock", ctypes.c_long),
        ("ru_oublock", ctypes.c_long),
        ("ru_msgsnd", ctypes.c_long),
        ("ru_msgrcv", ctypes.c_long),
        ("ru_nsignals", ctypes.c_long),
        ("ru_nvcsw", ctypes.c_long),
        ("ru_nivcsw", ctypes.c_long),
    ]


class RusageParam(StructParamBase):
    """Parameter decoder for struct rusage.

    Usage:
        RusageParam(ParamDirection.OUT)  # For getrusage
    """

    struct_type = RusageStruct
    excluded_fields: ClassVar[set[str]] = {"_padding1", "_padding2"}
    field_formatters: ClassVar[dict[str, str]] = {
        "ru_utime_sec": "_decode_time_sec",
        "ru_utime_usec": "_decode_time_usec",
        "ru_stime_sec": "_decode_time_sec",
        "ru_stime_usec": "_decode_time_usec",
    }

    def __init__(self, direction: ParamDirection) -> None:
        """Initialize RusageParam with direction."""
        self.direction = direction

    def _decode_time_sec(self, value: int, *, no_abbrev: bool) -> str:  # noqa: ARG002
        """Format seconds field of timeval."""
        return f"{value}s"

    def _decode_time_usec(self, value: int, *, no_abbrev: bool) -> str:  # noqa: ARG002
        """Format microseconds field of timeval."""
        return f"{value}µs"


__all__ = [
    "RlimitParam",
    "RusageParam",
]
