"""Time and timer syscall definitions.

Priority 6: Lower priority, implement after core functionality works.
"""

from __future__ import annotations

from strace_macos.syscalls import numbers
from strace_macos.syscalls.definitions import (
    ConstParam,
    IntParam,
    PointerParam,
    StringParam,
    SyscallDef,
)
from strace_macos.syscalls.symbols.time import ITIMER_CONSTANTS

# All time and timer syscalls (6 total) with full argument definitions
TIME_SYSCALLS: list[SyscallDef] = [
    SyscallDef(
        numbers.SYS_setitimer,
        "setitimer",
        params=[
            ConstParam(ITIMER_CONSTANTS),
            PointerParam(),
            PointerParam(),
        ],
    ),  # 83
    SyscallDef(
        numbers.SYS_getitimer,
        "getitimer",
        params=[
            ConstParam(ITIMER_CONSTANTS),
            PointerParam(),
        ],
    ),  # 86
    SyscallDef(
        numbers.SYS_gettimeofday,
        "gettimeofday",
        params=[PointerParam(), PointerParam()],
    ),  # 116
    SyscallDef(
        numbers.SYS_settimeofday,
        "settimeofday",
        params=[PointerParam(), PointerParam()],
    ),  # 122
    SyscallDef(
        numbers.SYS_utimes,
        "utimes",
        params=[StringParam(), PointerParam()],
    ),  # 138
    SyscallDef(
        numbers.SYS_futimes,
        "futimes",
        params=[IntParam(), PointerParam()],
    ),  # 139
    SyscallDef(
        numbers.SYS_adjtime,
        "adjtime",
        params=[PointerParam(), PointerParam()],
    ),  # 140
]
