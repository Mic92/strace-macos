"""Time and timer syscall definitions.

Priority 6: Lower priority, implement after core functionality works.
"""

from __future__ import annotations

from strace_macos.syscalls import numbers
from strace_macos.syscalls.definitions import SyscallDef
from strace_macos.syscalls.symbols.time import decode_itimer_which

# All time and timer syscalls (6 total) with full argument definitions
TIME_SYSCALLS: list[SyscallDef] = [
    SyscallDef(
        numbers.SYS_setitimer,
        "setitimer",
        ["int", "pointer", "pointer"],
        [decode_itimer_which, None, None],
    ),  # 83
    SyscallDef(
        numbers.SYS_getitimer,
        "getitimer",
        ["int", "pointer"],
        [decode_itimer_which, None],
    ),  # 86
    SyscallDef(numbers.SYS_gettimeofday, "gettimeofday", ["pointer", "pointer"]),  # 116
    SyscallDef(numbers.SYS_settimeofday, "settimeofday", ["pointer", "pointer"]),  # 122
    SyscallDef(numbers.SYS_utimes, "utimes", ["string", "pointer"]),  # 138
    SyscallDef(numbers.SYS_futimes, "futimes", ["int", "pointer"]),  # 139
    SyscallDef(numbers.SYS_adjtime, "adjtime", ["pointer", "pointer"]),  # 140
]
