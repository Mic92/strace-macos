"""Thread management syscall definitions.

Priority 5: Lower priority, implement after core functionality works.
"""

from __future__ import annotations

from strace_macos.syscalls import numbers
from strace_macos.syscalls.definitions import (
    IntParam,
    PointerParam,
    StringParam,
    SyscallDef,
    UnsignedParam,
)

# All thread management syscalls (10 total) with full argument definitions
THREAD_SYSCALLS: list[SyscallDef] = [
    SyscallDef(
        numbers.SYS___pthread_canceled,
        "__pthread_canceled",
        params=[IntParam()],
    ),  # 333
    SyscallDef(
        numbers.SYS___pthread_markcancel,
        "__pthread_markcancel",
        params=[IntParam()],
    ),  # 332
    SyscallDef(
        numbers.SYS___pthread_chdir,
        "__pthread_chdir",
        params=[StringParam()],
    ),  # 348
    SyscallDef(
        numbers.SYS___pthread_fchdir,
        "__pthread_fchdir",
        params=[IntParam()],
    ),  # 349
    SyscallDef(
        numbers.SYS_bsdthread_create,
        "bsdthread_create",
        params=[PointerParam(), PointerParam(), PointerParam(), PointerParam(), UnsignedParam()],
    ),  # 360
    SyscallDef(
        numbers.SYS_bsdthread_terminate,
        "bsdthread_terminate",
        params=[PointerParam(), UnsignedParam(), UnsignedParam(), UnsignedParam()],
    ),  # 361
    SyscallDef(
        numbers.SYS_bsdthread_register,
        "bsdthread_register",
        params=[PointerParam(), PointerParam(), IntParam()],
    ),  # 366
    SyscallDef(
        numbers.SYS_bsdthread_ctl,
        "bsdthread_ctl",
        params=[PointerParam(), UnsignedParam(), PointerParam(), PointerParam()],
    ),  # 449
    SyscallDef(numbers.SYS_thread_selfusage, "thread_selfusage", params=[]),  # 475
    SyscallDef(numbers.SYS_thread_selfid, "thread_selfid", params=[]),  # 539
]
