"""Miscellaneous syscall definitions.

These are syscalls that don't fit into the main categories.
Priority 7: Lowest priority.
"""

from __future__ import annotations

from strace_macos.syscalls import numbers
from strace_macos.syscalls.definitions import (
    FileDescriptorParam,
    IntParam,
    PointerParam,
    StringParam,
    SyscallDef,
    UnsignedParam,
)

# Miscellaneous syscalls (22 total) - truly miscellaneous syscalls that don't fit other categories
MISC_SYSCALLS: list[SyscallDef] = [
    SyscallDef(numbers.SYS_syscall, "syscall", params=[IntParam(), PointerParam()]),  # 0
    SyscallDef(
        numbers.SYS_crossarch_trap,
        "crossarch_trap",
        params=[UnsignedParam(), UnsignedParam(), UnsignedParam(), UnsignedParam()],
    ),  # 38
    SyscallDef(numbers.SYS_acct, "acct", params=[StringParam()]),  # 51
    SyscallDef(numbers.SYS_reboot, "reboot", params=[IntParam(), StringParam()]),  # 55
    SyscallDef(numbers.SYS_swapon, "swapon", params=[]),  # 85
    SyscallDef(
        numbers.SYS_connectx,
        "connectx",
        params=[
            FileDescriptorParam(),
            PointerParam(),
            UnsignedParam(),
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
            PointerParam(),
            PointerParam(),
        ],
    ),  # 455
    SyscallDef(
        numbers.SYS_grab_pgo_data,
        "grab_pgo_data",
        params=[
            PointerParam(),
            IntParam(),
            PointerParam(),
            UnsignedParam(),
            PointerParam(),
            PointerParam(),
        ],
    ),  # 469
    SyscallDef(
        numbers.SYS_map_with_linking_np,
        "map_with_linking_np",
        params=[
            PointerParam(),
            UnsignedParam(),
            IntParam(),
            IntParam(),
            IntParam(),
            UnsignedParam(),
            PointerParam(),
        ],
    ),  # 470
    SyscallDef(
        numbers.SYS_fileport_makeport, "fileport_makeport", params=[IntParam(), PointerParam()]
    ),  # 473
    SyscallDef(numbers.SYS_fileport_makefd, "fileport_makefd", params=[PointerParam()]),  # 474
    SyscallDef(numbers.SYS_necp_open, "necp_open", params=[IntParam()]),  # 501
    # Process/resource limit control
    SyscallDef(
        numbers.SYS_proc_rlimit_control,
        "proc_rlimit_control",
        params=[IntParam(), IntParam(), PointerParam()],
    ),  # 454
    # Code signing/profiling
    SyscallDef(
        numbers.SYS_csops_audittoken,
        "csops_audittoken",
        params=[IntParam(), UnsignedParam(), PointerParam(), UnsignedParam(), PointerParam()],
    ),  # 170
    # Thread self-accounting
    SyscallDef(
        numbers.SYS_thread_selfcounts,
        "thread_selfcounts",
        params=[IntParam(), PointerParam(), UnsignedParam()],
    ),  # 186
    # Duplicate entry already in file.py
    SyscallDef(
        numbers.SYS_fsetattrlist,
        "fsetattrlist",
        params=[
            FileDescriptorParam(),
            PointerParam(),
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
        ],
    ),  # 229
]
