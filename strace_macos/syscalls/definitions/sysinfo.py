"""System information and control syscall definitions.

Priority 7: Lowest priority, includes sysctl and system information queries.
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

# All system information syscalls (12 total) with full argument definitions
SYSINFO_SYSCALLS: list[SyscallDef] = [
    SyscallDef(numbers.SYS_getdtablesize, "getdtablesize", params=[]),  # 89
    SyscallDef(
        numbers.SYS_gethostuuid,
        "gethostuuid",
        params=[PointerParam(), PointerParam()],
    ),  # 142
    SyscallDef(
        numbers.SYS_sysctl,
        "sysctl",
        params=[
            PointerParam(),
            UnsignedParam(),
            PointerParam(),
            PointerParam(),
            PointerParam(),
            UnsignedParam(),
        ],
    ),  # 202
    SyscallDef(
        numbers.SYS_sysctlbyname,
        "sysctlbyname",
        params=[
            StringParam(),
            UnsignedParam(),
            PointerParam(),
            PointerParam(),
            PointerParam(),
            UnsignedParam(),
        ],
    ),  # 274
    SyscallDef(
        numbers.SYS_memorystatus_control,
        "memorystatus_control",
        params=[UnsignedParam(), IntParam(), UnsignedParam(), PointerParam(), UnsignedParam()],
    ),  # 337
    SyscallDef(numbers.SYS_usrctl, "usrctl", params=[UnsignedParam()]),  # 452
    SyscallDef(
        numbers.SYS_telemetry,
        "telemetry",
        params=[UnsignedParam(), UnsignedParam(), PointerParam(), PointerParam()],
    ),  # 464
    SyscallDef(
        numbers.SYS_ledger,
        "ledger",
        params=[IntParam(), PointerParam(), PointerParam(), PointerParam()],
    ),  # 478
    SyscallDef(
        numbers.SYS_kas_info,
        "kas_info",
        params=[IntParam(), PointerParam(), PointerParam(), PointerParam()],
    ),  # 487
    SyscallDef(
        numbers.SYS_work_interval_ctl,
        "work_interval_ctl",
        params=[UnsignedParam(), UnsignedParam(), PointerParam(), UnsignedParam()],
    ),  # 499
    SyscallDef(
        numbers.SYS_getentropy,
        "getentropy",
        params=[PointerParam(), UnsignedParam()],
    ),  # 500
    SyscallDef(
        numbers.SYS_memorystatus_available_memory,
        "memorystatus_available_memory",
        params=[],
    ),  # 520
]
