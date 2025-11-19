"""Memory management syscall definitions.

Priority 4: Lower priority, implement after core functionality works.
"""

from __future__ import annotations

from strace_macos.syscalls import numbers
from strace_macos.syscalls.definitions import (
    ConstParam,
    FlagsParam,
    IntParam,
    PointerParam,
    SyscallDef,
    UnsignedParam,
)
from strace_macos.syscalls.symbols.file import MSYNC_FLAGS
from strace_macos.syscalls.symbols.memory import (
    MADV_CONSTANTS,
    MAP_FLAGS,
    MCL_FLAGS,
    PROT_FLAGS,
    VM_INHERIT_CONSTANTS,
)

# All memory management syscalls (16 total) with full argument definitions
MEMORY_SYSCALLS: list[SyscallDef] = [
    SyscallDef(
        numbers.SYS_munmap,
        "munmap",
        params=[PointerParam(), UnsignedParam()],
    ),  # 73
    SyscallDef(
        numbers.SYS_mprotect,
        "mprotect",
        params=[PointerParam(), UnsignedParam(), FlagsParam(PROT_FLAGS)],
    ),  # 74
    SyscallDef(
        numbers.SYS_madvise,
        "madvise",
        params=[PointerParam(), UnsignedParam(), ConstParam(MADV_CONSTANTS)],
    ),  # 75
    SyscallDef(
        numbers.SYS_mincore,
        "mincore",
        params=[PointerParam(), UnsignedParam(), PointerParam()],
    ),  # 78
    SyscallDef(
        numbers.SYS_mmap,
        "mmap",
        params=[
            PointerParam(),
            UnsignedParam(),
            FlagsParam(PROT_FLAGS),
            FlagsParam(MAP_FLAGS),
            IntParam(),
            UnsignedParam(),
        ],
    ),  # 197
    SyscallDef(
        numbers.SYS_mlock,
        "mlock",
        params=[PointerParam(), UnsignedParam()],
    ),  # 203
    SyscallDef(
        numbers.SYS_munlock,
        "munlock",
        params=[PointerParam(), UnsignedParam()],
    ),  # 204
    SyscallDef(
        numbers.SYS_minherit,
        "minherit",
        params=[PointerParam(), UnsignedParam(), ConstParam(VM_INHERIT_CONSTANTS)],
    ),  # 250
    SyscallDef(
        numbers.SYS_shared_region_check_np,
        "shared_region_check_np",
        params=[PointerParam()],
    ),  # 294
    SyscallDef(
        numbers.SYS_vm_pressure_monitor,
        "vm_pressure_monitor",
        params=[IntParam(), IntParam(), PointerParam()],
    ),  # 296
    SyscallDef(
        numbers.SYS_mlockall,
        "mlockall",
        params=[FlagsParam(MCL_FLAGS)],
    ),  # 324
    SyscallDef(
        numbers.SYS_munlockall,
        "munlockall",
        params=[],
    ),  # 325
    SyscallDef(
        numbers.SYS_shared_region_map_and_slide_2_np,
        "shared_region_map_and_slide_2_np",
        params=[
            UnsignedParam(),
            UnsignedParam(),
            PointerParam(),
            UnsignedParam(),
            PointerParam(),
            UnsignedParam(),
        ],
    ),  # 536
    SyscallDef(
        numbers.SYS_msync,
        "msync",
        params=[PointerParam(), UnsignedParam(), FlagsParam(MSYNC_FLAGS)],
    ),  # 65 (from file.py but is memory op)
    SyscallDef(
        numbers.SYS_mremap_encrypted,
        "mremap_encrypted",
        params=[PointerParam(), UnsignedParam(), UnsignedParam(), UnsignedParam(), UnsignedParam()],
    ),  # 489 (also in file.py, but primarily memory op)
]
