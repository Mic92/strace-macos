"""Debugging and tracing syscall definitions.

Priority 8: Lowest priority, includes kernel debugging, tracing, and diagnostic syscalls.
"""

from __future__ import annotations

from strace_macos.syscalls import numbers
from strace_macos.syscalls.definitions import (
    ConstParam,
    IntParam,
    PointerParam,
    StringParam,
    SyscallDef,
    UnsignedParam,
)
from strace_macos.syscalls.symbols.ptrace import (
    PTRACE_REQUESTS,
)

# All debugging syscalls (15 total) with full argument definitions
DEBUG_SYSCALLS: list[SyscallDef] = [
    SyscallDef(
        numbers.SYS_ptrace,
        "ptrace",
        params=[
            ConstParam(PTRACE_REQUESTS),
            IntParam(),
            PointerParam(),
            IntParam(),
        ],
    ),  # 26
    SyscallDef(
        numbers.SYS_kdebug_typefilter,
        "kdebug_typefilter",
        params=[PointerParam(), PointerParam()],
    ),  # 177
    SyscallDef(
        numbers.SYS_kdebug_trace_string,
        "kdebug_trace_string",
        params=[UnsignedParam(), UnsignedParam(), StringParam()],
    ),  # 178
    SyscallDef(
        numbers.SYS_kdebug_trace64,
        "kdebug_trace64",
        params=[
            UnsignedParam(),
            UnsignedParam(),
            UnsignedParam(),
            UnsignedParam(),
            UnsignedParam(),
        ],
    ),  # 179
    SyscallDef(
        numbers.SYS_kdebug_trace,
        "kdebug_trace",
        params=[
            UnsignedParam(),
            UnsignedParam(),
            UnsignedParam(),
            UnsignedParam(),
            UnsignedParam(),
        ],
    ),  # 180
    SyscallDef(
        numbers.SYS_panic_with_data,
        "panic_with_data",
        params=[PointerParam(), PointerParam(), UnsignedParam(), UnsignedParam()],
    ),  # 185
    SyscallDef(
        numbers.SYS_microstackshot,
        "microstackshot",
        params=[PointerParam(), UnsignedParam(), UnsignedParam()],
    ),  # 287
    SyscallDef(
        numbers.SYS_stack_snapshot_with_config,
        "stack_snapshot_with_config",
        params=[IntParam(), PointerParam(), UnsignedParam()],
    ),  # 482
    SyscallDef(
        numbers.SYS_terminate_with_payload,
        "terminate_with_payload",
        params=[
            IntParam(),
            UnsignedParam(),
            PointerParam(),
            UnsignedParam(),
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
        ],
    ),  # 485
    SyscallDef(
        numbers.SYS_abort_with_payload,
        "abort_with_payload",
        params=[
            IntParam(),
            UnsignedParam(),
            PointerParam(),
            UnsignedParam(),
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
        ],
    ),  # 486
    SyscallDef(
        numbers.SYS_os_fault_with_payload,
        "os_fault_with_payload",
        params=[
            UnsignedParam(),
            PointerParam(),
            UnsignedParam(),
            PointerParam(),
            UnsignedParam(),
        ],
    ),  # 513
    SyscallDef(
        numbers.SYS_log_data,
        "log_data",
        params=[UnsignedParam(), UnsignedParam(), PointerParam(), UnsignedParam()],
    ),  # 519
    SyscallDef(
        numbers.SYS_objc_bp_assist_cfg_np,
        "objc_bp_assist_cfg_np",
        params=[PointerParam()],
    ),  # 521
    SyscallDef(
        numbers.SYS_debug_syscall_reject,
        "debug_syscall_reject",
        params=[PointerParam()],
    ),  # 542
    SyscallDef(
        numbers.SYS_debug_syscall_reject_config,
        "debug_syscall_reject_config",
        params=[PointerParam(), UnsignedParam()],
    ),  # 543
]
