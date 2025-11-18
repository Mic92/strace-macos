"""Debugging and tracing syscall definitions.

Priority 8: Lowest priority, includes kernel debugging, tracing, and diagnostic syscalls.
"""

from __future__ import annotations

from strace_macos.syscalls import numbers
from strace_macos.syscalls.definitions import SyscallDef
from strace_macos.syscalls.symbols.ptrace import decode_ptrace_request

# All debugging syscalls (15 total) with full argument definitions
DEBUG_SYSCALLS: list[SyscallDef] = [
    SyscallDef(
        numbers.SYS_ptrace,
        "ptrace",
        ["int", "pid_t", "pointer", "int"],
        [decode_ptrace_request, None, None, None],
    ),  # 26
    SyscallDef(numbers.SYS_kdebug_typefilter, "kdebug_typefilter", ["pointer", "pointer"]),  # 177
    SyscallDef(
        numbers.SYS_kdebug_trace_string,
        "kdebug_trace_string",
        ["uint32_t", "uint64_t", "string"],
    ),  # 178
    SyscallDef(
        numbers.SYS_kdebug_trace64,
        "kdebug_trace64",
        ["uint32_t", "uint64_t", "uint64_t", "uint64_t", "uint64_t"],
    ),  # 179
    SyscallDef(
        numbers.SYS_kdebug_trace,
        "kdebug_trace",
        ["uint32_t", "uint32_t", "uint32_t", "uint32_t", "uint32_t"],
    ),  # 180
    SyscallDef(
        numbers.SYS_panic_with_data,
        "panic_with_data",
        ["pointer", "pointer", "size_t", "uint64_t"],
    ),  # 185
    SyscallDef(
        numbers.SYS_microstackshot, "microstackshot", ["pointer", "size_t", "uint32_t"]
    ),  # 287
    SyscallDef(
        numbers.SYS_stack_snapshot_with_config,
        "stack_snapshot_with_config",
        ["int", "pointer", "size_t"],
    ),  # 482
    SyscallDef(
        numbers.SYS_terminate_with_payload,
        "terminate_with_payload",
        ["int", "uint32_t", "pointer", "uint32_t", "pointer", "uint32_t", "uint64_t"],
    ),  # 485
    SyscallDef(
        numbers.SYS_abort_with_payload,
        "abort_with_payload",
        ["int", "uint32_t", "pointer", "uint32_t", "pointer", "uint32_t", "uint64_t"],
    ),  # 486
    SyscallDef(
        numbers.SYS_os_fault_with_payload,
        "os_fault_with_payload",
        ["uint64_t", "pointer", "uint32_t", "pointer", "uint32_t"],
    ),  # 513
    SyscallDef(
        numbers.SYS_log_data,
        "log_data",
        ["uint32_t", "uint32_t", "pointer", "uint32_t"],
    ),  # 519
    SyscallDef(numbers.SYS_objc_bp_assist_cfg_np, "objc_bp_assist_cfg_np", ["pointer"]),  # 521
    SyscallDef(numbers.SYS_debug_syscall_reject, "debug_syscall_reject", ["pointer"]),  # 542
    SyscallDef(
        numbers.SYS_debug_syscall_reject_config,
        "debug_syscall_reject_config",
        ["pointer", "size_t"],
    ),  # 543
]
