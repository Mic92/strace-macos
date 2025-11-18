"""Signal handling syscall definitions.

Priority 5: Lower priority, implement after core functionality works.
"""

from __future__ import annotations

from strace_macos.syscalls import numbers
from strace_macos.syscalls.definitions import (
    ConstParam,
    IntParam,
    PointerParam,
    SyscallDef,
)
from strace_macos.syscalls.symbols.process import SIG_HOW
from strace_macos.syscalls.symbols.signal import SIGNAL_NUMBERS

# All signal handling syscalls (13 total) with full argument definitions
SIGNAL_SYSCALLS: list[SyscallDef] = [
    SyscallDef(
        numbers.SYS_kill,
        "kill",
        params=[IntParam(), ConstParam(SIGNAL_NUMBERS)],
    ),  # 37
    SyscallDef(
        numbers.SYS_sigaction,
        "sigaction",
        params=[ConstParam(SIGNAL_NUMBERS), PointerParam(), PointerParam()],
    ),  # 46
    SyscallDef(numbers.SYS_sigpending, "sigpending", params=[PointerParam()]),  # 52
    SyscallDef(
        numbers.SYS_sigaltstack,
        "sigaltstack",
        params=[PointerParam(), PointerParam()],
    ),  # 53
    SyscallDef(numbers.SYS_sigsuspend, "sigsuspend", params=[PointerParam()]),  # 111
    SyscallDef(
        numbers.SYS_sigreturn,
        "sigreturn",
        params=[PointerParam(), IntParam()],
    ),  # 184
    SyscallDef(
        numbers.SYS_sigsuspend_nocancel,
        "__sigsuspend_nocancel",
        params=[PointerParam()],
    ),  # 410
    SyscallDef(
        numbers.SYS___pthread_kill,
        "__pthread_kill",
        params=[PointerParam(), ConstParam(SIGNAL_NUMBERS)],
    ),  # 328
    SyscallDef(
        numbers.SYS___pthread_sigmask,
        "__pthread_sigmask",
        params=[ConstParam(SIG_HOW), PointerParam(), PointerParam()],
    ),  # 329
    SyscallDef(
        numbers.SYS_sigprocmask,
        "sigprocmask",
        params=[ConstParam(SIG_HOW), PointerParam(), PointerParam()],
    ),  # 48 (also in process, but primarily signal)
    SyscallDef(
        numbers.SYS___sigwait,
        "__sigwait",
        params=[PointerParam(), PointerParam()],
    ),  # 330 (also in process, but primarily signal)
    SyscallDef(
        numbers.SYS___sigwait_nocancel,
        "__sigwait_nocancel",
        params=[PointerParam(), PointerParam()],
    ),  # 422
    SyscallDef(
        numbers.SYS___disable_threadsignal,
        "__disable_threadsignal",
        params=[ConstParam(SIGNAL_NUMBERS)],
    ),  # 331
]
