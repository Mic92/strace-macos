"""Signal handling syscall definitions.

Priority 5: Lower priority, implement after core functionality works.
"""

from __future__ import annotations

from strace_macos.syscalls import numbers
from strace_macos.syscalls.definitions import (
    ConstParam,
    IntParam,
    ParamDirection,
    PointerParam,
    SyscallDef,
)
from strace_macos.syscalls.struct_params import IntPtrParam, SigactionParam, SigsetParam, StackParam
from strace_macos.syscalls.symbols.process import SIG_HOW
from strace_macos.syscalls.symbols.signal import SIGNAL_NUMBERS

# Signal handling syscalls (8 with public wrappers)
SIGNAL_SYSCALLS: list[SyscallDef] = [
    SyscallDef(
        numbers.SYS_kill,
        "kill",  # Use wrapper (has correct args before signal delivery)
        params=[IntParam(), ConstParam(SIGNAL_NUMBERS)],
    ),  # 37
    SyscallDef(
        numbers.SYS_sigaction,
        "sigaction",
        params=[
            ConstParam(SIGNAL_NUMBERS),
            SigactionParam(ParamDirection.IN),  # new action
            SigactionParam(ParamDirection.OUT),  # old action
        ],
    ),  # 46
    SyscallDef(
        numbers.SYS_sigpending,
        "sigpending",
        params=[SigsetParam(ParamDirection.OUT)],
    ),  # 52
    SyscallDef(
        numbers.SYS_sigaltstack,
        "sigaltstack",
        params=[
            StackParam(ParamDirection.IN),  # new stack
            StackParam(ParamDirection.OUT),  # old stack
        ],
    ),  # 53
    SyscallDef(
        numbers.SYS_sigsuspend,
        "sigsuspend",
        params=[SigsetParam(ParamDirection.IN)],
    ),  # 111
    SyscallDef(
        numbers.SYS___pthread_kill,
        "pthread_kill",
        params=[PointerParam(), ConstParam(SIGNAL_NUMBERS)],
    ),  # 328 (public wrapper calls __pthread_kill syscall)
    SyscallDef(
        numbers.SYS___pthread_sigmask,
        "pthread_sigmask",
        params=[
            ConstParam(SIG_HOW),
            SigsetParam(ParamDirection.IN),  # new mask
            SigsetParam(ParamDirection.OUT),  # old mask
        ],
    ),  # 329 (public wrapper calls __pthread_sigmask syscall)
    SyscallDef(
        numbers.SYS_sigprocmask,
        "sigprocmask",
        params=[
            ConstParam(SIG_HOW),
            SigsetParam(ParamDirection.IN),  # new mask
            SigsetParam(ParamDirection.OUT),  # old mask
        ],
    ),  # 48
    SyscallDef(
        numbers.SYS___sigwait,
        "sigwait",
        params=[
            SigsetParam(ParamDirection.IN),  # set of signals to wait for
            IntPtrParam(ParamDirection.OUT),  # pointer to int that receives signal number
        ],
    ),  # 330 (public wrapper calls __sigwait syscall)
]
