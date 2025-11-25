"""Process management syscall definitions.

Priority 3: Required for process tests.
"""

from __future__ import annotations

from strace_macos.syscalls import numbers
from strace_macos.syscalls.definitions import (
    ArrayOfStringsParam,
    BufferParam,
    ConstParam,
    FlagsParam,
    IntParam,
    ParamDirection,
    PointerParam,
    StringParam,
    SyscallDef,
    UidGidParam,
    UnsignedParam,
)
from strace_macos.syscalls.struct_params import IntArrayParam, IntPtrParam
from strace_macos.syscalls.struct_params.process_structs import (
    RlimitParam,
    RusageParam,
)
from strace_macos.syscalls.symbols.process import (
    IDTYPE_CONSTANTS,
    PRIO_WHICH,
    RLIMIT_RESOURCES,
    RUSAGE_WHO,
    WAIT_OPTIONS,
    WAITID_OPTIONS,
)

# All process management syscalls (75 total) with full argument definitions
PROCESS_SYSCALLS: list[SyscallDef] = [
    SyscallDef(numbers.SYS_exit, "exit", params=[IntParam()]),  # 1
    SyscallDef(numbers.SYS_fork, "fork", params=[]),  # 2
    SyscallDef(
        numbers.SYS_wait4,
        "wait4",
        params=[
            IntParam(),
            IntPtrParam(ParamDirection.OUT),
            FlagsParam(WAIT_OPTIONS),
            RusageParam(ParamDirection.OUT),
        ],
    ),  # 7
    SyscallDef(numbers.SYS_getpid, "getpid", params=[]),  # 20
    SyscallDef(numbers.SYS_setuid, "setuid", params=[UidGidParam()]),  # 23
    SyscallDef(numbers.SYS_getuid, "getuid", params=[]),  # 24
    SyscallDef(numbers.SYS_geteuid, "geteuid", params=[]),  # 25
    SyscallDef(numbers.SYS_getppid, "getppid", params=[]),  # 39
    SyscallDef(numbers.SYS_getegid, "getegid", params=[]),  # 43
    SyscallDef(numbers.SYS_getgid, "getgid", params=[]),  # 47
    SyscallDef(
        numbers.SYS_getlogin,
        "getlogin",
        params=[BufferParam(size_arg_index=1, direction=ParamDirection.OUT), UnsignedParam()],
    ),  # 49
    SyscallDef(numbers.SYS_setlogin, "setlogin", params=[StringParam()]),  # 50
    SyscallDef(
        numbers.SYS_execve,
        "execve",
        params=[StringParam(), ArrayOfStringsParam(), ArrayOfStringsParam()],
    ),  # 59
    SyscallDef(numbers.SYS_vfork, "vfork", params=[]),  # 66
    SyscallDef(
        numbers.SYS_oslog_coproc_reg,
        "oslog_coproc_reg",
        params=[PointerParam(), UnsignedParam()],
    ),  # 67
    SyscallDef(
        numbers.SYS_oslog_coproc,
        "oslog_coproc",
        params=[PointerParam(), UnsignedParam(), UnsignedParam()],
    ),  # 68
    SyscallDef(
        numbers.SYS_getgroups,
        "getgroups",
        params=[UnsignedParam(), IntArrayParam(count_arg_index=0, direction=ParamDirection.OUT)],
    ),  # 79
    SyscallDef(
        numbers.SYS_setgroups,
        "setgroups",
        params=[UnsignedParam(), IntArrayParam(count_arg_index=0, direction=ParamDirection.IN)],
    ),  # 80
    SyscallDef(numbers.SYS_getpgrp, "getpgrp", params=[]),  # 81
    SyscallDef(numbers.SYS_setpgid, "setpgid", params=[IntParam(), IntParam()]),  # 82
    SyscallDef(numbers.SYS_setreuid, "setreuid", params=[UidGidParam(), UidGidParam()]),  # 126
    SyscallDef(numbers.SYS_setregid, "setregid", params=[UidGidParam(), UidGidParam()]),  # 127
    SyscallDef(
        numbers.SYS_setpriority,
        "setpriority",
        params=[ConstParam(PRIO_WHICH), IntParam(), IntParam()],
    ),  # 96
    SyscallDef(
        numbers.SYS_getpriority,
        "getpriority",
        params=[ConstParam(PRIO_WHICH), IntParam()],
    ),  # 100
    SyscallDef(
        numbers.SYS_getrusage,
        "getrusage",
        params=[
            ConstParam(RUSAGE_WHO),  # who (int = 32-bit)
            RusageParam(ParamDirection.OUT),  # rusage (struct rusage output)
        ],
    ),  # 117
    SyscallDef(numbers.SYS_setsid, "setsid", params=[]),  # 147
    SyscallDef(numbers.SYS_getpgid, "getpgid", params=[IntParam()]),  # 151
    SyscallDef(numbers.SYS_setprivexec, "setprivexec", params=[IntParam()]),  # 152
    SyscallDef(
        numbers.SYS_waitid,
        "waitid",
        params=[
            ConstParam(IDTYPE_CONSTANTS),
            UnsignedParam(),
            PointerParam(),
            FlagsParam(WAITID_OPTIONS),
        ],
    ),  # 173
    SyscallDef(numbers.SYS_setgid, "setgid", params=[UidGidParam()]),  # 181
    SyscallDef(numbers.SYS_setegid, "setegid", params=[UidGidParam()]),  # 182
    SyscallDef(numbers.SYS_seteuid, "seteuid", params=[UidGidParam()]),  # 183
    SyscallDef(
        numbers.SYS_getrlimit,
        "getrlimit",
        params=[
            ConstParam(RLIMIT_RESOURCES),  # resource
            RlimitParam(ParamDirection.OUT),  # rlp (struct rlimit output)
        ],
    ),  # 194
    SyscallDef(
        numbers.SYS_setrlimit,
        "setrlimit",
        params=[
            ConstParam(RLIMIT_RESOURCES),  # resource
            RlimitParam(ParamDirection.IN),  # rlp (struct rlimit input)
        ],
    ),  # 195
    SyscallDef(
        numbers.SYS_initgroups,
        "initgroups",
        params=[StringParam(), IntParam(), PointerParam(), UnsignedParam()],
    ),  # 243
    SyscallDef(
        numbers.SYS_posix_spawn,
        "posix_spawn",
        params=[
            IntPtrParam(ParamDirection.OUT),  # pid_t *pid
            StringParam(),  # const char *path
            PointerParam(),  # const posix_spawn_file_actions_t *file_actions
            PointerParam(),  # const posix_spawnattr_t *attrp
            ArrayOfStringsParam(),  # char *const argv[]
            ArrayOfStringsParam(),  # char *const envp[]
        ],
    ),  # 244
    SyscallDef(numbers.SYS_sem_wait, "sem_wait", params=[PointerParam()]),  # 271
    SyscallDef(numbers.SYS_sem_trywait, "sem_trywait", params=[PointerParam()]),  # 272
    SyscallDef(numbers.SYS_getsid, "getsid", params=[IntParam()]),  # 310
    SyscallDef(numbers.SYS_issetugid, "issetugid", params=[]),  # 327
    SyscallDef(
        numbers.SYS___semwait_signal,
        "__semwait_signal",
        params=[
            IntParam(),
            IntParam(),
            IntParam(),
            IntParam(),
            IntParam(),
            IntParam(),
        ],
    ),  # 334
    SyscallDef(
        numbers.SYS_workq_kernreturn,
        "workq_kernreturn",
        params=[IntParam(), PointerParam(), IntParam(), IntParam()],
    ),  # 368
    SyscallDef(
        numbers.SYS___mac_execve,
        "__mac_execve",
        params=[StringParam(), ArrayOfStringsParam(), ArrayOfStringsParam(), PointerParam()],
    ),  # 380
    SyscallDef(numbers.SYS___mac_get_proc, "__mac_get_proc", params=[PointerParam()]),  # 386
    SyscallDef(numbers.SYS___mac_set_proc, "__mac_set_proc", params=[PointerParam()]),  # 387
    SyscallDef(
        numbers.SYS___mac_get_pid,
        "__mac_get_pid",
        params=[IntParam(), PointerParam()],
    ),  # 390
    SyscallDef(
        numbers.SYS_sfi_pidctl,
        "sfi_pidctl",
        params=[UnsignedParam(), IntParam(), UnsignedParam()],
    ),  # 457
    SyscallDef(
        numbers.SYS_coalition,
        "coalition",
        params=[UnsignedParam(), PointerParam(), UnsignedParam()],
    ),  # 458
    SyscallDef(
        numbers.SYS_coalition_info,
        "coalition_info",
        params=[UnsignedParam(), PointerParam(), PointerParam(), UnsignedParam()],
    ),  # 459
    SyscallDef(
        numbers.SYS_persona,
        "persona",
        params=[
            UnsignedParam(),
            UnsignedParam(),
            PointerParam(),
            PointerParam(),
            UnsignedParam(),
            PointerParam(),
        ],
    ),  # 494
    SyscallDef(
        numbers.SYS_ulock_wait,
        "ulock_wait",
        params=[UnsignedParam(), PointerParam(), UnsignedParam(), UnsignedParam()],
    ),  # 515
    SyscallDef(
        numbers.SYS_coalition_ledger,
        "coalition_ledger",
        params=[UnsignedParam(), UnsignedParam(), PointerParam(), UnsignedParam()],
    ),  # 532
    SyscallDef(
        numbers.SYS_task_inspect_for_pid,
        "task_inspect_for_pid",
        params=[IntParam(), IntParam(), UnsignedParam()],
    ),  # 538
    SyscallDef(
        numbers.SYS_ulock_wait2,
        "ulock_wait2",
        params=[
            UnsignedParam(),
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
            UnsignedParam(),
        ],
    ),  # 544
    SyscallDef(
        numbers.SYS_coalition_policy_set,
        "coalition_policy_set",
        params=[UnsignedParam(), UnsignedParam(), PointerParam(), UnsignedParam()],
    ),  # 556
    SyscallDef(
        numbers.SYS_coalition_policy_get,
        "coalition_policy_get",
        params=[UnsignedParam(), UnsignedParam(), PointerParam(), UnsignedParam()],
    ),  # 557
]
