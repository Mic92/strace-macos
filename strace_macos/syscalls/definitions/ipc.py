"""IPC (Inter-Process Communication) syscall definitions.

Priority 6: Lower priority, implement after core functionality works.
"""

from __future__ import annotations

from strace_macos.syscalls import numbers
from strace_macos.syscalls.definitions import (
    ConstParam,
    CustomParam,
    FileDescriptorParam,
    FlagsParam,
    IntParam,
    ParamDirection,
    PointerParam,
    SyscallDef,
    UnsignedParam,
)
from strace_macos.syscalls.struct_params import (
    AiocbArrayParam,
    AiocbParam,
    MsqidDsParam,
    SemidDsParam,
    ShmidDsParam,
    SigeventParam,
)
from strace_macos.syscalls.symbols.ipc import (
    IPC_COMMANDS,
    LIO_MODES,
    MSGRCV_FLAGS,
    SEMCTL_COMMANDS,
    SHM_FLAGS,
    decode_ipc_flags,
)

# All IPC syscalls (48 total) with full argument definitions
IPC_SYSCALLS: list[SyscallDef] = [
    # I/O multiplexing
    SyscallDef(
        numbers.SYS_select,
        "select",
        params=[
            IntParam(),
            PointerParam(),
            PointerParam(),
            PointerParam(),
            PointerParam(),
        ],
    ),  # 93
    SyscallDef(
        numbers.SYS_poll,
        "poll",
        params=[PointerParam(), UnsignedParam(), IntParam()],
    ),  # 230
    SyscallDef(
        numbers.SYS_pselect,
        "pselect",
        params=[
            IntParam(),
            PointerParam(),
            PointerParam(),
            PointerParam(),
            PointerParam(),
            PointerParam(),
        ],
    ),  # 312
    SyscallDef(
        numbers.SYS_select_nocancel,
        "__select_nocancel",
        params=[
            IntParam(),
            PointerParam(),
            PointerParam(),
            PointerParam(),
            PointerParam(),
        ],
    ),  # 407
    SyscallDef(
        numbers.SYS_pselect_nocancel,
        "__pselect_nocancel",
        params=[
            IntParam(),
            PointerParam(),
            PointerParam(),
            PointerParam(),
            PointerParam(),
            PointerParam(),
        ],
    ),  # 417
    SyscallDef(
        numbers.SYS_poll_nocancel,
        "__poll_nocancel",
        params=[PointerParam(), UnsignedParam(), IntParam()],
    ),  # 427
    # System V IPC
    SyscallDef(
        numbers.SYS_semsys,
        "semsys",
        params=[IntParam(), IntParam(), IntParam(), IntParam(), IntParam()],
    ),  # 251
    SyscallDef(
        numbers.SYS_msgsys,
        "msgsys",
        params=[IntParam(), IntParam(), IntParam(), IntParam(), IntParam()],
    ),  # 252
    SyscallDef(
        numbers.SYS_shmsys,
        "shmsys",
        params=[IntParam(), IntParam(), IntParam(), IntParam()],
    ),  # 253
    SyscallDef(
        numbers.SYS_semctl,
        "semctl",
        params=[
            IntParam(),
            IntParam(),
            ConstParam(SEMCTL_COMMANDS),
            SemidDsParam(ParamDirection.OUT),
        ],
        variadic_start=3,  # Fourth argument is variadic
    ),  # 254
    SyscallDef(
        numbers.SYS_semget,
        "semget",
        params=[IntParam(), IntParam(), CustomParam(decode_ipc_flags)],
    ),  # 255 - Keep CustomParam because decode_ipc_flags has special octal mode logic
    SyscallDef(
        numbers.SYS_semop,
        "semop",
        params=[IntParam(), PointerParam(), UnsignedParam()],
    ),  # 256
    SyscallDef(
        numbers.SYS_msgctl,
        "msgctl",
        params=[
            IntParam(),
            ConstParam(IPC_COMMANDS),
            MsqidDsParam(ParamDirection.OUT),
        ],
    ),  # 258
    SyscallDef(
        numbers.SYS_msgget,
        "msgget",
        params=[IntParam(), CustomParam(decode_ipc_flags)],
    ),  # 259 - Keep CustomParam because decode_ipc_flags has special octal mode logic
    SyscallDef(
        numbers.SYS_msgsnd,
        "msgsnd",
        params=[
            IntParam(),
            PointerParam(),
            UnsignedParam(),
            FlagsParam(MSGRCV_FLAGS),
        ],
    ),  # 260
    SyscallDef(
        numbers.SYS_msgrcv,
        "msgrcv",
        params=[
            IntParam(),
            PointerParam(),
            UnsignedParam(),
            IntParam(),
            FlagsParam(MSGRCV_FLAGS),
        ],
    ),  # 261
    SyscallDef(
        numbers.SYS_shmat,
        "shmat",
        params=[IntParam(), PointerParam(), FlagsParam(SHM_FLAGS)],
    ),  # 262
    SyscallDef(
        numbers.SYS_shmctl,
        "shmctl",
        params=[
            IntParam(),
            ConstParam(IPC_COMMANDS),
            ShmidDsParam(ParamDirection.OUT),
        ],
    ),  # 263
    SyscallDef(
        numbers.SYS_shmdt,
        "shmdt",
        params=[PointerParam()],
    ),  # 264
    SyscallDef(
        numbers.SYS_shmget,
        "shmget",
        params=[IntParam(), UnsignedParam(), CustomParam(decode_ipc_flags)],
    ),  # 265 - Keep CustomParam because decode_ipc_flags has special octal mode logic
    # POSIX semaphores
    SyscallDef(
        numbers.SYS_sem_wait,
        "sem_wait",
        params=[PointerParam()],
    ),  # 271
    SyscallDef(
        numbers.SYS_sem_trywait,
        "sem_trywait",
        params=[PointerParam()],
    ),  # 272
    SyscallDef(
        numbers.SYS_sem_post,
        "sem_post",
        params=[PointerParam()],
    ),  # 273
    # Async I/O
    SyscallDef(
        numbers.SYS_aio_return,
        "aio_return",
        params=[AiocbParam(ParamDirection.IN)],
    ),  # 314
    SyscallDef(
        numbers.SYS_aio_suspend,
        "aio_suspend",
        params=[
            AiocbArrayParam(count_arg_index=1, direction=ParamDirection.IN),
            IntParam(),
            PointerParam(),  # struct timespec* timeout
        ],
    ),  # 315
    SyscallDef(
        numbers.SYS_aio_cancel,
        "aio_cancel",
        params=[FileDescriptorParam(), AiocbParam(ParamDirection.IN)],
    ),  # 316
    SyscallDef(
        numbers.SYS_aio_error,
        "aio_error",
        params=[AiocbParam(ParamDirection.IN)],
    ),  # 317
    SyscallDef(
        numbers.SYS_lio_listio,
        "lio_listio",
        params=[
            ConstParam(LIO_MODES),
            AiocbArrayParam(count_arg_index=2, direction=ParamDirection.IN),
            IntParam(),
            SigeventParam(ParamDirection.IN),
        ],
    ),  # 320
    # kqueue
    SyscallDef(
        numbers.SYS_kqueue,
        "kqueue",
        params=[],
    ),  # 362
    SyscallDef(
        numbers.SYS_kevent,
        "kevent",
        params=[
            IntParam(),
            PointerParam(),
            IntParam(),
            PointerParam(),
            IntParam(),
            PointerParam(),
        ],
    ),  # 363
    SyscallDef(
        numbers.SYS_kevent64,
        "kevent64",
        params=[
            IntParam(),
            PointerParam(),
            IntParam(),
            PointerParam(),
            IntParam(),
            UnsignedParam(),
            PointerParam(),
        ],
    ),  # 369
    SyscallDef(
        numbers.SYS_kevent_qos,
        "kevent_qos",
        params=[
            IntParam(),
            PointerParam(),
            IntParam(),
            PointerParam(),
            IntParam(),
            PointerParam(),
            PointerParam(),
            UnsignedParam(),
        ],
    ),  # 374
    SyscallDef(
        numbers.SYS_kevent_id,
        "kevent_id",
        params=[
            UnsignedParam(),
            PointerParam(),
            IntParam(),
            PointerParam(),
            IntParam(),
            PointerParam(),
            PointerParam(),
            UnsignedParam(),
        ],
    ),  # 375
    # Pthread synchronization (psynch)
    SyscallDef(
        numbers.SYS_psynch_rw_rdlock,
        "psynch_rw_rdlock",
        params=[
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
            UnsignedParam(),
            IntParam(),
        ],
    ),  # 301
    SyscallDef(
        numbers.SYS_psynch_rw_wrlock,
        "psynch_rw_wrlock",
        params=[
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
            UnsignedParam(),
            IntParam(),
        ],
    ),  # 302
    SyscallDef(
        numbers.SYS_psynch_rw_unlock,
        "psynch_rw_unlock",
        params=[
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
            UnsignedParam(),
            IntParam(),
        ],
    ),  # 303
    SyscallDef(
        numbers.SYS_psynch_cvwait,
        "psynch_cvwait",
        params=[
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
            UnsignedParam(),
            UnsignedParam(),
        ],
    ),  # 305
    SyscallDef(
        numbers.SYS_psynch_cvbroad,
        "psynch_cvbroad",
        params=[
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
            UnsignedParam(),
            UnsignedParam(),
        ],
    ),  # 303
    SyscallDef(
        numbers.SYS_psynch_cvsignal,
        "psynch_cvsignal",
        params=[
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
            UnsignedParam(),
            UnsignedParam(),
        ],
    ),  # 304
    SyscallDef(
        numbers.SYS_psynch_mutexwait,
        "psynch_mutexwait",
        params=[
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
            UnsignedParam(),
            UnsignedParam(),
        ],
    ),  # 301
    SyscallDef(
        numbers.SYS_psynch_mutexdrop,
        "psynch_mutexdrop",
        params=[
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
            UnsignedParam(),
            UnsignedParam(),
        ],
    ),  # 302
    # Non-cancelable variants
    SyscallDef(
        numbers.SYS_msgsnd_nocancel,
        "__msgsnd_nocancel",
        params=[
            IntParam(),
            PointerParam(),
            UnsignedParam(),
            FlagsParam(MSGRCV_FLAGS),
        ],
    ),  # 418
    SyscallDef(
        numbers.SYS_msgrcv_nocancel,
        "__msgrcv_nocancel",
        params=[
            IntParam(),
            PointerParam(),
            UnsignedParam(),
            IntParam(),
            FlagsParam(MSGRCV_FLAGS),
        ],
    ),  # 419
    SyscallDef(
        numbers.SYS_aio_suspend_nocancel,
        "__aio_suspend_nocancel",
        params=[PointerParam(), IntParam(), PointerParam()],  # Array of aiocb*, count, timeout
    ),  # 421
    SyscallDef(
        numbers.SYS_sem_wait_nocancel,
        "__sem_wait_nocancel",
        params=[PointerParam()],
    ),  # 420
    # Other IPC
    SyscallDef(
        numbers.SYS_guarded_kqueue_np,
        "guarded_kqueue_np",
        params=[PointerParam(), IntParam()],
    ),  # 443
    SyscallDef(
        numbers.SYS_ulock_wake,
        "ulock_wake",
        params=[UnsignedParam(), PointerParam(), UnsignedParam()],
    ),  # 516
    SyscallDef(
        numbers.SYS_kqueue_workloop_ctl,
        "kqueue_workloop_ctl",
        params=[PointerParam(), UnsignedParam(), PointerParam(), UnsignedParam()],
    ),  # 530
]
