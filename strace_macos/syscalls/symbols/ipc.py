"""IPC-related constants and decoders for macOS/Darwin."""

from __future__ import annotations

# IPC flags for semget/msgget/shmget
IPC_FLAGS: dict[int, str] = {
    0x200: "IPC_CREAT",
    0x400: "IPC_EXCL",
    0x800: "IPC_NOWAIT",
    0x100: "IPC_R",
    0x80: "IPC_W",
    0x1000: "IPC_M",
}

# IPC commands for semctl/msgctl/shmctl
IPC_COMMANDS: dict[int, str] = {
    0: "IPC_RMID",
    1: "IPC_SET",
    2: "IPC_STAT",
}

# semctl-specific commands (in addition to IPC_COMMANDS)
SEMCTL_COMMANDS: dict[int, str] = {
    0: "IPC_RMID",
    1: "IPC_SET",
    2: "IPC_STAT",
    3: "GETNCNT",
    4: "GETPID",
    5: "GETVAL",
    6: "GETALL",
    7: "GETZCNT",
    8: "SETVAL",
    9: "SETALL",
}

# semop flags
SEMOP_FLAGS: dict[int, str] = {
    0o10000: "SEM_UNDO",
}

# msgrcv flags
MSGRCV_FLAGS: dict[int, str] = {
    0o4000: "IPC_NOWAIT",  # 004000
    0o10000: "MSG_NOERROR",  # 010000
}

# shmat flags
SHM_FLAGS: dict[int, str] = {
    0o10000: "SHM_RDONLY",  # 010000
    0o20000: "SHM_RND",  # 020000
}

# AIO lio_listio modes
LIO_MODES: dict[int, str] = {
    0x1: "LIO_NOWAIT",
    0x2: "LIO_WAIT",
}

# AIO lio_listio operations (aio_lio_opcode in aiocb)
LIO_OPCODES: dict[int, str] = {
    0x0: "LIO_NOP",
    0x1: "LIO_READ",
    0x2: "LIO_WRITE",
}

# AIO cancel return values
AIO_CANCEL_RETURN: dict[int, str] = {
    0x1: "AIO_ALLDONE",
    0x2: "AIO_CANCELED",
    0x4: "AIO_NOTCANCELED",
}


def decode_ipc_flags(value: int) -> str:
    if value == 0:
        return "0"
    flags = []
    remaining = value
    for flag_val, flag_name in IPC_FLAGS.items():
        if value & flag_val:
            flags.append(flag_name)
            remaining &= ~flag_val
    if remaining & 0o777:
        flags.append(f"0{remaining & 0o777:o}")
    return "|".join(flags) if flags else hex(value)
