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

# semop flags
SEM_FLAGS: dict[int, str] = {
    0o10000: "SEM_UNDO",
}

# shmat flags
SHM_FLAGS: dict[int, str] = {
    0x1000: "SHM_RDONLY",
    0x2000: "SHM_RND",
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
