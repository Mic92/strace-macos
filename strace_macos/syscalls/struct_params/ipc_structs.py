"""System V IPC struct parameter decoders.

This module contains parameter decoders for System V IPC structures:
- msqid_ds (message queue)
- semid_ds (semaphore set)
- shmid_ds (shared memory)
- sembuf (semaphore operation)
"""

from __future__ import annotations

import ctypes
from typing import ClassVar

from strace_macos.syscalls.definitions import ParamDirection, StructParamBase
from strace_macos.syscalls.symbols.ipc import SEMOP_FLAGS


# IPC perm structure (common to all IPC structures)
class IpcPermStruct(ctypes.Structure):
    """ctypes definition for struct ipc_perm on macOS."""

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("uid", ctypes.c_uint32),  # Owner's user ID
        ("gid", ctypes.c_uint32),  # Owner's group ID
        ("cuid", ctypes.c_uint32),  # Creator's user ID
        ("cgid", ctypes.c_uint32),  # Creator's group ID
        ("mode", ctypes.c_uint16),  # Permission mode
        ("_seq", ctypes.c_uint16),  # Sequence number
        ("_key", ctypes.c_int32),  # IPC key
    ]


class MsqidDsStruct(ctypes.Structure):
    """ctypes definition for struct msqid_ds on macOS."""

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("msg_perm", IpcPermStruct),  # Operation permission struct
        ("msg_first", ctypes.c_int32),  # Reserved/kernel use
        ("msg_last", ctypes.c_int32),  # Reserved/kernel use
        ("msg_cbytes", ctypes.c_uint64),  # Number of bytes on the queue
        ("msg_qnum", ctypes.c_uint64),  # Number of messages on the queue
        ("msg_qbytes", ctypes.c_uint64),  # Max bytes on the queue
        ("msg_lspid", ctypes.c_int32),  # PID of last msgsnd()
        ("msg_lrpid", ctypes.c_int32),  # PID of last msgrcv()
        ("msg_stime", ctypes.c_int64),  # Time of last msgsnd()
        ("msg_pad1", ctypes.c_int32),  # Reserved
        ("msg_rtime", ctypes.c_int64),  # Time of last msgrcv()
        ("msg_pad2", ctypes.c_int32),  # Reserved
        ("msg_ctime", ctypes.c_int64),  # Time of last msgctl()
        ("msg_pad3", ctypes.c_int32),  # Reserved
        ("msg_pad4", ctypes.c_int32 * 4),  # Reserved
    ]


class SemidDsStruct(ctypes.Structure):
    """ctypes definition for struct semid_ds on macOS."""

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("sem_perm", IpcPermStruct),  # Operation permission struct
        ("sem_base", ctypes.c_int32),  # Base pointer (kernel use)
        ("sem_nsems", ctypes.c_uint16),  # Number of semaphores in set
        ("sem_otime", ctypes.c_int64),  # Last semop time
        ("sem_pad1", ctypes.c_int32),  # Reserved
        ("sem_ctime", ctypes.c_int64),  # Last change time
        ("sem_pad2", ctypes.c_int32),  # Reserved
        ("sem_pad3", ctypes.c_int32 * 4),  # Reserved
    ]


class ShmidDsStruct(ctypes.Structure):
    """ctypes definition for struct shmid_ds on macOS."""

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("shm_perm", IpcPermStruct),  # Operation permission struct
        ("shm_segsz", ctypes.c_size_t),  # Size of segment in bytes
        ("shm_lpid", ctypes.c_int32),  # PID of last shmat/shmdt
        ("shm_cpid", ctypes.c_int32),  # PID of creator
        ("shm_nattch", ctypes.c_uint16),  # Number of current attaches
        ("shm_atime", ctypes.c_int64),  # Time of last shmat()
        ("shm_dtime", ctypes.c_int64),  # Time of last shmdt()
        ("shm_ctime", ctypes.c_int64),  # Time of last shmctl()
        ("shm_internal", ctypes.c_void_p),  # Reserved for kernel use
    ]


class SembufStruct(ctypes.Structure):
    """ctypes definition for struct sembuf on macOS."""

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("sem_num", ctypes.c_uint16),  # Semaphore number
        ("sem_op", ctypes.c_int16),  # Semaphore operation
        ("sem_flg", ctypes.c_int16),  # Operation flags
    ]


class MsqidDsParam(StructParamBase):
    """Parameter decoder for struct msqid_ds on macOS."""

    struct_type = MsqidDsStruct

    excluded_fields: ClassVar[set[str]] = {
        "msg_first",
        "msg_last",
        "msg_pad1",
        "msg_pad2",
        "msg_pad3",
        "msg_pad4",
        "msg_perm",  # Exclude nested struct for brevity
    }

    def __init__(self, direction: ParamDirection) -> None:
        """Initialize MsqidDsParam with direction."""
        self.direction = direction


class SemidDsParam(StructParamBase):
    """Parameter decoder for struct semid_ds on macOS."""

    struct_type = SemidDsStruct

    excluded_fields: ClassVar[set[str]] = {
        "sem_base",
        "sem_pad1",
        "sem_pad2",
        "sem_pad3",
        "sem_perm",  # Exclude nested struct for brevity
    }

    def __init__(self, direction: ParamDirection) -> None:
        """Initialize SemidDsParam with direction."""
        self.direction = direction


class ShmidDsParam(StructParamBase):
    """Parameter decoder for struct shmid_ds on macOS."""

    struct_type = ShmidDsStruct

    excluded_fields: ClassVar[set[str]] = {
        "shm_internal",
        "shm_perm",  # Exclude nested struct for brevity
    }

    def __init__(self, direction: ParamDirection) -> None:
        """Initialize ShmidDsParam with direction."""
        self.direction = direction


class SembufParam(StructParamBase):
    """Parameter decoder for struct sembuf on macOS."""

    struct_type = SembufStruct

    # Custom formatters for specific fields
    field_formatters: ClassVar[dict[str, str]] = {
        "sem_flg": "_decode_sem_flg",
    }

    def __init__(self, direction: ParamDirection) -> None:
        """Initialize SembufParam with direction."""
        self.direction = direction

    def _decode_sem_flg(self, flags: int, *, no_abbrev: bool) -> str:
        """Decode sem_flg into symbolic flags.

        Args:
            flags: sem_flg value
            no_abbrev: If True, show raw value instead of symbolic

        Returns:
            String like "SEM_UNDO|IPC_NOWAIT" or raw value
        """
        if no_abbrev or flags == 0:
            return str(flags)

        parts = []
        for flag_val, flag_name in SEMOP_FLAGS.items():
            if flags & flag_val:
                parts.append(flag_name)
                flags &= ~flag_val

        if flags:  # Remaining unknown flags
            parts.append(f"0x{flags:x}")

        return "|".join(parts) if parts else "0"


__all__ = [
    "MsqidDsParam",
    "SembufParam",
    "SemidDsParam",
    "ShmidDsParam",
]
