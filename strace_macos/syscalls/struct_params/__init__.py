"""Struct parameter decoders package.

This package contains individual StructParam implementations for various
system structures (winsize, stat, sockaddr, etc.).

Each module exports its Param class via __all__.
"""

from strace_macos.syscalls.struct_params.aiocb import AiocbParam
from strace_macos.syscalls.struct_params.aiocb_array import AiocbArrayParam
from strace_macos.syscalls.struct_params.attrlist import AttrListParam
from strace_macos.syscalls.struct_params.event_structs import (
    FdSetParam,
    Kevent64Param,
    KeventParam,
    PollfdParam,
    TimespecParam,
    TimevalParam,
)
from strace_macos.syscalls.struct_params.fssearchblock import FssearchblockParam
from strace_macos.syscalls.struct_params.int_ptr import FdPairParam, IntArrayParam, IntPtrParam
from strace_macos.syscalls.struct_params.iovec import IovecParam
from strace_macos.syscalls.struct_params.ipc_structs import (
    MsqidDsParam,
    SembufParam,
    SemidDsParam,
    ShmidDsParam,
)
from strace_macos.syscalls.struct_params.msghdr import MsghdrParam
from strace_macos.syscalls.struct_params.sigevent import SigeventParam
from strace_macos.syscalls.struct_params.signal_structs import (
    SigactionParam,
    SigsetParam,
    StackParam,
)
from strace_macos.syscalls.struct_params.sockaddr import SockaddrParam
from strace_macos.syscalls.struct_params.stat import StatParam
from strace_macos.syscalls.struct_params.statfs import StatfsParam
from strace_macos.syscalls.struct_params.termios import TermiosParam
from strace_macos.syscalls.struct_params.winsize import WinsizeParam

__all__ = [
    "AiocbArrayParam",
    "AiocbParam",
    "AttrListParam",
    "FdPairParam",
    "FdSetParam",
    "FssearchblockParam",
    "IntArrayParam",
    "IntPtrParam",
    "IovecParam",
    "Kevent64Param",
    "KeventParam",
    "MsghdrParam",
    "MsqidDsParam",
    "PollfdParam",
    "SembufParam",
    "SemidDsParam",
    "ShmidDsParam",
    "SigactionParam",
    "SigeventParam",
    "SigsetParam",
    "SockaddrParam",
    "StackParam",
    "StatParam",
    "StatfsParam",
    "TermiosParam",
    "TimespecParam",
    "TimevalParam",
    "WinsizeParam",
]
