"""Symbolic constant decoders for syscall arguments and return values."""

from __future__ import annotations

from strace_macos.syscalls.symbols.errno import decode_errno
from strace_macos.syscalls.symbols.file import (
    decode_access_mode,
    decode_file_mode,
    decode_file_type_mode,
    decode_flock_op,
    decode_ioctl_cmd,
    decode_open_flags,
)
from strace_macos.syscalls.symbols.ipc import decode_ipc_flags
from strace_macos.syscalls.symbols.memory import decode_prot_flags

__all__ = [
    "decode_access_mode",
    "decode_errno",
    "decode_file_mode",
    "decode_file_type_mode",
    "decode_flock_op",
    "decode_ioctl_cmd",
    "decode_ipc_flags",
    "decode_open_flags",
    "decode_prot_flags",
]
