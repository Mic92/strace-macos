"""Struct aiocb parameter decoder.

This module contains the AiocbParam class for decoding syscall arguments that
point to struct aiocb (POSIX asynchronous I/O control block).
"""

from __future__ import annotations

import ctypes
from typing import ClassVar

from strace_macos.syscalls.definitions import ParamDirection, StructParamBase
from strace_macos.syscalls.symbols.ipc import LIO_OPCODES


class AiocbStruct(ctypes.Structure):
    """ctypes definition for struct aiocb on macOS.

    This matches the Darwin aiocb structure layout.
    Total size varies due to embedded sigevent structure.
    """

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("aio_fildes", ctypes.c_int),  # File descriptor
        ("aio_offset", ctypes.c_int64),  # File offset (off_t)
        ("aio_buf", ctypes.c_void_p),  # Location of buffer
        ("aio_nbytes", ctypes.c_size_t),  # Length of transfer
        ("aio_reqprio", ctypes.c_int),  # Request priority offset
        # aio_sigevent is struct sigevent - we skip detailed decoding for now
        ("aio_sigevent_notify", ctypes.c_int),  # First field of sigevent
        ("aio_sigevent_padding", ctypes.c_byte * 60),  # Rest of sigevent (approximate)
        ("aio_lio_opcode", ctypes.c_int),  # Operation to be performed
    ]


class AiocbParam(StructParamBase):
    """Parameter decoder for struct aiocb on macOS.

    Decodes asynchronous I/O control block showing file descriptor, offset,
    buffer, number of bytes, and operation type.

    Usage:
        AiocbParam(ParamDirection.IN)   # For aio_read, aio_write, lio_listio
        AiocbParam(ParamDirection.IN)   # For aio_cancel, aio_error, aio_return
    """

    struct_type = AiocbStruct

    # Exclude internal padding and detailed sigevent decoding
    excluded_fields: ClassVar[set[str]] = {
        "aio_sigevent_notify",
        "aio_sigevent_padding",
        "aio_reqprio",  # Usually 0, not very interesting
    }

    # Custom formatters for specific fields
    field_formatters: ClassVar[dict[str, str]] = {
        "aio_lio_opcode": "_decode_lio_opcode",
    }

    def __init__(self, direction: ParamDirection) -> None:
        """Initialize AiocbParam with direction."""
        self.direction = direction

    def _decode_lio_opcode(self, opcode: int, *, no_abbrev: bool) -> str:
        """Decode aio_lio_opcode into symbolic constant.

        Args:
            opcode: aio_lio_opcode value
            no_abbrev: If True, show raw value instead of symbolic

        Returns:
            String like "LIO_READ" or raw value
        """
        if no_abbrev:
            return str(opcode)

        return LIO_OPCODES.get(opcode, str(opcode))


__all__ = [
    "AiocbParam",
]
