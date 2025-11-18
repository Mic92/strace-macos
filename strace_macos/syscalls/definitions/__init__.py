"""Syscall definitions organized by category."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


class ParamDirection(Enum):
    """Direction of parameter flow."""

    IN = "in"  # Input parameter (read at syscall entry)
    OUT = "out"  # Output parameter (read at syscall exit)


@dataclass
class StructParam:
    """Definition of a struct parameter to decode.

    Attributes:
        arg_index: Index of the argument (0-based)
        struct_name: Name of the struct type (e.g., "stat", "sockaddr")
        direction: Whether this is an input or output parameter
    """

    arg_index: int
    struct_name: str
    direction: ParamDirection


@dataclass
class BufferParam:
    """Definition of a buffer parameter to decode.

    Attributes:
        arg_index: Index of the buffer argument (0-based)
        size_arg_index: Index of the argument containing the buffer size
        direction: Whether this is an input or output buffer
    """

    arg_index: int
    size_arg_index: int
    direction: ParamDirection


@dataclass
class IovecParam:
    """Definition of an iovec array parameter to decode.

    Attributes:
        arg_index: Index of the iovec array argument (0-based)
        count_arg_index: Index of the argument containing the iovec count
        direction: Whether this is an input or output iovec array
    """

    arg_index: int
    count_arg_index: int
    direction: ParamDirection


@dataclass
class SyscallDef:
    """Definition of a single syscall.

    Attributes:
        number: Syscall number (from sys/syscall.h)
        name: Syscall name (e.g., "open", "read")
        arg_types: List of argument type hints (e.g., ["string", "int", "int"])
        arg_decoders: Optional list of decoder functions for symbolic decoding
                      (None means no decoder for that argument position)
        struct_params: Optional list of struct parameters to decode.
                       E.g., [StructParam(1, "sockaddr", ParamDirection.IN)] for bind
        buffer_params: Optional list of buffer parameters to decode.
                       E.g., [BufferParam(1, 2, ParamDirection.OUT)] for read(fd, buf, count)
        iovec_params: Optional list of iovec array parameters to decode.
                      E.g., [IovecParam(1, 2, ParamDirection.OUT)] for readv(fd, iov, iovcnt)
    """

    number: int
    name: str
    arg_types: list[str]
    arg_decoders: list[Callable[[int], str] | None] | None = field(default=None)
    struct_params: list[StructParam] | None = field(default=None)
    buffer_params: list[BufferParam] | None = field(default=None)
    iovec_params: list[IovecParam] | None = field(default=None)
