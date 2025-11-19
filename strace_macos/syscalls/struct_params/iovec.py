"""Parameter decoder for iovec arrays (readv/writev).

Handles struct iovec arrays for scatter-gather I/O operations.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Any, ClassVar

from strace_macos.lldb_loader import load_lldb_module
from strace_macos.syscalls.args import BufferArg, PointerArg, StructArrayArg
from strace_macos.syscalls.definitions import Param, ParamDirection, SyscallArg


class Iovec(ctypes.Structure):
    """I/O vector (struct iovec)."""

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("iov_base", ctypes.c_void_p),  # Pointer to buffer
        ("iov_len", ctypes.c_size_t),  # Length of buffer
    ]


@dataclass
class IovecParam(Param):
    """Parameter decoder for iovec arrays (for readv/writev).

    Decodes arrays of struct iovec for scatter-gather I/O operations.
    Each iovec contains a pointer to a buffer and its length.

    Usage:
        IovecParam(count_arg_index=2, direction=ParamDirection.OUT)  # readv
        IovecParam(count_arg_index=2, direction=ParamDirection.IN)   # writev
    """

    count_arg_index: int
    direction: ParamDirection

    def decode(
        self,
        tracer: Any,  # noqa: ARG002
        process: Any,
        raw_value: int,
        all_args: list[int],
        *,
        at_entry: bool,
    ) -> SyscallArg | None:
        """Decode iovec array pointer to StructArrayArg.

        Args:
            tracer: The Tracer instance (unused)
            process: The lldb process object for reading memory
            raw_value: The raw register value (pointer to iovec array)
            all_args: All raw argument values (to get count)
            at_entry: True if decoding at syscall entry, False at exit

        Returns:
            StructArrayArg with decoded buffers, or PointerArg if not ready/failed
        """
        # Direction filtering
        if at_entry and self.direction != ParamDirection.IN:
            return PointerArg(raw_value)
        if not at_entry and self.direction != ParamDirection.OUT:
            return None

        # Skip NULL pointers
        if raw_value == 0:
            return PointerArg(0)

        # Get count from referenced argument
        if self.count_arg_index >= len(all_args):
            return PointerArg(raw_value)

        count = all_args[self.count_arg_index]

        # Validate count is reasonable
        if count < 0 or count > 1024:
            return PointerArg(raw_value)

        # Decode the iovec array
        iov_list = self._decode_array(process, raw_value, count)

        if iov_list:
            return StructArrayArg(iov_list)

        return PointerArg(raw_value)

    def _decode_array(
        self,
        process: Any,
        address: int,
        count: int,
    ) -> list[dict[str, str | int]] | None:
        """Decode an array of iovec structures.

        Args:
            process: LLDB process to read memory from
            address: Memory address of the iovec array
            count: Number of iovec elements

        Returns:
            List of iovec dictionaries with decoded buffers, or None if failed
        """
        # Limit to reasonable count
        if count <= 0 or count > 1024:
            return None

        lldb = load_lldb_module()
        error = lldb.SBError()
        iov_size = ctypes.sizeof(Iovec)
        total_size = iov_size * count

        data = process.ReadMemory(address, total_size, error)
        if error.Fail() or not data:
            return None

        iov_list = []
        for i in range(count):
            offset = i * iov_size
            try:
                iov = Iovec.from_buffer_copy(data[offset : offset + iov_size])
            except (ValueError, TypeError):
                continue

            # Read and format buffer contents
            buf_str = self._read_iovec_buffer(process, iov.iov_base, iov.iov_len)
            iov_list.append({"iov_base": buf_str, "iov_len": iov.iov_len})

        return iov_list if iov_list else None

    @staticmethod
    def _read_iovec_buffer(process: Any, address: int, size: int) -> str:
        """Read and format an iovec buffer.

        Args:
            process: LLDB process to read memory from
            address: Buffer address
            size: Buffer size

        Returns:
            Formatted buffer string
        """
        if address == 0 or size <= 0:
            return "?"

        lldb = load_lldb_module()
        error = lldb.SBError()
        read_len = min(size, 32)
        buf_data = process.ReadMemory(address, read_len, error)

        if error.Fail() or not buf_data:
            return "?"

        # For output buffers (readv), show the actual data read
        # For input buffers (writev), show the data being written
        return BufferArg.format_buffer(buf_data, max_display=32)


__all__ = ["IovecParam"]
