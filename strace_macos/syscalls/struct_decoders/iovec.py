"""Decoder for iovec structure (used by readv/writev).

Handles:
- struct iovec (I/O vector for scatter-gather operations)
"""

from __future__ import annotations

import ctypes
from typing import TYPE_CHECKING, ClassVar

from strace_macos.lldb_loader import load_lldb_module
from strace_macos.syscalls.args import BufferArg
from strace_macos.syscalls.struct_decoders import StructDecoder

if TYPE_CHECKING:
    import lldb


class Iovec(ctypes.Structure):
    """I/O vector (struct iovec)."""

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("iov_base", ctypes.c_void_p),  # Pointer to buffer
        ("iov_len", ctypes.c_size_t),  # Length of buffer
    ]


class IovecArrayDecoder(StructDecoder):
    """Decoder for iovec array structure."""

    struct_type = Iovec

    def decode(
        self, process: lldb.SBProcess, address: int, *, no_abbrev: bool = False
    ) -> dict[str, str | int | list] | None:
        """Decode an iovec array from process memory.

        This method is not used directly - use decode_array instead.

        Args:
            process: LLDB process to read memory from
            address: Memory address of the iovec array
            no_abbrev: If True, disable symbolic decoding (unused)

        Returns:
            None (use decode_array for iovec arrays)
        """
        _ = process, address, no_abbrev  # Unused
        return None

    def decode_array(
        self,
        process: lldb.SBProcess,
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

    def _read_iovec_buffer(self, process: lldb.SBProcess, address: int, size: int) -> str:
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
