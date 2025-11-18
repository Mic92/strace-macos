"""Decoder for msghdr structure (used by sendmsg/recvmsg).

Handles:
- struct msghdr
- struct iovec (I/O vector for scatter-gather)
"""

from __future__ import annotations

import ctypes
from typing import TYPE_CHECKING, ClassVar

from strace_macos.lldb_loader import load_lldb_module
from strace_macos.syscalls.args import BufferArg
from strace_macos.syscalls.struct_decoders import StructDecoder

if TYPE_CHECKING:
    import lldb


# Define ctypes structures for msghdr and iovec
class Iovec(ctypes.Structure):
    """I/O vector (struct iovec)."""

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("iov_base", ctypes.c_void_p),  # Pointer to buffer
        ("iov_len", ctypes.c_size_t),  # Length of buffer
    ]


class Msghdr(ctypes.Structure):
    """Message header (struct msghdr)."""

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("msg_name", ctypes.c_void_p),  # Optional address
        ("msg_namelen", ctypes.c_uint32),  # Size of address
        ("msg_iov", ctypes.c_void_p),  # Scatter/gather array
        ("msg_iovlen", ctypes.c_int),  # # elements in msg_iov
        ("msg_control", ctypes.c_void_p),  # Ancillary data
        ("msg_controllen", ctypes.c_uint32),  # Ancillary data buffer len
        ("msg_flags", ctypes.c_int),  # Flags on received message
    ]


class MsghdrDecoder(StructDecoder):
    """Decoder for msghdr structure."""

    struct_type = Msghdr

    def decode(
        self, process: lldb.SBProcess, address: int, *, no_abbrev: bool = False
    ) -> dict[str, str | int | list] | None:
        """Decode a msghdr structure from process memory.

        Args:
            process: LLDB process to read memory from
            address: Memory address of the struct
            no_abbrev: If True, disable symbolic decoding (unused)

        Returns:
            Dictionary of field names to decoded values, or None if read failed
        """
        _ = no_abbrev  # Unused for now, but part of base class interface

        # Read msghdr structure
        msghdr = self._read_struct(process, address, Msghdr)
        if not msghdr:
            return None

        result: dict[str, str | int | list] = {}

        # Decode msg_name (optional sockaddr)
        result["msg_name"] = self._format_pointer(msghdr.msg_name)
        result["msg_namelen"] = msghdr.msg_namelen if msghdr.msg_name else 0

        # Decode msg_iov (I/O vector array)
        if msghdr.msg_iov is None or msghdr.msg_iov == 0 or msghdr.msg_iovlen == 0:
            result["msg_iov"] = "NULL"
            result["msg_iovlen"] = 0
        else:
            iov_array = self._decode_iovec_array(process, msghdr.msg_iov, msghdr.msg_iovlen)
            if iov_array:
                result["msg_iov"] = iov_array
                result["msg_iovlen"] = msghdr.msg_iovlen
            else:
                result["msg_iov"] = self._format_pointer(msghdr.msg_iov)
                result["msg_iovlen"] = msghdr.msg_iovlen

        # Decode msg_control (ancillary data)
        result["msg_control"] = self._format_pointer(msghdr.msg_control)
        result["msg_controllen"] = msghdr.msg_controllen if msghdr.msg_control else 0

        # msg_flags
        if msghdr.msg_flags != 0:
            result["msg_flags"] = msghdr.msg_flags

        return result

    def _decode_iovec_array(
        self, process: lldb.SBProcess, address: int, count: int
    ) -> list[dict[str, str | int]] | None:
        """Decode an array of iovec structures.

        Args:
            process: LLDB process to read memory from
            address: Memory address of the iovec array
            count: Number of iovec elements

        Returns:
            List of iovec dictionaries, or None if failed
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

        return BufferArg.format_buffer(buf_data, max_display=32)
