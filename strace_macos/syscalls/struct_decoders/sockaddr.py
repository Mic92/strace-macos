"""Decoders for socket address structures (struct sockaddr and variants).

Handles:
- struct sockaddr_un (Unix domain sockets)
- struct sockaddr_in (IPv4)
- struct sockaddr_in6 (IPv6)
- Generic struct sockaddr (just sa_family)
"""

from __future__ import annotations

import ctypes
import socket
from typing import TYPE_CHECKING, ClassVar

from strace_macos.syscalls.struct_decoders import StructDecoder
from strace_macos.syscalls.symbols.network import AF_CONSTANTS

if TYPE_CHECKING:
    import lldb


# Define ctypes structures for different sockaddr types
class SockaddrBase(ctypes.Structure):
    """Base sockaddr structure - just the family field."""

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("sa_len", ctypes.c_uint8),  # macOS has sa_len field
        ("sa_family", ctypes.c_uint8),
    ]


class SockaddrUn(ctypes.Structure):
    """Unix domain socket address (struct sockaddr_un)."""

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("sun_len", ctypes.c_uint8),
        ("sun_family", ctypes.c_uint8),
        ("sun_path", ctypes.c_char * 104),  # 104 bytes on macOS
    ]


class SockaddrIn(ctypes.Structure):
    """IPv4 socket address (struct sockaddr_in)."""

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("sin_len", ctypes.c_uint8),
        ("sin_family", ctypes.c_uint8),
        ("sin_port", ctypes.c_uint16),
        ("sin_addr", ctypes.c_uint32),
        ("sin_zero", ctypes.c_char * 8),
    ]


class SockaddrIn6(ctypes.Structure):
    """IPv6 socket address (struct sockaddr_in6)."""

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("sin6_len", ctypes.c_uint8),
        ("sin6_family", ctypes.c_uint8),
        ("sin6_port", ctypes.c_uint16),
        ("sin6_flowinfo", ctypes.c_uint32),
        ("sin6_addr", ctypes.c_uint8 * 16),
        ("sin6_scope_id", ctypes.c_uint32),
    ]


class SockaddrDecoder(StructDecoder):
    """Decoder for socket address structures.

    Automatically detects the sockaddr type based on sa_family and
    decodes the appropriate structure variant.
    """

    # We don't set struct_type here since we dynamically choose based on sa_family
    struct_type = None

    excluded_fields: ClassVar[set[str]] = {"sin_zero", "sun_len", "sin_len", "sin6_len"}

    def decode(
        self, process: lldb.SBProcess, address: int, *, no_abbrev: bool = False
    ) -> dict[str, str | int | list] | None:
        """Decode a sockaddr structure from process memory.

        Args:
            process: LLDB process to read memory from
            address: Memory address of the struct
            no_abbrev: If True, disable symbolic decoding (unused)

        Returns:
            Dictionary of field names to decoded values, or None if read failed
        """
        _ = no_abbrev  # Unused for now, but part of base class interface

        # Read just the family field to determine the type
        sa_family = self._read_family(process, address)
        if sa_family is None:
            return None

        # Dispatch to family-specific decoder
        if sa_family == 1:  # AF_UNIX
            return self._decode_unix(process, address)
        if sa_family == 2:  # AF_INET
            return self._decode_inet(process, address)
        if sa_family == 30:  # AF_INET6
            return self._decode_inet6(process, address)

        # Unknown family - just return the family field
        family_name = AF_CONSTANTS.get(sa_family, str(sa_family))
        return {"sa_family": family_name}

    def _read_family(self, process: lldb.SBProcess, address: int) -> int | None:
        """Read the sa_family field from a sockaddr.

        Args:
            process: LLDB process to read memory from
            address: Memory address of the sockaddr

        Returns:
            The sa_family value, or None if read failed
        """
        base = self._read_struct(process, address, SockaddrBase)
        return base.sa_family if base else None

    def _decode_unix(self, process: lldb.SBProcess, address: int) -> dict[str, str | int | list]:
        """Decode AF_UNIX sockaddr.

        Args:
            process: LLDB process to read memory from
            address: Memory address of the sockaddr_un

        Returns:
            Dictionary with sa_family and sun_path fields
        """
        struct_obj = self._read_struct(process, address, SockaddrUn)
        if not struct_obj:
            return {"sa_family": "AF_UNIX"}

        result: dict[str, str | int | list] = {"sa_family": "AF_UNIX"}

        # Extract the path (null-terminated string)
        sun_path = struct_obj.sun_path
        if isinstance(sun_path, bytes):
            null_pos = sun_path.find(b"\x00")
            if null_pos >= 0:
                sun_path = sun_path[:null_pos]
            try:
                path_str = sun_path.decode("utf-8")
                if path_str:
                    result["sun_path"] = f'"{path_str}"'
            except UnicodeDecodeError:
                pass

        return result

    def _decode_inet(self, process: lldb.SBProcess, address: int) -> dict[str, str | int | list]:
        """Decode AF_INET sockaddr.

        Args:
            process: LLDB process to read memory from
            address: Memory address of the sockaddr_in

        Returns:
            Dictionary with sa_family, sin_port, and sin_addr fields
        """
        struct_obj = self._read_struct(process, address, SockaddrIn)
        if not struct_obj:
            return {"sa_family": "AF_INET"}

        result: dict[str, str | int | list] = {"sa_family": "AF_INET"}

        # Convert port from network byte order
        port = socket.ntohs(struct_obj.sin_port)
        if port != 0:
            result["sin_port"] = f"htons({port})"

        # Format IP address as dotted quad
        ip_str = socket.inet_ntoa(struct_obj.sin_addr.to_bytes(4, "big"))
        result["sin_addr"] = f'inet_addr("{ip_str}")'

        return result

    def _decode_inet6(self, process: lldb.SBProcess, address: int) -> dict[str, str | int | list]:
        """Decode AF_INET6 sockaddr.

        Args:
            process: LLDB process to read memory from
            address: Memory address of the sockaddr_in6

        Returns:
            Dictionary with sa_family, sin6_port, sin6_addr, and optionally sin6_scope_id
        """
        struct_obj = self._read_struct(process, address, SockaddrIn6)
        if not struct_obj:
            return {"sa_family": "AF_INET6"}

        result: dict[str, str | int | list] = {"sa_family": "AF_INET6"}

        # Convert port from network byte order
        port = socket.ntohs(struct_obj.sin6_port)
        if port != 0:
            result["sin6_port"] = f"htons({port})"

        # Format IPv6 address
        addr_bytes = bytes(struct_obj.sin6_addr)
        ip_str = socket.inet_ntop(socket.AF_INET6, addr_bytes)
        result["sin6_addr"] = f'inet_pton(AF_INET6, "{ip_str}")'

        if struct_obj.sin6_scope_id != 0:
            result["sin6_scope_id"] = struct_obj.sin6_scope_id

        return result
