"""Decoders for output structures (structs written by syscalls).

This module provides decoders for structures that syscalls write to output
parameters, such as struct stat, struct timeval, etc.

Uses ctypes for clean struct definitions and generic decoding.

Organized by category:
- stat: File stat structures (struct stat, struct stat64)
- network: Network structures (struct sockaddr, etc.)
- time: Time structures (struct timeval, struct timespec) - future
"""

from __future__ import annotations

import ctypes
from typing import TYPE_CHECKING, ClassVar

from strace_macos.lldb_loader import load_lldb_module

if TYPE_CHECKING:
    import lldb


class StructDecoder:
    """Base class for struct decoders using ctypes.

    Subclasses should:
    1. Define a ctypes.Structure subclass as `struct_type`
    2. Optionally define `field_formatters` dict mapping field names to method names
    3. Optionally define `excluded_fields` set to skip internal/padding fields

    Example:
        class MyDecoder(StructDecoder):
            struct_type = MyStruct
            field_formatters = {
                "flags": "_decode_flags",  # Calls self._decode_flags(value, no_abbrev)
            }
            excluded_fields = {"_padding", "_reserved"}

            def _decode_flags(self, value: int, no_abbrev: bool) -> str:
                return hex(value) if no_abbrev else decode_symbolic(value)
    """

    # Subclasses must set this to their ctypes.Structure class
    struct_type: type[ctypes.Structure] | None = None

    # Subclasses can define custom formatters for specific fields
    # Dict maps field_name -> method_name (string)
    field_formatters: ClassVar[dict[str, str]] = {}

    # Subclasses can exclude fields (e.g., padding, reserved fields)
    excluded_fields: ClassVar[set[str]] = set()

    def decode(
        self, process: lldb.SBProcess, address: int, *, no_abbrev: bool = False
    ) -> dict[str, str | int | list] | None:
        """Decode a struct from process memory.

        Args:
            process: LLDB process to read memory from
            address: Memory address of the struct
            no_abbrev: If True, disable symbolic decoding

        Returns:
            Dictionary of field names to decoded values, or None if read failed
        """
        if self.struct_type is None:
            msg = "Subclasses must define struct_type"
            raise NotImplementedError(msg)

        # Read memory
        lldb = load_lldb_module()
        error = lldb.SBError()
        size = ctypes.sizeof(self.struct_type)
        data = process.ReadMemory(address, size, error)

        if error.Fail() or not data:
            return None

        # Parse struct using ctypes
        try:
            struct_obj = self.struct_type.from_buffer_copy(data)
        except (ValueError, TypeError):
            return None

        # Build result dict from struct fields
        result = {}
        for field_name, _field_type in self.struct_type._fields_:  # type: ignore[misc]
            # Skip excluded fields
            if field_name in self.excluded_fields:
                continue

            raw_value = getattr(struct_obj, field_name)

            # Apply custom formatter if available
            if field_name in self.field_formatters:
                method_name = self.field_formatters[field_name]
                formatter = getattr(self, method_name)
                formatted_value = formatter(raw_value, no_abbrev=no_abbrev)
            else:
                formatted_value = raw_value

            result[field_name] = formatted_value

        return result

    def _read_struct(
        self, process: lldb.SBProcess, address: int, struct_type: type[ctypes.Structure]
    ) -> ctypes.Structure | None:
        """Read a ctypes structure from process memory.

        Args:
            process: LLDB process to read memory from
            address: Memory address of the struct
            struct_type: The ctypes.Structure class to read

        Returns:
            The decoded structure object, or None if read failed
        """
        lldb = load_lldb_module()
        error = lldb.SBError()
        size = ctypes.sizeof(struct_type)
        data = process.ReadMemory(address, size, error)

        if error.Fail() or not data:
            return None

        try:
            return struct_type.from_buffer_copy(data)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _format_pointer(value: int | None) -> str:
        """Format a pointer value as NULL or hex address.

        Args:
            value: Pointer value (may be None or 0 for NULL)

        Returns:
            "NULL" if zero/None, otherwise hex address
        """
        if value is None or value == 0:
            return "NULL"
        return f"0x{value:x}"


# Import decoders after StructDecoder is defined to avoid circular import
from strace_macos.syscalls.struct_decoders.kevent import (  # noqa: E402
    Kevent64Decoder,
    KeventDecoder,
)
from strace_macos.syscalls.struct_decoders.msghdr import MsghdrDecoder  # noqa: E402
from strace_macos.syscalls.struct_decoders.sockaddr import SockaddrDecoder  # noqa: E402
from strace_macos.syscalls.struct_decoders.stat import StatDecoder  # noqa: E402

# Registry of struct decoders by name
STRUCT_DECODERS: dict[str, StructDecoder] = {
    "stat": StatDecoder(),
    "stat64": StatDecoder(),  # Same layout on modern macOS
    "kevent": KeventDecoder(),
    "kevent64_s": Kevent64Decoder(),
    "sockaddr": SockaddrDecoder(),
    "msghdr": MsghdrDecoder(),
}


def get_struct_decoder(struct_name: str) -> StructDecoder | None:
    """Get a struct decoder by name.

    Args:
        struct_name: Name of the struct (e.g., "stat", "timeval")

    Returns:
        StructDecoder instance, or None if not found
    """
    return STRUCT_DECODERS.get(struct_name)


__all__ = [
    "Kevent64Decoder",
    "KeventDecoder",
    "MsghdrDecoder",
    "SockaddrDecoder",
    "StatDecoder",
    "StructDecoder",
    "get_struct_decoder",
]
