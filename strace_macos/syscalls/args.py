"""Typed syscall arguments for better formatting and highlighting."""

from __future__ import annotations

from abc import ABC, abstractmethod


class SyscallArg(ABC):
    """Base class for typed syscall arguments."""

    @abstractmethod
    def __str__(self) -> str:
        """Return string representation of the argument."""
        ...


class IntArg(SyscallArg):
    """Signed integer argument."""

    def __init__(self, value: int, symbolic: str | None = None) -> None:
        """Initialize an integer argument.

        Args:
            value: The integer value
            symbolic: Optional symbolic representation (e.g., "AT_FDCWD" for -2)
        """
        self.value = value
        self.symbolic = symbolic

    def __str__(self) -> str:
        """Return string representation."""
        return self.symbolic if self.symbolic else str(self.value)


class UnsignedArg(SyscallArg):
    """Unsigned integer argument."""

    def __init__(self, value: int) -> None:
        """Initialize an unsigned integer argument.

        Args:
            value: The unsigned integer value
        """
        self.value = value

    def __str__(self) -> str:
        """Return string representation."""
        return str(self.value)


class PointerArg(SyscallArg):
    """Memory pointer/address argument."""

    def __init__(self, address: int) -> None:
        """Initialize a pointer argument.

        Args:
            address: The memory address
        """
        self.address = address

    def __str__(self) -> str:
        """Return string representation as hex."""
        return f"0x{self.address:x}"


class StringArg(SyscallArg):
    """String argument (typically a file path or text)."""

    def __init__(self, value: str) -> None:
        """Initialize a string argument.

        Args:
            value: The string value
        """
        self.value = value

    def __str__(self) -> str:
        """Return string representation with quotes."""
        # Escape special characters for display
        escaped = self.value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'


class FileDescriptorArg(SyscallArg):
    """File descriptor argument (special case of int)."""

    def __init__(self, fd: int) -> None:
        """Initialize a file descriptor argument.

        Args:
            fd: The file descriptor number
        """
        self.fd = fd

    def __str__(self) -> str:
        """Return string representation."""
        return str(self.fd)


class FlagsArg(SyscallArg):
    """Flags/bitmask argument (displayed as hex or symbolic)."""

    def __init__(self, value: int, symbolic: str | None = None) -> None:
        """Initialize a flags argument.

        Args:
            value: The flags value
            symbolic: Optional symbolic representation (e.g., "O_WRONLY|O_CREAT")
        """
        self.value = value
        self.symbolic = symbolic

    def __str__(self) -> str:
        """Return string representation."""
        return self.symbolic if self.symbolic else f"0x{self.value:x}"


class StructArg(SyscallArg):
    """Decoded struct argument (e.g., struct stat output)."""

    def __init__(self, fields: dict[str, str | int | list]) -> None:
        """Initialize a struct argument.

        Args:
            fields: Dictionary of field names to their decoded values
                   Values can be strings, ints, or lists (for nested structures)
        """
        self.fields = fields

    def __str__(self) -> str:
        """Return string representation as {field1=value1, field2=value2, ...}."""
        if not self.fields:
            return "{}"

        field_strs = []
        for name, value in self.fields.items():
            if isinstance(value, str):
                field_strs.append(f"{name}={value}")
            else:
                field_strs.append(f"{name}={value}")

        return "{" + ", ".join(field_strs) + "}"


class BufferArg(SyscallArg):
    """Buffer argument showing actual data (for read/write syscalls)."""

    def __init__(self, data: bytes, address: int, max_display: int = 32) -> None:
        """Initialize a buffer argument.

        Args:
            data: The actual buffer data
            address: The memory address of the buffer
            max_display: Maximum number of bytes to display (default 32)
        """
        self.data = data
        self.address = address
        self.max_display = max_display

    @staticmethod
    def format_buffer(data: bytes, max_display: int = 32) -> str:
        """Format buffer data as an escaped string (without outer quotes).

        Args:
            data: The buffer data to format
            max_display: Maximum number of bytes to display

        Returns:
            Escaped string representation without outer quotes
        """
        if not data:
            return ""

        display_data = data[:max_display]
        suffix = "..." if len(data) > max_display else ""

        # Try to decode as UTF-8 text
        try:
            text = display_data.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            # Binary data - show as hex
            hex_data = display_data.hex()
            hex_bytes = "\\x".join(hex_data[i : i + 2] for i in range(0, len(hex_data), 2))
            return f"\\x{hex_bytes}{suffix}"
        else:
            # Escape special characters
            escaped = (
                text.replace("\\", "\\\\")
                .replace('"', '\\"')
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t")
            )
            return f"{escaped}{suffix}"

    def __str__(self) -> str:
        """Return string representation showing buffer contents."""
        # Add quotes for text output
        formatted = self.format_buffer(self.data, self.max_display)
        return f'"{formatted}"' if formatted else '""'


class IovecArrayArg(SyscallArg):
    """I/O vector array argument (for readv/writev)."""

    def __init__(self, iov_list: list[dict[str, str | int]]) -> None:
        """Initialize an iovec array argument.

        Args:
            iov_list: List of iovec dictionaries with 'iov_base' and 'iov_len' keys
        """
        self.iov_list = iov_list

    def __str__(self) -> str:
        """Return string representation as [{iov_base="...", iov_len=N}, ...]."""
        if not self.iov_list:
            return "[]"

        iov_strs = []
        for iov in self.iov_list:
            iov_base = iov.get("iov_base", "?")
            iov_len = iov.get("iov_len", 0)
            # Format iov_base with quotes if it's a string
            if isinstance(iov_base, str) and iov_base != "?":
                iov_strs.append(f'{{iov_base="{iov_base}", iov_len={iov_len}}}')
            else:
                iov_strs.append(f"{{iov_base={iov_base}, iov_len={iov_len}}}")

        return "[" + ", ".join(iov_strs) + "]"


class UnknownArg(SyscallArg):
    """Unknown or unparsable argument."""

    def __str__(self) -> str:
        """Return string representation."""
        return "?"
