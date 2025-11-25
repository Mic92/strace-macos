"""Typed syscall arguments for better formatting and highlighting."""

from __future__ import annotations

from abc import ABC, abstractmethod

from strace_macos.string_quote import quote_string


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
            if isinstance(value, list):
                # Format list of dicts as [{key=val, ...}, ...]
                formatted_list = self._format_list(value)
                field_strs.append(f"{name}={formatted_list}")
            elif isinstance(value, str):
                field_strs.append(f"{name}={value}")
            else:
                field_strs.append(f"{name}={value}")

        return "{" + ", ".join(field_strs) + "}"

    def _format_list(self, lst: list) -> str:
        """Format a list of items (usually dicts) for text output."""
        if not lst:
            return "[]"

        formatted_items = []
        for item in lst:
            if isinstance(item, dict):
                # Format dict as {key=val, key=val, ...}
                item_strs = []
                for k, v in item.items():
                    if isinstance(v, str) and v not in {"?", "NULL"}:
                        item_strs.append(f'{k}="{v}"')
                    else:
                        item_strs.append(f"{k}={v}")
                formatted_items.append("{" + ", ".join(item_strs) + "}")
            else:
                formatted_items.append(str(item))

        return "[" + ", ".join(formatted_items) + "]"


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
        return quote_string(data, max_display)

    def __str__(self) -> str:
        """Return string representation showing buffer contents."""
        # Add quotes for text output
        formatted = self.format_buffer(self.data, self.max_display)
        return f'"{formatted}"' if formatted else '""'


class StringArrayArg(SyscallArg):
    """String array argument (for argv[], envp[], etc.)."""

    def __init__(self, strings: list[str]) -> None:
        """Initialize a string array argument.

        Args:
            strings: List of string values
        """
        self.strings = strings

    def __str__(self) -> str:
        """Return string representation as ["str1", "str2", ...]."""
        if not self.strings:
            return "[]"

        # Escape each string
        escaped_strs = []
        for s in self.strings:
            escaped = s.replace("\\", "\\\\").replace('"', '\\"')
            escaped_strs.append(f'"{escaped}"')

        return "[" + ", ".join(escaped_strs) + "]"


class StructArrayArg(SyscallArg):
    """Generic struct array argument (for arrays of structures)."""

    def __init__(self, struct_list: list[dict[str, str | int]] | list[str]) -> None:
        """Initialize a struct array argument.

        Args:
            struct_list: List of struct dictionaries with arbitrary field names,
                        or list of pre-formatted strings
        """
        self.struct_list = struct_list

    def __str__(self) -> str:
        """Return string representation as [{field1=val1, field2=val2}, ...]."""
        if not self.struct_list:
            return "[]"

        struct_strs = []
        for item in self.struct_list:
            if isinstance(item, str):
                # Pre-formatted string
                struct_strs.append(item)
            elif isinstance(item, dict):
                # Dictionary with fields - format each field
                field_strs = []
                for key, value in item.items():
                    # For text output, add quotes around string values
                    if isinstance(value, str) and value not in {"?", "NULL"}:
                        field_strs.append(f'{key}="{value}"')
                    else:
                        field_strs.append(f"{key}={value}")
                struct_strs.append("{" + ", ".join(field_strs) + "}")
            else:
                struct_strs.append(str(item))

        return "[" + ", ".join(struct_strs) + "]"


class UnknownArg(SyscallArg):
    """Unknown or unparsable argument."""

    def __str__(self) -> str:
        """Return string representation."""
        return "?"


class SkipArg(SyscallArg):
    """Marker for arguments that should be skipped/not displayed.

    Used for syscalls with variable argument counts (e.g., fcntl F_GETFD
    has no third argument, so we mark it as SkipArg to omit it from output).
    """

    def __str__(self) -> str:
        """Return empty string (should be filtered out before display)."""
        return ""


class UuidArg(SyscallArg):
    """UUID argument (16-byte identifier shown in standard format).

    Displays without quotes like: A1B2C3D4-E5F6-7890-ABCD-EF1234567890
    """

    def __init__(self, uuid_str: str) -> None:
        """Initialize a UUID argument.

        Args:
            uuid_str: UUID in standard format (XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX)
        """
        self.uuid_str = uuid_str

    def __str__(self) -> str:
        """Return UUID string without quotes."""
        return self.uuid_str


class IntPtrArg(SyscallArg):
    """Argument that is an int* pointer (shows as [value] in output).

    Used for ioctl commands like FIONREAD that take an int* output parameter.
    """

    def __init__(self, value: int) -> None:
        """Initialize an int pointer argument.

        Args:
            value: The integer value read from the pointer
        """
        self.value = value

    def __str__(self) -> str:
        """Return string representation as [value]."""
        return f"[{self.value}]"
