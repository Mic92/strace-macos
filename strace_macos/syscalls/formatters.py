"""Output formatters for syscall traces."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from strace_macos.syscalls.args import (
    FileDescriptorArg,
    IntArg,
    IovecArrayArg,
    PointerArg,
    StringArg,
    StructArg,
    UnsignedArg,
)

if TYPE_CHECKING:
    from strace_macos.syscalls.args import SyscallArg


class SyscallEvent:
    """Represents a captured syscall event."""

    def __init__(
        self,
        pid: int,
        syscall_name: str,
        args: list[SyscallArg],
        return_value: int | str,
        timestamp: float,
    ) -> None:
        """Initialize a syscall event.

        Args:
            pid: Process ID
            syscall_name: Name of the syscall
            args: List of typed syscall arguments
            return_value: Return value (or "?" if not captured)
            timestamp: Timestamp in seconds since epoch
        """
        self.pid = pid
        self.syscall_name = syscall_name
        self.args = args
        self.return_value = return_value
        self.timestamp = timestamp


class JSONFormatter:
    """Format syscalls as JSON Lines."""

    @staticmethod
    def format(event: SyscallEvent) -> str:
        """Format a syscall event as a JSON line.

        Args:
            event: The syscall event to format

        Returns:
            JSON string (no trailing newline)
        """
        # Format args: preserve types for JSON
        formatted_args: list[dict[str, dict[str, str | int | list]] | list | str | int] = []
        for arg in event.args:
            if isinstance(arg, StructArg):
                # For JSON, include the struct fields as a nested dict
                formatted_args.append({"output": arg.fields})
            elif isinstance(arg, IovecArrayArg):
                # For JSON, include the iovec list directly
                formatted_args.append(arg.iov_list)
            elif isinstance(arg, FileDescriptorArg):
                # For JSON, preserve fd as integer
                formatted_args.append(arg.fd)
            elif isinstance(arg, (IntArg, UnsignedArg)):
                # For JSON, preserve integer values
                formatted_args.append(arg.value)
            elif isinstance(arg, PointerArg):
                # For JSON, format pointers as hex strings
                formatted_args.append(f"0x{arg.address:x}")
            else:
                # For everything else, use string representation
                formatted_args.append(str(arg))

        data = {
            "syscall": event.syscall_name,
            "args": formatted_args,
            "return": event.return_value,
            "pid": event.pid,
            "timestamp": event.timestamp,
        }
        return json.dumps(data)


class TextFormatter:
    """Format syscalls in strace-compatible text format."""

    @staticmethod
    def format(event: SyscallEvent) -> str:
        """Format a syscall event as strace-style text.

        Args:
            event: The syscall event to format

        Returns:
            Text string (no trailing newline)
        """
        # Format arguments
        args_str = ", ".join(str(arg) for arg in event.args)

        # Format return value
        if isinstance(event.return_value, str):
            ret_str = event.return_value
        else:
            ret_str = str(event.return_value)

        # strace format: syscall(args) = return
        return f"{event.syscall_name}({args_str}) = {ret_str}"


class ColorTextFormatter:
    """Format syscalls in strace-compatible text format with ANSI colors."""

    # ANSI color codes
    RESET = "\033[0m"
    SYSCALL = "\033[1;36m"  # Bright cyan for syscall names
    STRING = "\033[0;33m"  # Yellow for strings
    NUMBER = "\033[0;35m"  # Magenta for numbers
    POINTER = "\033[0;34m"  # Blue for pointers/addresses
    FD = "\033[0;32m"  # Green for file descriptors
    RETURN_OK = "\033[1;32m"  # Bright green for successful returns
    RETURN_ERR = "\033[1;31m"  # Bright red for errors
    PUNCTUATION = "\033[0;37m"  # White for punctuation

    @staticmethod
    def format(event: SyscallEvent) -> str:
        """Format a syscall event as strace-style text with colors.

        Args:
            event: The syscall event to format

        Returns:
            Colored text string (no trailing newline)
        """
        # Format arguments with type-aware coloring
        colored_args = []
        for arg in event.args:
            if isinstance(arg, StringArg):
                colored_args.append(f"{ColorTextFormatter.STRING}{arg}{ColorTextFormatter.RESET}")
            elif isinstance(arg, PointerArg):
                colored_args.append(f"{ColorTextFormatter.POINTER}{arg}{ColorTextFormatter.RESET}")
            elif isinstance(arg, FileDescriptorArg):
                colored_args.append(f"{ColorTextFormatter.FD}{arg}{ColorTextFormatter.RESET}")
            elif isinstance(arg, (IntArg, UnsignedArg)):
                colored_args.append(f"{ColorTextFormatter.NUMBER}{arg}{ColorTextFormatter.RESET}")
            else:
                # Unknown type - no color
                colored_args.append(str(arg))

        args_str = f"{ColorTextFormatter.PUNCTUATION},{ColorTextFormatter.RESET} ".join(
            colored_args
        )

        # Format return value with color based on success/error
        if isinstance(event.return_value, str):
            ret_str = event.return_value
            ret_color = ColorTextFormatter.RETURN_OK
        elif event.return_value < 0:
            ret_str = str(event.return_value)
            ret_color = ColorTextFormatter.RETURN_ERR
        else:
            ret_str = str(event.return_value)
            ret_color = ColorTextFormatter.RETURN_OK

        # strace format with colors: syscall(args) = return
        return (
            f"{ColorTextFormatter.SYSCALL}{event.syscall_name}{ColorTextFormatter.RESET}"
            f"{ColorTextFormatter.PUNCTUATION}({ColorTextFormatter.RESET}"
            f"{args_str}"
            f"{ColorTextFormatter.PUNCTUATION}){ColorTextFormatter.RESET} "
            f"{ColorTextFormatter.PUNCTUATION}={ColorTextFormatter.RESET} "
            f"{ret_color}{ret_str}{ColorTextFormatter.RESET}"
        )


class SummaryFormatter:
    """Format syscall statistics as a summary table."""

    def __init__(self) -> None:
        """Initialize the summary formatter."""
        self.stats: dict[str, dict[str, int]] = {}

    def add_event(self, event: SyscallEvent) -> None:
        """Add a syscall event to the statistics.

        Args:
            event: The syscall event to record
        """
        if event.syscall_name not in self.stats:
            self.stats[event.syscall_name] = {
                "count": 0,
                "errors": 0,
            }

        self.stats[event.syscall_name]["count"] += 1

        # Count errors (negative return values typically indicate errors)
        if isinstance(event.return_value, int) and event.return_value < 0:
            self.stats[event.syscall_name]["errors"] += 1

    def format(self) -> str:
        """Format the summary statistics as a table.

        Returns:
            Summary table string
        """
        if not self.stats:
            return "No syscalls captured.\n"

        lines = ["% time     calls      errors syscall"]
        lines.append("-" * 50)

        total_calls = sum(s["count"] for s in self.stats.values())

        for syscall_name in sorted(self.stats.keys()):
            stats = self.stats[syscall_name]
            count = stats["count"]
            errors = stats["errors"]

            # Calculate percentage of time (simplified: just based on call count)
            percent = (count / total_calls * 100) if total_calls > 0 else 0.0

            # Format errors column (show only if > 0)
            errors_str = str(errors) if errors > 0 else ""

            lines.append(f"{percent:6.2f} {count:10d} {errors_str:>10s} {syscall_name}")

        lines.append("-" * 50)
        lines.append(f"100.00 {total_calls:10d}             total")
        lines.append("")

        return "\n".join(lines)
