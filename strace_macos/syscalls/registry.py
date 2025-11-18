from __future__ import annotations

from typing import TYPE_CHECKING

from strace_macos.syscalls.definitions.file import FILE_SYSCALLS
from strace_macos.syscalls.definitions.ipc import IPC_SYSCALLS
from strace_macos.syscalls.definitions.memory import MEMORY_SYSCALLS
from strace_macos.syscalls.definitions.misc import MISC_SYSCALLS
from strace_macos.syscalls.definitions.network import NETWORK_SYSCALLS
from strace_macos.syscalls.definitions.process import PROCESS_SYSCALLS
from strace_macos.syscalls.definitions.signal import SIGNAL_SYSCALLS
from strace_macos.syscalls.definitions.sysinfo import SYSINFO_SYSCALLS
from strace_macos.syscalls.definitions.thread import THREAD_SYSCALLS

if TYPE_CHECKING:
    from strace_macos.syscalls.definitions import SyscallDef


class SyscallRegistry:
    """Central registry for all syscall definitions."""

    def __init__(self) -> None:
        """Initialize the registry with all syscall definitions."""
        self._by_number: dict[int, SyscallDef] = {}
        self._by_name: dict[str, SyscallDef] = {}
        self._file_syscalls: set[str] = set()
        self._network_syscalls: set[str] = set()

        # Register file syscalls
        for syscall in FILE_SYSCALLS:
            self._register(syscall, is_file=True)

        # Register network syscalls
        for syscall in NETWORK_SYSCALLS:
            self._register(syscall, is_network=True)

        # Register process syscalls
        for syscall in PROCESS_SYSCALLS:
            self._register(syscall)

        # Register memory syscalls
        for syscall in MEMORY_SYSCALLS:
            self._register(syscall)

        # Register signal syscalls
        for syscall in SIGNAL_SYSCALLS:
            self._register(syscall)

        # Register IPC syscalls
        for syscall in IPC_SYSCALLS:
            self._register(syscall)

        # Register misc syscalls
        for syscall in MISC_SYSCALLS:
            self._register(syscall)

        # Register sysinfo syscalls
        for syscall in SYSINFO_SYSCALLS:
            self._register(syscall)

        # Register thread syscalls
        for syscall in THREAD_SYSCALLS:
            self._register(syscall)

    def _register(
        self,
        syscall: SyscallDef,
        *,
        is_file: bool = False,
        is_network: bool = False,
    ) -> None:
        """Register a syscall definition.

        Args:
            syscall: The syscall definition to register
            is_file: Whether this is a file I/O syscall
            is_network: Whether this is a network syscall
        """
        self._by_number[syscall.number] = syscall
        self._by_name[syscall.name] = syscall

        if is_file:
            self._file_syscalls.add(syscall.name)
        if is_network:
            self._network_syscalls.add(syscall.name)

    def lookup_by_name(self, name: str) -> SyscallDef | None:
        """Look up syscall by name.

        Args:
            name: The syscall name

        Returns:
            SyscallDef if found, None otherwise
        """
        return self._by_name.get(name)

    def is_file_syscall(self, name: str) -> bool:
        """Check if syscall is a file I/O syscall.

        Args:
            name: The syscall name

        Returns:
            True if this is a file syscall
        """
        return name in self._file_syscalls

    def is_network_syscall(self, name: str) -> bool:
        """Check if syscall is a network syscall.

        Args:
            name: The syscall name

        Returns:
            True if this is a network syscall
        """
        return name in self._network_syscalls

    def get_all_syscalls(self) -> list[SyscallDef]:
        """Get all registered syscalls.

        Returns:
            List of all syscall definitions
        """
        return list(self._by_number.values())
