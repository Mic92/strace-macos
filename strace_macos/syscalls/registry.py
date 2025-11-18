from __future__ import annotations

from typing import TYPE_CHECKING

from strace_macos.syscalls.category import SyscallCategory
from strace_macos.syscalls.definitions.debug import DEBUG_SYSCALLS
from strace_macos.syscalls.definitions.file import FILE_SYSCALLS
from strace_macos.syscalls.definitions.ipc import IPC_SYSCALLS
from strace_macos.syscalls.definitions.memory import MEMORY_SYSCALLS
from strace_macos.syscalls.definitions.misc import MISC_SYSCALLS
from strace_macos.syscalls.definitions.network import NETWORK_SYSCALLS
from strace_macos.syscalls.definitions.process import PROCESS_SYSCALLS
from strace_macos.syscalls.definitions.security import SECURITY_SYSCALLS
from strace_macos.syscalls.definitions.signal import SIGNAL_SYSCALLS
from strace_macos.syscalls.definitions.sysinfo import SYSINFO_SYSCALLS
from strace_macos.syscalls.definitions.thread import THREAD_SYSCALLS
from strace_macos.syscalls.definitions.time import TIME_SYSCALLS

if TYPE_CHECKING:
    from strace_macos.syscalls.definitions import SyscallDef


class SyscallRegistry:
    """Central registry for all syscall definitions."""

    def __init__(self) -> None:
        """Initialize the registry with all syscall definitions."""
        self._by_number: dict[int, SyscallDef] = {}
        self._by_name: dict[str, SyscallDef] = {}
        self._categories: dict[str, SyscallCategory] = {}

        # Register all syscall categories
        categories = [
            (FILE_SYSCALLS, SyscallCategory.FILE),
            (NETWORK_SYSCALLS, SyscallCategory.NETWORK),
            (PROCESS_SYSCALLS, SyscallCategory.PROCESS),
            (MEMORY_SYSCALLS, SyscallCategory.MEMORY),
            (SIGNAL_SYSCALLS, SyscallCategory.SIGNAL),
            (IPC_SYSCALLS, SyscallCategory.IPC),
            (MISC_SYSCALLS, SyscallCategory.MISC),
            (SYSINFO_SYSCALLS, SyscallCategory.SYSINFO),
            (THREAD_SYSCALLS, SyscallCategory.THREAD),
            (TIME_SYSCALLS, SyscallCategory.TIME),
            (SECURITY_SYSCALLS, SyscallCategory.SECURITY),
            (DEBUG_SYSCALLS, SyscallCategory.DEBUG),
        ]
        for syscalls, category in categories:
            for syscall in syscalls:
                self._register(syscall, category=category)

    def _register(
        self,
        syscall: SyscallDef,
        *,
        category: SyscallCategory,
    ) -> None:
        """Register a syscall definition.

        Args:
            syscall: The syscall definition to register
            category: The category this syscall belongs to
        """
        self._by_number[syscall.number] = syscall
        self._by_name[syscall.name] = syscall
        self._categories[syscall.name] = category

    def lookup_by_name(self, name: str) -> SyscallDef | None:
        """Look up syscall by name.

        Args:
            name: The syscall name

        Returns:
            SyscallDef if found, None otherwise
        """
        return self._by_name.get(name)

    def get_category(self, name: str) -> SyscallCategory | None:
        """Get the category of a syscall.

        Args:
            name: The syscall name

        Returns:
            The syscall category, or None if not found
        """
        return self._categories.get(name)

    def get_syscalls_by_category(self, category: SyscallCategory) -> list[SyscallDef]:
        """Get all syscalls in a specific category.

        Args:
            category: The category to filter by

        Returns:
            List of syscall definitions in the category
        """
        return [self._by_name[name] for name, cat in self._categories.items() if cat == category]

    def get_all_syscalls(self) -> list[SyscallDef]:
        """Get all registered syscalls.

        Returns:
            List of all syscall definitions
        """
        return list(self._by_number.values())
