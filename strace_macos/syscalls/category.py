"""Syscall category classification compatible with strace."""

from __future__ import annotations

from enum import Enum, auto


class SyscallCategory(Enum):
    """Syscall categories compatible with strace filtering.

    These match strace's -e trace= categories for compatibility.
    """

    FILE = auto()  # File operations (open, read, write, stat, etc.)
    NETWORK = auto()  # Network operations (socket, connect, send, recv, etc.)
    PROCESS = auto()  # Process management (fork, exec, wait, exit, etc.)
    MEMORY = auto()  # Memory management (mmap, munmap, brk, etc.)
    SIGNAL = auto()  # Signal handling (signal, sigaction, kill, etc.)
    IPC = auto()  # Inter-process communication (pipe, msgget, semop, etc.)
    THREAD = auto()  # Thread operations (pthread_*, bsdthread_*)
    TIME = auto()  # Time and timer operations (gettimeofday, setitimer, etc.)
    SYSINFO = auto()  # System information (sysctl, getpid, getuid, etc.)
    SECURITY = auto()  # Security/MAC operations (__mac_*, csops, etc.)
    DEBUG = auto()  # Debugging and tracing (ptrace, kdebug_*, etc.)
    MISC = auto()  # Miscellaneous/uncategorized syscalls

    def __str__(self) -> str:
        """Return lowercase name for display."""
        return self.name.lower()
