"""Custom exceptions for strace-macos."""

from __future__ import annotations


class StraceError(Exception):
    """Base exception for user-facing strace errors.

    These exceptions are caught at the top level and displayed
    without a stack trace for better user experience.
    """


class TargetCreationError(StraceError):
    """Failed to create LLDB target for the specified binary."""


class UnsupportedArchitectureError(StraceError):
    """The target binary uses an unsupported architecture."""


class ProcessLaunchError(StraceError):
    """Failed to launch the target process."""


class ProcessAttachError(StraceError):
    """Failed to attach to the target process."""


class LLDBLoadError(StraceError):
    """Failed to load LLDB Python module."""


class InvalidFilterError(StraceError):
    """Invalid syscall filter expression."""


class InvalidCommandError(StraceError):
    """Invalid command or arguments provided."""
