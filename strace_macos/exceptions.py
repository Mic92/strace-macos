"""Custom exceptions for strace-macos."""

from __future__ import annotations


class StraceError(Exception):
    """Base exception for user-facing strace errors.

    These exceptions are caught at the top level and displayed
    without a stack trace for better user experience.
    """


class LLDBLoadError(StraceError):
    """Failed to load LLDB Python module."""


class SIPProtectedError(StraceError):
    """Binary is protected by System Integrity Protection (SIP)."""
