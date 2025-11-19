"""Struct stat parameter decoder.

This module contains the StatParam class for decoding syscall arguments that
point to struct stat (file statistics).
"""

from __future__ import annotations

import ctypes
from typing import ClassVar

from strace_macos.syscalls.definitions import ParamDirection, StructParamBase
from strace_macos.syscalls.symbols.file import S_FILE_TYPES


class StatStruct(ctypes.Structure):
    """ctypes definition for struct stat on macOS.

    This matches the Darwin stat structure layout for both ARM64 and x86_64.
    Total size: 144 bytes
    """

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("st_dev", ctypes.c_int32),  # Device ID (offset 0)
        ("st_mode", ctypes.c_uint16),  # File mode (offset 4)
        ("st_nlink", ctypes.c_uint16),  # Number of hard links (offset 6)
        ("st_ino", ctypes.c_uint64),  # Inode number (offset 8)
        ("st_uid", ctypes.c_uint32),  # User ID (offset 16)
        ("st_gid", ctypes.c_uint32),  # Group ID (offset 20)
        ("st_rdev", ctypes.c_int32),  # Device ID (if special file) (offset 24)
        ("st_atimespec_sec", ctypes.c_int64),  # Access time seconds (offset 32)
        ("st_atimespec_nsec", ctypes.c_int64),  # Access time nanoseconds (offset 40)
        ("st_mtimespec_sec", ctypes.c_int64),  # Modification time seconds (offset 48)
        (
            "st_mtimespec_nsec",
            ctypes.c_int64,
        ),  # Modification time nanoseconds (offset 56)
        ("st_ctimespec_sec", ctypes.c_int64),  # Change time seconds (offset 64)
        ("st_ctimespec_nsec", ctypes.c_int64),  # Change time nanoseconds (offset 72)
        ("st_birthtimespec_sec", ctypes.c_int64),  # Birth time seconds (offset 80)
        ("st_birthtimespec_nsec", ctypes.c_int64),  # Birth time nanoseconds (offset 88)
        ("st_size", ctypes.c_int64),  # File size in bytes (offset 96)
        ("st_blocks", ctypes.c_int64),  # Blocks allocated (offset 104)
        ("st_blksize", ctypes.c_int32),  # Optimal block size (offset 112)
        ("st_flags", ctypes.c_uint32),  # User defined flags (offset 116)
        ("st_gen", ctypes.c_uint32),  # File generation number (offset 120)
        ("st_lspare", ctypes.c_int32),  # Reserved (offset 124)
        ("st_qspare_0", ctypes.c_int64),  # Reserved (offset 128)
        ("st_qspare_1", ctypes.c_int64),  # Reserved (offset 136)
    ]


class StatParam(StructParamBase):
    """Parameter decoder for struct stat on macOS.

    Decodes file statistics including mode, size, timestamps, etc.
    Provides symbolic decoding for st_mode field.

    Usage:
        StatParam(ParamDirection.OUT)  # For stat, fstat, lstat
        StatParam(ParamDirection.OUT)  # Also for stat64 (same layout on modern macOS)
    """

    struct_type = StatStruct

    # Exclude internal/reserved fields and nanosecond components of timestamps
    # (we show the second components only for brevity)
    excluded_fields: ClassVar[set[str]] = {
        "st_lspare",
        "st_qspare_0",
        "st_qspare_1",
        "st_atimespec_nsec",
        "st_mtimespec_nsec",
        "st_ctimespec_nsec",
        "st_birthtimespec_nsec",
    }

    # Custom formatters for specific fields
    # Maps field_name -> method_name
    field_formatters: ClassVar[dict[str, str]] = {
        "st_mode": "_decode_mode",
    }

    def __init__(self, direction: ParamDirection) -> None:
        """Initialize StatParam with direction."""
        self.direction = direction

    def _decode_mode(self, mode: int, *, no_abbrev: bool) -> str:
        """Decode st_mode into symbolic file type and permissions.

        Args:
            mode: st_mode value
            no_abbrev: If True, show raw octal instead of symbolic

        Returns:
            String like "S_IFREG|0644" or "0100644"
        """
        if no_abbrev:
            return f"0{mode:o}"

        # Extract file type (high bits)
        file_type = mode & 0o170000
        file_type_str = S_FILE_TYPES.get(file_type, f"0{file_type:o}")

        # Extract permission bits (low 12 bits: rwx for user/group/other + special bits)
        perms = mode & 0o7777

        return f"{file_type_str}|0{perms:o}"


__all__ = [
    "StatParam",
]
