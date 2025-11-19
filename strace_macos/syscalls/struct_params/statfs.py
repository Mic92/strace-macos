"""Struct parameter decoder for statfs (filesystem statistics structure)."""

from __future__ import annotations

import ctypes
from typing import ClassVar

from strace_macos.syscalls.definitions import ParamDirection, StructParamBase


class StatfsStruct(ctypes.Structure):
    """ctypes definition for struct statfs on macOS.

    struct statfs {
        uint32_t f_bsize;       // fundamental file system block size
        int32_t  f_iosize;      // optimal transfer block size
        uint64_t f_blocks;      // total data blocks in file system
        uint64_t f_bfree;       // free blocks in fs
        uint64_t f_bavail;      // free blocks avail to non-superuser
        uint64_t f_files;       // total file nodes in file system
        uint64_t f_ffree;       // free file nodes in fs
        fsid_t   f_fsid;        // file system id (2 x int32_t)
        uid_t    f_owner;       // user that mounted the filesystem
        uint32_t f_type;        // type of filesystem
        uint32_t f_flags;       // copy of mount exported flags
        uint32_t f_fssubtype;   // fs sub-type (flavor)
        char     f_fstypename[16];  // fs type name
        char     f_mntonname[1024]; // directory on which mounted
        char     f_mntfromname[1024]; // mounted filesystem
        uint32_t f_flags_ext;   // extended flags
        uint32_t f_reserved[7]; // for future use
    };

    Total size: ~2120 bytes
    """

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("f_bsize", ctypes.c_uint32),
        ("f_iosize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64),
        ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64),
        ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64),
        ("f_fsid", ctypes.c_int32 * 2),  # fsid_t is array of 2 int32_t
        ("f_owner", ctypes.c_uint32),  # uid_t
        ("f_type", ctypes.c_uint32),
        ("f_flags", ctypes.c_uint32),
        ("f_fssubtype", ctypes.c_uint32),
        ("f_fstypename", ctypes.c_char * 16),
        ("f_mntonname", ctypes.c_char * 1024),
        ("f_mntfromname", ctypes.c_char * 1024),
        ("f_flags_ext", ctypes.c_uint32),
        ("f_reserved", ctypes.c_uint32 * 7),
    ]


class StatfsParam(StructParamBase):
    """Parameter decoder for struct statfs on macOS.

    Decodes filesystem statistics including block counts, mount paths, and filesystem type.
    Provides UTF-8 decoding for string fields.

    Usage:
        StatfsParam(ParamDirection.OUT)  # For statfs, fstatfs, getfsstat
        StatfsParam(ParamDirection.OUT)  # Also for statfs64 (same layout on modern macOS)
    """

    struct_type = StatfsStruct

    # Exclude internal/reserved fields and fsid (not human readable)
    excluded_fields: ClassVar[set[str]] = {"f_reserved", "f_flags_ext", "f_fsid"}

    # Custom formatters for byte string fields
    # Maps field_name -> method_name
    field_formatters: ClassVar[dict[str, str]] = {
        "f_fstypename": "_decode_fstypename",
        "f_mntonname": "_decode_mntonname",
        "f_mntfromname": "_decode_mntfromname",
    }

    def __init__(self, direction: ParamDirection) -> None:
        """Initialize StatfsParam with direction."""
        self.direction = direction

    def _decode_fstypename(self, value: bytes, *, no_abbrev: bool) -> str:  # noqa: ARG002
        """Decode filesystem type name from null-terminated byte string.

        Args:
            value: Raw bytes from f_fstypename field
            no_abbrev: Unused for this formatter

        Returns:
            UTF-8 decoded string with null bytes stripped, or repr on error
        """
        try:
            return value.decode("utf-8").rstrip("\x00")
        except UnicodeDecodeError:
            return repr(value)

    def _decode_mntonname(self, value: bytes, *, no_abbrev: bool) -> str:  # noqa: ARG002
        """Decode mount point path from null-terminated byte string.

        Args:
            value: Raw bytes from f_mntonname field
            no_abbrev: Unused for this formatter

        Returns:
            UTF-8 decoded string with null bytes stripped, or repr on error
        """
        try:
            return value.decode("utf-8").rstrip("\x00")
        except UnicodeDecodeError:
            return repr(value)

    def _decode_mntfromname(self, value: bytes, *, no_abbrev: bool) -> str:  # noqa: ARG002
        """Decode mounted filesystem name from null-terminated byte string.

        Args:
            value: Raw bytes from f_mntfromname field
            no_abbrev: Unused for this formatter

        Returns:
            UTF-8 decoded string with null bytes stripped, or repr on error
        """
        try:
            return value.decode("utf-8").rstrip("\x00")
        except UnicodeDecodeError:
            return repr(value)


__all__ = [
    "StatfsParam",
]
