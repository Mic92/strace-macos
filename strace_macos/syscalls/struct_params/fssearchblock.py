"""Parameter decoder for struct fssearchblock (filesystem search parameters)."""

from __future__ import annotations

import ctypes
from typing import ClassVar

from strace_macos.syscalls.definitions import ParamDirection, StructParamBase


class TimevalStruct(ctypes.Structure):
    """struct timeval on macOS."""

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("tv_sec", ctypes.c_long),
        ("tv_usec", ctypes.c_int),
    ]


class AttrListInlineStruct(ctypes.Structure):
    """struct attrlist embedded in fssearchblock."""

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("bitmapcount", ctypes.c_uint16),
        ("reserved", ctypes.c_uint16),
        ("commonattr", ctypes.c_uint32),
        ("volattr", ctypes.c_uint32),
        ("dirattr", ctypes.c_uint32),
        ("fileattr", ctypes.c_uint32),
        ("forkattr", ctypes.c_uint32),
    ]


class FssearchblockStruct(ctypes.Structure):
    """ctypes definition for struct fssearchblock on macOS.

    struct fssearchblock {
        struct attrlist *returnattrs;
        void *returnbuffer;
        size_t returnbuffersize;
        u_long maxmatches;
        struct timeval timelimit;
        void *searchparams1;
        size_t sizeofsearchparams1;
        void *searchparams2;
        size_t sizeofsearchparams2;
        struct attrlist searchattrs;
    };
    """

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("returnattrs", ctypes.c_void_p),
        ("returnbuffer", ctypes.c_void_p),
        ("returnbuffersize", ctypes.c_size_t),
        ("maxmatches", ctypes.c_ulong),
        ("timelimit", TimevalStruct),
        ("searchparams1", ctypes.c_void_p),
        ("sizeofsearchparams1", ctypes.c_size_t),
        ("searchparams2", ctypes.c_void_p),
        ("sizeofsearchparams2", ctypes.c_size_t),
        ("searchattrs", AttrListInlineStruct),
    ]


class FssearchblockParam(StructParamBase):
    """Parameter decoder for struct fssearchblock on macOS.

    Decodes the filesystem search parameters structure used by searchfs() syscall.

    Usage:
        FssearchblockParam(ParamDirection.IN)  # For searchfs input parameter
    """

    struct_type = FssearchblockStruct

    # Exclude pointer fields, timelimit (complex nested struct), and searchattrs
    excluded_fields: ClassVar[set[str]] = {
        "searchparams1",
        "searchparams2",
        "searchattrs",
        "returnattrs",
        "returnbuffer",
        "timelimit",
    }

    # No custom formatters needed
    field_formatters: ClassVar[dict[str, str]] = {}

    def __init__(self, direction: ParamDirection) -> None:
        """Initialize FssearchblockParam with direction."""
        self.direction = direction


__all__ = [
    "FssearchblockParam",
]
