"""Decoder for struct fssearchblock (filesystem search parameters)."""

from __future__ import annotations

import ctypes
from typing import ClassVar

from strace_macos.syscalls.struct_decoders import StructDecoder


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


class FssearchblockDecoder(StructDecoder):
    """Decoder for struct fssearchblock on macOS.

    Decodes the filesystem search parameters structure used by searchfs() syscall.
    """

    struct_type = FssearchblockStruct

    excluded_fields: ClassVar[set[str]] = {
        "searchparams1",
        "searchparams2",
        "searchattrs",
        "returnattrs",
        "returnbuffer",
        "timelimit",  # Exclude timeval for now - complex nested struct
    }

    field_formatters: ClassVar[dict[str, str]] = {}
