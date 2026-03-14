"""Struct parameter decoders for kqueue/kevent/select/poll structures."""

from __future__ import annotations

import ctypes
from typing import ClassVar

from dataclasses import dataclass

from strace_macos.syscalls.definitions import (
    Param,
    ParamDirection,
    StructParamBase,
)


class TimespecStruct(ctypes.Structure):
    """ctypes definition for struct timespec.

    struct timespec {
        time_t  tv_sec;   // seconds
        long    tv_nsec;  // nanoseconds
    };
    """

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("tv_sec", ctypes.c_int64),  # time_t
        ("tv_nsec", ctypes.c_long),  # long
    ]


class TimespecParam(StructParamBase):
    """Parameter decoder for struct timespec."""

    struct_type = TimespecStruct
    excluded_fields: ClassVar[set[str]] = set()
    field_formatters: ClassVar[dict[str, str]] = {}

    def __init__(self, direction: ParamDirection) -> None:
        """Initialize TimespecParam."""
        self.direction = direction


class TimevalStruct(ctypes.Structure):
    """ctypes definition for struct timeval.

    struct timeval {
        time_t       tv_sec;   // seconds
        suseconds_t  tv_usec;  // microseconds
    };
    """

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("tv_sec", ctypes.c_int64),  # time_t
        ("tv_usec", ctypes.c_int32),  # suseconds_t (int32 on macOS)
    ]


class TimevalParam(StructParamBase):
    """Parameter decoder for struct timeval."""

    struct_type = TimevalStruct
    excluded_fields: ClassVar[set[str]] = set()
    field_formatters: ClassVar[dict[str, str]] = {}

    def __init__(self, direction: ParamDirection) -> None:
        """Initialize TimevalParam."""
        self.direction = direction

class TimezoneStruct(ctypes.Structure):
    """
    struct timezone {
            int     tz_minuteswest; /* of Greenwich */
            int     tz_dsttime;     /* type of dst correction to apply */
    };
    """

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("tz_minuteswest", ctypes.c_int),  # tz_minuteswest
        ("tz_dsttime", ctypes.c_int),  # tz_dsttime
    ]


class TimezoneParam(StructParamBase):
    """Parameter decoder for struct timezone."""

    struct_type = TimezoneStruct
    excluded_fields: ClassVar[set[str]] = set()
    field_formatters: ClassVar[dict[str, str]] = {}

    def __init__(self, direction: ParamDirection) -> None:
        """Initialize TimezoneParam."""
        self.direction = direction

@dataclass
class TimevalArrayParam(Param):
    """Parameter decoder for struct timeval array, used in utimes() / futimes() .
    """

    def decode(self, ctx: DecodeContext) -> SyscallArg | None:
        if not ctx.at_entry:
            return None

        if ctx.raw_value == 0:
            return PointerArg(0)

        timeval_list = decode_array.decode_array(ctx.process, ctx.raw_value, 2)
        if timeval_list:
            return StructArrayArg(timeval_list)

        return PointerArg(ctx.raw_value)


__all__ = ["TimespecParam", "TimevalParam", "TimezoneParam"]
