"""System information and control syscall definitions.

Priority 7: Lowest priority, includes sysctl and system information queries.
"""

from __future__ import annotations

import struct
from typing import Any

from strace_macos.lldb_loader import load_lldb_module
from strace_macos.syscalls import numbers
from strace_macos.syscalls.args import IntArg, PointerArg, StringArg, StructArg, UuidArg
from strace_macos.syscalls.definitions import (
    Param,
    PointerParam,
    StringParam,
    SyscallArg,
    SyscallDef,
    UnsignedParam,
)
from strace_macos.syscalls.struct_decoders.sysctl import (
    SysctlType,
    decode_sysctl_mib,
    decode_uuid,
    get_sysctl_type,
    get_sysctl_type_by_name,
)


class SysctlMibParam(Param):
    """Decoder for sysctl MIB array (int *name parameter).

    Decodes the MIB pointer by reading the integer array and formatting it.
    Requires the namelen parameter (next arg) to know how many ints to read.
    Stores the MIB values in tracer for use by buffer decoder.
    """

    def decode(
        self,
        tracer: Any,
        process: Any,
        raw_value: int,
        all_args: list[int],
        *,
        at_entry: bool,  # noqa: ARG002
    ) -> SyscallArg:
        """Decode MIB array pointer."""
        if raw_value == 0:
            return PointerArg(0)

        # namelen is the next argument (index 1)
        if len(all_args) < 2:
            return PointerArg(raw_value)

        namelen = all_args[1]
        decoded, mib_values = decode_sysctl_mib(process, raw_value, namelen)

        # Store MIB values in tracer for buffer decoder to use
        tracer.sysctl_mib_cache[id(all_args)] = mib_values

        return StringArg(decoded)


class SysctlBufferParam(Param):
    """Decoder for sysctl void *oldp buffer parameter.

    Decodes buffer contents based on MIB type (string/int/int64).
    Only decodes at exit, shows raw pointer at entry.
    """

    def _decode_by_type(self, process: Any, raw_value: int, sysctl_type: SysctlType) -> SyscallArg:
        """Decode buffer based on sysctl type."""
        if sysctl_type == SysctlType.STRING:
            string_val = self._read_string(process, raw_value, max_length=256)
            if string_val.startswith("0x"):
                return PointerArg(raw_value)
            return StringArg(string_val)

        lldb = load_lldb_module()
        error = lldb.SBError()

        if sysctl_type == SysctlType.INT:
            data = process.ReadMemory(raw_value, 4, error)
            if error.Fail():
                return PointerArg(raw_value)
            return IntArg(struct.unpack("<i", data)[0])

        if sysctl_type == SysctlType.INT64:
            data = process.ReadMemory(raw_value, 8, error)
            if error.Fail():
                return PointerArg(raw_value)
            return IntArg(struct.unpack("<q", data)[0])

        return PointerArg(raw_value)

    def decode(
        self,
        tracer: Any,
        process: Any,
        raw_value: int,
        all_args: list[int],
        *,
        at_entry: bool,
    ) -> SyscallArg:
        """Decode buffer contents."""
        if raw_value == 0 or at_entry:
            return PointerArg(raw_value)

        # Get MIB values from cache to determine type
        mib_values = tracer.sysctl_mib_cache.get(id(all_args), [])
        if not mib_values:
            return PointerArg(raw_value)

        sysctl_type = get_sysctl_type(mib_values)
        if not sysctl_type:
            return PointerArg(raw_value)

        return self._decode_by_type(process, raw_value, sysctl_type)


class SysctlBynameNameParam(Param):
    """Decoder for sysctlbyname name parameter.

    Decodes the string AND caches it for the buffer decoder to use.
    """

    def decode(
        self,
        tracer: Any,
        process: Any,
        raw_value: int,
        all_args: list[int],
        *,
        at_entry: bool,
    ) -> SyscallArg:
        """Decode name string and cache it."""
        # Use standard StringParam logic

        string_param = StringParam()
        result = string_param.decode(tracer, process, raw_value, all_args, at_entry=at_entry)

        # Cache the name for buffer decoder
        if isinstance(result, StringArg):
            tracer.sysctlbyname_cache[id(all_args)] = result.value

        return result


class SysctlBynameBufferParam(Param):
    """Decoder for sysctlbyname void *oldp buffer parameter.

    Decodes buffer contents based on sysctl name (first arg).
    Only decodes at exit, shows raw pointer at entry.
    """

    def _decode_by_type(self, process: Any, raw_value: int, sysctl_type: SysctlType) -> SyscallArg:
        """Decode buffer based on sysctl type."""
        if sysctl_type == SysctlType.STRING:
            string_val = self._read_string(process, raw_value, max_length=256)
            if string_val.startswith("0x"):
                return PointerArg(raw_value)
            return StringArg(string_val)

        lldb = load_lldb_module()
        error = lldb.SBError()

        if sysctl_type == SysctlType.INT:
            data = process.ReadMemory(raw_value, 4, error)
            if error.Fail():
                return PointerArg(raw_value)
            return IntArg(struct.unpack("<i", data)[0])

        if sysctl_type == SysctlType.INT64:
            data = process.ReadMemory(raw_value, 8, error)
            if error.Fail():
                return PointerArg(raw_value)
            return IntArg(struct.unpack("<q", data)[0])

        return PointerArg(raw_value)

    def decode(
        self,
        tracer: Any,
        process: Any,
        raw_value: int,
        all_args: list[int],
        *,
        at_entry: bool,
    ) -> SyscallArg:
        """Decode buffer contents."""
        if raw_value == 0 or at_entry:
            return PointerArg(raw_value)

        # Get sysctl name from first argument (should be stored in tracer cache)
        sysctl_name = tracer.sysctlbyname_cache.get(id(all_args))
        if not sysctl_name:
            return PointerArg(raw_value)

        sysctl_type = get_sysctl_type_by_name(sysctl_name)
        if not sysctl_type:
            return PointerArg(raw_value)

        return self._decode_by_type(process, raw_value, sysctl_type)


class UuidParam(Param):
    """Decoder for uuid_t parameter (16-byte UUID)."""

    def decode(
        self,
        tracer: Any,  # noqa: ARG002
        process: Any,
        raw_value: int,
        all_args: list[int],  # noqa: ARG002
        *,
        at_entry: bool,
    ) -> SyscallArg:
        """Decode UUID - can decode at entry or exit."""
        if raw_value == 0:
            return PointerArg(0)

        # UUIDs are output params, decode at exit
        if at_entry:
            return PointerArg(raw_value)

        uuid_str = decode_uuid(process, raw_value)
        return UuidArg(uuid_str)


class TimespecParam(Param):
    """Decoder for struct timespec pointer parameter."""

    def decode(
        self,
        tracer: Any,  # noqa: ARG002
        process: Any,
        raw_value: int,
        all_args: list[int],  # noqa: ARG002
        *,
        at_entry: bool,  # noqa: ARG002
    ) -> SyscallArg:
        """Decode timespec - can decode at entry (input param)."""
        if raw_value == 0:
            return PointerArg(0)

        lldb = load_lldb_module()
        error = lldb.SBError()

        # struct timespec is 16 bytes (tv_sec: 8 bytes, tv_nsec: 8 bytes)
        data = process.ReadMemory(raw_value, 16, error)
        if error.Fail():
            return PointerArg(raw_value)

        tv_sec = struct.unpack("<q", data[0:8])[0]  # signed 64-bit
        tv_nsec = struct.unpack("<q", data[8:16])[0]  # signed 64-bit

        return StructArg({"tv_sec": tv_sec, "tv_nsec": tv_nsec})


class SysctlSizePointerParam(Param):
    """Decoder for sysctl size_t *oldlenp parameter.

    Shows the size pointer value like [256] or [256->7] (before->after).
    """

    def decode(
        self,
        tracer: Any,  # noqa: ARG002
        process: Any,
        raw_value: int,
        all_args: list[int],  # noqa: ARG002
        *,
        at_entry: bool,  # noqa: ARG002
    ) -> SyscallArg:
        """Decode size pointer."""
        if raw_value == 0:
            return PointerArg(0)

        lldb = load_lldb_module()
        error = lldb.SBError()

        # Read size_t (8 bytes on 64-bit macOS)
        data = process.ReadMemory(raw_value, 8, error)
        if error.Fail():
            return PointerArg(raw_value)

        size_value = struct.unpack("<Q", data)[0]  # unsigned 64-bit
        return StringArg(f"[{size_value}]")


# All system information syscalls (12 total) with full argument definitions
SYSINFO_SYSCALLS: list[SyscallDef] = [
    SyscallDef(numbers.SYS_getdtablesize, "getdtablesize", params=[]),  # 89
    SyscallDef(
        numbers.SYS_gethostuuid,
        "gethostuuid",
        params=[
            UuidParam(),  # uuid_t uuid - decode as UUID string
            TimespecParam(),  # const struct timespec *timeout - decode struct
        ],
    ),  # 142
    SyscallDef(
        numbers.SYS_sysctl,
        "sysctl",
        params=[
            SysctlMibParam(),  # int *name - decode as MIB array
            UnsignedParam(),  # u_int namelen
            SysctlBufferParam(),  # void *oldp - decode buffer based on MIB type
            SysctlSizePointerParam(),  # size_t *oldlenp - decode as [size]
            PointerParam(),  # void *newp
            UnsignedParam(),  # size_t newlen
        ],
    ),  # 202
    SyscallDef(
        numbers.SYS_sysctlbyname,
        "sysctlbyname",
        params=[
            SysctlBynameNameParam(),  # const char *name - cache for buffer decoder
            SysctlBynameBufferParam(),  # void *oldp - decode buffer based on name
            SysctlSizePointerParam(),  # size_t *oldlenp - decode as [size]
            PointerParam(),  # void *newp
            UnsignedParam(),  # size_t newlen
        ],
    ),  # 274
    SyscallDef(numbers.SYS_usrctl, "usrctl", params=[UnsignedParam()]),  # 452
    SyscallDef(
        numbers.SYS_getentropy,
        "getentropy",
        params=[PointerParam(), UnsignedParam()],
    ),  # 500
]
