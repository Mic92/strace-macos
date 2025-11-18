"""Security and access control syscall definitions.

Priority 7: Lowest priority, includes MAC (Mandatory Access Control),
code signing, and System Integrity Protection syscalls.
"""

from __future__ import annotations

from strace_macos.syscalls import numbers
from strace_macos.syscalls.definitions import (
    FileDescriptorParam,
    IntParam,
    PointerParam,
    StringParam,
    SyscallDef,
    UnsignedParam,
)

# All security syscalls (11 total) with full argument definitions
SECURITY_SYSCALLS: list[SyscallDef] = [
    # MAC (Mandatory Access Control) syscalls
    SyscallDef(
        numbers.SYS___mac_syscall,
        "__mac_syscall",
        params=[StringParam(), IntParam(), PointerParam()],
    ),  # 381
    SyscallDef(
        numbers.SYS___mac_get_file,
        "__mac_get_file",
        params=[StringParam(), PointerParam()],
    ),  # 382
    SyscallDef(
        numbers.SYS___mac_set_file,
        "__mac_set_file",
        params=[StringParam(), PointerParam()],
    ),  # 383
    SyscallDef(
        numbers.SYS___mac_get_link,
        "__mac_get_link",
        params=[StringParam(), PointerParam()],
    ),  # 384
    SyscallDef(
        numbers.SYS___mac_set_link,
        "__mac_set_link",
        params=[StringParam(), PointerParam()],
    ),  # 385
    SyscallDef(
        numbers.SYS___mac_get_fd,
        "__mac_get_fd",
        params=[FileDescriptorParam(), PointerParam()],
    ),  # 388
    SyscallDef(
        numbers.SYS___mac_set_fd,
        "__mac_set_fd",
        params=[FileDescriptorParam(), PointerParam()],
    ),  # 389
    SyscallDef(
        numbers.SYS___mac_mount,
        "__mac_mount",
        params=[StringParam(), StringParam(), IntParam(), PointerParam(), PointerParam()],
    ),  # 424
    SyscallDef(
        numbers.SYS___mac_getfsstat,
        "__mac_getfsstat",
        params=[PointerParam(), IntParam(), IntParam()],
    ),  # 426
    # Code signing and SIP
    SyscallDef(
        numbers.SYS_csops,
        "csops",
        params=[IntParam(), UnsignedParam(), PointerParam(), UnsignedParam()],
    ),  # 169
    SyscallDef(
        numbers.SYS_csrctl,
        "csrctl",
        params=[UnsignedParam(), PointerParam(), UnsignedParam()],
    ),  # 465
]
