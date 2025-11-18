"""Network syscall definitions.

Priority 2: Required for network tests.
"""

from __future__ import annotations

from strace_macos.syscalls import numbers
from strace_macos.syscalls.definitions import (
    BufferParam,
    ConstParam,
    FileDescriptorParam,
    FlagsParam,
    IntParam,
    ParamDirection,
    PointerParam,
    StructParam,
    SyscallDef,
    UnsignedParam,
)
from strace_macos.syscalls.symbols.network import (
    AF_CONSTANTS,
    IPPROTO_CONSTANTS,
    MSG_FLAGS,
    SHUT_CONSTANTS,
    SO_OPTIONS,
    SOCK_CONSTANTS,
    SOL_CONSTANTS,
)

# All network syscalls (33 total) with full argument definitions
NETWORK_SYSCALLS: list[SyscallDef] = [
    SyscallDef(
        numbers.SYS_recvmsg,
        "recvmsg",
        params=[
            FileDescriptorParam(),
            StructParam("msghdr", ParamDirection.IN),
            FlagsParam(MSG_FLAGS),
        ],
    ),  # 27
    SyscallDef(
        numbers.SYS_sendmsg,
        "sendmsg",
        params=[
            FileDescriptorParam(),
            StructParam("msghdr", ParamDirection.IN),
            FlagsParam(MSG_FLAGS),
        ],
    ),  # 28
    SyscallDef(
        numbers.SYS_recvfrom,
        "recvfrom",
        params=[
            FileDescriptorParam(),
            BufferParam(size_arg_index=2, direction=ParamDirection.OUT),
            UnsignedParam(),
            FlagsParam(MSG_FLAGS),
            PointerParam(),
            PointerParam(),
        ],
    ),  # 29
    SyscallDef(
        numbers.SYS_accept,
        "accept",
        params=[
            FileDescriptorParam(),
            StructParam("sockaddr", ParamDirection.OUT),
            PointerParam(),
        ],
    ),  # 30
    SyscallDef(
        numbers.SYS_getpeername,
        "getpeername",
        params=[
            FileDescriptorParam(),
            StructParam("sockaddr", ParamDirection.OUT),
            PointerParam(),
        ],
    ),  # 31
    SyscallDef(
        numbers.SYS_getsockname,
        "getsockname",
        params=[
            FileDescriptorParam(),
            StructParam("sockaddr", ParamDirection.OUT),
            PointerParam(),
        ],
    ),  # 32
    SyscallDef(
        numbers.SYS_socket,
        "socket",
        params=[
            ConstParam(AF_CONSTANTS),
            ConstParam(SOCK_CONSTANTS),
            ConstParam(IPPROTO_CONSTANTS),
        ],
    ),  # 97
    SyscallDef(
        numbers.SYS_connect,
        "connect",
        params=[
            FileDescriptorParam(),
            StructParam("sockaddr", ParamDirection.IN),
            UnsignedParam(),
        ],
    ),  # 98
    SyscallDef(
        numbers.SYS_bind,
        "bind",
        params=[
            FileDescriptorParam(),
            StructParam("sockaddr", ParamDirection.IN),
            UnsignedParam(),
        ],
    ),  # 104
    SyscallDef(
        numbers.SYS_setsockopt,
        "setsockopt",
        params=[
            FileDescriptorParam(),
            ConstParam(SOL_CONSTANTS),
            ConstParam(SO_OPTIONS),
            PointerParam(),
            UnsignedParam(),
        ],
    ),  # 105
    SyscallDef(numbers.SYS_listen, "listen", params=[FileDescriptorParam(), IntParam()]),  # 106
    SyscallDef(
        numbers.SYS_getsockopt,
        "getsockopt",
        params=[
            FileDescriptorParam(),
            ConstParam(SOL_CONSTANTS),
            ConstParam(SO_OPTIONS),
            PointerParam(),
            PointerParam(),
        ],
    ),  # 118
    SyscallDef(
        numbers.SYS_sendto,
        "sendto",
        params=[
            FileDescriptorParam(),
            BufferParam(size_arg_index=2, direction=ParamDirection.IN),
            UnsignedParam(),
            FlagsParam(MSG_FLAGS),
            PointerParam(),
            UnsignedParam(),
        ],
    ),  # 133
    SyscallDef(
        numbers.SYS_shutdown,
        "shutdown",
        params=[FileDescriptorParam(), ConstParam(SHUT_CONSTANTS)],
    ),  # 134
    SyscallDef(
        numbers.SYS_socketpair,
        "socketpair",
        params=[
            ConstParam(AF_CONSTANTS),
            ConstParam(SOCK_CONSTANTS),
            ConstParam(IPPROTO_CONSTANTS),
            PointerParam(),
        ],
    ),  # 135
    SyscallDef(
        numbers.SYS_recvmsg_nocancel,
        "__recvmsg_nocancel",
        params=[
            FileDescriptorParam(),
            StructParam("msghdr", ParamDirection.IN),
            FlagsParam(MSG_FLAGS),
        ],
    ),  # 401
    SyscallDef(
        numbers.SYS_sendmsg_nocancel,
        "__sendmsg_nocancel",
        params=[
            FileDescriptorParam(),
            StructParam("msghdr", ParamDirection.IN),
            FlagsParam(MSG_FLAGS),
        ],
    ),  # 402
    SyscallDef(
        numbers.SYS_recvfrom_nocancel,
        "__recvfrom_nocancel",
        params=[
            FileDescriptorParam(),
            BufferParam(size_arg_index=2, direction=ParamDirection.OUT),
            UnsignedParam(),
            FlagsParam(MSG_FLAGS),
            PointerParam(),
            PointerParam(),
        ],
    ),  # 403
    SyscallDef(
        numbers.SYS_accept_nocancel,
        "__accept_nocancel",
        params=[
            FileDescriptorParam(),
            StructParam("sockaddr", ParamDirection.OUT),
            PointerParam(),
        ],
    ),  # 404
    SyscallDef(
        numbers.SYS_connect_nocancel,
        "__connect_nocancel",
        params=[
            FileDescriptorParam(),
            StructParam("sockaddr", ParamDirection.IN),
            UnsignedParam(),
        ],
    ),  # 409
    SyscallDef(
        numbers.SYS_sendto_nocancel,
        "__sendto_nocancel",
        params=[
            FileDescriptorParam(),
            BufferParam(size_arg_index=2, direction=ParamDirection.IN),
            UnsignedParam(),
            FlagsParam(MSG_FLAGS),
            PointerParam(),
            UnsignedParam(),
        ],
    ),  # 413
    SyscallDef(
        numbers.SYS_pid_shutdown_sockets,
        "pid_shutdown_sockets",
        params=[IntParam(), IntParam()],
    ),  # 453
    SyscallDef(
        numbers.SYS_connectx,
        "connectx",
        params=[
            FileDescriptorParam(),
            PointerParam(),
            UnsignedParam(),
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
            PointerParam(),
            PointerParam(),
        ],
    ),  # 447
    SyscallDef(
        numbers.SYS_disconnectx,
        "disconnectx",
        params=[FileDescriptorParam(), UnsignedParam(), UnsignedParam()],
    ),  # 448
    SyscallDef(
        numbers.SYS_peeloff,
        "peeloff",
        params=[FileDescriptorParam(), UnsignedParam()],
    ),  # 449
    SyscallDef(
        numbers.SYS_socket_delegate,
        "socket_delegate",
        params=[
            ConstParam(AF_CONSTANTS),
            ConstParam(SOCK_CONSTANTS),
            ConstParam(IPPROTO_CONSTANTS),
            IntParam(),
        ],
    ),  # 450
    SyscallDef(
        numbers.SYS_necp_match_policy,
        "necp_match_policy",
        params=[PointerParam(), UnsignedParam(), PointerParam()],
    ),  # 460
    SyscallDef(
        numbers.SYS_recvmsg_x,
        "recvmsg_x",
        params=[
            FileDescriptorParam(),
            PointerParam(),
            UnsignedParam(),
            FlagsParam(MSG_FLAGS),
        ],
    ),  # 480
    SyscallDef(
        numbers.SYS_sendmsg_x,
        "sendmsg_x",
        params=[
            FileDescriptorParam(),
            PointerParam(),
            UnsignedParam(),
            FlagsParam(MSG_FLAGS),
        ],
    ),  # 481
    SyscallDef(
        numbers.SYS_netagent_trigger,
        "netagent_trigger",
        params=[PointerParam(), UnsignedParam()],
    ),  # 490
    SyscallDef(
        numbers.SYS_necp_client_action,
        "necp_client_action",
        params=[
            IntParam(),
            UnsignedParam(),
            PointerParam(),
            UnsignedParam(),
            PointerParam(),
            UnsignedParam(),
        ],
    ),  # 502
    SyscallDef(
        numbers.SYS_necp_session_action,
        "necp_session_action",
        params=[IntParam(), UnsignedParam(), PointerParam(), UnsignedParam()],
    ),  # 523
    SyscallDef(
        numbers.SYS_net_qos_guideline,
        "net_qos_guideline",
        params=[PointerParam(), PointerParam()],
    ),  # 525
]
