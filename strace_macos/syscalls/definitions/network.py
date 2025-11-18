"""Network syscall definitions.

Priority 2: Required for network tests.
"""

from __future__ import annotations

from strace_macos.syscalls import numbers
from strace_macos.syscalls.definitions import BufferParam, ParamDirection, StructParam, SyscallDef
from strace_macos.syscalls.symbols import (
    decode_msg_flags,
    decode_shutdown_how,
    decode_so_option,
    decode_socket_family,
    decode_socket_protocol,
    decode_socket_type,
    decode_sol_level,
)

# All network syscalls (33 total) with full argument definitions
NETWORK_SYSCALLS: list[SyscallDef] = [
    SyscallDef(
        numbers.SYS_recvmsg,
        "recvmsg",
        ["int", "pointer", "int"],
        [None, None, decode_msg_flags],
        struct_params=[StructParam(1, "msghdr", ParamDirection.IN)],
    ),  # 27
    SyscallDef(
        numbers.SYS_sendmsg,
        "sendmsg",
        ["int", "pointer", "int"],
        [None, None, decode_msg_flags],
        struct_params=[StructParam(1, "msghdr", ParamDirection.IN)],
    ),  # 28
    SyscallDef(
        numbers.SYS_recvfrom,
        "recvfrom",
        ["int", "pointer", "size_t", "int", "pointer", "pointer"],
        [None, None, None, decode_msg_flags, None, None],
        buffer_params=[BufferParam(1, 2, ParamDirection.OUT)],
    ),  # 29
    SyscallDef(
        numbers.SYS_accept,
        "accept",
        ["int", "pointer", "pointer"],
        struct_params=[StructParam(1, "sockaddr", ParamDirection.OUT)],
    ),  # 30
    SyscallDef(
        numbers.SYS_getpeername,
        "getpeername",
        ["int", "pointer", "pointer"],
        struct_params=[StructParam(1, "sockaddr", ParamDirection.OUT)],
    ),  # 31
    SyscallDef(
        numbers.SYS_getsockname,
        "getsockname",
        ["int", "pointer", "pointer"],
        struct_params=[StructParam(1, "sockaddr", ParamDirection.OUT)],
    ),  # 32
    SyscallDef(
        numbers.SYS_socket,
        "socket",
        ["int", "int", "int"],
        [decode_socket_family, decode_socket_type, decode_socket_protocol],
    ),  # 97
    SyscallDef(
        numbers.SYS_connect,
        "connect",
        ["int", "pointer", "socklen_t"],
        struct_params=[StructParam(1, "sockaddr", ParamDirection.IN)],
    ),  # 98
    SyscallDef(
        numbers.SYS_bind,
        "bind",
        ["int", "pointer", "socklen_t"],
        struct_params=[StructParam(1, "sockaddr", ParamDirection.IN)],
    ),  # 104
    SyscallDef(
        numbers.SYS_setsockopt,
        "setsockopt",
        ["int", "int", "int", "pointer", "socklen_t"],
        [None, decode_sol_level, decode_so_option, None, None],
    ),  # 105
    SyscallDef(numbers.SYS_listen, "listen", ["int", "int"]),  # 106
    SyscallDef(
        numbers.SYS_getsockopt,
        "getsockopt",
        ["int", "int", "int", "pointer", "pointer"],
        [None, decode_sol_level, decode_so_option, None, None],
    ),  # 118
    SyscallDef(
        numbers.SYS_sendto,
        "sendto",
        ["int", "pointer", "size_t", "int", "pointer", "socklen_t"],
        [None, None, None, decode_msg_flags, None, None],
        buffer_params=[BufferParam(1, 2, ParamDirection.IN)],
    ),  # 133
    SyscallDef(
        numbers.SYS_shutdown, "shutdown", ["int", "int"], [None, decode_shutdown_how]
    ),  # 134
    SyscallDef(
        numbers.SYS_socketpair,
        "socketpair",
        ["int", "int", "int", "pointer"],
        [decode_socket_family, decode_socket_type, decode_socket_protocol, None],
    ),  # 135
    SyscallDef(
        numbers.SYS_recvmsg_nocancel,
        "__recvmsg_nocancel",
        ["int", "pointer", "int"],
        [None, None, decode_msg_flags],
        struct_params=[StructParam(1, "msghdr", ParamDirection.IN)],
    ),  # 401
    SyscallDef(
        numbers.SYS_sendmsg_nocancel,
        "__sendmsg_nocancel",
        ["int", "pointer", "int"],
        [None, None, decode_msg_flags],
        struct_params=[StructParam(1, "msghdr", ParamDirection.IN)],
    ),  # 402
    SyscallDef(
        numbers.SYS_recvfrom_nocancel,
        "__recvfrom_nocancel",
        ["int", "pointer", "size_t", "int", "pointer", "pointer"],
        [None, None, None, decode_msg_flags, None, None],
        buffer_params=[BufferParam(1, 2, ParamDirection.OUT)],
    ),  # 403
    SyscallDef(
        numbers.SYS_accept_nocancel,
        "__accept_nocancel",
        ["int", "pointer", "pointer"],
        struct_params=[StructParam(1, "sockaddr", ParamDirection.OUT)],
    ),  # 404
    SyscallDef(
        numbers.SYS_connect_nocancel,
        "__connect_nocancel",
        ["int", "pointer", "socklen_t"],
        struct_params=[StructParam(1, "sockaddr", ParamDirection.IN)],
    ),  # 409
    SyscallDef(
        numbers.SYS_sendto_nocancel,
        "__sendto_nocancel",
        ["int", "pointer", "size_t", "int", "pointer", "socklen_t"],
        [None, None, None, decode_msg_flags, None, None],
        buffer_params=[BufferParam(1, 2, ParamDirection.IN)],
    ),  # 413
    SyscallDef(numbers.SYS_pid_shutdown_sockets, "pid_shutdown_sockets", ["int", "int"]),  # 453
    SyscallDef(
        numbers.SYS_connectx,
        "connectx",
        [
            "int",
            "pointer",
            "socklen_t",
            "pointer",
            "socklen_t",
            "uint32_t",
            "pointer",
            "pointer",
        ],
    ),  # 447
    SyscallDef(numbers.SYS_disconnectx, "disconnectx", ["int", "uint32_t", "uint32_t"]),  # 448
    SyscallDef(numbers.SYS_peeloff, "peeloff", ["int", "uint32_t"]),  # 449
    SyscallDef(
        numbers.SYS_socket_delegate,
        "socket_delegate",
        ["int", "int", "int", "pid_t"],
        [decode_socket_family, decode_socket_type, decode_socket_protocol, None],
    ),  # 450
    SyscallDef(
        numbers.SYS_necp_match_policy,
        "necp_match_policy",
        ["pointer", "size_t", "pointer"],
    ),  # 460
    SyscallDef(
        numbers.SYS_recvmsg_x,
        "recvmsg_x",
        ["int", "pointer", "uint32_t", "int"],
        [None, None, None, decode_msg_flags],
    ),  # 480
    SyscallDef(
        numbers.SYS_sendmsg_x,
        "sendmsg_x",
        ["int", "pointer", "uint32_t", "int"],
        [None, None, None, decode_msg_flags],
    ),  # 481
    SyscallDef(numbers.SYS_netagent_trigger, "netagent_trigger", ["pointer", "size_t"]),  # 490
    SyscallDef(
        numbers.SYS_necp_client_action,
        "necp_client_action",
        ["int", "uint32_t", "pointer", "size_t", "pointer", "size_t"],
    ),  # 502
    SyscallDef(
        numbers.SYS_necp_session_action,
        "necp_session_action",
        ["int", "uint32_t", "pointer", "size_t"],
    ),  # 523
    SyscallDef(numbers.SYS_net_qos_guideline, "net_qos_guideline", ["pointer", "pointer"]),  # 525
]
