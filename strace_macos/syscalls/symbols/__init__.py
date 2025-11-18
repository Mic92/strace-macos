"""Symbolic constant decoders for syscall arguments and return values."""

from __future__ import annotations

from strace_macos.syscalls.symbols._helpers import (
    make_const_decoder,
    make_flag_decoder,
)
from strace_macos.syscalls.symbols.errno import decode_errno
from strace_macos.syscalls.symbols.file import (
    decode_access_mode,
    decode_at_flags,
    decode_chflags,
    decode_copyfile_flags,
    decode_dirfd,
    decode_fcntl_cmd,
    decode_fd_flags,
    decode_file_mode,
    decode_file_type_mode,
    decode_flock_op,
    decode_fsopt_flags,
    decode_ioctl_cmd,
    decode_mount_flags,
    decode_msync_flags,
    decode_open_flags,
    decode_pathconf_name,
    decode_poll_events,
    decode_seek_whence,
    decode_unmount_flags,
    decode_xattr_flags,
)
from strace_macos.syscalls.symbols.ipc import (
    decode_ipc_cmd,
    decode_ipc_flags,
    decode_shm_flags,
)
from strace_macos.syscalls.symbols.kqueue import (
    decode_ev_flags,
    decode_evfilt,
    decode_note_proc,
    decode_note_vnode,
)
from strace_macos.syscalls.symbols.memory import (
    decode_madvise_advice,
    decode_map_flags,
    decode_mlockall_flags,
    decode_prot_flags,
)
from strace_macos.syscalls.symbols.network import (
    decode_msg_flags,
    decode_shutdown_how,
    decode_so_option,
    decode_socket_family,
    decode_socket_protocol,
    decode_socket_type,
    decode_sol_level,
)
from strace_macos.syscalls.symbols.process import (
    decode_idtype,
    decode_prio_which,
    decode_rlimit_resource,
    decode_rusage_who,
    decode_sigprocmask_how,
    decode_wait_options,
    decode_waitid_options,
)
from strace_macos.syscalls.symbols.ptrace import (
    decode_ptrace_request,
)
from strace_macos.syscalls.symbols.signal import (
    decode_signal,
)
from strace_macos.syscalls.symbols.time import (
    decode_itimer_which,
)

__all__ = [
    "decode_access_mode",
    "decode_at_flags",
    "decode_chflags",
    "decode_copyfile_flags",
    "decode_dirfd",
    # Error decoder
    "decode_errno",
    "decode_ev_flags",
    "decode_evfilt",
    "decode_fcntl_cmd",
    "decode_fd_flags",
    "decode_file_mode",
    "decode_file_type_mode",
    "decode_flock_op",
    "decode_fsopt_flags",
    "decode_idtype",
    "decode_ioctl_cmd",
    "decode_ipc_cmd",
    # IPC decoders
    "decode_ipc_flags",
    "decode_itimer_which",
    "decode_madvise_advice",
    "decode_map_flags",
    "decode_mlockall_flags",
    "decode_mount_flags",
    "decode_msg_flags",
    "decode_msync_flags",
    "decode_note_proc",
    "decode_note_vnode",
    # File decoders
    "decode_open_flags",
    "decode_pathconf_name",
    "decode_poll_events",
    "decode_prio_which",
    # Memory decoders
    "decode_prot_flags",
    "decode_ptrace_request",
    "decode_rlimit_resource",
    "decode_rusage_who",
    "decode_seek_whence",
    "decode_shm_flags",
    "decode_shutdown_how",
    # Signal decoders
    "decode_signal",
    "decode_sigprocmask_how",
    "decode_so_option",
    # Network decoders
    "decode_socket_family",
    "decode_socket_protocol",
    "decode_socket_type",
    "decode_sol_level",
    "decode_unmount_flags",
    # Process decoders
    "decode_wait_options",
    "decode_waitid_options",
    "decode_xattr_flags",
    # Helpers
    "make_const_decoder",
    "make_flag_decoder",
]
