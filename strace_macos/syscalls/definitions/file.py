"""File I/O syscall definitions.

Priority 1: Required for tests to pass.
"""

from __future__ import annotations

from strace_macos.syscalls import numbers
from strace_macos.syscalls.definitions import (
    BufferParam,
    ConstParam,
    CustomParam,
    FileDescriptorParam,
    FlagsParam,
    IntParam,
    IovecParam,
    OctalParam,
    ParamDirection,
    PointerParam,
    StringParam,
    StructParam,
    SyscallDef,
    UnsignedParam,
)
from strace_macos.syscalls.symbols import (
    decode_access_mode,
    decode_dirfd,
    decode_flock_op,
    decode_ioctl_cmd,
    decode_open_flags,
)
from strace_macos.syscalls.symbols.file import (
    AT_FLAGS,
    CHFLAGS_FLAGS,
    COPYFILE_FLAGS,
    FCNTL_COMMANDS,
    FSOPT_FLAGS,
    MOUNT_FLAGS,
    MSYNC_FLAGS,
    PATHCONF_NAMES,
    SEEK_CONSTANTS,
    UNMOUNT_FLAGS,
    XATTR_FLAGS,
)

# All file I/O syscalls (162 total) with full argument definitions
FILE_SYSCALLS: list[SyscallDef] = [
    SyscallDef(
        numbers.SYS_read,
        "read",
        params=[
            FileDescriptorParam(),
            BufferParam(size_arg_index=2, direction=ParamDirection.OUT),
            UnsignedParam(),
        ],
    ),  # 3 - show buffer on exit
    SyscallDef(
        numbers.SYS_write,
        "write",
        params=[
            FileDescriptorParam(),
            BufferParam(size_arg_index=2, direction=ParamDirection.IN),
            UnsignedParam(),
        ],
    ),  # 4 - show buffer on entry
    SyscallDef(
        numbers.SYS_open,
        "open",
        params=[
            StringParam(),
            CustomParam(decode_open_flags),
            OctalParam(),
        ],
    ),  # 5
    SyscallDef(numbers.SYS_close, "close", params=[FileDescriptorParam()]),  # 6
    SyscallDef(numbers.SYS_link, "link", params=[StringParam(), StringParam()]),  # 9
    SyscallDef(numbers.SYS_unlink, "unlink", params=[StringParam()]),  # 10
    SyscallDef(numbers.SYS_chdir, "chdir", params=[StringParam()]),  # 12
    SyscallDef(numbers.SYS_fchdir, "fchdir", params=[FileDescriptorParam()]),  # 13
    SyscallDef(
        numbers.SYS_mknod,
        "mknod",
        params=[StringParam(), OctalParam(), IntParam()],
    ),  # 14
    SyscallDef(numbers.SYS_chmod, "chmod", params=[StringParam(), OctalParam()]),  # 15
    SyscallDef(numbers.SYS_chown, "chown", params=[StringParam(), IntParam(), IntParam()]),  # 16
    SyscallDef(
        numbers.SYS_chflags,
        "chflags",
        params=[StringParam(), FlagsParam(CHFLAGS_FLAGS)],
    ),  # 34
    SyscallDef(
        numbers.SYS_getfsstat,
        "getfsstat",
        params=[PointerParam(), IntParam(), FlagsParam(UNMOUNT_FLAGS)],
    ),  # 18
    SyscallDef(
        numbers.SYS_access,
        "access",
        params=[StringParam(), CustomParam(decode_access_mode)],
    ),  # 33
    SyscallDef(numbers.SYS_sync, "sync", params=[]),  # 36
    SyscallDef(numbers.SYS_dup, "dup", params=[FileDescriptorParam()]),  # 41
    SyscallDef(numbers.SYS_pipe, "pipe", params=[]),  # 42
    SyscallDef(
        numbers.SYS_ioctl,
        "ioctl",
        params=[
            FileDescriptorParam(),
            CustomParam(decode_ioctl_cmd),
            PointerParam(),
        ],
    ),  # 54
    SyscallDef(numbers.SYS_revoke, "revoke", params=[StringParam()]),  # 56
    SyscallDef(numbers.SYS_symlink, "symlink", params=[StringParam(), StringParam()]),  # 57
    SyscallDef(
        numbers.SYS_readlink,
        "readlink",
        params=[StringParam(), PointerParam(), UnsignedParam()],
    ),  # 58
    SyscallDef(numbers.SYS_umask, "umask", params=[OctalParam()]),  # 60
    SyscallDef(numbers.SYS_chroot, "chroot", params=[StringParam()]),  # 61
    SyscallDef(
        numbers.SYS_msync,
        "msync",
        params=[PointerParam(), UnsignedParam(), FlagsParam(MSYNC_FLAGS)],
    ),  # 65
    SyscallDef(
        numbers.SYS_dup2, "dup2", params=[FileDescriptorParam(), FileDescriptorParam()]
    ),  # 90
    SyscallDef(
        numbers.SYS_fcntl,
        "fcntl",
        params=[FileDescriptorParam(), ConstParam(FCNTL_COMMANDS), IntParam()],
    ),  # 92
    SyscallDef(numbers.SYS_fsync, "fsync", params=[FileDescriptorParam()]),  # 95
    SyscallDef(
        numbers.SYS_readv,
        "readv",
        params=[
            FileDescriptorParam(),
            IovecParam(count_arg_index=2, direction=ParamDirection.OUT),
            IntParam(),
        ],
    ),  # 120
    SyscallDef(
        numbers.SYS_writev,
        "writev",
        params=[
            FileDescriptorParam(),
            IovecParam(count_arg_index=2, direction=ParamDirection.IN),
            IntParam(),
        ],
    ),  # 121
    SyscallDef(
        numbers.SYS_fchown,
        "fchown",
        params=[FileDescriptorParam(), IntParam(), IntParam()],
    ),  # 123
    SyscallDef(numbers.SYS_fchmod, "fchmod", params=[FileDescriptorParam(), OctalParam()]),  # 124
    SyscallDef(numbers.SYS_rename, "rename", params=[StringParam(), StringParam()]),  # 128
    SyscallDef(
        numbers.SYS_flock,
        "flock",
        params=[FileDescriptorParam(), CustomParam(decode_flock_op)],
    ),  # 131
    SyscallDef(numbers.SYS_mkfifo, "mkfifo", params=[StringParam(), OctalParam()]),  # 132
    SyscallDef(numbers.SYS_mkdir, "mkdir", params=[StringParam(), OctalParam()]),  # 136
    SyscallDef(numbers.SYS_rmdir, "rmdir", params=[StringParam()]),  # 137
    SyscallDef(
        numbers.SYS_pread,
        "pread",
        params=[
            FileDescriptorParam(),
            BufferParam(size_arg_index=2, direction=ParamDirection.OUT),
            UnsignedParam(),
            IntParam(),
        ],
    ),  # 153
    SyscallDef(
        numbers.SYS_pwrite,
        "pwrite",
        params=[
            FileDescriptorParam(),
            BufferParam(size_arg_index=2, direction=ParamDirection.IN),
            UnsignedParam(),
            IntParam(),
        ],
    ),  # 154
    SyscallDef(
        numbers.SYS_preadv,
        "preadv",
        params=[
            FileDescriptorParam(),
            IovecParam(count_arg_index=2, direction=ParamDirection.OUT),
            IntParam(),
            IntParam(),
        ],
    ),  # 526
    SyscallDef(
        numbers.SYS_pwritev,
        "pwritev",
        params=[
            FileDescriptorParam(),
            IovecParam(count_arg_index=2, direction=ParamDirection.IN),
            IntParam(),
            IntParam(),
        ],
    ),  # 527
    SyscallDef(
        numbers.SYS_preadv_nocancel,
        "__preadv_nocancel",
        params=[
            FileDescriptorParam(),
            IovecParam(count_arg_index=2, direction=ParamDirection.OUT),
            IntParam(),
            IntParam(),
        ],
    ),  # 528
    SyscallDef(
        numbers.SYS_pwritev_nocancel,
        "__pwritev_nocancel",
        params=[
            FileDescriptorParam(),
            IovecParam(count_arg_index=2, direction=ParamDirection.IN),
            IntParam(),
            IntParam(),
        ],
    ),  # 529
    SyscallDef(numbers.SYS_nfssvc, "nfssvc", params=[IntParam(), PointerParam()]),  # 155
    SyscallDef(numbers.SYS_statfs, "statfs", params=[StringParam(), PointerParam()]),  # 157
    SyscallDef(
        numbers.SYS_fstatfs, "fstatfs", params=[FileDescriptorParam(), PointerParam()]
    ),  # 158
    SyscallDef(
        numbers.SYS_unmount,
        "unmount",
        params=[StringParam(), FlagsParam(UNMOUNT_FLAGS)],
    ),  # 159
    SyscallDef(numbers.SYS_getfh, "getfh", params=[StringParam(), PointerParam()]),  # 161
    SyscallDef(
        numbers.SYS_quotactl,
        "quotactl",
        params=[StringParam(), IntParam(), IntParam(), PointerParam()],
    ),  # 165
    SyscallDef(
        numbers.SYS_mount,
        "mount",
        params=[
            StringParam(),
            StringParam(),
            FlagsParam(MOUNT_FLAGS),
            PointerParam(),
        ],
    ),  # 167
    SyscallDef(
        numbers.SYS_csops_audittoken,
        "csops_audittoken",
        params=[
            IntParam(),
            UnsignedParam(),
            PointerParam(),
            UnsignedParam(),
            PointerParam(),
        ],
    ),  # 170
    SyscallDef(
        numbers.SYS_thread_selfcounts,
        "thread_selfcounts",
        params=[IntParam(), PointerParam(), UnsignedParam()],
    ),  # 186
    SyscallDef(numbers.SYS_fdatasync, "fdatasync", params=[FileDescriptorParam()]),  # 187
    SyscallDef(
        numbers.SYS_stat,
        "stat",
        params=[StringParam(), StructParam("stat", ParamDirection.OUT)],
    ),  # 188
    SyscallDef(
        numbers.SYS_fstat,
        "fstat",
        params=[FileDescriptorParam(), StructParam("stat", ParamDirection.OUT)],
    ),  # 189
    SyscallDef(
        numbers.SYS_lstat,
        "lstat",
        params=[StringParam(), StructParam("stat", ParamDirection.OUT)],
    ),  # 190
    SyscallDef(
        numbers.SYS_pathconf,
        "pathconf",
        params=[StringParam(), ConstParam(PATHCONF_NAMES)],
    ),  # 191
    SyscallDef(
        numbers.SYS_fpathconf,
        "fpathconf",
        params=[FileDescriptorParam(), ConstParam(PATHCONF_NAMES)],
    ),  # 192
    SyscallDef(
        numbers.SYS_getdirentries,
        "getdirentries",
        params=[FileDescriptorParam(), PointerParam(), UnsignedParam(), PointerParam()],
    ),  # 196
    SyscallDef(
        numbers.SYS_lseek,
        "lseek",
        params=[FileDescriptorParam(), IntParam(), ConstParam(SEEK_CONSTANTS)],
    ),  # 199
    SyscallDef(numbers.SYS_truncate, "truncate", params=[StringParam(), IntParam()]),  # 200
    SyscallDef(
        numbers.SYS_ftruncate,
        "ftruncate",
        params=[FileDescriptorParam(), IntParam()],
    ),  # 201
    SyscallDef(numbers.SYS_undelete, "undelete", params=[StringParam()]),  # 205
    SyscallDef(
        numbers.SYS_open_dprotected_np,
        "open_dprotected_np",
        params=[
            StringParam(),
            CustomParam(decode_open_flags),
            OctalParam(),
            IntParam(),
            IntParam(),
        ],
    ),  # 216
    SyscallDef(
        numbers.SYS_fsgetpath_ext,
        "fsgetpath_ext",
        params=[PointerParam(), UnsignedParam(), PointerParam(), UnsignedParam()],
    ),  # 217
    SyscallDef(
        numbers.SYS_openat_dprotected_np,
        "openat_dprotected_np",
        params=[
            CustomParam(decode_dirfd),
            StringParam(),
            CustomParam(decode_open_flags),
            OctalParam(),
            IntParam(),
            IntParam(),
        ],
    ),  # 218
    SyscallDef(
        numbers.SYS_getattrlist,
        "getattrlist",
        params=[
            StringParam(),
            PointerParam(),
            PointerParam(),
            UnsignedParam(),
            FlagsParam(FSOPT_FLAGS),
        ],
    ),  # 220
    SyscallDef(
        numbers.SYS_setattrlist,
        "setattrlist",
        params=[
            StringParam(),
            PointerParam(),
            PointerParam(),
            UnsignedParam(),
            FlagsParam(FSOPT_FLAGS),
        ],
    ),  # 221
    SyscallDef(
        numbers.SYS_getdirentriesattr,
        "getdirentriesattr",
        params=[
            FileDescriptorParam(),
            PointerParam(),
            PointerParam(),
            UnsignedParam(),
            PointerParam(),
            PointerParam(),
            PointerParam(),
            UnsignedParam(),
        ],
    ),  # 222
    SyscallDef(
        numbers.SYS_exchangedata,
        "exchangedata",
        params=[StringParam(), StringParam(), UnsignedParam()],
    ),  # 223
    SyscallDef(
        numbers.SYS_searchfs,
        "searchfs",
        params=[
            StringParam(),
            PointerParam(),
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
            PointerParam(),
        ],
    ),  # 225
    SyscallDef(numbers.SYS_delete, "delete", params=[StringParam()]),  # 226
    SyscallDef(
        numbers.SYS_copyfile,
        "copyfile",
        params=[
            StringParam(),
            StringParam(),
            IntParam(),
            FlagsParam(COPYFILE_FLAGS),
        ],
    ),  # 227
    SyscallDef(
        numbers.SYS_fgetattrlist,
        "fgetattrlist",
        params=[
            FileDescriptorParam(),
            PointerParam(),
            PointerParam(),
            UnsignedParam(),
            FlagsParam(FSOPT_FLAGS),
        ],
    ),  # 228
    SyscallDef(
        numbers.SYS_fsetattrlist,
        "fsetattrlist",
        params=[
            FileDescriptorParam(),
            PointerParam(),
            PointerParam(),
            UnsignedParam(),
            FlagsParam(FSOPT_FLAGS),
        ],
    ),  # 229
    SyscallDef(
        numbers.SYS_getxattr,
        "getxattr",
        params=[
            StringParam(),
            StringParam(),
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
            FlagsParam(XATTR_FLAGS),
        ],
    ),  # 234
    SyscallDef(
        numbers.SYS_fgetxattr,
        "fgetxattr",
        params=[
            FileDescriptorParam(),
            StringParam(),
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
            FlagsParam(XATTR_FLAGS),
        ],
    ),  # 235
    SyscallDef(
        numbers.SYS_setxattr,
        "setxattr",
        params=[
            StringParam(),
            StringParam(),
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
            FlagsParam(XATTR_FLAGS),
        ],
    ),  # 236
    SyscallDef(
        numbers.SYS_fsetxattr,
        "fsetxattr",
        params=[
            FileDescriptorParam(),
            StringParam(),
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
            FlagsParam(XATTR_FLAGS),
        ],
    ),  # 237
    SyscallDef(
        numbers.SYS_removexattr,
        "removexattr",
        params=[StringParam(), StringParam(), FlagsParam(XATTR_FLAGS)],
    ),  # 238
    SyscallDef(
        numbers.SYS_fremovexattr,
        "fremovexattr",
        params=[FileDescriptorParam(), StringParam(), FlagsParam(XATTR_FLAGS)],
    ),  # 239
    SyscallDef(
        numbers.SYS_listxattr,
        "listxattr",
        params=[
            StringParam(),
            PointerParam(),
            UnsignedParam(),
            FlagsParam(XATTR_FLAGS),
        ],
    ),  # 240
    SyscallDef(
        numbers.SYS_flistxattr,
        "flistxattr",
        params=[
            FileDescriptorParam(),
            PointerParam(),
            UnsignedParam(),
            FlagsParam(XATTR_FLAGS),
        ],
    ),  # 241
    SyscallDef(
        numbers.SYS_fsctl,
        "fsctl",
        params=[StringParam(), UnsignedParam(), PointerParam(), UnsignedParam()],
    ),  # 242
    SyscallDef(
        numbers.SYS_ffsctl,
        "ffsctl",
        params=[
            FileDescriptorParam(),
            UnsignedParam(),
            PointerParam(),
            UnsignedParam(),
        ],
    ),  # 245
    SyscallDef(numbers.SYS_fhopen, "fhopen", params=[PointerParam(), IntParam()]),  # 248
    SyscallDef(
        numbers.SYS_shm_open,
        "shm_open",
        params=[StringParam(), IntParam(), IntParam()],
    ),  # 266
    SyscallDef(numbers.SYS_shm_unlink, "shm_unlink", params=[StringParam()]),  # 267
    SyscallDef(
        numbers.SYS_sem_open,
        "sem_open",
        params=[StringParam(), IntParam(), IntParam(), IntParam()],
    ),  # 268
    SyscallDef(numbers.SYS_sem_close, "sem_close", params=[PointerParam()]),  # 269
    SyscallDef(numbers.SYS_sem_unlink, "sem_unlink", params=[StringParam()]),  # 270
    SyscallDef(
        numbers.SYS_open_extended,
        "open_extended",
        params=[
            StringParam(),
            IntParam(),
            UnsignedParam(),
            UnsignedParam(),
            IntParam(),
            PointerParam(),
        ],
    ),  # 277
    SyscallDef(
        numbers.SYS_umask_extended,
        "umask_extended",
        params=[IntParam(), PointerParam()],
    ),  # 278
    SyscallDef(
        numbers.SYS_stat_extended,
        "stat_extended",
        params=[StringParam(), PointerParam(), PointerParam(), PointerParam()],
    ),  # 279
    SyscallDef(
        numbers.SYS_lstat_extended,
        "lstat_extended",
        params=[StringParam(), PointerParam(), PointerParam(), PointerParam()],
    ),  # 280
    SyscallDef(
        numbers.SYS_fstat_extended,
        "fstat_extended",
        params=[
            FileDescriptorParam(),
            PointerParam(),
            PointerParam(),
            PointerParam(),
        ],
    ),  # 281
    SyscallDef(
        numbers.SYS_chmod_extended,
        "chmod_extended",
        params=[
            StringParam(),
            UnsignedParam(),
            UnsignedParam(),
            IntParam(),
            PointerParam(),
        ],
    ),  # 282
    SyscallDef(
        numbers.SYS_fchmod_extended,
        "fchmod_extended",
        params=[
            FileDescriptorParam(),
            UnsignedParam(),
            UnsignedParam(),
            IntParam(),
            PointerParam(),
        ],
    ),  # 283
    SyscallDef(
        numbers.SYS_access_extended,
        "access_extended",
        params=[
            StringParam(),
            CustomParam(decode_access_mode),
            PointerParam(),
            UnsignedParam(),
        ],
    ),  # 284
    SyscallDef(
        numbers.SYS_mkfifo_extended,
        "mkfifo_extended",
        params=[
            StringParam(),
            UnsignedParam(),
            UnsignedParam(),
            IntParam(),
            PointerParam(),
        ],
    ),  # 291
    SyscallDef(
        numbers.SYS_mkdir_extended,
        "mkdir_extended",
        params=[
            StringParam(),
            UnsignedParam(),
            UnsignedParam(),
            IntParam(),
            PointerParam(),
        ],
    ),  # 292
    SyscallDef(
        numbers.SYS_psynch_rw_longrdlock,
        "psynch_rw_longrdlock",
        params=[
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
            UnsignedParam(),
            IntParam(),
        ],
    ),  # 297
    SyscallDef(
        numbers.SYS_psynch_rw_yieldwrlock,
        "psynch_rw_yieldwrlock",
        params=[
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
            UnsignedParam(),
            IntParam(),
        ],
    ),  # 298
    SyscallDef(
        numbers.SYS_psynch_rw_downgrade,
        "psynch_rw_downgrade",
        params=[
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
            UnsignedParam(),
            IntParam(),
        ],
    ),  # 299
    SyscallDef(
        numbers.SYS_psynch_rw_upgrade,
        "psynch_rw_upgrade",
        params=[
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
            UnsignedParam(),
            IntParam(),
        ],
    ),  # 300
    SyscallDef(numbers.SYS_audit, "audit", params=[PointerParam(), IntParam()]),  # 350
    SyscallDef(
        numbers.SYS_auditon,
        "auditon",
        params=[IntParam(), PointerParam(), IntParam()],
    ),  # 351
    SyscallDef(numbers.SYS_getauid, "getauid", params=[PointerParam()]),  # 353
    SyscallDef(numbers.SYS_setauid, "setauid", params=[PointerParam()]),  # 354
    SyscallDef(
        numbers.SYS_getaudit_addr,
        "getaudit_addr",
        params=[PointerParam(), IntParam()],
    ),  # 357
    SyscallDef(
        numbers.SYS_setaudit_addr,
        "setaudit_addr",
        params=[PointerParam(), IntParam()],
    ),  # 358
    SyscallDef(numbers.SYS_auditctl, "auditctl", params=[StringParam()]),  # 359
    SyscallDef(
        numbers.SYS_openat,
        "openat",
        params=[
            CustomParam(decode_dirfd),
            StringParam(),
            CustomParam(decode_open_flags),
            OctalParam(),
        ],
    ),  # 406
    SyscallDef(
        numbers.SYS_openbyid_np,
        "openbyid_np",
        params=[PointerParam(), UnsignedParam(), IntParam()],
    ),  # 407
    SyscallDef(
        numbers.SYS_fstatat,
        "fstatat",
        params=[
            CustomParam(decode_dirfd),
            StringParam(),
            StructParam("stat", ParamDirection.OUT),
            FlagsParam(AT_FLAGS),
        ],
    ),  # 411
    SyscallDef(
        numbers.SYS_linkat,
        "linkat",
        params=[
            CustomParam(decode_dirfd),
            StringParam(),
            CustomParam(decode_dirfd),
            StringParam(),
            FlagsParam(AT_FLAGS),
        ],
    ),  # 413
    SyscallDef(
        numbers.SYS_unlinkat,
        "unlinkat",
        params=[
            CustomParam(decode_dirfd),
            StringParam(),
            FlagsParam(AT_FLAGS),
        ],
    ),  # 414
    SyscallDef(
        numbers.SYS_readlinkat,
        "readlinkat",
        params=[
            CustomParam(decode_dirfd),
            StringParam(),
            PointerParam(),
            UnsignedParam(),
        ],
    ),  # 415
    SyscallDef(
        numbers.SYS_symlinkat,
        "symlinkat",
        params=[StringParam(), CustomParam(decode_dirfd), StringParam()],
    ),  # 416
    SyscallDef(
        numbers.SYS_mkdirat,
        "mkdirat",
        params=[CustomParam(decode_dirfd), StringParam(), OctalParam()],
    ),  # 417
    SyscallDef(
        numbers.SYS_getattrlistat,
        "getattrlistat",
        params=[
            CustomParam(decode_dirfd),
            StringParam(),
            PointerParam(),
            PointerParam(),
            UnsignedParam(),
            FlagsParam(FSOPT_FLAGS),
        ],
    ),  # 418
    SyscallDef(
        numbers.SYS_fchmodat,
        "fchmodat",
        params=[
            CustomParam(decode_dirfd),
            StringParam(),
            OctalParam(),
            FlagsParam(AT_FLAGS),
        ],
    ),  # 421
    SyscallDef(
        numbers.SYS_fchownat,
        "fchownat",
        params=[
            CustomParam(decode_dirfd),
            StringParam(),
            UnsignedParam(),
            UnsignedParam(),
            FlagsParam(AT_FLAGS),
        ],
    ),  # 422
    SyscallDef(
        numbers.SYS_fstatat64,
        "fstatat64",
        params=[
            CustomParam(decode_dirfd),
            StringParam(),
            StructParam("stat64", ParamDirection.OUT),
            FlagsParam(AT_FLAGS),
        ],
    ),  # 423
    SyscallDef(
        numbers.SYS_openat_nocancel,
        "__openat_nocancel",
        params=[
            CustomParam(decode_dirfd),
            StringParam(),
            CustomParam(decode_open_flags),
            OctalParam(),
        ],
    ),  # 424
    SyscallDef(
        numbers.SYS_renameat,
        "renameat",
        params=[
            CustomParam(decode_dirfd),
            StringParam(),
            CustomParam(decode_dirfd),
            StringParam(),
        ],
    ),  # 426
    SyscallDef(
        numbers.SYS_faccessat,
        "faccessat",
        params=[
            CustomParam(decode_dirfd),
            StringParam(),
            CustomParam(decode_access_mode),
            FlagsParam(AT_FLAGS),
        ],
    ),  # 428
    SyscallDef(
        numbers.SYS_fchflags,
        "fchflags",
        params=[FileDescriptorParam(), FlagsParam(CHFLAGS_FLAGS)],
    ),  # 429
    SyscallDef(
        numbers.SYS_getattrlistbulk,
        "getattrlistbulk",
        params=[
            FileDescriptorParam(),
            PointerParam(),
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
        ],
    ),  # 432
    SyscallDef(
        numbers.SYS_guarded_open_np,
        "guarded_open_np",
        params=[StringParam(), PointerParam(), IntParam(), IntParam()],
    ),  # 442
    SyscallDef(
        numbers.SYS_guarded_close_np,
        "guarded_close_np",
        params=[FileDescriptorParam(), PointerParam()],
    ),  # 444
    SyscallDef(
        numbers.SYS_guarded_open_dprotected_np,
        "guarded_open_dprotected_np",
        params=[
            StringParam(),
            PointerParam(),
            IntParam(),
            IntParam(),
            IntParam(),
            IntParam(),
        ],
    ),  # 446
    SyscallDef(
        numbers.SYS_change_fdguard_np,
        "change_fdguard_np",
        params=[
            FileDescriptorParam(),
            PointerParam(),
            UnsignedParam(),
            PointerParam(),
            UnsignedParam(),
            PointerParam(),
        ],
    ),  # 451
    SyscallDef(
        numbers.SYS_guarded_writev_np,
        "guarded_writev_np",
        params=[
            FileDescriptorParam(),
            PointerParam(),
            PointerParam(),
            IntParam(),
        ],
    ),  # 554
    SyscallDef(
        numbers.SYS_fsgetpath,
        "fsgetpath",
        params=[PointerParam(), UnsignedParam(), PointerParam(), UnsignedParam()],
    ),  # 435
    SyscallDef(
        numbers.SYS_fmount,
        "fmount",
        params=[StringParam(), FileDescriptorParam(), IntParam(), PointerParam()],
    ),  # 436
    SyscallDef(
        numbers.SYS_fclonefileat,
        "fclonefileat",
        params=[
            FileDescriptorParam(),
            CustomParam(decode_dirfd),
            StringParam(),
            IntParam(),
        ],
    ),  # 447
    SyscallDef(
        numbers.SYS_fs_snapshot,
        "fs_snapshot",
        params=[
            UnsignedParam(),
            FileDescriptorParam(),
            StringParam(),
            StringParam(),
            PointerParam(),
            UnsignedParam(),
        ],
    ),  # 448
    SyscallDef(
        numbers.SYS_mkfifoat,
        "mkfifoat",
        params=[CustomParam(decode_dirfd), StringParam(), OctalParam()],
    ),  # 456
    SyscallDef(
        numbers.SYS_mknodat,
        "mknodat",
        params=[
            CustomParam(decode_dirfd),
            StringParam(),
            OctalParam(),
            IntParam(),
        ],
    ),  # 457
    SyscallDef(
        numbers.SYS_renameatx_np,
        "renameatx_np",
        params=[
            CustomParam(decode_dirfd),
            StringParam(),
            CustomParam(decode_dirfd),
            StringParam(),
            UnsignedParam(),
        ],
    ),  # 488
    SyscallDef(
        numbers.SYS_mremap_encrypted,
        "mremap_encrypted",
        params=[
            PointerParam(),
            UnsignedParam(),
            UnsignedParam(),
            UnsignedParam(),
            UnsignedParam(),
        ],
    ),  # 489
    SyscallDef(
        numbers.SYS_fsync_nocancel,
        "__fsync_nocancel",
        params=[FileDescriptorParam()],
    ),  # 408
    SyscallDef(
        numbers.SYS_open_nocancel,
        "__open_nocancel",
        params=[StringParam(), CustomParam(decode_open_flags), OctalParam()],
    ),  # 398
    SyscallDef(
        numbers.SYS_close_nocancel,
        "__close_nocancel",
        params=[FileDescriptorParam()],
    ),  # 399
    SyscallDef(
        numbers.SYS_read_nocancel,
        "__read_nocancel",
        params=[
            FileDescriptorParam(),
            BufferParam(size_arg_index=2, direction=ParamDirection.OUT),
            UnsignedParam(),
        ],
    ),  # 396
    SyscallDef(
        numbers.SYS_write_nocancel,
        "__write_nocancel",
        params=[
            FileDescriptorParam(),
            BufferParam(size_arg_index=2, direction=ParamDirection.IN),
            UnsignedParam(),
        ],
    ),  # 397
    SyscallDef(
        numbers.SYS_pread_nocancel,
        "__pread_nocancel",
        params=[
            FileDescriptorParam(),
            BufferParam(size_arg_index=2, direction=ParamDirection.OUT),
            UnsignedParam(),
            IntParam(),
        ],
    ),  # 414
    SyscallDef(
        numbers.SYS_pwrite_nocancel,
        "__pwrite_nocancel",
        params=[
            FileDescriptorParam(),
            BufferParam(size_arg_index=2, direction=ParamDirection.IN),
            UnsignedParam(),
            IntParam(),
        ],
    ),  # 415
    SyscallDef(
        numbers.SYS_readv_nocancel,
        "__readv_nocancel",
        params=[
            FileDescriptorParam(),
            IovecParam(count_arg_index=2, direction=ParamDirection.OUT),
            IntParam(),
        ],
    ),  # 411
    SyscallDef(
        numbers.SYS_writev_nocancel,
        "__writev_nocancel",
        params=[
            FileDescriptorParam(),
            IovecParam(count_arg_index=2, direction=ParamDirection.IN),
            IntParam(),
        ],
    ),  # 412
    SyscallDef(
        numbers.SYS_fcntl_nocancel,
        "__fcntl_nocancel",
        params=[FileDescriptorParam(), ConstParam(FCNTL_COMMANDS), IntParam()],
    ),  # 406
    SyscallDef(
        numbers.SYS_stat64,
        "stat64",
        params=[StringParam(), StructParam("stat64", ParamDirection.OUT)],
    ),  # 338
    SyscallDef(
        numbers.SYS_fstat64,
        "fstat64",
        params=[FileDescriptorParam(), StructParam("stat64", ParamDirection.OUT)],
    ),  # 339
    SyscallDef(
        numbers.SYS_lstat64,
        "lstat64",
        params=[StringParam(), StructParam("stat64", ParamDirection.OUT)],
    ),  # 340
    SyscallDef(
        numbers.SYS_stat64_extended,
        "stat64_extended",
        params=[StringParam(), PointerParam(), PointerParam(), PointerParam()],
    ),  # 341
    SyscallDef(
        numbers.SYS_lstat64_extended,
        "lstat64_extended",
        params=[StringParam(), PointerParam(), PointerParam(), PointerParam()],
    ),  # 342
    SyscallDef(
        numbers.SYS_fstat64_extended,
        "fstat64_extended",
        params=[
            FileDescriptorParam(),
            PointerParam(),
            PointerParam(),
            PointerParam(),
        ],
    ),  # 343
    SyscallDef(
        numbers.SYS_getdirentries64,
        "getdirentries64",
        params=[FileDescriptorParam(), PointerParam(), UnsignedParam(), PointerParam()],
    ),  # 344
    SyscallDef(numbers.SYS_statfs64, "statfs64", params=[StringParam(), PointerParam()]),  # 345
    SyscallDef(
        numbers.SYS_fstatfs64,
        "fstatfs64",
        params=[FileDescriptorParam(), PointerParam()],
    ),  # 346
    SyscallDef(
        numbers.SYS_getfsstat64,
        "getfsstat64",
        params=[PointerParam(), IntParam(), FlagsParam(UNMOUNT_FLAGS)],
    ),  # 347
    SyscallDef(
        numbers.SYS_clonefileat,
        "clonefileat",
        params=[
            CustomParam(decode_dirfd),
            StringParam(),
            CustomParam(decode_dirfd),
            StringParam(),
            UnsignedParam(),
        ],
    ),  # 462
]
