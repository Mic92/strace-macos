"""File I/O syscall definitions.

Priority 1: Required for tests to pass.
"""

from __future__ import annotations

from strace_macos.syscalls import numbers
from strace_macos.syscalls.definitions import (
    BufferParam,
    IovecParam,
    ParamDirection,
    StructParam,
    SyscallDef,
)
from strace_macos.syscalls.symbols import (
    decode_access_mode,
    decode_at_flags,
    decode_chflags,
    decode_copyfile_flags,
    decode_dirfd,
    decode_fcntl_cmd,
    decode_file_mode,
    decode_flock_op,
    decode_fsopt_flags,
    decode_ioctl_cmd,
    decode_mount_flags,
    decode_msync_flags,
    decode_open_flags,
    decode_pathconf_name,
    decode_seek_whence,
    decode_unmount_flags,
    decode_xattr_flags,
)

# All file I/O syscalls (224 total) with full argument definitions
FILE_SYSCALLS: list[SyscallDef] = [
    SyscallDef(
        numbers.SYS_read,
        "read",
        ["int", "pointer", "size_t"],
        buffer_params=[BufferParam(1, 2, ParamDirection.OUT)],
    ),  # 3 - show buffer on exit
    SyscallDef(
        numbers.SYS_write,
        "write",
        ["int", "pointer", "size_t"],
        buffer_params=[BufferParam(1, 2, ParamDirection.IN)],
    ),  # 4 - show buffer on entry
    SyscallDef(
        numbers.SYS_open,
        "open",
        ["string", "int", "int"],
        [None, decode_open_flags, decode_file_mode],
    ),  # 5
    SyscallDef(numbers.SYS_close, "close", ["int"]),  # 6
    SyscallDef(numbers.SYS_link, "link", ["string", "string"]),  # 9
    SyscallDef(numbers.SYS_unlink, "unlink", ["string"]),  # 10
    SyscallDef(numbers.SYS_chdir, "chdir", ["string"]),  # 12
    SyscallDef(numbers.SYS_fchdir, "fchdir", ["int"]),  # 13
    SyscallDef(
        numbers.SYS_mknod,
        "mknod",
        ["string", "int", "int"],
        [None, decode_file_mode, None],
    ),  # 14
    SyscallDef(numbers.SYS_chmod, "chmod", ["string", "int"], [None, decode_file_mode]),  # 15
    SyscallDef(numbers.SYS_chown, "chown", ["string", "int", "int"]),  # 16
    SyscallDef(
        numbers.SYS_chflags, "chflags", ["string", "uint32_t"], [None, decode_chflags]
    ),  # 34
    SyscallDef(
        numbers.SYS_getfsstat,
        "getfsstat",
        ["pointer", "int", "int"],
        [None, None, decode_unmount_flags],
    ),  # 18
    SyscallDef(numbers.SYS_access, "access", ["string", "int"], [None, decode_access_mode]),  # 33
    SyscallDef(numbers.SYS_sync, "sync", []),  # 36
    SyscallDef(numbers.SYS_dup, "dup", ["int"]),  # 41
    SyscallDef(numbers.SYS_pipe, "pipe", []),  # 42
    SyscallDef(
        numbers.SYS_ioctl,
        "ioctl",
        ["int", "unsigned long", "pointer"],
        [None, decode_ioctl_cmd, None],
    ),  # 54
    SyscallDef(numbers.SYS_revoke, "revoke", ["string"]),  # 56
    SyscallDef(numbers.SYS_symlink, "symlink", ["string", "string"]),  # 57
    SyscallDef(numbers.SYS_readlink, "readlink", ["string", "pointer", "size_t"]),  # 58
    SyscallDef(numbers.SYS_umask, "umask", ["int"], [decode_file_mode]),  # 60
    SyscallDef(numbers.SYS_chroot, "chroot", ["string"]),  # 61
    SyscallDef(
        numbers.SYS_msync,
        "msync",
        ["pointer", "size_t", "int"],
        [None, None, decode_msync_flags],
    ),  # 65
    SyscallDef(numbers.SYS_dup2, "dup2", ["int", "int"]),  # 90
    SyscallDef(
        numbers.SYS_fcntl,
        "fcntl",
        ["int", "int", "long"],
        [None, decode_fcntl_cmd, None],
    ),  # 92
    SyscallDef(numbers.SYS_fsync, "fsync", ["int"]),  # 95
    SyscallDef(
        numbers.SYS_readv,
        "readv",
        ["int", "pointer", "int"],
        iovec_params=[IovecParam(1, 2, ParamDirection.OUT)],
    ),  # 120
    SyscallDef(
        numbers.SYS_writev,
        "writev",
        ["int", "pointer", "int"],
        iovec_params=[IovecParam(1, 2, ParamDirection.IN)],
    ),  # 121
    SyscallDef(numbers.SYS_fchown, "fchown", ["int", "int", "int"]),  # 123
    SyscallDef(numbers.SYS_fchmod, "fchmod", ["int", "int"], [None, decode_file_mode]),  # 124
    SyscallDef(numbers.SYS_rename, "rename", ["string", "string"]),  # 128
    SyscallDef(numbers.SYS_flock, "flock", ["int", "int"], [None, decode_flock_op]),  # 131
    SyscallDef(numbers.SYS_mkfifo, "mkfifo", ["string", "int"], [None, decode_file_mode]),  # 132
    SyscallDef(numbers.SYS_mkdir, "mkdir", ["string", "int"], [None, decode_file_mode]),  # 136
    SyscallDef(numbers.SYS_rmdir, "rmdir", ["string"]),  # 137
    SyscallDef(
        numbers.SYS_pread,
        "pread",
        ["int", "pointer", "size_t", "off_t"],
        buffer_params=[BufferParam(1, 2, ParamDirection.OUT)],
    ),  # 153
    SyscallDef(
        numbers.SYS_pwrite,
        "pwrite",
        ["int", "pointer", "size_t", "off_t"],
        buffer_params=[BufferParam(1, 2, ParamDirection.IN)],
    ),  # 154
    SyscallDef(numbers.SYS_preadv, "preadv", ["int", "pointer", "int", "off_t"]),  # 526
    SyscallDef(numbers.SYS_pwritev, "pwritev", ["int", "pointer", "int", "off_t"]),  # 527
    SyscallDef(
        numbers.SYS_preadv_nocancel,
        "__preadv_nocancel",
        ["int", "pointer", "int", "off_t"],
    ),  # 528
    SyscallDef(
        numbers.SYS_pwritev_nocancel,
        "__pwritev_nocancel",
        ["int", "pointer", "int", "off_t"],
    ),  # 529
    SyscallDef(numbers.SYS_nfssvc, "nfssvc", ["int", "pointer"]),  # 155
    SyscallDef(numbers.SYS_statfs, "statfs", ["string", "pointer"]),  # 157
    SyscallDef(numbers.SYS_fstatfs, "fstatfs", ["int", "pointer"]),  # 158
    SyscallDef(
        numbers.SYS_unmount, "unmount", ["string", "int"], [None, decode_unmount_flags]
    ),  # 159
    SyscallDef(numbers.SYS_getfh, "getfh", ["string", "pointer"]),  # 161
    SyscallDef(numbers.SYS_quotactl, "quotactl", ["string", "int", "int", "pointer"]),  # 165
    SyscallDef(
        numbers.SYS_mount,
        "mount",
        ["string", "string", "int", "pointer"],
        [None, None, decode_mount_flags, None],
    ),  # 167
    SyscallDef(
        numbers.SYS_csops_audittoken,
        "csops_audittoken",
        ["pid_t", "unsigned int", "pointer", "size_t", "pointer"],
    ),  # 170
    SyscallDef(
        numbers.SYS_thread_selfcounts, "thread_selfcounts", ["int", "pointer", "size_t"]
    ),  # 186
    SyscallDef(numbers.SYS_fdatasync, "fdatasync", ["int"]),  # 187
    SyscallDef(
        numbers.SYS_stat,
        "stat",
        ["string", "pointer"],
        struct_params=[StructParam(1, "stat", ParamDirection.OUT)],
    ),  # 188
    SyscallDef(
        numbers.SYS_fstat,
        "fstat",
        ["int", "pointer"],
        struct_params=[StructParam(1, "stat", ParamDirection.OUT)],
    ),  # 189
    SyscallDef(
        numbers.SYS_lstat,
        "lstat",
        ["string", "pointer"],
        struct_params=[StructParam(1, "stat", ParamDirection.OUT)],
    ),  # 190
    SyscallDef(
        numbers.SYS_pathconf,
        "pathconf",
        ["string", "int"],
        [None, decode_pathconf_name],
    ),  # 191
    SyscallDef(
        numbers.SYS_fpathconf, "fpathconf", ["int", "int"], [None, decode_pathconf_name]
    ),  # 192
    SyscallDef(
        numbers.SYS_getdirentries,
        "getdirentries",
        ["int", "pointer", "unsigned int", "pointer"],
    ),  # 196
    SyscallDef(
        numbers.SYS_lseek,
        "lseek",
        ["int", "off_t", "int"],
        [None, None, decode_seek_whence],
    ),  # 199
    SyscallDef(numbers.SYS_truncate, "truncate", ["string", "off_t"]),  # 200
    SyscallDef(numbers.SYS_ftruncate, "ftruncate", ["int", "off_t"]),  # 201
    SyscallDef(numbers.SYS_undelete, "undelete", ["string"]),  # 205
    SyscallDef(
        numbers.SYS_open_dprotected_np,
        "open_dprotected_np",
        ["string", "int", "int", "int", "int"],
    ),  # 216
    SyscallDef(
        numbers.SYS_fsgetpath_ext,
        "fsgetpath_ext",
        ["pointer", "size_t", "pointer", "uint64_t"],
    ),  # 217
    SyscallDef(
        numbers.SYS_openat_dprotected_np,
        "openat_dprotected_np",
        ["int", "string", "int", "int", "int", "int"],
    ),  # 218
    SyscallDef(
        numbers.SYS_getattrlist,
        "getattrlist",
        ["string", "pointer", "pointer", "size_t", "unsigned long"],
        [None, None, None, None, decode_fsopt_flags],
    ),  # 220
    SyscallDef(
        numbers.SYS_setattrlist,
        "setattrlist",
        ["string", "pointer", "pointer", "size_t", "unsigned long"],
        [None, None, None, None, decode_fsopt_flags],
    ),  # 221
    SyscallDef(
        numbers.SYS_getdirentriesattr,
        "getdirentriesattr",
        [
            "int",
            "pointer",
            "pointer",
            "size_t",
            "pointer",
            "pointer",
            "pointer",
            "unsigned long",
        ],
    ),  # 222
    SyscallDef(
        numbers.SYS_exchangedata, "exchangedata", ["string", "string", "unsigned long"]
    ),  # 223
    SyscallDef(
        numbers.SYS_searchfs,
        "searchfs",
        ["string", "pointer", "pointer", "unsigned int", "unsigned int", "pointer"],
    ),  # 225
    SyscallDef(numbers.SYS_delete, "delete", ["string"]),  # 226
    SyscallDef(
        numbers.SYS_copyfile,
        "copyfile",
        ["string", "string", "int", "int"],
        [None, None, None, decode_copyfile_flags],
    ),  # 227
    SyscallDef(
        numbers.SYS_fgetattrlist,
        "fgetattrlist",
        ["int", "pointer", "pointer", "size_t", "unsigned long"],
        [None, None, None, None, decode_fsopt_flags],
    ),  # 228
    SyscallDef(
        numbers.SYS_fsetattrlist,
        "fsetattrlist",
        ["int", "pointer", "pointer", "size_t", "unsigned long"],
        [None, None, None, None, decode_fsopt_flags],
    ),  # 229
    SyscallDef(
        numbers.SYS_getxattr,
        "getxattr",
        ["string", "string", "pointer", "size_t", "uint32_t", "int"],
        [None, None, None, None, None, decode_xattr_flags],
    ),  # 234
    SyscallDef(
        numbers.SYS_fgetxattr,
        "fgetxattr",
        ["int", "string", "pointer", "size_t", "uint32_t", "int"],
        [None, None, None, None, None, decode_xattr_flags],
    ),  # 235
    SyscallDef(
        numbers.SYS_setxattr,
        "setxattr",
        ["string", "string", "pointer", "size_t", "uint32_t", "int"],
        [None, None, None, None, None, decode_xattr_flags],
    ),  # 236
    SyscallDef(
        numbers.SYS_fsetxattr,
        "fsetxattr",
        ["int", "string", "pointer", "size_t", "uint32_t", "int"],
        [None, None, None, None, None, decode_xattr_flags],
    ),  # 237
    SyscallDef(
        numbers.SYS_removexattr,
        "removexattr",
        ["string", "string", "int"],
        [None, None, decode_xattr_flags],
    ),  # 238
    SyscallDef(
        numbers.SYS_fremovexattr,
        "fremovexattr",
        ["int", "string", "int"],
        [None, None, decode_xattr_flags],
    ),  # 239
    SyscallDef(
        numbers.SYS_listxattr,
        "listxattr",
        ["string", "pointer", "size_t", "int"],
        [None, None, None, decode_xattr_flags],
    ),  # 240
    SyscallDef(
        numbers.SYS_flistxattr,
        "flistxattr",
        ["int", "pointer", "size_t", "int"],
        [None, None, None, decode_xattr_flags],
    ),  # 241
    SyscallDef(
        numbers.SYS_fsctl,
        "fsctl",
        ["string", "unsigned long", "pointer", "unsigned int"],
    ),  # 242
    SyscallDef(
        numbers.SYS_ffsctl,
        "ffsctl",
        ["int", "unsigned long", "pointer", "unsigned int"],
    ),  # 245
    SyscallDef(numbers.SYS_fhopen, "fhopen", ["pointer", "int"]),  # 248
    SyscallDef(numbers.SYS_shm_open, "shm_open", ["string", "int", "int"]),  # 266
    SyscallDef(numbers.SYS_shm_unlink, "shm_unlink", ["string"]),  # 267
    SyscallDef(numbers.SYS_sem_open, "sem_open", ["string", "int", "int", "int"]),  # 268
    SyscallDef(numbers.SYS_sem_close, "sem_close", ["pointer"]),  # 269
    SyscallDef(numbers.SYS_sem_unlink, "sem_unlink", ["string"]),  # 270
    SyscallDef(
        numbers.SYS_open_extended,
        "open_extended",
        ["string", "int", "uid_t", "gid_t", "int", "pointer"],
    ),  # 277
    SyscallDef(numbers.SYS_umask_extended, "umask_extended", ["int", "pointer"]),  # 278
    SyscallDef(
        numbers.SYS_stat_extended,
        "stat_extended",
        ["string", "pointer", "pointer", "pointer"],
    ),  # 279
    SyscallDef(
        numbers.SYS_lstat_extended,
        "lstat_extended",
        ["string", "pointer", "pointer", "pointer"],
    ),  # 280
    SyscallDef(
        numbers.SYS_fstat_extended,
        "fstat_extended",
        ["int", "pointer", "pointer", "pointer"],
    ),  # 281
    SyscallDef(
        numbers.SYS_chmod_extended,
        "chmod_extended",
        ["string", "uid_t", "gid_t", "int", "pointer"],
    ),  # 282
    SyscallDef(
        numbers.SYS_fchmod_extended,
        "fchmod_extended",
        ["int", "uid_t", "gid_t", "int", "pointer"],
    ),  # 283
    SyscallDef(
        numbers.SYS_access_extended,
        "access_extended",
        ["string", "int", "pointer", "uid_t"],
        [None, decode_access_mode, None, None],
    ),  # 284
    SyscallDef(
        numbers.SYS_mkfifo_extended,
        "mkfifo_extended",
        ["string", "uid_t", "gid_t", "int", "pointer"],
    ),  # 291
    SyscallDef(
        numbers.SYS_mkdir_extended,
        "mkdir_extended",
        ["string", "uid_t", "gid_t", "int", "pointer"],
    ),  # 292
    SyscallDef(
        numbers.SYS_psynch_rw_longrdlock,
        "psynch_rw_longrdlock",
        ["pointer", "uint32_t", "uint32_t", "uint32_t", "int"],
    ),  # 297
    SyscallDef(
        numbers.SYS_psynch_rw_yieldwrlock,
        "psynch_rw_yieldwrlock",
        ["pointer", "uint32_t", "uint32_t", "uint32_t", "int"],
    ),  # 298
    SyscallDef(
        numbers.SYS_psynch_rw_downgrade,
        "psynch_rw_downgrade",
        ["pointer", "uint32_t", "uint32_t", "uint32_t", "int"],
    ),  # 299
    SyscallDef(
        numbers.SYS_psynch_rw_upgrade,
        "psynch_rw_upgrade",
        ["pointer", "uint32_t", "uint32_t", "uint32_t", "int"],
    ),  # 300
    SyscallDef(numbers.SYS_audit, "audit", ["pointer", "int"]),  # 350
    SyscallDef(numbers.SYS_auditon, "auditon", ["int", "pointer", "int"]),  # 351
    SyscallDef(numbers.SYS_getauid, "getauid", ["pointer"]),  # 353
    SyscallDef(numbers.SYS_setauid, "setauid", ["pointer"]),  # 354
    SyscallDef(numbers.SYS_getaudit_addr, "getaudit_addr", ["pointer", "int"]),  # 357
    SyscallDef(numbers.SYS_setaudit_addr, "setaudit_addr", ["pointer", "int"]),  # 358
    SyscallDef(numbers.SYS_auditctl, "auditctl", ["string"]),  # 359
    SyscallDef(
        numbers.SYS_openat,
        "openat",
        ["int", "string", "int", "int"],
        [decode_dirfd, None, decode_open_flags, decode_file_mode],
    ),  # 406
    SyscallDef(numbers.SYS_openbyid_np, "openbyid_np", ["pointer", "size_t", "int"]),  # 407
    SyscallDef(
        numbers.SYS_fstatat,
        "fstatat",
        ["int", "string", "pointer", "int"],
        [decode_dirfd, None, None, decode_at_flags],
        struct_params=[StructParam(2, "stat", ParamDirection.OUT)],
    ),  # 411
    SyscallDef(
        numbers.SYS_linkat,
        "linkat",
        ["int", "string", "int", "string", "int"],
        [decode_dirfd, None, decode_dirfd, None, decode_at_flags],
    ),  # 413
    SyscallDef(
        numbers.SYS_unlinkat,
        "unlinkat",
        ["int", "string", "int"],
        [decode_dirfd, None, decode_at_flags],
    ),  # 414
    SyscallDef(
        numbers.SYS_readlinkat,
        "readlinkat",
        ["int", "string", "pointer", "size_t"],
        [decode_dirfd, None, None, None],
    ),  # 415
    SyscallDef(
        numbers.SYS_symlinkat,
        "symlinkat",
        ["string", "int", "string"],
        [None, decode_dirfd, None],
    ),  # 416
    SyscallDef(
        numbers.SYS_mkdirat,
        "mkdirat",
        ["int", "string", "int"],
        [decode_dirfd, None, decode_file_mode],
    ),  # 417
    SyscallDef(
        numbers.SYS_getattrlistat,
        "getattrlistat",
        ["int", "string", "pointer", "pointer", "size_t", "unsigned long"],
        [decode_dirfd, None, None, None, None, decode_fsopt_flags],
    ),  # 418
    SyscallDef(
        numbers.SYS_fchmodat,
        "fchmodat",
        ["int", "string", "int", "int"],
        [decode_dirfd, None, decode_file_mode, decode_at_flags],
    ),  # 421
    SyscallDef(
        numbers.SYS_fchownat,
        "fchownat",
        ["int", "string", "uid_t", "gid_t", "int"],
        [decode_dirfd, None, None, None, decode_at_flags],
    ),  # 422
    SyscallDef(
        numbers.SYS_fstatat64,
        "fstatat64",
        ["int", "string", "pointer", "int"],
        [decode_dirfd, None, None, decode_at_flags],
        struct_params=[StructParam(2, "stat64", ParamDirection.OUT)],
    ),  # 423
    SyscallDef(
        numbers.SYS_openat_nocancel,
        "__openat_nocancel",
        ["int", "string", "int", "int"],
        [decode_dirfd, None, decode_open_flags, decode_file_mode],
    ),  # 424
    SyscallDef(
        numbers.SYS_renameat,
        "renameat",
        ["int", "string", "int", "string"],
        [decode_dirfd, None, decode_dirfd, None],
    ),  # 426
    SyscallDef(
        numbers.SYS_faccessat,
        "faccessat",
        ["int", "string", "int", "int"],
        [decode_dirfd, None, decode_access_mode, decode_at_flags],
    ),  # 428
    SyscallDef(
        numbers.SYS_fchflags, "fchflags", ["int", "uint32_t"], [None, decode_chflags]
    ),  # 429
    SyscallDef(
        numbers.SYS_getattrlistbulk,
        "getattrlistbulk",
        ["int", "pointer", "pointer", "size_t", "uint64_t"],
    ),  # 432
    SyscallDef(
        numbers.SYS_guarded_open_np,
        "guarded_open_np",
        ["string", "pointer", "int", "int"],
    ),  # 442
    SyscallDef(numbers.SYS_guarded_close_np, "guarded_close_np", ["int", "pointer"]),  # 444
    SyscallDef(
        numbers.SYS_guarded_open_dprotected_np,
        "guarded_open_dprotected_np",
        ["string", "pointer", "int", "int", "int", "int"],
    ),  # 446
    SyscallDef(
        numbers.SYS_change_fdguard_np,
        "change_fdguard_np",
        ["int", "pointer", "uint32_t", "pointer", "uint32_t", "pointer"],
    ),  # 451
    SyscallDef(
        numbers.SYS_guarded_writev_np,
        "guarded_writev_np",
        ["int", "pointer", "pointer", "int"],
    ),  # 554
    SyscallDef(
        numbers.SYS_fsgetpath, "fsgetpath", ["pointer", "size_t", "pointer", "uint64_t"]
    ),  # 435
    SyscallDef(numbers.SYS_fmount, "fmount", ["string", "int", "int", "pointer"]),  # 436
    SyscallDef(
        numbers.SYS_fclonefileat,
        "fclonefileat",
        ["int", "int", "string", "int"],
        [None, decode_dirfd, None, None],
    ),  # 447
    SyscallDef(
        numbers.SYS_fs_snapshot,
        "fs_snapshot",
        ["unsigned int", "int", "string", "string", "pointer", "uint32_t"],
    ),  # 448
    SyscallDef(
        numbers.SYS_mkfifoat,
        "mkfifoat",
        ["int", "string", "int"],
        [decode_dirfd, None, decode_file_mode],
    ),  # 456
    SyscallDef(
        numbers.SYS_mknodat,
        "mknodat",
        ["int", "string", "int", "int"],
        [decode_dirfd, None, decode_file_mode, None],
    ),  # 457
    SyscallDef(
        numbers.SYS_renameatx_np,
        "renameatx_np",
        ["int", "string", "int", "string", "unsigned int"],
        [decode_dirfd, None, decode_dirfd, None, None],
    ),  # 488
    SyscallDef(
        numbers.SYS_mremap_encrypted,
        "mremap_encrypted",
        ["pointer", "size_t", "uint32_t", "uint32_t", "uint32_t"],
    ),  # 489
    SyscallDef(numbers.SYS_fsync_nocancel, "__fsync_nocancel", ["int"]),  # 408
    SyscallDef(
        numbers.SYS_open_nocancel,
        "__open_nocancel",
        ["string", "int", "int"],
        [None, decode_open_flags, decode_file_mode],
    ),  # 398
    SyscallDef(numbers.SYS_close_nocancel, "__close_nocancel", ["int"]),  # 399
    SyscallDef(
        numbers.SYS_read_nocancel,
        "__read_nocancel",
        ["int", "pointer", "size_t"],
        buffer_params=[BufferParam(1, 2, ParamDirection.OUT)],
    ),  # 396
    SyscallDef(
        numbers.SYS_write_nocancel,
        "__write_nocancel",
        ["int", "pointer", "size_t"],
        buffer_params=[BufferParam(1, 2, ParamDirection.IN)],
    ),  # 397
    SyscallDef(
        numbers.SYS_pread_nocancel,
        "__pread_nocancel",
        ["int", "pointer", "size_t", "off_t"],
        buffer_params=[BufferParam(1, 2, ParamDirection.OUT)],
    ),  # 414
    SyscallDef(
        numbers.SYS_pwrite_nocancel,
        "__pwrite_nocancel",
        ["int", "pointer", "size_t", "off_t"],
        buffer_params=[BufferParam(1, 2, ParamDirection.IN)],
    ),  # 415
    SyscallDef(
        numbers.SYS_readv_nocancel,
        "__readv_nocancel",
        ["int", "pointer", "int"],
        iovec_params=[IovecParam(1, 2, ParamDirection.OUT)],
    ),  # 411
    SyscallDef(
        numbers.SYS_writev_nocancel,
        "__writev_nocancel",
        ["int", "pointer", "int"],
        iovec_params=[IovecParam(1, 2, ParamDirection.IN)],
    ),  # 412
    SyscallDef(
        numbers.SYS_fcntl_nocancel,
        "__fcntl_nocancel",
        ["int", "int", "long"],
        [None, decode_fcntl_cmd, None],
    ),  # 406
    SyscallDef(
        numbers.SYS_stat64,
        "stat64",
        ["string", "pointer"],
        struct_params=[StructParam(1, "stat64", ParamDirection.OUT)],
    ),  # 338
    SyscallDef(
        numbers.SYS_fstat64,
        "fstat64",
        ["int", "pointer"],
        struct_params=[StructParam(1, "stat64", ParamDirection.OUT)],
    ),  # 339
    SyscallDef(
        numbers.SYS_lstat64,
        "lstat64",
        ["string", "pointer"],
        struct_params=[StructParam(1, "stat64", ParamDirection.OUT)],
    ),  # 340
    SyscallDef(
        numbers.SYS_stat64_extended,
        "stat64_extended",
        ["string", "pointer", "pointer", "pointer"],
    ),  # 341
    SyscallDef(
        numbers.SYS_lstat64_extended,
        "lstat64_extended",
        ["string", "pointer", "pointer", "pointer"],
    ),  # 342
    SyscallDef(
        numbers.SYS_fstat64_extended,
        "fstat64_extended",
        ["int", "pointer", "pointer", "pointer"],
    ),  # 343
    SyscallDef(
        numbers.SYS_getdirentries64,
        "getdirentries64",
        ["int", "pointer", "size_t", "pointer"],
    ),  # 344
    SyscallDef(numbers.SYS_statfs64, "statfs64", ["string", "pointer"]),  # 345
    SyscallDef(numbers.SYS_fstatfs64, "fstatfs64", ["int", "pointer"]),  # 346
    SyscallDef(
        numbers.SYS_getfsstat64,
        "getfsstat64",
        ["pointer", "int", "int"],
        [None, None, decode_unmount_flags],
    ),  # 347
    SyscallDef(
        numbers.SYS_clonefileat,
        "clonefileat",
        ["int", "string", "int", "string", "uint32_t"],
        [decode_dirfd, None, decode_dirfd, None, None],
    ),  # 462
]
