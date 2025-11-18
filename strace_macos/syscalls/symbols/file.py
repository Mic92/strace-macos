"""File-related constants and decoders for macOS/Darwin."""

from __future__ import annotations

from . import make_const_decoder, make_flag_decoder

# Poll event flags
POLL_FLAGS: dict[int, str] = {
    0x0001: "POLLIN",
    0x0002: "POLLPRI",
    0x0004: "POLLOUT",
    0x0008: "POLLERR",
    0x0010: "POLLHUP",
    0x0020: "POLLNVAL",
    0x0040: "POLLRDNORM",
    0x0080: "POLLRDBAND",
    0x0100: "POLLWRBAND",
    0x0200: "POLLEXTEND",
    0x0400: "POLLATTRIB",
    0x0800: "POLLNLINK",
    0x1000: "POLLWRITE",
}

# File open flags (O_* constants)
# From libc/src/unix/bsd/mod.rs and libc/src/unix/bsd/apple/mod.rs
O_FLAGS: dict[int, str] = {
    # Access mode (first 2 bits) - mutually exclusive
    0x0000: "O_RDONLY",
    0x0001: "O_WRONLY",
    0x0002: "O_RDWR",
    # Other flags (can be combined with |)
    0x0008: "O_APPEND",
    0x0200: "O_CREAT",
    0x0400: "O_TRUNC",
    0x0800: "O_EXCL",
    0x0004: "O_NONBLOCK",
    0x0040: "O_ASYNC",
    0x0080: "O_SYNC",
    0x0100: "O_NOFOLLOW",
    0x0010: "O_SHLOCK",
    0x0020: "O_EXLOCK",
    # Darwin-specific
    0x00008000: "O_EVTONLY",
    0x00020000: "O_NOCTTY",
    0x00100000: "O_DIRECTORY",
    0x00200000: "O_SYMLINK",
    0x00400000: "O_DSYNC",
    0x01000000: "O_CLOEXEC",
    0x20000000: "O_NOFOLLOW_ANY",
    0x40000000: "O_EXEC",
}

# File mode/permission bits (S_* constants)
# From libc/src/unix/bsd/apple/mod.rs
S_IFMT = 0o170000  # File type mask

S_FILE_TYPES: dict[int, str] = {
    0o010000: "S_IFIFO",  # FIFO (named pipe)
    0o020000: "S_IFCHR",  # Character device
    0o060000: "S_IFBLK",  # Block device
    0o040000: "S_IFDIR",  # Directory
    0o100000: "S_IFREG",  # Regular file
    0o120000: "S_IFLNK",  # Symbolic link
    0o140000: "S_IFSOCK",  # Socket
}

S_PERMISSION_BITS: dict[int, str] = {
    0o0400: "S_IRUSR",  # User read
    0o0200: "S_IWUSR",  # User write
    0o0100: "S_IXUSR",  # User execute
    0o0040: "S_IRGRP",  # Group read
    0o0020: "S_IWGRP",  # Group write
    0o0010: "S_IXGRP",  # Group execute
    0o0004: "S_IROTH",  # Other read
    0o0002: "S_IWOTH",  # Other write
    0o0001: "S_IXOTH",  # Other execute
    0o4000: "S_ISUID",  # Set UID bit
    0o2000: "S_ISGID",  # Set GID bit
    0o1000: "S_ISVTX",  # Sticky bit
}

# Seek whence constants
SEEK_CONSTANTS: dict[int, str] = {
    0: "SEEK_SET",
    1: "SEEK_CUR",
    2: "SEEK_END",
    3: "SEEK_HOLE",
    4: "SEEK_DATA",
}

# Special file descriptor constants for *at() syscalls
AT_FDCWD = -2  # Use current working directory

# AT_* flags for *at() syscalls
AT_FLAGS: dict[int, str] = {
    0x0010: "AT_EACCESS",
    0x0020: "AT_SYMLINK_NOFOLLOW",
    0x0040: "AT_SYMLINK_FOLLOW",
    0x0080: "AT_REMOVEDIR",
}

# Access mode constants (for access(), faccessat())
ACCESS_MODES: dict[int, str] = {
    0: "F_OK",  # Existence
    1: "X_OK",  # Execute
    2: "W_OK",  # Write
    4: "R_OK",  # Read
}

# fcntl() command constants
FCNTL_COMMANDS: dict[int, str] = {
    0: "F_DUPFD",
    67: "F_DUPFD_CLOEXEC",
    1: "F_GETFD",
    2: "F_SETFD",
    3: "F_GETFL",
    4: "F_SETFL",
    7: "F_GETLK",
    8: "F_SETLK",
    9: "F_SETLKW",
    42: "F_PREALLOCATE",
    44: "F_RDADVISE",
    45: "F_RDAHEAD",
    48: "F_NOCACHE",
    49: "F_LOG2PHYS",
    50: "F_GETPATH",
    51: "F_FULLFSYNC",
    53: "F_FREEZE_FS",
    54: "F_THAW_FS",
    55: "F_GLOBAL_NOCACHE",
    62: "F_NODIRECT",
    65: "F_LOG2PHYS_EXT",
    85: "F_BARRIERFSYNC",
    90: "F_OFD_SETLK",
    91: "F_OFD_SETLKW",
    92: "F_OFD_GETLK",
    99: "F_PUNCHHOLE",
    100: "F_TRIM_ACTIVE_FILE",
    101: "F_SPECULATIVE_READ",
    102: "F_GETPATH_NOFIRMLINK",
    110: "F_TRANSFEREXTENTS",
}

# FD_* flags (file descriptor flags)
FD_FLAGS: dict[int, str] = {
    1: "FD_CLOEXEC",
}

# flock() operation constants
FLOCK_OPS: dict[int, str] = {
    1: "LOCK_SH",  # Shared lock
    2: "LOCK_EX",  # Exclusive lock
    4: "LOCK_NB",  # Non-blocking
    8: "LOCK_UN",  # Unlock
}

# msync() flags
MSYNC_FLAGS: dict[int, str] = {
    0x0001: "MS_ASYNC",
    0x0002: "MS_INVALIDATE",
    0x0010: "MS_SYNC",
    0x0004: "MS_KILLPAGES",
    0x0008: "MS_DEACTIVATE",
}

# mount() flags
MOUNT_FLAGS: dict[int, str] = {
    0x00000010: "MNT_NODEV",
    0x00000020: "MNT_UNION",
    0x00000080: "MNT_CPROTECT",
    0x00000400: "MNT_QUARANTINE",
    0x00001000: "MNT_LOCAL",
    0x00002000: "MNT_QUOTA",
    0x00004000: "MNT_ROOTFS",
    0x00008000: "MNT_DOVOLFS",
    0x00100000: "MNT_DONTBROWSE",
    0x00200000: "MNT_IGNORE_OWNERSHIP",
    0x00400000: "MNT_AUTOMOUNTED",
    0x00800000: "MNT_JOURNALED",
    0x01000000: "MNT_NOUSERXATTR",
    0x02000000: "MNT_DEFWRITE",
    0x04000000: "MNT_MULTILABEL",
    0x10000000: "MNT_NOATIME",
    0x40000000: "MNT_SNAPSHOT",
    0x00020000: "MNT_NOBLOCK",
}

# unmount() flags / getfsstat() flags
UNMOUNT_FLAGS: dict[int, str] = {
    1: "MNT_WAIT",
    2: "MNT_NOWAIT",
}

# chflags/fchflags file flags (user and system flags)
CHFLAGS_FLAGS: dict[int, str] = {
    # User flags
    0x00000001: "UF_NODUMP",
    0x00000002: "UF_IMMUTABLE",
    0x00000004: "UF_APPEND",
    0x00000008: "UF_OPAQUE",
    0x00000020: "UF_COMPRESSED",
    0x00000040: "UF_TRACKED",
    0x00008000: "UF_HIDDEN",
    # System flags
    0x00010000: "SF_ARCHIVED",
    0x00020000: "SF_IMMUTABLE",
    0x00040000: "SF_APPEND",
}

# pathconf/fpathconf name constants
PATHCONF_NAMES: dict[int, str] = {
    1: "_PC_LINK_MAX",
    2: "_PC_MAX_CANON",
    3: "_PC_MAX_INPUT",
    4: "_PC_NAME_MAX",
    5: "_PC_PATH_MAX",
    6: "_PC_PIPE_BUF",
    7: "_PC_CHOWN_RESTRICTED",
    8: "_PC_NO_TRUNC",
    9: "_PC_VDISABLE",
    10: "_PC_NAME_CHARS_MAX",
    11: "_PC_CASE_SENSITIVE",
    12: "_PC_CASE_PRESERVING",
    13: "_PC_EXTENDED_SECURITY_NP",
    14: "_PC_AUTH_OPAQUE_NP",
    15: "_PC_2_SYMLINKS",
    16: "_PC_ALLOC_SIZE_MIN",
    17: "_PC_ASYNC_IO",
    18: "_PC_FILESIZEBITS",
    19: "_PC_PRIO_IO",
    20: "_PC_REC_INCR_XFER_SIZE",
    21: "_PC_REC_MAX_XFER_SIZE",
    22: "_PC_REC_MIN_XFER_SIZE",
    23: "_PC_REC_XFER_ALIGN",
    24: "_PC_SYMLINK_MAX",
    25: "_PC_SYNC_IO",
    26: "_PC_XATTR_SIZE_BITS",
    27: "_PC_MIN_HOLE_SIZE",
}

# Extended attribute (xattr) flags
XATTR_FLAGS: dict[int, str] = {
    0x0001: "XATTR_NOFOLLOW",
    0x0002: "XATTR_CREATE",
    0x0004: "XATTR_REPLACE",
    0x0008: "XATTR_NOSECURITY",
    0x0010: "XATTR_NODEFAULT",
    0x0020: "XATTR_SHOWCOMPRESSION",
}

# copyfile() flags
COPYFILE_FLAGS: dict[int, str] = {
    1 << 0: "COPYFILE_ACL",
    1 << 1: "COPYFILE_STAT",
    1 << 2: "COPYFILE_XATTR",
    1 << 3: "COPYFILE_DATA",
    1 << 15: "COPYFILE_RECURSIVE",
    1 << 16: "COPYFILE_CHECK",
    1 << 17: "COPYFILE_EXCL",
    1 << 18: "COPYFILE_NOFOLLOW_SRC",
    1 << 19: "COPYFILE_NOFOLLOW_DST",
    1 << 20: "COPYFILE_MOVE",
    1 << 21: "COPYFILE_UNLINK",
    1 << 22: "COPYFILE_PACK",
    1 << 23: "COPYFILE_UNPACK",
    1 << 24: "COPYFILE_CLONE",
    1 << 25: "COPYFILE_CLONE_FORCE",
    1 << 26: "COPYFILE_RUN_IN_PLACE",
    1 << 27: "COPYFILE_DATA_SPARSE",
    1 << 28: "COPYFILE_PRESERVE_DST_TRACKED",
    1 << 30: "COPYFILE_VERBOSE",
}

# getattrlist/setattrlist option flags
FSOPT_FLAGS: dict[int, str] = {
    0x1: "FSOPT_NOFOLLOW",
    0x4: "FSOPT_REPORT_FULLSIZE",
    0x8: "FSOPT_PACK_INVAL_ATTRS",
    0x20: "FSOPT_ATTR_CMN_EXTENDED",
    0x200: "FSOPT_RETURN_REALDEV",
    0x800: "FSOPT_NOFOLLOW_ANY",
}

# ioctl commands - Complete set from libc
IOCTL_COMMANDS: dict[int, str] = {
    # Terminal I/O control (TIOC*)
    0x40487413: "TIOCGETA",  # Get terminal attributes
    0x80487414: "TIOCSETA",  # Set terminal attributes
    0x80487415: "TIOCSETAW",  # Set attributes with drain
    0x80487416: "TIOCSETAF",  # Set attributes with flush
    0x40087468: "TIOCGWINSZ",  # Get window size
    0x80087467: "TIOCSWINSZ",  # Set window size
    0x40047477: "TIOCGPGRP",  # Get process group
    0x80047476: "TIOCSPGRP",  # Set process group
    0x20007471: "TIOCNOTTY",  # Disconnect from controlling terminal
    0x2000746F: "TIOCSTOP",  # Stop output
    0x2000746E: "TIOCSTART",  # Start output
    0x2000745E: "TIOCDRAIN",  # Wait for output to drain
    0x80047410: "TIOCFLUSH",  # Flush buffers
    0x4004746A: "TIOCMGET",  # Get modem bits
    0x8004746D: "TIOCMSET",  # Set modem bits
    0x8004746C: "TIOCMBIS",  # Set modem bits (OR)
    0x8004746B: "TIOCMBIC",  # Clear modem bits (AND NOT)
    0x20007461: "TIOCSCTTY",  # Set controlling terminal
    0x2000740D: "TIOCEXCL",  # Set exclusive mode
    0x2000740E: "TIOCNXCL",  # Clear exclusive mode
    0x40047473: "TIOCOUTQ",  # Output queue size
    0x80017472: "TIOCSTI",  # Simulate terminal input
    0x80047470: "TIOCPKT",  # Packet mode
    0x4004741A: "TIOCGETD",  # Get line discipline
    0x8004741B: "TIOCSETD",  # Set line discipline
    0x20007465: "TIOCSTAT",  # Generate status message
    0x20007463: "TIOCSCONS",  # Set console device
    0x80047462: "TIOCCONS",  # Redirect console output
    0x2000745F: "TIOCSIG",  # Send signal to process group
    0x20007479: "TIOCSDTR",  # Set DTR
    0x20007478: "TIOCCDTR",  # Clear DTR
    0x20007481: "TIOCIXON",  # Start input
    0x20007480: "TIOCIXOFF",  # Stop input
    0x80047469: "TIOCREMOTE",  # Remote mode
    0x20007454: "TIOCPTYGRANT",  # Grant pty
    0x40807453: "TIOCPTYGNAME",  # Get pty name
    0x20007452: "TIOCPTYUNLK",  # Unlock pty
    0x40047403: "TIOCMODG",  # Get modem state
    0x80047404: "TIOCMODS",  # Set modem state
    0x80047466: "TIOCUCNTL",  # User control
    0x80047460: "TIOCEXT",  # External processing
    0x8004745B: "TIOCMSDTRWAIT",  # Set DTR wait time
    0x4004745A: "TIOCMGDTRWAIT",  # Get DTR wait time
    0x80047457: "TIOCSDRAINWAIT",  # Set drain wait time
    0x40047456: "TIOCGDRAINWAIT",  # Get drain wait time
    0x20007455: "TIOCDSIMICROCODE",  # Download microcode
    # File I/O control (FIO*)
    0x20006601: "FIOCLEX",  # Set close-on-exec
    0x20006602: "FIONCLEX",  # Clear close-on-exec
    0x4004667F: "FIONREAD",  # Get # bytes to read
    0x8004667E: "FIONBIO",  # Set/clear non-blocking I/O
    0x8004667D: "FIOASYNC",  # Set/clear async I/O
    0x8004667C: "FIOSETOWN",  # Set owner
    0x4004667B: "FIOGETOWN",  # Get owner
    0x4004667A: "FIODTYPE",  # Get descriptor type
    # Socket I/O control (SIOC*)
    0x80047300: "SIOCSHIWAT",  # Set high watermark
    0x40047301: "SIOCGHIWAT",  # Get high watermark
    0x80047302: "SIOCSLOWAT",  # Set low watermark
    0x40047303: "SIOCGLOWAT",  # Get low watermark
    0x40047307: "SIOCATMARK",  # At OOB mark?
    0x80047308: "SIOCSPGRP",  # Set process group
    0x40047309: "SIOCGPGRP",  # Get process group
    0x8020690C: "SIOCSIFADDR",  # Set interface address
    0xC020690C: "SIOCAIFADDR",  # Add/change IF alias
    0xC0206921: "SIOCGIFADDR",  # Get interface address
    0xC00C6924: "SIOCGIFCONF",  # Get interface list
    0x80206910: "SIOCSIFFLAGS",  # Set interface flags
    0xC0206911: "SIOCGIFFLAGS",  # Get interface flags
    0xC0206933: "SIOCGIFMTU",  # Get interface MTU
    0x80206934: "SIOCSIFMTU",  # Set interface MTU
    0x80206931: "SIOCADDMULTI",  # Add multicast address
    0x80206932: "SIOCDELMULTI",  # Delete multicast address
    0xC0206922: "SIOCGIFDSTADDR",  # Get p-p destination address
    0x80206923: "SIOCGIFBRDADDR",  # Get broadcast address
    0xC0206925: "SIOCGIFNETMASK",  # Get network mask
    0x8020691A: "SIOCSIFDSTADDR",  # Set p-p destination address
    0x80206916: "SIOCSIFNETMASK",  # Set network mask
    0x80206919: "SIOCDIFADDR",  # Delete interface address (was duplicate with SIOCSIFBRDADDR)
    # BPF device control (BIOC*)
    0x40044272: "BIOCGRSIG",  # Get read signal
    0x80044273: "BIOCSRSIG",  # Set read signal
    0x80044278: "BIOCSDLT",  # Set data link type
    0x40044276: "BIOCGSEESENT",  # Get see sent packets
    0x80044277: "BIOCSSEESENT",  # Set see sent packets
    0xC00C4279: "BIOCGDLTLIST",  # Get DLT list
    # System kernel control (CTL*)
    0xC0644E03: "CTLIOCGINFO",  # Get kernel control info
}


def decode_open_flags(value: int) -> str:
    if value == 0:
        return "O_RDONLY"
    flags = []
    access_mode = value & 0x3
    if access_mode in O_FLAGS:
        flags.append(O_FLAGS[access_mode])
    remaining = value & ~0x3
    for flag_val, flag_name in O_FLAGS.items():
        if flag_val <= 0x3:
            continue
        if remaining & flag_val:
            flags.append(flag_name)
    return "|".join(flags) if flags else hex(value)


def decode_file_mode(value: int) -> str:
    return f"0{value:o}"


def decode_file_type_mode(value: int) -> str:
    file_type = value & S_IFMT
    file_type_str = S_FILE_TYPES.get(file_type, f"0{file_type:o}")
    perms = value & 0o7777
    return f"{file_type_str}|0{perms:o}"


# Auto-generate const decoders
decode_seek_whence = make_const_decoder(SEEK_CONSTANTS)
decode_fcntl_cmd = make_const_decoder(FCNTL_COMMANDS)
decode_unmount_flags = make_const_decoder(UNMOUNT_FLAGS)
decode_pathconf_name = make_const_decoder(PATHCONF_NAMES)

# Auto-generate flag decoders
decode_at_flags = make_flag_decoder(AT_FLAGS)
decode_fd_flags = make_flag_decoder(FD_FLAGS)
decode_msync_flags = make_flag_decoder(MSYNC_FLAGS)
decode_mount_flags = make_flag_decoder(MOUNT_FLAGS)
decode_chflags = make_flag_decoder(CHFLAGS_FLAGS)
decode_xattr_flags = make_flag_decoder(XATTR_FLAGS)
decode_copyfile_flags = make_flag_decoder(COPYFILE_FLAGS)
decode_fsopt_flags = make_flag_decoder(FSOPT_FLAGS)


def decode_dirfd(value: int) -> str:
    if value == AT_FDCWD:
        return "AT_FDCWD"
    return str(value)


def decode_access_mode(value: int) -> str:
    if value == 0:
        return "F_OK"
    modes = [name for val, name in ACCESS_MODES.items() if val > 0 and (value & val)]
    return "|".join(modes) if modes else str(value)


def decode_flock_op(value: int) -> str:
    flags = []
    base_op = value & ~4
    if base_op in FLOCK_OPS:
        flags.append(FLOCK_OPS[base_op])
    if value & 4:
        flags.append("LOCK_NB")
    return "|".join(flags) if flags else str(value)


def decode_ioctl_cmd(value: int) -> str:
    unsigned_value = value & 0xFFFFFFFF if value < 0 else value
    return IOCTL_COMMANDS.get(unsigned_value, hex(unsigned_value))


decode_poll_events = make_flag_decoder(POLL_FLAGS)
