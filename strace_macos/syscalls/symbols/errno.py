"""Error number (errno) constants and decoder for macOS/Darwin.

Manually curated from libc/src/unix/bsd/apple/mod.rs
"""

from __future__ import annotations

# Error number constants (errno values)
# Maps errno number to (symbolic name, description)
ERRNO_MAP: dict[int, tuple[str, str]] = {
    1: ("EPERM", "Operation not permitted"),
    2: ("ENOENT", "No such file or directory"),
    3: ("ESRCH", "No such process"),
    4: ("EINTR", "Interrupted system call"),
    5: ("EIO", "Input/output error"),
    6: ("ENXIO", "No such device or address"),
    7: ("E2BIG", "Argument list too long"),
    8: ("ENOEXEC", "Exec format error"),
    9: ("EBADF", "Bad file descriptor"),
    10: ("ECHILD", "No child processes"),
    11: ("EDEADLK", "Resource deadlock avoided"),
    12: ("ENOMEM", "Cannot allocate memory"),
    13: ("EACCES", "Permission denied"),
    14: ("EFAULT", "Bad address"),
    15: ("ENOTBLK", "Block device required"),
    16: ("EBUSY", "Device or resource busy"),
    17: ("EEXIST", "File exists"),
    18: ("EXDEV", "Invalid cross-device link"),
    19: ("ENODEV", "No such device"),
    20: ("ENOTDIR", "Not a directory"),
    21: ("EISDIR", "Is a directory"),
    22: ("EINVAL", "Invalid argument"),
    23: ("ENFILE", "Too many open files in system"),
    24: ("EMFILE", "Too many open files"),
    25: ("ENOTTY", "Inappropriate ioctl for device"),
    26: ("ETXTBSY", "Text file busy"),
    27: ("EFBIG", "File too large"),
    28: ("ENOSPC", "No space left on device"),
    29: ("ESPIPE", "Illegal seek"),
    30: ("EROFS", "Read-only file system"),
    31: ("EMLINK", "Too many links"),
    32: ("EPIPE", "Broken pipe"),
    33: ("EDOM", "Numerical argument out of domain"),
    34: ("ERANGE", "Numerical result out of range"),
    35: ("EAGAIN", "Resource temporarily unavailable"),
    36: ("EINPROGRESS", "Operation now in progress"),
    37: ("EALREADY", "Operation already in progress"),
    38: ("ENOTSOCK", "Socket operation on non-socket"),
    39: ("EDESTADDRREQ", "Destination address required"),
    40: ("EMSGSIZE", "Message too long"),
    41: ("EPROTOTYPE", "Protocol wrong type for socket"),
    42: ("ENOPROTOOPT", "Protocol not available"),
    43: ("EPROTONOSUPPORT", "Protocol not supported"),
    44: ("ESOCKTNOSUPPORT", "Socket type not supported"),
    45: ("ENOTSUP", "Operation not supported"),
    46: ("EPFNOSUPPORT", "Protocol family not supported"),
    47: ("EAFNOSUPPORT", "Address family not supported by protocol"),
    48: ("EADDRINUSE", "Address already in use"),
    49: ("EADDRNOTAVAIL", "Cannot assign requested address"),
    50: ("ENETDOWN", "Network is down"),
    51: ("ENETUNREACH", "Network is unreachable"),
    52: ("ENETRESET", "Network dropped connection on reset"),
    53: ("ECONNABORTED", "Software caused connection abort"),
    54: ("ECONNRESET", "Connection reset by peer"),
    55: ("ENOBUFS", "No buffer space available"),
    56: ("EISCONN", "Transport endpoint already connected"),
    57: ("ENOTCONN", "Transport endpoint not connected"),
    58: ("ESHUTDOWN", "Cannot send after transport endpoint shutdown"),
    59: ("ETOOMANYREFS", "Too many references: cannot splice"),
    60: ("ETIMEDOUT", "Connection timed out"),
    61: ("ECONNREFUSED", "Connection refused"),
    62: ("ELOOP", "Too many levels of symbolic links"),
    63: ("ENAMETOOLONG", "File name too long"),
    64: ("EHOSTDOWN", "Host is down"),
    65: ("EHOSTUNREACH", "No route to host"),
    66: ("ENOTEMPTY", "Directory not empty"),
    67: ("EPROCLIM", "Too many processes"),
    68: ("EUSERS", "Too many users"),
    69: ("EDQUOT", "Disk quota exceeded"),
    70: ("ESTALE", "Stale file handle"),
    71: ("EREMOTE", "Object is remote"),
    72: ("EBADRPC", "RPC struct is bad"),
    73: ("ERPCMISMATCH", "RPC version wrong"),
    74: ("EPROGUNAVAIL", "RPC program not available"),
    75: ("EPROGMISMATCH", "RPC program version wrong"),
    76: ("EPROCUNAVAIL", "RPC bad procedure for program"),
    77: ("ENOLCK", "No locks available"),
    78: ("ENOSYS", "Function not implemented"),
    79: ("EFTYPE", "Inappropriate file type or format"),
    80: ("EAUTH", "Authentication error"),
    81: ("ENEEDAUTH", "Need authenticator"),
    82: ("EPWROFF", "Device power is off"),
    83: ("EDEVERR", "Device error"),
    84: ("EOVERFLOW", "Value too large to be stored in data type"),
    85: ("EBADEXEC", "Bad executable (or shared library)"),
    86: ("EBADARCH", "Bad CPU type in executable"),
    87: ("ESHLIBVERS", "Shared library version mismatch"),
    88: ("EBADMACHO", "Malformed Mach-o file"),
    89: ("ECANCELED", "Operation canceled"),
    90: ("EIDRM", "Identifier removed"),
    91: ("ENOMSG", "No message of desired type"),
    92: ("EILSEQ", "Invalid or incomplete multibyte or wide character"),
    93: ("ENOATTR", "Attribute not found"),
    94: ("EBADMSG", "Bad message"),
    95: ("EMULTIHOP", "Multihop attempted"),
    96: ("ENODATA", "No message available on STREAM"),
    97: ("ENOLINK", "Link has been severed"),
    98: ("ENOSR", "No STREAM resources"),
    99: ("ENOSTR", "Not a STREAM"),
    100: ("EPROTO", "Protocol error"),
    101: ("ETIME", "STREAM ioctl timeout"),
    102: ("EOPNOTSUPP", "Operation not supported on socket"),
    103: ("ENOPOLICY", "Policy not found"),
    104: ("ENOTRECOVERABLE", "State not recoverable"),
    105: ("EOWNERDEAD", "Previous owner died"),
    106: ("EQFULL", "Interface output queue is full"),
}


def decode_errno(value: int) -> str:
    """Decode errno return value to symbolic name with description.

    Args:
        value: Return value from syscall (typically -1 to -106 for errors)

    Returns:
        Symbolic representation like "-1 ENOENT (No such file or directory)"
        or just the numeric value if not an error or unknown errno

    Note:
        On macOS, libc wrappers return -1 on error and set errno in thread-local storage.

    Ref:
        https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/syscall.2.html
    """
    if value >= 0:
        return str(value)

    # On macOS, syscalls return -1 on error (not -errno like Linux)
    if value == -1:
        return "-1"

    # If we see other negative values (shouldn't happen on macOS libc wrappers,
    # but might occur if tracing kernel directly), try to decode as errno
    errno_num = -value
    if errno_num in ERRNO_MAP:
        name, desc = ERRNO_MAP[errno_num]
        return f"-1 {name} ({desc})"

    # Unknown errno
    return str(value)
