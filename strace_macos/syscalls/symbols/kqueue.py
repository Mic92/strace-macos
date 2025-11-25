"""Kqueue/kevent-related constants and decoders for macOS/Darwin."""

from __future__ import annotations

# Event filter types (EVFILT_*)
EVFILT_CONSTANTS: dict[int, str] = {
    -1: "EVFILT_READ",
    -2: "EVFILT_WRITE",
    -3: "EVFILT_AIO",
    -4: "EVFILT_VNODE",
    -5: "EVFILT_PROC",
    -6: "EVFILT_SIGNAL",
    -7: "EVFILT_TIMER",
    -8: "EVFILT_MACHPORT",
    -9: "EVFILT_FS",
    -10: "EVFILT_USER",
    -12: "EVFILT_VM",
    -15: "EVFILT_EXCEPT",
}

# Event flags (EV_*)
EV_FLAGS: dict[int, str] = {
    0x0001: "EV_ADD",
    0x0002: "EV_DELETE",
    0x0004: "EV_ENABLE",
    0x0008: "EV_DISABLE",
    0x0010: "EV_ONESHOT",
    0x0020: "EV_CLEAR",
    0x0040: "EV_RECEIPT",
    0x0080: "EV_DISPATCH",
    0x0100: "EV_UDATA_SPECIFIC",
    0x0200: "EV_VANISHED",
    0x1000: "EV_FLAG0",
    0x2000: "EV_FLAG1",
    0x4000: "EV_ERROR",
    0x8000: "EV_EOF",
}

# Filter flags (NOTE_*) - these are context-dependent
# For EVFILT_VNODE
NOTE_VNODE_FLAGS: dict[int, str] = {
    0x00000001: "NOTE_DELETE",
    0x00000002: "NOTE_WRITE",
    0x00000004: "NOTE_EXTEND",
    0x00000008: "NOTE_ATTRIB",
    0x00000010: "NOTE_LINK",
    0x00000020: "NOTE_RENAME",
    0x00000040: "NOTE_REVOKE",
    0x00000080: "NOTE_NONE",
}

# For EVFILT_PROC
NOTE_PROC_FLAGS: dict[int, str] = {
    0x80000000: "NOTE_EXIT",
    0x40000000: "NOTE_FORK",
    0x20000000: "NOTE_EXEC",
    0x10000000: "NOTE_REAP",
    0x08000000: "NOTE_SIGNAL",
    0x04000000: "NOTE_EXITSTATUS",
    0x02000000: "NOTE_EXIT_DETAIL",
}

# For EVFILT_READ/WRITE
NOTE_LOWAT_FLAGS: dict[int, str] = {
    0x00000001: "NOTE_LOWAT",
}

# For EVFILT_TIMER
# Note: Time unit flags are mutually exclusive (bits 0-2), additional flags can be OR'd
NOTE_TIMER_FLAGS: dict[int, str] = {
    0x00000001: "NOTE_SECONDS",
    0x00000002: "NOTE_USECONDS",
    0x00000004: "NOTE_NSECONDS",
    0x00000008: "NOTE_ABSOLUTE",
    0x00000010: "NOTE_LEEWAY",
    0x00000020: "NOTE_CRITICAL",
    0x00000040: "NOTE_BACKGROUND",
    0x00000080: "NOTE_MACH_CONTINUOUS_TIME",
    0x00000100: "NOTE_MACHTIME",
}

# For EVFILT_USER
NOTE_USER_FLAGS: dict[int, str] = {
    0x01000000: "NOTE_TRIGGER",
    0x00000000: "NOTE_FFNOP",
    0x40000000: "NOTE_FFAND",
    0x80000000: "NOTE_FFOR",
    0xC0000000: "NOTE_FFCOPY",
}
