"""Process-related constants and decoders for macOS/Darwin."""

from __future__ import annotations

# wait4/waitpid options
WAIT_OPTIONS: dict[int, str] = {
    0x00000001: "WNOHANG",
    0x00000002: "WUNTRACED",
    0x00000010: "WCONTINUED",
}

# waitid idtype constants
IDTYPE_CONSTANTS: dict[int, str] = {
    0: "P_ALL",
    1: "P_PID",
    2: "P_PGID",
}

# waitid options (WEXITED, WSTOPPED, etc.)
WAITID_OPTIONS: dict[int, str] = {
    0x00000004: "WEXITED",
    0x00000008: "WSTOPPED",
    0x00000010: "WCONTINUED",
    0x00000020: "WNOWAIT",
}

# getpriority/setpriority which constants
PRIO_WHICH: dict[int, str] = {
    0: "PRIO_PROCESS",  # Standard POSIX
    1: "PRIO_PGRP",  # Standard POSIX
    2: "PRIO_USER",  # Standard POSIX
    3: "PRIO_DARWIN_THREAD",
    4: "PRIO_DARWIN_PROCESS",
    0x1000: "PRIO_DARWIN_BG",
    0x1001: "PRIO_DARWIN_NONUI",
}

# getrusage who constants
RUSAGE_WHO: dict[int, str] = {
    -1: "RUSAGE_CHILDREN",
    0: "RUSAGE_SELF",
}

# Resource limit constants for getrlimit/setrlimit
RLIMIT_RESOURCES: dict[int, str] = {
    0: "RLIMIT_CPU",
    1: "RLIMIT_FSIZE",
    2: "RLIMIT_DATA",
    3: "RLIMIT_STACK",
    4: "RLIMIT_CORE",
    5: "RLIMIT_AS",  # Also RLIMIT_RSS
    6: "RLIMIT_MEMLOCK",
    7: "RLIMIT_NPROC",
    8: "RLIMIT_NOFILE",
}

# sigprocmask how constants
SIG_HOW: dict[int, str] = {
    1: "SIG_BLOCK",
    2: "SIG_UNBLOCK",
    3: "SIG_SETMASK",
}

# reboot() flags
REBOOT_FLAGS: dict[int, str] = {
    0x00: "RB_AUTOBOOT",
    0x01: "RB_ASKNAME",
    0x02: "RB_SINGLE",
    0x04: "RB_NOSYNC",
    0x08: "RB_HALT",
    0x10: "RB_INITNAME",
    0x20: "RB_DFLTROOT",
    0x40: "RB_ALTBOOT",
    0x80: "RB_UNIPROC",
    0x100: "RB_SAFEBOOT",
    0x200: "RB_UPSDELAY",
    0x400: "RB_QUICK",
    0x800: "RB_PANIC",
    0x1000: "RB_PANIC_ZPRINT",
    0x2000: "RB_PANIC_FORCERESET",
}
