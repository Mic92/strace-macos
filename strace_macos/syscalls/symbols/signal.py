"""Signal-related constants and decoders for macOS/Darwin."""

from __future__ import annotations

# Signal numbers
SIGNAL_NUMBERS: dict[int, str] = {
    1: "SIGHUP",
    2: "SIGINT",
    3: "SIGQUIT",
    4: "SIGILL",
    5: "SIGTRAP",
    6: "SIGABRT",
    7: "SIGEMT",
    8: "SIGFPE",
    9: "SIGKILL",
    10: "SIGBUS",
    11: "SIGSEGV",
    12: "SIGSYS",
    13: "SIGPIPE",
    14: "SIGALRM",
    15: "SIGTERM",
    16: "SIGURG",
    17: "SIGSTOP",
    18: "SIGTSTP",
    19: "SIGCONT",
    20: "SIGCHLD",
    21: "SIGTTIN",
    22: "SIGTTOU",
    23: "SIGIO",
    24: "SIGXCPU",
    25: "SIGXFSZ",
    26: "SIGVTALRM",
    27: "SIGPROF",
    28: "SIGWINCH",
    29: "SIGINFO",
    30: "SIGUSR1",
    31: "SIGUSR2",
}

# sigaction sa_flags
SA_FLAGS: dict[int, str] = {
    0x0001: "SA_ONSTACK",
    0x0002: "SA_RESTART",
    0x0004: "SA_RESETHAND",
    0x0008: "SA_NOCLDSTOP",
    0x0010: "SA_NODEFER",
    0x0020: "SA_NOCLDWAIT",
    0x0040: "SA_SIGINFO",
    0x0080: "SA_USERTRAMP",
    0x0100: "SA_64REGSET",
    0x0200: "SA_USERSPACE_MASK",
}

# sigaltstack ss_flags
SS_FLAGS: dict[int, str] = {
    0x0001: "SS_ONSTACK",
    0x0002: "SS_DISABLE",
}
