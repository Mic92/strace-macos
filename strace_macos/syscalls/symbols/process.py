"""Process-related constants and decoders for macOS/Darwin."""

from __future__ import annotations

from . import make_const_decoder, make_flag_decoder

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

# Import helpers

# Auto-generate const decoders
decode_idtype = make_const_decoder(IDTYPE_CONSTANTS)
decode_prio_which = make_const_decoder(PRIO_WHICH)
decode_rusage_who = make_const_decoder(RUSAGE_WHO)
decode_rlimit_resource = make_const_decoder(RLIMIT_RESOURCES)
decode_sigprocmask_how = make_const_decoder(SIG_HOW)

# Auto-generate flag decoders
decode_wait_options = make_flag_decoder(WAIT_OPTIONS)
decode_waitid_options = make_flag_decoder(WAITID_OPTIONS)
