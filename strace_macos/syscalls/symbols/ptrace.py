"""Ptrace-related constants and decoders for macOS/Darwin."""

from __future__ import annotations

from . import make_const_decoder

# Ptrace request constants (PT_*)
PTRACE_REQUESTS: dict[int, str] = {
    0: "PT_TRACE_ME",
    1: "PT_READ_I",
    2: "PT_READ_D",
    3: "PT_READ_U",
    4: "PT_WRITE_I",
    5: "PT_WRITE_D",
    6: "PT_WRITE_U",
    7: "PT_CONTINUE",
    8: "PT_KILL",
    9: "PT_STEP",
    10: "PT_ATTACH",
    11: "PT_DETACH",
    12: "PT_SIGEXC",
    13: "PT_THUPDATE",
    14: "PT_ATTACHEXC",
    30: "PT_FORCEQUOTA",
    31: "PT_DENY_ATTACH",
    32: "PT_FIRSTMACH",
}

# Auto-generate decoder
decode_ptrace_request = make_const_decoder(PTRACE_REQUESTS)
