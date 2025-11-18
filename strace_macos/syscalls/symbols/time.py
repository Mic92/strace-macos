"""Time-related constants and decoders for macOS/Darwin."""

from __future__ import annotations

from . import make_const_decoder

# Interval timer constants for setitimer/getitimer
ITIMER_CONSTANTS: dict[int, str] = {
    0: "ITIMER_REAL",
    1: "ITIMER_VIRTUAL",
    2: "ITIMER_PROF",
}

# Auto-generate decoders
decode_itimer_which = make_const_decoder(ITIMER_CONSTANTS)
