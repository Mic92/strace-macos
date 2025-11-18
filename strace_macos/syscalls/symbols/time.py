"""Time-related constants and decoders for macOS/Darwin."""

from __future__ import annotations

# Interval timer constants for setitimer/getitimer
ITIMER_CONSTANTS: dict[int, str] = {
    0: "ITIMER_REAL",
    1: "ITIMER_VIRTUAL",
    2: "ITIMER_PROF",
}
