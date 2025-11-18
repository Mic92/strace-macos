"""Memory management constants and decoders for macOS/Darwin."""

from __future__ import annotations

# mmap/mprotect protection flags
PROT_FLAGS: dict[int, str] = {
    0: "PROT_NONE",
    1: "PROT_READ",
    2: "PROT_WRITE",
    4: "PROT_EXEC",
}

# mmap flags
MAP_FLAGS: dict[int, str] = {
    0x0001: "MAP_SHARED",
    0x0002: "MAP_PRIVATE",
    0x0010: "MAP_FIXED",
    0x1000: "MAP_ANON",
    0x0020: "MAP_RENAME",
    0x0040: "MAP_NORESERVE",
    0x0100: "MAP_NOEXTEND",
    0x0200: "MAP_HASSEMAPHORE",
    0x0400: "MAP_NOCACHE",
    0x0800: "MAP_JIT",
    0x2000: "MAP_RESILIENT_CODESIGN",
    0x4000: "MAP_RESILIENT_MEDIA",
    0x8000: "MAP_32BIT",
}

# madvise advice constants
MADV_CONSTANTS: dict[int, str] = {
    0: "MADV_NORMAL",
    1: "MADV_RANDOM",
    2: "MADV_SEQUENTIAL",
    3: "MADV_WILLNEED",
    4: "MADV_DONTNEED",
    5: "MADV_FREE",
    6: "MADV_ZERO_WIRED_PAGES",
    7: "MADV_FREE_REUSABLE",
    8: "MADV_FREE_REUSE",
    9: "MADV_CAN_REUSE",
    10: "MADV_PAGEOUT",
    11: "MADV_ZERO",
}

# mlockall flags
MCL_FLAGS: dict[int, str] = {
    0x0001: "MCL_CURRENT",
    0x0002: "MCL_FUTURE",
}


def decode_prot_flags(value: int) -> str:
    if value == 0:
        return "PROT_NONE"
    flags = [name for val, name in PROT_FLAGS.items() if val > 0 and (value & val)]
    return "|".join(flags) if flags else hex(value)
