"""StructParam for struct termios (terminal attributes)."""

from __future__ import annotations

import ctypes
from typing import Any, ClassVar

from strace_macos.lldb_loader import load_lldb_module
from strace_macos.syscalls.definitions import ParamDirection, StructParamBase


class Termios(ctypes.Structure):
    """Terminal attributes structure (struct termios).

    From sys/termios.h on macOS.
    """

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("c_iflag", ctypes.c_ulong),  # Input flags
        ("c_oflag", ctypes.c_ulong),  # Output flags
        ("c_cflag", ctypes.c_ulong),  # Control flags
        ("c_lflag", ctypes.c_ulong),  # Local flags
        ("c_cc", ctypes.c_ubyte * 20),  # Control characters (NCCS=20)
        ("c_ispeed", ctypes.c_ulong),  # Input speed
        ("c_ospeed", ctypes.c_ulong),  # Output speed
    ]


# Input flags (c_iflag)
TERMIOS_IFLAG: dict[int, str] = {
    0x00000001: "IGNBRK",
    0x00000002: "BRKINT",
    0x00000004: "IGNPAR",
    0x00000008: "PARMRK",
    0x00000010: "INPCK",
    0x00000020: "ISTRIP",
    0x00000040: "INLCR",
    0x00000080: "IGNCR",
    0x00000100: "ICRNL",
    0x00000200: "IXON",
    0x00000400: "IXOFF",
    0x00000800: "IXANY",
    0x00002000: "IMAXBEL",
    0x00004000: "IUTF8",
}

# Output flags (c_oflag)
TERMIOS_OFLAG: dict[int, str] = {
    0x00000001: "OPOST",
    0x00000002: "ONLCR",
    0x00000004: "OXTABS",
    0x00000008: "ONOEOT",
}

# Control flags (c_cflag) - simplified
TERMIOS_CFLAG: dict[int, str] = {
    0x00004000: "CREAD",
    0x00008000: "PARENB",
    0x00010000: "PARODD",
    0x00020000: "HUPCL",
    0x00040000: "CLOCAL",
}

# Local flags (c_lflag)
TERMIOS_LFLAG: dict[int, str] = {
    0x00000001: "ECHOKE",
    0x00000002: "ECHOE",
    0x00000004: "ECHOK",
    0x00000008: "ECHO",
    0x00000010: "ECHONL",
    0x00000020: "ECHOPRT",
    0x00000040: "ECHOCTL",
    0x00000080: "ISIG",
    0x00000100: "ICANON",
    0x00000400: "IEXTEN",
    0x00000800: "EXTPROC",
    0x00001000: "TOSTOP",
    0x00002000: "FLUSHO",
    0x00008000: "PENDIN",
    0x00010000: "NOFLSH",
}


class TermiosParam(StructParamBase):
    """StructParam for struct termios.

    This param completely overrides decode_struct() to provide custom
    flag decoding logic for terminal attributes.
    """

    struct_type = Termios

    def __init__(self, direction: ParamDirection) -> None:
        """Initialize TermiosParam.

        Args:
            direction: ParamDirection.IN or ParamDirection.OUT
        """
        self.direction = direction

    @staticmethod
    def _decode_flags_symbolic(term: Termios) -> dict[str, str | int | list]:
        """Decode termios flags symbolically.

        Args:
            term: The Termios structure to decode

        Returns:
            Dictionary with decoded flag fields
        """
        result: dict[str, str | int | list] = {}

        # Input flags
        if term.c_iflag:
            iflag_names = [name for val, name in TERMIOS_IFLAG.items() if term.c_iflag & val]
            if iflag_names:
                result["c_iflag"] = "|".join(iflag_names)

        # Output flags
        if term.c_oflag:
            oflag_names = [name for val, name in TERMIOS_OFLAG.items() if term.c_oflag & val]
            if oflag_names:
                result["c_oflag"] = "|".join(oflag_names)

        # Control flags (abbreviated - too many to show all)
        if term.c_cflag:
            cflag_names = [name for val, name in TERMIOS_CFLAG.items() if term.c_cflag & val]
            if cflag_names:
                # Add "..." to indicate there are more flags
                result["c_cflag"] = "|".join(cflag_names) + "|..."

        # Local flags
        if term.c_lflag:
            lflag_names = [name for val, name in TERMIOS_LFLAG.items() if term.c_lflag & val]
            if lflag_names:
                result["c_lflag"] = "|".join(lflag_names)

        return result if result else {"c_iflag": "0"}

    def decode_struct(
        self, process: Any, address: int, *, no_abbrev: bool = False
    ) -> dict[str, str | int | list] | None:
        """Decode a struct termios from process memory.

        This completely overrides the base class decode_struct() to provide
        custom flag decoding logic.

        Args:
            process: LLDB process to read memory from
            address: Memory address of the termios structure
            no_abbrev: If True, show raw hex values instead of symbolic flags

        Returns:
            Dictionary with decoded termios fields, or None if failed
        """
        if address == 0:
            return None

        lldb = load_lldb_module()
        error = lldb.SBError()
        size = ctypes.sizeof(Termios)

        data = process.ReadMemory(address, size, error)
        if error.Fail() or not data:
            return None

        try:
            term = Termios.from_buffer_copy(data)
        except (ValueError, TypeError):
            return None
        else:
            if no_abbrev:
                # Show raw hex values
                return {
                    "c_iflag": f"0x{term.c_iflag:x}",
                    "c_oflag": f"0x{term.c_oflag:x}",
                    "c_cflag": f"0x{term.c_cflag:x}",
                    "c_lflag": f"0x{term.c_lflag:x}",
                }

            # Decode flags symbolically (abbreviated - just show main flags)
            return self._decode_flags_symbolic(term)


__all__ = ["TermiosParam"]
