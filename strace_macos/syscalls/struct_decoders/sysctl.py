"""Decoders for sysctl-related structures and parameters."""

from __future__ import annotations

import struct
from enum import Enum
from typing import TYPE_CHECKING

from strace_macos.lldb_loader import load_lldb_module

if TYPE_CHECKING:
    from typing import Any


class SysctlType(Enum):
    """Data type for sysctl values."""

    STRING = "string"
    INT = "int"
    INT64 = "int64"


# Top-level sysctl identifiers (from sys/sysctl.h)
CTL_NAMES = {
    0: "CTL_UNSPEC",
    1: "CTL_KERN",
    2: "CTL_VM",
    3: "CTL_VFS",
    4: "CTL_NET",
    5: "CTL_DEBUG",
    6: "CTL_HW",
    7: "CTL_MACHDEP",
    8: "CTL_USER",
}

# KERN_* identifiers (from sys/sysctl.h)
KERN_NAMES = {
    1: "KERN_OSTYPE",
    2: "KERN_OSRELEASE",
    3: "KERN_OSREV",
    4: "KERN_VERSION",
    5: "KERN_MAXVNODES",
    6: "KERN_MAXPROC",
    7: "KERN_MAXFILES",
    8: "KERN_ARGMAX",
    9: "KERN_SECURELVL",
    10: "KERN_HOSTNAME",
    11: "KERN_HOSTID",
    12: "KERN_CLOCKRATE",
    13: "KERN_VNODE",
    14: "KERN_PROC",
    15: "KERN_FILE",
    16: "KERN_PROF",
    17: "KERN_POSIX1",
    18: "KERN_NGROUPS",
    19: "KERN_JOB_CONTROL",
    20: "KERN_SAVED_IDS",
    21: "KERN_BOOTTIME",
    22: "KERN_NISDOMAINNAME",
    23: "KERN_MAXPARTITIONS",
    24: "KERN_KDEBUG",
    25: "KERN_UPDATEINTERVAL",
    26: "KERN_OSRELDATE",
    27: "KERN_NTP_PLL",
    28: "KERN_BOOTFILE",
    29: "KERN_MAXFILESPERPROC",
    30: "KERN_MAXPROCPERUID",
    31: "KERN_DUMPDEV",
    32: "KERN_IPC",
    33: "KERN_DUMMY",
    34: "KERN_PS_STRINGS",
    35: "KERN_USRSTACK32",
    36: "KERN_LOGSIGEXIT",
    37: "KERN_SYMFILE",
    38: "KERN_PROCARGS",
    40: "KERN_NETBOOT",
}

# HW_* identifiers (from sys/sysctl.h)
HW_NAMES = {
    1: "HW_MACHINE",
    2: "HW_MODEL",
    3: "HW_NCPU",
    4: "HW_BYTEORDER",
    5: "HW_PHYSMEM",
    6: "HW_USERMEM",
    7: "HW_PAGESIZE",
    8: "HW_DISKNAMES",
    9: "HW_DISKSTATS",
    10: "HW_EPOCH",
    11: "HW_FLOATINGPT",
    12: "HW_MACHINE_ARCH",
    13: "HW_VECTORUNIT",
    14: "HW_BUS_FREQ",
    15: "HW_CPU_FREQ",
    16: "HW_CACHELINE",
    17: "HW_L1ICACHESIZE",
    18: "HW_L1DCACHESIZE",
    19: "HW_L2SETTINGS",
    20: "HW_L2CACHESIZE",
    21: "HW_L3SETTINGS",
    22: "HW_L3CACHESIZE",
    23: "HW_TB_FREQ",
    24: "HW_MEMSIZE",
    25: "HW_AVAILCPU",
    26: "HW_TARGET",
    27: "HW_PRODUCT",
}

# Type information for sysctl values
# Maps (CTL_*, KERN_*/HW_*) tuples to data type
SYSCTL_TYPES: dict[tuple[int, int], SysctlType] = {
    # CTL_KERN values
    (1, 1): SysctlType.STRING,  # KERN_OSTYPE
    (1, 2): SysctlType.STRING,  # KERN_OSRELEASE
    (1, 3): SysctlType.INT,  # KERN_OSREV
    (1, 4): SysctlType.STRING,  # KERN_VERSION
    (1, 5): SysctlType.INT,  # KERN_MAXVNODES
    (1, 6): SysctlType.INT,  # KERN_MAXPROC
    (1, 7): SysctlType.INT,  # KERN_MAXFILES
    (1, 8): SysctlType.INT,  # KERN_ARGMAX
    (1, 9): SysctlType.INT,  # KERN_SECURELVL
    (1, 10): SysctlType.STRING,  # KERN_HOSTNAME
    (1, 11): SysctlType.INT,  # KERN_HOSTID
    (1, 17): SysctlType.INT,  # KERN_POSIX1
    (1, 18): SysctlType.INT,  # KERN_NGROUPS
    (1, 19): SysctlType.INT,  # KERN_JOB_CONTROL
    (1, 20): SysctlType.INT,  # KERN_SAVED_IDS
    (1, 22): SysctlType.STRING,  # KERN_NISDOMAINNAME
    (1, 29): SysctlType.INT,  # KERN_MAXFILESPERPROC
    (1, 30): SysctlType.INT,  # KERN_MAXPROCPERUID
    (1, 40): SysctlType.INT,  # KERN_NETBOOT
    # CTL_HW values
    (6, 1): SysctlType.STRING,  # HW_MACHINE
    (6, 2): SysctlType.STRING,  # HW_MODEL
    (6, 3): SysctlType.INT,  # HW_NCPU
    (6, 4): SysctlType.INT,  # HW_BYTEORDER
    (6, 5): SysctlType.INT,  # HW_PHYSMEM
    (6, 6): SysctlType.INT,  # HW_USERMEM
    (6, 7): SysctlType.INT,  # HW_PAGESIZE
    (6, 10): SysctlType.INT,  # HW_EPOCH
    (6, 11): SysctlType.INT,  # HW_FLOATINGPT
    (6, 12): SysctlType.STRING,  # HW_MACHINE_ARCH
    (6, 13): SysctlType.INT,  # HW_VECTORUNIT
    (6, 14): SysctlType.INT,  # HW_BUS_FREQ
    (6, 15): SysctlType.INT,  # HW_CPU_FREQ
    (6, 16): SysctlType.INT,  # HW_CACHELINE
    (6, 17): SysctlType.INT,  # HW_L1ICACHESIZE
    (6, 18): SysctlType.INT,  # HW_L1DCACHESIZE
    (6, 19): SysctlType.INT,  # HW_L2SETTINGS
    (6, 20): SysctlType.INT,  # HW_L2CACHESIZE
    (6, 21): SysctlType.INT,  # HW_L3SETTINGS
    (6, 22): SysctlType.INT,  # HW_L3CACHESIZE
    (6, 23): SysctlType.INT,  # HW_TB_FREQ
    (6, 24): SysctlType.INT64,  # HW_MEMSIZE (64-bit)
    (6, 25): SysctlType.INT,  # HW_AVAILCPU
    (6, 26): SysctlType.STRING,  # HW_TARGET
    (6, 27): SysctlType.STRING,  # HW_PRODUCT
}


def get_sysctl_type(mib_values: list[int]) -> SysctlType | None:
    """Get the data type for a sysctl MIB.

    Args:
        mib_values: List of MIB integers

    Returns:
        SysctlType enum or None if unknown
    """
    if len(mib_values) < 2:
        return None

    key = (mib_values[0], mib_values[1])
    return SYSCTL_TYPES.get(key)


_NAME_TO_TYPE: dict[str, SysctlType] = {
    "kern.ostype": SysctlType.STRING,
    "kern.osrelease": SysctlType.STRING,
    "kern.osrev": SysctlType.INT,
    "kern.version": SysctlType.STRING,
    "kern.hostname": SysctlType.STRING,
    "kern.maxproc": SysctlType.INT,
    "kern.maxfiles": SysctlType.INT,
    "kern.maxfilesperproc": SysctlType.INT,
    "hw.machine": SysctlType.STRING,
    "hw.model": SysctlType.STRING,
    "hw.ncpu": SysctlType.INT,
    "hw.byteorder": SysctlType.INT,
    "hw.physmem": SysctlType.INT,
    "hw.usermem": SysctlType.INT,
    "hw.pagesize": SysctlType.INT,
    "hw.memsize": SysctlType.INT64,
    "hw.availcpu": SysctlType.INT,
    "hw.machine_arch": SysctlType.STRING,
    "hw.target": SysctlType.STRING,
    "hw.product": SysctlType.STRING,
}


def get_sysctl_type_by_name(name: str) -> SysctlType | None:
    """Get the data type for a sysctl by name string.

    Args:
        name: Sysctl name like "kern.ostype" or "hw.ncpu"

    Returns:
        SysctlType enum or None if unknown
    """
    return _NAME_TO_TYPE.get(name)


def decode_sysctl_mib(process: Any, mib_ptr: int, namelen: int) -> tuple[str, list[int]]:
    """Decode sysctl MIB array to string representation.

    Args:
        process: LLDB process object
        mib_ptr: Pointer to int array (MIB)
        namelen: Number of integers in MIB array

    Returns:
        Tuple of (formatted_string, mib_values)
        - formatted_string like "[CTL_KERN, KERN_OSTYPE]"
        - mib_values like [1, 1]
    """
    if mib_ptr == 0 or namelen == 0:
        return ("NULL", [])

    if namelen > 12:  # CTL_MAXNAME
        return (f"<invalid namelen={namelen}>", [])

    lldb = load_lldb_module()
    error = lldb.SBError()
    mib_values = []

    # Read each int from the MIB array
    for i in range(namelen):
        # Each int is 4 bytes on macOS
        addr = mib_ptr + (i * 4)
        data = process.ReadMemory(addr, 4, error)
        if error.Fail():
            return (f"[<unreadable {i}/{namelen}>]", [])

        # Unpack as signed 32-bit integer (little-endian)
        value = struct.unpack("<i", data)[0]
        mib_values.append(value)

    # Decode MIB values to symbolic names
    decoded = []
    for i, val in enumerate(mib_values):
        if i == 0:
            # First element is top-level CTL_* identifier
            decoded.append(CTL_NAMES.get(val, str(val)))
        elif i == 1 and len(mib_values) >= 2:
            # Second element depends on first
            if mib_values[0] == 1:  # CTL_KERN
                decoded.append(KERN_NAMES.get(val, str(val)))
            elif mib_values[0] == 6:  # CTL_HW
                decoded.append(HW_NAMES.get(val, str(val)))
            else:
                decoded.append(str(val))
        else:
            # Rest are just numeric
            decoded.append(str(val))

    # Format as array
    formatted = "[" + ", ".join(decoded) + "]"
    return (formatted, mib_values)


def decode_uuid(process: Any, uuid_ptr: int) -> str:
    """Decode UUID from memory.

    Args:
        process: LLDB process object
        uuid_ptr: Pointer to uuid_t (16 bytes)

    Returns:
        UUID string like "A1B2C3D4-E5F6-7890-ABCD-EF1234567890"
    """
    if uuid_ptr == 0:
        return "NULL"

    lldb = load_lldb_module()
    error = lldb.SBError()

    # UUID is 16 bytes
    data = process.ReadMemory(uuid_ptr, 16, error)
    if error.Fail():
        return "<unreadable>"

    # Format as standard UUID: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
    uuid_bytes = data[:16]
    return "-".join(
        [
            uuid_bytes[0:4].hex(),
            uuid_bytes[4:6].hex(),
            uuid_bytes[6:8].hex(),
            uuid_bytes[8:10].hex(),
            uuid_bytes[10:16].hex(),
        ]
    ).upper()


def decode_timespec(process: Any, timespec_ptr: int) -> str:
    """Decode struct timespec from memory.

    Args:
        process: LLDB process object
        timespec_ptr: Pointer to struct timespec

    Returns:
        String like "{tv_sec=5, tv_nsec=0}"
    """
    if timespec_ptr == 0:
        return "NULL"

    lldb = load_lldb_module()
    error = lldb.SBError()

    # struct timespec is 16 bytes (tv_sec: 8 bytes, tv_nsec: 8 bytes)
    data = process.ReadMemory(timespec_ptr, 16, error)
    if error.Fail():
        return "<unreadable>"

    tv_sec = struct.unpack("<q", data[0:8])[0]  # signed 64-bit
    tv_nsec = struct.unpack("<q", data[8:16])[0]  # signed 64-bit

    return f"{{tv_sec={tv_sec}, tv_nsec={tv_nsec}}}"
