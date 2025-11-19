"""Parameter decoder for struct attrlist (attribute list structure for getattrlist/setattrlist)."""

from __future__ import annotations

import ctypes
from typing import ClassVar

from strace_macos.syscalls.definitions import ParamDirection, StructParamBase

# Common attributes (ATTR_CMN_*)
ATTR_CMN_FLAGS = {
    0x00000001: "ATTR_CMN_NAME",
    0x00000002: "ATTR_CMN_DEVID",
    0x00000004: "ATTR_CMN_FSID",
    0x00000008: "ATTR_CMN_OBJTYPE",
    0x00000010: "ATTR_CMN_OBJTAG",
    0x00000020: "ATTR_CMN_OBJID",
    0x00000040: "ATTR_CMN_OBJPERMANENTID",
    0x00000080: "ATTR_CMN_PAROBJID",
    0x00000100: "ATTR_CMN_SCRIPT",
    0x00000200: "ATTR_CMN_CRTIME",
    0x00000400: "ATTR_CMN_MODTIME",
    0x00000800: "ATTR_CMN_CHGTIME",
    0x00001000: "ATTR_CMN_ACCTIME",
    0x00002000: "ATTR_CMN_BKUPTIME",
    0x00004000: "ATTR_CMN_FNDRINFO",
    0x00008000: "ATTR_CMN_OWNERID",
    0x00010000: "ATTR_CMN_GRPID",
    0x00020000: "ATTR_CMN_ACCESSMASK",
    0x00040000: "ATTR_CMN_FLAGS",
    0x00080000: "ATTR_CMN_GEN_COUNT",
    0x00100000: "ATTR_CMN_DOCUMENT_ID",
    0x00200000: "ATTR_CMN_USERACCESS",
    0x00400000: "ATTR_CMN_EXTENDED_SECURITY",
    0x00800000: "ATTR_CMN_UUID",
    0x01000000: "ATTR_CMN_GRPUUID",
    0x02000000: "ATTR_CMN_FILEID",
    0x04000000: "ATTR_CMN_PARENTID",
    0x08000000: "ATTR_CMN_FULLPATH",
    0x10000000: "ATTR_CMN_ADDEDTIME",
    0x20000000: "ATTR_CMN_ERROR",
    0x40000000: "ATTR_CMN_DATA_PROTECT_FLAGS",
    0x80000000: "ATTR_CMN_RETURNED_ATTRS",
}

# Volume attributes (ATTR_VOL_*)
ATTR_VOL_FLAGS = {
    0x00000001: "ATTR_VOL_FSTYPE",
    0x00000002: "ATTR_VOL_SIGNATURE",
    0x00000004: "ATTR_VOL_SIZE",
    0x00000008: "ATTR_VOL_SPACEFREE",
    0x00000010: "ATTR_VOL_SPACEAVAIL",
    0x00000020: "ATTR_VOL_MINALLOCATION",
    0x00000040: "ATTR_VOL_ALLOCATIONCLUMP",
    0x00000080: "ATTR_VOL_IOBLOCKSIZE",
    0x00000100: "ATTR_VOL_OBJCOUNT",
    0x00000200: "ATTR_VOL_FILECOUNT",
    0x00000400: "ATTR_VOL_DIRCOUNT",
    0x00000800: "ATTR_VOL_MAXOBJCOUNT",
    0x00001000: "ATTR_VOL_MOUNTPOINT",
    0x00002000: "ATTR_VOL_NAME",
    0x00004000: "ATTR_VOL_MOUNTFLAGS",
}

# Directory attributes (ATTR_DIR_*)
ATTR_DIR_FLAGS = {
    0x00000001: "ATTR_DIR_LINKCOUNT",
    0x00000002: "ATTR_DIR_ENTRYCOUNT",
    0x00000004: "ATTR_DIR_MOUNTSTATUS",
}

# File attributes (ATTR_FILE_*)
ATTR_FILE_FLAGS = {
    0x00000001: "ATTR_FILE_LINKCOUNT",
    0x00000002: "ATTR_FILE_TOTALSIZE",
    0x00000004: "ATTR_FILE_ALLOCSIZE",
    0x00000008: "ATTR_FILE_IOBLOCKSIZE",
    0x00000010: "ATTR_FILE_DEVTYPE",
    0x00000020: "ATTR_FILE_FORKCOUNT",
    0x00000040: "ATTR_FILE_FORKLIST",
    0x00000080: "ATTR_FILE_DATALENGTH",
    0x00000100: "ATTR_FILE_DATAALLOCSIZE",
    0x00000200: "ATTR_FILE_RSRCLENGTH",
    0x00000400: "ATTR_FILE_RSRCALLOCSIZE",
}


def decode_attr_flags(value: int, flag_map: dict[int, str]) -> str:
    """Decode attribute flags into symbolic names joined by |."""
    if value == 0:
        return "0"
    flags = []
    for bit_val, name in flag_map.items():
        if value & bit_val:
            flags.append(name)
    return "|".join(flags) if flags else f"0x{value:x}"


class AttrListStruct(ctypes.Structure):
    """ctypes definition for struct attrlist on macOS.

    struct attrlist {
        u_short bitmapcount;
        u_int16_t reserved;
        attrgroup_t commonattr;
        attrgroup_t volattr;
        attrgroup_t dirattr;
        attrgroup_t fileattr;
        attrgroup_t forkattr;
    };

    Total size: 24 bytes
    """

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("bitmapcount", ctypes.c_uint16),
        ("reserved", ctypes.c_uint16),
        ("commonattr", ctypes.c_uint32),
        ("volattr", ctypes.c_uint32),
        ("dirattr", ctypes.c_uint32),
        ("fileattr", ctypes.c_uint32),
        ("forkattr", ctypes.c_uint32),
    ]


class AttrListParam(StructParamBase):
    """Parameter decoder for struct attrlist on macOS.

    Decodes the attribute list structure used by getattrlist/setattrlist syscalls.

    Usage:
        AttrListParam(ParamDirection.IN)   # For getattrlist/setattrlist input
        AttrListParam(ParamDirection.OUT)  # For getattrlist output (if applicable)
    """

    struct_type = AttrListStruct

    # Custom formatters for specific fields
    # Maps field_name -> method_name
    field_formatters: ClassVar[dict[str, str]] = {
        "commonattr": "_decode_commonattr",
        "volattr": "_decode_volattr",
        "dirattr": "_decode_dirattr",
        "fileattr": "_decode_fileattr",
        "forkattr": "_decode_forkattr",
    }

    # Exclude reserved field
    excluded_fields: ClassVar[set[str]] = {"reserved"}

    def __init__(self, direction: ParamDirection) -> None:
        """Initialize AttrListParam with direction."""
        self.direction = direction

    def _decode_commonattr(self, value: int, *, no_abbrev: bool) -> str:  # noqa: ARG002
        """Decode common attributes."""
        return decode_attr_flags(value, ATTR_CMN_FLAGS)

    def _decode_volattr(self, value: int, *, no_abbrev: bool) -> str:  # noqa: ARG002
        """Decode volume attributes."""
        return decode_attr_flags(value, ATTR_VOL_FLAGS)

    def _decode_dirattr(self, value: int, *, no_abbrev: bool) -> str:  # noqa: ARG002
        """Decode directory attributes."""
        return decode_attr_flags(value, ATTR_DIR_FLAGS)

    def _decode_fileattr(self, value: int, *, no_abbrev: bool) -> str:  # noqa: ARG002
        """Decode file attributes."""
        return decode_attr_flags(value, ATTR_FILE_FLAGS)

    def _decode_forkattr(self, value: int, *, no_abbrev: bool) -> str:  # noqa: ARG002
        """Decode fork attributes."""
        return f"0x{value:x}" if value else "0"


__all__ = [
    "AttrListParam",
]
