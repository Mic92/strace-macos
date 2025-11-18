"""Network-related constants and decoders for macOS/Darwin."""

from __future__ import annotations

# Address family constants (AF_*)
AF_CONSTANTS: dict[int, str] = {
    0: "AF_UNSPEC",
    1: "AF_UNIX",  # Also AF_LOCAL
    2: "AF_INET",
    3: "AF_IMPLINK",
    4: "AF_PUP",
    5: "AF_CHAOS",
    6: "AF_NS",
    7: "AF_ISO",
    8: "AF_ECMA",
    9: "AF_DATAKIT",
    10: "AF_CCITT",
    11: "AF_SNA",
    12: "AF_DECnet",
    13: "AF_DLI",
    14: "AF_LAT",
    15: "AF_HYLINK",
    16: "AF_APPLETALK",
    17: "AF_ROUTE",
    18: "AF_LINK",
    20: "AF_COIP",
    21: "AF_CNT",
    23: "AF_IPX",
    24: "AF_SIP",
    27: "AF_NDRV",
    28: "AF_ISDN",
    30: "AF_INET6",
    31: "AF_NATM",
    32: "AF_SYSTEM",
    33: "AF_NETBIOS",
    34: "AF_PPP",
    37: "AF_IEEE80211",
    38: "AF_UTUN",
    40: "AF_VSOCK",
}

# Socket type constants (SOCK_*)
SOCK_CONSTANTS: dict[int, str] = {
    1: "SOCK_STREAM",  # TCP - stream socket
    2: "SOCK_DGRAM",  # UDP - datagram socket
    3: "SOCK_RAW",  # Raw socket
    4: "SOCK_RDM",  # Reliably-delivered message
    5: "SOCK_SEQPACKET",  # Sequenced packet stream
}

# Protocol constants (IPPROTO_*)
# Most common ones for socket() third argument
IPPROTO_CONSTANTS: dict[int, str] = {
    0: "IPPROTO_IP",
    1: "IPPROTO_ICMP",
    2: "IPPROTO_IGMP",
    4: "IPPROTO_IPIP",
    6: "IPPROTO_TCP",
    8: "IPPROTO_EGP",
    12: "IPPROTO_PUP",
    17: "IPPROTO_UDP",
    22: "IPPROTO_IDP",
    29: "IPPROTO_TP",
    41: "IPPROTO_IPV6",
    43: "IPPROTO_ROUTING",
    44: "IPPROTO_FRAGMENT",
    46: "IPPROTO_RSVP",
    47: "IPPROTO_GRE",
    50: "IPPROTO_ESP",
    51: "IPPROTO_AH",
    58: "IPPROTO_ICMPV6",
    59: "IPPROTO_NONE",
    60: "IPPROTO_DSTOPTS",
    94: "IPPROTO_IPCOMP",
    132: "IPPROTO_SCTP",
    255: "IPPROTO_RAW",
}

# Message flags (MSG_*) for send*/recv*
MSG_FLAGS: dict[int, str] = {
    0x1: "MSG_OOB",
    0x2: "MSG_PEEK",
    0x4: "MSG_DONTROUTE",
    0x8: "MSG_EOR",
    0x10: "MSG_TRUNC",
    0x20: "MSG_CTRUNC",
    0x40: "MSG_WAITALL",
    0x80: "MSG_DONTWAIT",
    0x100: "MSG_EOF",
    0x400: "MSG_FLUSH",
    0x800: "MSG_HOLD",
    0x1000: "MSG_SEND",
    0x2000: "MSG_HAVEMORE",
    0x4000: "MSG_RCVMORE",
    0x10000: "MSG_NEEDSA",
    0x80000: "MSG_NOSIGNAL",
}

# Socket level (SOL_*) for setsockopt/getsockopt
SOL_CONSTANTS: dict[int, str] = {
    0: "SOL_LOCAL",
    0xFFFF: "SOL_SOCKET",
}

# Socket options (SO_*) for setsockopt/getsockopt at SOL_SOCKET level
SO_OPTIONS: dict[int, str] = {
    0x01: "SO_DEBUG",
    0x0002: "SO_ACCEPTCONN",
    0x0004: "SO_REUSEADDR",
    0x0008: "SO_KEEPALIVE",
    0x0010: "SO_DONTROUTE",
    0x0020: "SO_BROADCAST",
    0x0040: "SO_USELOOPBACK",
    0x0080: "SO_LINGER",
    0x0100: "SO_OOBINLINE",
    0x0200: "SO_REUSEPORT",
    0x0400: "SO_TIMESTAMP",
    0x0800: "SO_TIMESTAMP_MONOTONIC",
    0x2000: "SO_DONTTRUNC",
    0x4000: "SO_WANTMORE",
    0x8000: "SO_WANTOOBFLAG",
    0x1001: "SO_SNDBUF",
    0x1002: "SO_RCVBUF",
    0x1003: "SO_SNDLOWAT",
    0x1004: "SO_RCVLOWAT",
    0x1005: "SO_SNDTIMEO",
    0x1006: "SO_RCVTIMEO",
    0x1007: "SO_ERROR",
    0x1008: "SO_TYPE",
    0x1010: "SO_LABEL",
    0x1011: "SO_PEERLABEL",
    0x1020: "SO_NREAD",
    0x1021: "SO_NKE",
    0x1022: "SO_NOSIGPIPE",
    0x1023: "SO_NOADDRERR",
    0x1024: "SO_NWRITE",
    0x1025: "SO_REUSESHAREUID",
    0x1026: "SO_NOTIFYCONFLICT",
    0x1080: "SO_LINGER_SEC",
    0x1082: "SO_RANDOMPORT",
    0x1083: "SO_NP_EXTENSIONS",
}

# Shutdown how constants (SHUT_*)
SHUT_CONSTANTS: dict[int, str] = {
    0: "SHUT_RD",
    1: "SHUT_WR",
    2: "SHUT_RDWR",
}
