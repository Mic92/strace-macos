
from __future__ import annotations

import ctypes

from strace_macos.lldb_loader import load_lldb_module

from strace_macos.syscalls.args import StructArg

def _generic_decode(ctx, param, data):
    # Decode the struct using the scalar param 
    decoded_fields = param.parse_struct(data, no_abbrev=ctx.tracer.no_abbrev)

    if decoded_fields:
        return StructArg(decoded_fields)
    return None

def decode_array(
    ctx: DecodeContext,
    address: int,
    count: int,
    param: StructParamBase,
    decode_fn: callable = _generic_decode, # FIXME - better annotation
) -> list[dict[str, str | int]] | None:
    """Decode an array of structures."""

    # is now the right time to decode (ie check param direction)
    sd, _ = param.should_decode(ctx=ctx)
    if not sd:
        return None

    lldb = load_lldb_module()
    error = lldb.SBError()
    struct_type = param.struct_type
    size = ctypes.sizeof(struct_type)
    total_size = size * count

    data = ctx.process.ReadMemory(address, total_size, error)
    if error.Fail() or not data:
        return None

    struct_list = []
    for i in range(count):
        offset = i * size
        try:
            struct = struct_type.from_buffer_copy(data[offset : offset + size])
        except (ValueError, TypeError):
            continue

        s = decode_fn(ctx, param, struct)
        struct_list.append(s)

    return struct_list if struct_list else None
