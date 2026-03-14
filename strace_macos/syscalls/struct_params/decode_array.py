
from __future__ import annotations

import ctypes

from strace_macos.lldb_loader import load_lldb_module

from strace_macos.syscalls.args import StructArg

def _generic_decode(ctx, param, struct):
    # Decode the struct using the scalar param 
    decoded_fields = param.decode_struct(
            ctx.process, ctx.raw_value, no_abbrev=ctx.tracer.no_abbrev
    )
    if decoded_fields:
        return StructArg(decoded_fields)
    return None

#def _generic_decode(ctx, struct):
#    out = dict()
#    for field in struct._fields_:
#        field_name = field[0]
#        field_value = getattr(struct, field[0])
#        out[field_name] = field_value
#
#    # FIXME: what to do here if no fields?
#    return out

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

        struct_list.append(
            decode_fn(ctx, param, struct)
        )

    return struct_list if struct_list else None
