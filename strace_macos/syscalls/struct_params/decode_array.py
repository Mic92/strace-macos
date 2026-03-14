
from strace_macos.lldb_loader import load_lldb_module

def decode_array(
    self,
    process: Any,
    address: int,
    count: int,
    struct_type: type # FIXME
) -> list[dict[str, str | int]] | None:
    """Decode an array of structures."""

    lldb = load_lldb_module()
    error = lldb.SBError()
    size = ctypes.sizeof(struct_type)
    total_size = size * count

    data = process.ReadMemory(address, total_size, error)
    if error.Fail() or not data:
        return None

    struct_list = []
    for i in range(count):
        offset = i * size
        try:
            pfd = struct_type.from_buffer_copy(data[offset : offset + size])
        except (ValueError, TypeError):
            continue

        struct_list.append(
            {
                "fd": pfd.fd,
                "events": self._decode_events(pfd.events),
            }
        )

    return struct_list if struct_list else None
