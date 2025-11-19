"""Parameter decoder for aiocb pointer arrays (aio_suspend, lio_listio).

Handles arrays of struct aiocb pointers for AIO operations.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Any

from strace_macos.lldb_loader import load_lldb_module
from strace_macos.syscalls.args import StructArrayArg, SyscallArg
from strace_macos.syscalls.definitions import Param, ParamDirection
from strace_macos.syscalls.struct_params.aiocb import AiocbStruct
from strace_macos.syscalls.symbols.ipc import LIO_OPCODES


@dataclass
class AiocbArrayParam(Param):
    """Parameter decoder for aiocb pointer arrays.

    Decodes arrays of pointers to struct aiocb for AIO operations.
    Each array element is a pointer to an aiocb structure.

    Usage:
        AiocbArrayParam(count_arg_index=1, direction=ParamDirection.IN)  # aio_suspend
        AiocbArrayParam(count_arg_index=2, direction=ParamDirection.IN)  # lio_listio
    """

    count_arg_index: int
    direction: ParamDirection

    def decode(
        self,
        tracer: Any,  # noqa: ARG002
        process: Any,
        raw_value: int,
        all_args: list[int],
        *,
        at_entry: bool,
    ) -> SyscallArg | None:
        """Decode aiocb pointer array to StructArrayArg.

        Args:
            tracer: The Tracer instance (unused)
            process: The lldb process object for reading memory
            raw_value: The raw register value (pointer to aiocb* array)
            all_args: All raw argument values (to get count)
            at_entry: True if decoding at syscall entry, False at exit

        Returns:
            StructArrayArg with decoded aiocb array or None
        """
        # Direction filtering
        if at_entry and self.direction != ParamDirection.IN:
            return None
        if not at_entry and self.direction != ParamDirection.OUT:
            return None

        # Skip NULL pointers
        if raw_value == 0:
            return None

        # Get count from referenced argument
        if self.count_arg_index >= len(all_args):
            return None

        count = all_args[self.count_arg_index]

        # Validate count is reasonable
        if count < 0 or count > 64:  # AIO_LISTIO_MAX is 16, but be generous
            return None

        # Decode the aiocb pointer array
        struct_list = self._decode_array(process, raw_value, count)

        if struct_list:
            return StructArrayArg(struct_list)

        return None

    def _decode_array(
        self,
        process: Any,
        address: int,
        count: int,
    ) -> list[str] | None:
        """Decode an array of aiocb pointers.

        Args:
            process: LLDB process to read memory from
            address: Memory address of the aiocb* array
            count: Number of aiocb* elements

        Returns:
            List of aiocb summary strings, or None if failed
        """
        if count <= 0 or count > 64:
            return None

        lldb = load_lldb_module()
        error = lldb.SBError()
        ptr_size = 8  # 64-bit pointers
        total_size = ptr_size * count

        # Read the array of pointers
        data = process.ReadMemory(address, total_size, error)
        if error.Fail() or not data:
            return None

        summaries = []
        for i in range(count):
            offset = i * ptr_size
            try:
                # Read pointer value
                aiocb_ptr = int.from_bytes(data[offset : offset + ptr_size], byteorder="little")

                if aiocb_ptr == 0:
                    summaries.append("NULL")
                    continue

                # Read the aiocb structure
                aiocb = self._read_aiocb(process, aiocb_ptr)
                if aiocb:
                    summaries.append(aiocb)
                else:
                    summaries.append("?")

            except (ValueError, TypeError):
                summaries.append("?")

        return summaries if summaries else None

    def _read_aiocb(self, process: Any, address: int) -> str | None:
        """Read and format a single aiocb structure.

        Args:
            process: LLDB process to read memory from
            address: Address of aiocb structure

        Returns:
            Formatted string summary of aiocb, or None if failed
        """
        lldb = load_lldb_module()
        error = lldb.SBError()
        aiocb_size = ctypes.sizeof(AiocbStruct)

        data = process.ReadMemory(address, aiocb_size, error)
        if error.Fail() or not data:
            return None

        try:
            aiocb = AiocbStruct.from_buffer_copy(data)
        except (ValueError, TypeError):
            return None

        # Format key fields
        parts = [f"fd={aiocb.aio_fildes}"]

        if aiocb.aio_nbytes > 0:
            parts.append(f"nbytes={aiocb.aio_nbytes}")

        if aiocb.aio_offset != 0:
            parts.append(f"offset={aiocb.aio_offset}")

        # Decode opcode if present
        if aiocb.aio_lio_opcode != 0:
            opcode_str = LIO_OPCODES.get(aiocb.aio_lio_opcode, str(aiocb.aio_lio_opcode))
            parts.append(f"op={opcode_str}")

        return "{" + ", ".join(parts) + "}"


__all__ = ["AiocbArrayParam"]
