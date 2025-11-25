"""Syscall definitions organized by category."""

from __future__ import annotations

import ctypes
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, ClassVar, Protocol

# Runtime imports (not lldb - that's system Python only)
from strace_macos.lldb_loader import load_lldb_module
from strace_macos.syscalls.args import (
    BufferArg,
    FileDescriptorArg,
    FlagsArg,
    IntArg,
    PointerArg,
    SkipArg,
    StringArg,
    StringArrayArg,
    StructArg,
    SyscallArg,
    UnsignedArg,
)
from strace_macos.syscalls.symbols.file import AT_FDCWD, FLOCK_OPS

if TYPE_CHECKING:
    from collections.abc import Callable


class ReturnDecoder(Protocol):
    """Protocol for return value decoder functions."""

    def __call__(self, ret_value: int, all_args: list[int], *, no_abbrev: bool) -> str | int:
        """Decode a return value based on syscall arguments."""
        ...


class ParamDirection(Enum):
    """Direction of parameter flow."""

    IN = "in"  # Input parameter (read at syscall entry)
    OUT = "out"  # Output parameter (read at syscall exit)


class Param(ABC):
    """Base class for all syscall parameter decoders.

    Each Param subclass knows how to decode a specific type of argument
    (int, string, pointer, struct, buffer, etc.) from raw register values
    to typed SyscallArg objects for display.

    The position of a Param in the params list determines which argument
    it decodes (Param at index 0 decodes arg 0, etc.).
    """

    @abstractmethod
    def decode(
        self,
        tracer: Any,
        process: Any,
        raw_value: int,
        all_args: list[int],
        *,
        at_entry: bool,
    ) -> SyscallArg | None:
        """Decode a raw register value to a typed SyscallArg.

        Args:
            tracer: The Tracer instance (for accessing no_abbrev, etc.)
            process: The lldb process object (for reading memory)
            raw_value: The raw register value for this argument
            all_args: All raw argument values (for cross-references like buffer sizes)
            at_entry: True if decoding at syscall entry, False at exit

        Returns:
            A typed SyscallArg object, or None if not ready to decode yet
            (e.g., OUT params return None at entry time)
        """
        ...

    @staticmethod
    def _to_signed_int(reg_value: int) -> int:
        """Convert unsigned 64-bit register value to signed int."""
        return (
            int(reg_value)
            if reg_value < 0x8000000000000000
            else int(reg_value) - 0x10000000000000000
        )

    @staticmethod
    def _to_signed_int32(reg_value: int) -> int:
        """Convert unsigned 32-bit value to signed int.

        Handles values like 0xFFFFFFFF (-1 as unsigned 32-bit).
        """
        # Mask to 32 bits
        val32 = reg_value & 0xFFFFFFFF
        # Convert to signed
        return val32 if val32 < 0x80000000 else val32 - 0x100000000

    @staticmethod
    def _read_string(process: Any, address: int, max_length: int = 4096) -> str:
        """Read a null-terminated string from process memory."""
        import lldb  # noqa: PLC0415 - lazy import required for system Python

        if address == 0:
            return "NULL"

        chunk_size = 256
        result_bytes = bytearray()
        current_address = address
        bytes_read = 0
        error = lldb.SBError()

        while bytes_read < max_length:
            chunk = process.ReadMemory(
                current_address, min(chunk_size, max_length - bytes_read), error
            )

            if error.Fail():
                if bytes_read == 0:
                    return f"0x{address:x}"
                break

            try:
                null_pos = chunk.index(b"\x00")
                result_bytes.extend(chunk[:null_pos])
                break
            except ValueError:
                result_bytes.extend(chunk)
                current_address += len(chunk)
                bytes_read += len(chunk)

        try:
            return result_bytes.decode("utf-8", errors="replace")
        except (UnicodeDecodeError, AttributeError):
            return f"0x{address:x}"


class IntParam(Param):
    """Parameter decoder for signed integers."""

    def decode(
        self,
        tracer: Any,  # noqa: ARG002
        process: Any,  # noqa: ARG002
        raw_value: int,
        all_args: list[int],  # noqa: ARG002
        *,
        at_entry: bool,  # noqa: ARG002
    ) -> SyscallArg:
        """Decode signed integer to IntArg."""
        signed_val = self._to_signed_int(raw_value)
        return IntArg(signed_val)


class UnsignedParam(Param):
    """Parameter decoder for unsigned integers (size_t, off_t, etc.)."""

    def decode(
        self,
        tracer: Any,  # noqa: ARG002
        process: Any,  # noqa: ARG002
        raw_value: int,
        all_args: list[int],  # noqa: ARG002
        *,
        at_entry: bool,  # noqa: ARG002
    ) -> SyscallArg:
        """Decode unsigned integer to UnsignedArg."""
        return UnsignedArg(raw_value)


class StringParam(Param):
    """Parameter decoder for null-terminated strings."""

    def decode(
        self,
        tracer: Any,  # noqa: ARG002
        process: Any,
        raw_value: int,
        all_args: list[int],  # noqa: ARG002
        *,
        at_entry: bool,  # noqa: ARG002
    ) -> SyscallArg:
        """Decode string pointer to StringArg."""
        string_val = self._read_string(process, raw_value)
        return StringArg(string_val)


class ArrayOfStringsParam(Param):
    """Parameter decoder for null-terminated arrays of strings (char *[]).

    Used for argv[], envp[] in execve/posix_spawn.
    Reads array of pointers until null pointer is found.
    """

    def __init__(self, max_strings: int = 1024) -> None:
        """Initialize array of strings parameter.

        Args:
            max_strings: Maximum number of strings to read (safety limit)
        """
        self.max_strings = max_strings

    def decode(
        self,
        tracer: Any,  # noqa: ARG002
        process: Any,
        raw_value: int,
        all_args: list[int],  # noqa: ARG002
        *,
        at_entry: bool,  # noqa: ARG002
    ) -> SyscallArg:
        """Decode array of string pointers to StringArrayArg."""
        import lldb  # noqa: PLC0415 - lazy import required for system Python

        if raw_value == 0:
            return PointerArg(0)

        strings = []
        error = lldb.SBError()
        pointer_size = 8  # 64-bit pointers

        for i in range(self.max_strings):
            # Read pointer at index i
            ptr_address = raw_value + (i * pointer_size)
            ptr_data = process.ReadMemory(ptr_address, pointer_size, error)

            if error.Fail():
                # Can't read more pointers
                break

            # Convert bytes to pointer value (little-endian)
            ptr_value = int.from_bytes(ptr_data, byteorder="little")

            # Null pointer terminates the array
            if ptr_value == 0:
                break

            string_val = self._read_string(process, ptr_value)
            strings.append(string_val)

        return StringArrayArg(strings)


class DirFdParam(Param):
    """Parameter decoder for directory file descriptors (like AT_FDCWD).

    File descriptors are 32-bit signed integers on macOS.
    """

    def decode(
        self,
        tracer: Any,
        process: Any,  # noqa: ARG002
        raw_value: int,
        all_args: list[int],  # noqa: ARG002
        *,
        at_entry: bool,  # noqa: ARG002
    ) -> SyscallArg:
        """Decode directory fd to IntArg with symbolic AT_FDCWD."""

        # File descriptors are 32-bit signed integers
        signed_val = ctypes.c_int32(raw_value & 0xFFFFFFFF).value

        if tracer.no_abbrev:
            return IntArg(signed_val, f"0x{raw_value:x}")

        # Decode AT_FDCWD
        if signed_val == AT_FDCWD:
            return IntArg(signed_val, "AT_FDCWD")
        return IntArg(signed_val, None)


class FlockOpParam(Param):
    """Parameter decoder for flock() operation flags.

    Decodes LOCK_SH, LOCK_EX, LOCK_UN, and LOCK_NB flags.
    """

    def decode(
        self,
        tracer: Any,
        process: Any,  # noqa: ARG002
        raw_value: int,
        all_args: list[int],  # noqa: ARG002
        *,
        at_entry: bool,  # noqa: ARG002
    ) -> SyscallArg:
        """Decode flock operation to FlagsArg with symbolic names."""
        if tracer.no_abbrev:
            return IntArg(raw_value, f"0x{raw_value:x}")

        flags = []
        # LOCK_NB is bit 2 (value 4), can be combined with other operations
        base_op = raw_value & ~4
        if base_op in FLOCK_OPS:
            flags.append(FLOCK_OPS[base_op])
        if raw_value & 4:
            flags.append("LOCK_NB")

        if flags:
            return FlagsArg(raw_value, "|".join(flags))
        return IntArg(raw_value, None)


class PointerParam(Param):
    """Parameter decoder for raw pointers/addresses."""

    def decode(
        self,
        tracer: Any,  # noqa: ARG002
        process: Any,  # noqa: ARG002
        raw_value: int,
        all_args: list[int],  # noqa: ARG002
        *,
        at_entry: bool,  # noqa: ARG002
    ) -> SyscallArg:
        """Decode pointer to PointerArg."""
        return PointerArg(raw_value)


class FileDescriptorParam(Param):
    """Parameter decoder for file descriptors."""

    def decode(
        self,
        tracer: Any,  # noqa: ARG002
        process: Any,  # noqa: ARG002
        raw_value: int,
        all_args: list[int],  # noqa: ARG002
        *,
        at_entry: bool,  # noqa: ARG002
    ) -> SyscallArg:
        """Decode file descriptor to FileDescriptorArg."""
        signed_val = self._to_signed_int(raw_value)
        return FileDescriptorArg(signed_val)


def FlagsParam(flag_map: dict[int, str]) -> Param:  # noqa: N802
    """Factory function to create a Param for decoding flag bitmasks."""

    class _FlagsParam(Param):
        def decode(
            self,
            tracer: Any,
            process: Any,  # noqa: ARG002
            raw_value: int,
            all_args: list[int],  # noqa: ARG002
            *,
            at_entry: bool,  # noqa: ARG002
        ) -> SyscallArg:
            """Decode flags to FlagsArg with symbolic representation."""
            if tracer.no_abbrev:
                # With --no-abbrev, FlagsArg will format as hex automatically
                return FlagsArg(raw_value, None)

            if raw_value == 0:
                # Check if there's a special symbolic name for 0 (e.g., PROT_NONE)
                symbolic_zero = flag_map.get(0, "0")
                return FlagsArg(0, symbolic_zero)

            flags = [name for val, name in flag_map.items() if val > 0 and (raw_value & val)]
            symbolic = "|".join(flags) if flags else None
            return FlagsArg(raw_value, symbolic)

    return _FlagsParam()


def ConstParam(const_map: dict[int, str]) -> Param:  # noqa: N802
    """Factory function to create a Param for decoding constant values.

    Constant parameters are always 32-bit int in syscalls (e.g., flags, commands).

    Args:
        const_map: Dictionary mapping integer values to symbolic names
    """

    class _ConstParam(Param):
        def decode(
            self,
            tracer: Any,
            process: Any,  # noqa: ARG002
            raw_value: int,
            all_args: list[int],  # noqa: ARG002
            *,
            at_entry: bool,  # noqa: ARG002
        ) -> SyscallArg:
            """Decode constant to IntArg with symbolic representation."""
            # All constant parameters are 32-bit int
            signed_val = self._to_signed_int32(raw_value)

            if tracer.no_abbrev:
                return IntArg(signed_val, None)

            symbolic = const_map.get(signed_val)
            return IntArg(signed_val, symbolic)

    return _ConstParam()


def CustomParam(decode_func: Callable[[int], str]) -> Param:  # noqa: N802
    """Factory function to create a Param using a custom decoder function."""

    class _CustomParam(Param):
        def decode(
            self,
            tracer: Any,
            process: Any,  # noqa: ARG002
            raw_value: int,
            all_args: list[int],  # noqa: ARG002
            *,
            at_entry: bool,  # noqa: ARG002
        ) -> SyscallArg:
            """Decode using custom function to IntArg with symbolic representation."""
            signed_val = self._to_signed_int(raw_value)

            if tracer.no_abbrev:
                # With --no-abbrev, show as hex
                return IntArg(signed_val, f"0x{raw_value:x}")

            symbolic = decode_func(signed_val)
            # If the decoder returns the same as str(value), don't use it as symbolic
            if symbolic == str(signed_val):
                return IntArg(signed_val, None)
            return IntArg(signed_val, symbolic)

    return _CustomParam()


class OctalParam(Param):
    """Parameter decoder for octal file mode/permissions."""

    def decode(
        self,
        tracer: Any,
        process: Any,  # noqa: ARG002
        raw_value: int,
        all_args: list[int],  # noqa: ARG002
        *,
        at_entry: bool,  # noqa: ARG002
    ) -> SyscallArg:
        """Decode mode to IntArg with octal representation."""
        signed_val = self._to_signed_int(raw_value)
        if tracer.no_abbrev:
            # With --no-abbrev, show as hex (like strace -X)
            return IntArg(signed_val, f"0x{raw_value:x}")

        # Format as octal with leading 0
        symbolic = f"0{signed_val:o}" if signed_val >= 0 else None
        return IntArg(signed_val, symbolic)


class StructParamBase(Param):
    """Base class for struct-based parameter decoders.

    This combines the functionality of the old StructDecoder and StructParam:
    - Direction-aware decoding (IN params at entry, OUT params at exit)
    - ctypes-based struct reading and field iteration
    - Custom field formatters
    - Field exclusion

    Subclasses should:
    1. Set struct_type to their ctypes.Structure class
    2. Set direction in __init__ (ParamDirection.IN or OUT)
    3. Optionally define field_formatters dict
    4. Optionally define excluded_fields set
    5. Override decode_struct() for custom struct decoding logic

    Example:
        class StatParam(StructParamBase):
            struct_type = StatStruct
            field_formatters = {"st_mode": "_decode_mode"}
            excluded_fields = {"st_lspare", "_padding"}

            def __init__(self, direction: ParamDirection):
                self.direction = direction

            def _decode_mode(self, value: int, no_abbrev: bool) -> str:
                return f"0{value:o}" if no_abbrev else f"S_IFREG|0{value:o}"
    """

    # Subclasses must set this to their ctypes.Structure class
    struct_type: type[ctypes.Structure] | None = None

    # Subclasses can define custom formatters for specific fields
    # Dict maps field_name -> method_name (string)
    field_formatters: ClassVar[dict[str, str]] = {}

    # Subclasses can exclude fields (e.g., padding, reserved fields)
    excluded_fields: ClassVar[set[str]] = set()

    # Subclasses must set this in __init__
    direction: ParamDirection

    def decode(
        self,
        tracer: Any,
        process: Any,
        raw_value: int,
        all_args: list[int],  # noqa: ARG002
        *,
        at_entry: bool,
    ) -> SyscallArg | None:
        """Decode struct pointer to StructArg.

        This handles direction filtering and delegates to decode_struct()
        for the actual struct decoding logic.
        """
        # Direction filtering: only decode at appropriate time
        if at_entry and self.direction != ParamDirection.IN:
            return PointerArg(raw_value)  # Return as pointer for now
        if not at_entry and self.direction != ParamDirection.OUT:
            return None  # Already decoded at entry

        # Skip NULL pointers
        if raw_value == 0:
            return PointerArg(0)

        # Decode the struct
        decoded_fields = self.decode_struct(process, raw_value, no_abbrev=tracer.no_abbrev)
        if decoded_fields:
            return StructArg(decoded_fields)

        return PointerArg(raw_value)

    def decode_struct(
        self, process: Any, address: int, *, no_abbrev: bool = False
    ) -> dict[str, str | int | list[Any]] | None:
        """Decode a struct from process memory.

        Default implementation uses struct_type and field_formatters.
        Subclasses can override this for custom decoding logic.

        Args:
            process: LLDB process to read memory from
            address: Memory address of the struct
            no_abbrev: If True, disable symbolic decoding

        Returns:
            Dictionary of field names to decoded values, or None if read failed
        """
        if self.struct_type is None:
            msg = "Subclasses must define struct_type"
            raise NotImplementedError(msg)

        # Read memory
        lldb = load_lldb_module()
        error = lldb.SBError()
        size = ctypes.sizeof(self.struct_type)
        data = process.ReadMemory(address, size, error)

        if error.Fail() or not data:
            return None

        # Parse struct using ctypes
        try:
            struct_obj = self.struct_type.from_buffer_copy(data)
        except (ValueError, TypeError):
            return None

        # Build result dict from struct fields
        result = {}
        for field_name, _field_type in self.struct_type._fields_:  # type: ignore[misc]
            # Skip excluded fields
            if field_name in self.excluded_fields:
                continue

            raw_value = getattr(struct_obj, field_name)

            # Apply custom formatter if available
            if field_name in self.field_formatters:
                method_name = self.field_formatters[field_name]
                formatter = getattr(self, method_name)
                formatted_value = formatter(raw_value, no_abbrev=no_abbrev)
            else:
                formatted_value = raw_value

            result[field_name] = formatted_value

        return result

    def _read_struct(self, process: Any, address: int, struct_type: type[ctypes.Structure]) -> Any:
        """Read a ctypes struct from process memory.

        Utility method for subclasses that need to read nested structs.

        Args:
            process: LLDB process to read memory from
            address: Memory address of the struct
            struct_type: The ctypes.Structure subclass to read

        Returns:
            The struct instance, or None if read failed
        """
        lldb = load_lldb_module()
        error = lldb.SBError()
        size = ctypes.sizeof(struct_type)
        data = process.ReadMemory(address, size, error)

        if error.Fail() or not data:
            return None

        try:
            return struct_type.from_buffer_copy(data)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _format_pointer(address: int) -> str:
        """Format a pointer address for display."""
        if address == 0:
            return "NULL"
        return f"0x{address:x}"


@dataclass
class BufferParam(Param):
    """Parameter decoder for raw buffer data (e.g., read/write buffers)."""

    size_arg_index: int
    direction: ParamDirection

    def decode(
        self,
        tracer: Any,
        process: Any,
        raw_value: int,
        all_args: list[int],
        *,
        at_entry: bool,
    ) -> SyscallArg | None:
        """Decode buffer pointer to BufferArg."""
        import lldb  # noqa: PLC0415 - lazy import required for system Python

        # Direction filtering
        if at_entry and self.direction != ParamDirection.IN:
            return PointerArg(raw_value)
        if not at_entry and self.direction != ParamDirection.OUT:
            return None

        # Skip NULL pointers
        if raw_value == 0:
            return PointerArg(0)

        # Get size from referenced argument
        if self.size_arg_index >= len(all_args):
            return PointerArg(raw_value)

        size_value = all_args[self.size_arg_index]
        size = size_value

        # Validate size is reasonable (including 0 - LLDB doesn't like 0-byte reads)
        if size <= 0:
            return PointerArg(raw_value)

        # Cap the size to avoid reading huge buffers (like strace's -s option)
        # Default is 32 bytes like strace, but we allow up to 4096 for large reads
        max_buffer_size = 4096
        actual_size = min(size, max_buffer_size) if not tracer.no_abbrev else min(size, 65536)

        # Read the buffer data
        error = lldb.SBError()
        data = process.ReadMemory(raw_value, actual_size, error)

        if error.Fail() or not data:
            return PointerArg(raw_value)

        return BufferArg(data, raw_value)


@dataclass
class VariantParam(Param):
    """Parameter that decodes differently based on a discriminator argument.

    Used for syscalls like fcntl/ioctl where one argument (discriminator)
    determines how another argument should be decoded.

    Example for fcntl(fd, cmd, arg):
        - cmd=F_GETFD: arg doesn't exist (skip)
        - cmd=F_SETFD: arg is FD_CLOEXEC flags
        - cmd=F_SETFL: arg is O_* file status flags

    Example for open(path, flags, mode):
        - If O_CREAT not set in flags: mode doesn't exist (skip)
        - If O_CREAT set: mode is used

    Attributes:
        discriminator_index: Index of the discriminator arg (e.g., fcntl cmd)
        variants: Map from discriminator value to Param for decoding this arg
        default_param: Fallback Param if discriminator value not in variants
        skip_for: Set of discriminator values where this arg doesn't exist
        skip_when_not_set: Flag bits that must be set in discriminator for arg to exist
                          (e.g., O_CREAT for open's mode parameter)
    """

    discriminator_index: int
    variants: dict[int, Param] = field(default_factory=dict)
    default_param: Param | None = None
    skip_for: set[int] = field(default_factory=set)
    skip_when_not_set: int | None = None

    def decode(
        self,
        tracer: Any,
        process: Any,
        raw_value: int,
        all_args: list[int],
        *,
        at_entry: bool,
    ) -> SyscallArg | None:
        """Decode argument based on discriminator value."""
        # Get discriminator value
        if self.discriminator_index >= len(all_args):
            return PointerArg(raw_value)

        disc_value = all_args[self.discriminator_index]

        # Skip if discriminator says this arg doesn't exist (exact match)
        if disc_value in self.skip_for:
            return SkipArg()  # Mark for removal from output

        # Skip if required flag bits are not set (for open/O_CREAT etc.)
        if self.skip_when_not_set is not None and (disc_value & self.skip_when_not_set) == 0:
            return SkipArg()  # Flag bit not set, arg doesn't exist

        # Get the right param for this discriminator value
        param = self.variants.get(disc_value, self.default_param)
        if param is None:
            return PointerArg(raw_value)

        # Decode using the selected param
        return param.decode(tracer, process, raw_value, all_args, at_entry=at_entry)


@dataclass
class SyscallDef:
    """Definition of a single syscall.

    Attributes:
        number: Syscall number (from sys/syscall.h)
        name: Syscall name (e.g., "open", "read")
        params: List of Param decoders (one per argument).
                E.g., [StringParam(), FlagsParam(O_FLAGS), FlagsParam(FILE_MODE)]
                Position in list determines which argument it decodes.
        return_decoder: Optional function to decode return value based on arguments.
                Takes (return_value, all_args, no_abbrev) and returns string or int.
        variadic_start: Optional index where variadic arguments start (for fcntl, ioctl).
                On macOS ARM64, arguments at this index and beyond are passed on the
                stack instead of in registers.
    """

    number: int
    name: str
    params: list[Param]
    return_decoder: ReturnDecoder | None = None
    variadic_start: int | None = None
