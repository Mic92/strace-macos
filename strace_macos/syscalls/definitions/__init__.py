"""Syscall definitions organized by category."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol

# Runtime imports (not lldb - that's system Python only)
from strace_macos.syscalls.args import (
    BufferArg,
    FileDescriptorArg,
    FlagsArg,
    IntArg,
    IntPtrArg,
    IovecArrayArg,
    PointerArg,
    SkipArg,
    StringArg,
    StructArg,
    SyscallArg,
    UnsignedArg,
)
from strace_macos.syscalls.struct_decoders import get_struct_decoder
from strace_macos.syscalls.struct_decoders.iovec import IovecArrayDecoder

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
        """Convert unsigned register value to signed int."""
        return (
            int(reg_value)
            if reg_value < 0x8000000000000000
            else int(reg_value) - 0x10000000000000000
        )

    @staticmethod
    def _read_string(process: Any, address: int, max_length: int = 4096) -> str:
        """Read a null-terminated string from process memory."""
        import lldb  # noqa: PLC0415

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
                return FlagsArg(0, "0")

            flags = [name for val, name in flag_map.items() if raw_value & val]
            symbolic = "|".join(flags) if flags else None
            return FlagsArg(raw_value, symbolic)

    return _FlagsParam()


def ConstParam(const_map: dict[int, str]) -> Param:  # noqa: N802
    """Factory function to create a Param for decoding constant values."""

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
            if tracer.no_abbrev:
                signed_val = self._to_signed_int(raw_value)
                return IntArg(signed_val, None)

            signed_val = self._to_signed_int(raw_value)
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


@dataclass
class StructParam(Param):
    """Parameter decoder for structured data (e.g., struct stat, struct sockaddr)."""

    struct_name: str
    direction: ParamDirection

    def decode(  # noqa: PLR0911
        self,
        tracer: Any,
        process: Any,
        raw_value: int,
        all_args: list[int],  # noqa: ARG002
        *,
        at_entry: bool,
    ) -> SyscallArg | None:
        """Decode struct pointer to StructArg."""
        # Direction filtering: only decode at appropriate time
        if at_entry and self.direction != ParamDirection.IN:
            return PointerArg(raw_value)  # Return as pointer for now
        if not at_entry and self.direction != ParamDirection.OUT:
            return None  # Already decoded at entry

        # Skip NULL pointers
        if raw_value == 0:
            return PointerArg(0)

        # Get the struct decoder
        decoder = get_struct_decoder(self.struct_name)
        if not decoder:
            return PointerArg(raw_value)

        # Decode the struct from memory
        decoded_fields = decoder.decode(process, raw_value, no_abbrev=tracer.no_abbrev)
        if decoded_fields:
            # Special case for int_ptr: return IntPtrArg instead of StructArg
            if self.struct_name == "int_ptr" and "value" in decoded_fields:
                value = decoded_fields["value"]
                if isinstance(value, int):
                    return IntPtrArg(value)
            return StructArg(decoded_fields)

        return PointerArg(raw_value)


@dataclass
class BufferParam(Param):
    """Parameter decoder for raw buffer data (e.g., read/write buffers)."""

    size_arg_index: int
    direction: ParamDirection

    def decode(  # noqa: PLR0911
        self,
        tracer: Any,  # noqa: ARG002
        process: Any,
        raw_value: int,
        all_args: list[int],
        *,
        at_entry: bool,
    ) -> SyscallArg | None:
        """Decode buffer pointer to BufferArg."""
        import lldb  # noqa: PLC0415

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

        # Validate size is reasonable
        if size < 0 or size > 65536:
            return PointerArg(raw_value)

        # Read the buffer data
        error = lldb.SBError()
        data = process.ReadMemory(raw_value, size, error)

        if error.Fail() or not data:
            return PointerArg(raw_value)

        return BufferArg(data, raw_value)


@dataclass
class IovecParam(Param):
    """Parameter decoder for iovec arrays (for readv/writev)."""

    count_arg_index: int
    direction: ParamDirection

    def decode(  # noqa: PLR0911
        self,
        tracer: Any,  # noqa: ARG002
        process: Any,
        raw_value: int,
        all_args: list[int],
        *,
        at_entry: bool,
    ) -> SyscallArg | None:
        """Decode iovec array pointer to IovecArrayArg."""
        # Direction filtering
        if at_entry and self.direction != ParamDirection.IN:
            return PointerArg(raw_value)
        if not at_entry and self.direction != ParamDirection.OUT:
            return None

        # Skip NULL pointers
        if raw_value == 0:
            return PointerArg(0)

        # Get count from referenced argument
        if self.count_arg_index >= len(all_args):
            return PointerArg(raw_value)

        count = all_args[self.count_arg_index]

        # Validate count is reasonable
        if count < 0 or count > 1024:
            return PointerArg(raw_value)

        # Use the iovec decoder
        decoder = IovecArrayDecoder()
        iov_list = decoder.decode_array(process, raw_value, count)

        if iov_list:
            return IovecArrayArg(iov_list)

        return PointerArg(raw_value)


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
