"""Architecture-specific abstractions for syscall tracing."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import lldb


class Architecture(ABC):
    """Abstract base class for architecture-specific behavior."""

    @property
    @abstractmethod
    def arg_registers(self) -> list[str]:
        """Register names for function arguments."""

    @property
    @abstractmethod
    def return_register(self) -> str:
        """Register name for return values."""

    @abstractmethod
    def get_return_address(
        self, frame: lldb.SBFrame, process: lldb.SBProcess, lldb_module: object
    ) -> int | None:
        """Get the return address for the current function call.

        Args:
            frame: LLDB stack frame
            process: LLDB process
            lldb_module: LLDB module for error handling

        Returns:
            Return address or None if unable to determine
        """

    @abstractmethod
    def read_variadic_arg(
        self, frame: lldb.SBFrame, process: lldb.SBProcess, lldb_module: object, index: int
    ) -> int | None:
        """Read a variadic argument value.

        On some platforms (macOS ARM64), variadic arguments are passed on the stack
        instead of in registers. This method handles reading them correctly.

        Args:
            frame: LLDB stack frame
            process: LLDB process
            lldb_module: LLDB module for error handling
            index: Index of the variadic argument (0 = first variadic arg)

        Returns:
            Argument value or None if unable to read
        """


class ARM64Architecture(Architecture):
    """ARM64 (AArch64) architecture."""

    @property
    def arg_registers(self) -> list[str]:
        """ARM64 calling convention: x0-x7 for first 8 arguments."""
        return ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]

    @property
    def return_register(self) -> str:
        """ARM64 uses x0 for return values."""
        return "x0"

    def get_return_address(
        self,
        frame: lldb.SBFrame,
        process: lldb.SBProcess,  # noqa: ARG002
        lldb_module: object,  # noqa: ARG002
    ) -> int | None:
        """Get return address from lr (link register / x30).

        Args:
            frame: LLDB stack frame
            process: LLDB process (unused on ARM64)
            lldb_module: LLDB module (unused on ARM64)

        Returns:
            Return address from lr register or None if invalid
        """
        lr_reg = frame.FindRegister("lr")
        if not lr_reg or not lr_reg.IsValid():
            return None
        return lr_reg.GetValueAsUnsigned()  # type: ignore[no-any-return]

    def read_variadic_arg(
        self, frame: lldb.SBFrame, process: lldb.SBProcess, lldb_module: object, index: int
    ) -> int | None:
        """Read variadic argument from stack on macOS ARM64.

        On macOS ARM64, variadic arguments are passed on the stack at [sp + 0],
        [sp + 8], [sp + 16], etc. This is different from Linux ARM64 where they
        use registers.

        Args:
            frame: LLDB stack frame
            process: LLDB process
            lldb_module: LLDB module for error handling
            index: Index of the variadic argument (0 = first variadic arg)

        Returns:
            Argument value or None if unable to read
        """
        sp_reg = frame.FindRegister("sp")
        if not sp_reg or not sp_reg.IsValid():
            return None

        sp = sp_reg.GetValueAsUnsigned()
        # Calculate offset: index * 8 bytes (each arg is 8 bytes)
        offset = index * 8
        stack_address = sp + offset

        error = lldb_module.SBError()  # type: ignore[attr-defined]
        data = process.ReadMemory(stack_address, 8, error)
        if error.Fail() or not data:
            return None

        return int.from_bytes(data, byteorder="little")


class X8664Architecture(Architecture):
    """x86_64 (AMD64) architecture."""

    @property
    def arg_registers(self) -> list[str]:
        """x86_64 calling convention: rdi, rsi, rdx, rcx, r8, r9 for first 6 arguments."""
        return ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

    @property
    def return_register(self) -> str:
        """x86_64 uses rax for return values."""
        return "rax"

    def get_return_address(
        self, frame: lldb.SBFrame, process: lldb.SBProcess, lldb_module: object
    ) -> int | None:
        """Get return address from stack (at [rsp]).

        Args:
            frame: LLDB stack frame
            process: LLDB process
            lldb_module: LLDB module for error handling

        Returns:
            Return address from stack or None if unable to read
        """
        sp_reg = frame.FindRegister("rsp")
        if not sp_reg or not sp_reg.IsValid():
            return None

        sp = sp_reg.GetValueAsUnsigned()
        error = lldb_module.SBError()  # type: ignore[attr-defined]
        return_address_bytes = process.ReadMemory(sp, 8, error)
        if error.Fail():
            return None

        return int.from_bytes(return_address_bytes, byteorder="little")

    def read_variadic_arg(
        self, frame: lldb.SBFrame, process: lldb.SBProcess, lldb_module: object, index: int
    ) -> int | None:
        """Read variadic argument on x86_64.

        On x86_64, variadic arguments beyond the 6th argument are also passed on
        the stack. However, for syscalls like fcntl/ioctl, the variadic argument
        is typically the 3rd argument, so it's still passed in a register (rdx).

        Args:
            frame: LLDB stack frame
            process: LLDB process
            lldb_module: LLDB module for error handling
            index: Index of the variadic argument (0 = first variadic arg)

        Returns:
            Argument value or None if unable to read
        """
        # For x86_64, variadic args beyond the 6 register args go on the stack
        # Stack layout: args are at [rsp + 8], [rsp + 16], etc. ([rsp + 0] is return addr)
        sp_reg = frame.FindRegister("rsp")
        if not sp_reg or not sp_reg.IsValid():
            return None

        sp = sp_reg.GetValueAsUnsigned()
        # Calculate offset: (index + 1) * 8 bytes (skip return address)
        offset = (index + 1) * 8
        stack_address = sp + offset

        error = lldb_module.SBError()  # type: ignore[attr-defined]
        data = process.ReadMemory(stack_address, 8, error)
        if error.Fail() or not data:
            return None

        return int.from_bytes(data, byteorder="little")


def detect_architecture(target: lldb.SBTarget) -> Architecture | None:
    """Detect architecture from LLDB target.

    Args:
        target: LLDB target

    Returns:
        Architecture instance or None if unsupported
    """
    arch = target.GetTriple().split("-")[0]

    if arch in ("arm64", "aarch64", "arm64e"):
        return ARM64Architecture()
    if arch in ("x86_64", "i386"):
        return X8664Architecture()
    return None
