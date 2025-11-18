"""Core syscall tracer using LLDB."""

from __future__ import annotations

import contextlib
import signal
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, TextIO

from strace_macos.arch import Architecture, detect_architecture
from strace_macos.exceptions import SIPProtectedError
from strace_macos.lldb_loader import load_lldb_module
from strace_macos.sip import get_sip_error_message, is_sip_protected, resolve_binary_path
from strace_macos.syscalls.args import (
    SyscallArg,
    UnknownArg,
)
from strace_macos.syscalls.category import SyscallCategory
from strace_macos.syscalls.formatters import (
    ColorTextFormatter,
    JSONFormatter,
    SummaryFormatter,
    SyscallEvent,
    TextFormatter,
)
from strace_macos.syscalls.registry import SyscallRegistry
from strace_macos.syscalls.symbols import decode_errno

if TYPE_CHECKING:
    import lldb

    from strace_macos.syscalls.definitions import Param


class Tracer:
    """System call tracer using LLDB."""

    def __init__(
        self,
        output_file: Path | None = None,
        *,
        json_output: bool = False,
        summary_only: bool = False,
        filter_expr: str | None = None,
        no_abbrev: bool = False,
    ) -> None:
        """Initialize the tracer.

        Args:
            output_file: File to write output to (None for stderr)
            json_output: Whether to output JSON Lines format
            summary_only: Whether to only output summary statistics
            filter_expr: Filter expression (e.g., "trace=open,close")
            no_abbrev: Disable symbolic decoding (show raw numeric values)
        """
        self.output_file = output_file
        self.json_output = json_output
        self.summary_only = summary_only
        self.filter_expr = filter_expr
        self.no_abbrev = no_abbrev

        # Load LLDB
        self.lldb = load_lldb_module()

        # Create syscall registry
        self.registry = SyscallRegistry()

        # Parse filter expression
        self.filtered_syscalls: set[str] | None = None
        self.filter_category: SyscallCategory | None = None
        if filter_expr:
            self._parse_filter(filter_expr)

        # Setup formatters
        self.summary_formatter = SummaryFormatter()
        self.output_handle: TextIO | None = None
        # Defer creating formatter until we know if output is a TTY
        self.formatter: JSONFormatter | TextFormatter | ColorTextFormatter

        # Architecture-specific behavior (will be set based on target)
        # This is always set during spawn() or attach(), so we can assume it's available
        self.arch: Architecture

        # Track pending syscalls (entry without exit yet)
        # Key: (thread_id, return_address), Value: SyscallEvent with partial data
        self.pending_syscalls: dict[tuple[int, int], SyscallEvent] = {}

        # Signal handling for graceful shutdown
        self.interrupted = False

    def _parse_filter(self, filter_expr: str) -> None:
        """Parse the filter expression.

        Args:
            filter_expr: Filter expression (e.g., "trace=open,close" or "trace=file")
        """
        if not filter_expr.startswith("trace="):
            msg = f"Invalid filter expression: {filter_expr}"
            raise ValueError(msg)

        value = filter_expr[6:]  # Remove "trace=" prefix

        # Check if it's a category (match strace categories)
        category_map = {
            "file": SyscallCategory.FILE,
            "network": SyscallCategory.NETWORK,
            "process": SyscallCategory.PROCESS,
            "memory": SyscallCategory.MEMORY,
            "signal": SyscallCategory.SIGNAL,
            "ipc": SyscallCategory.IPC,
            "thread": SyscallCategory.THREAD,
            "time": SyscallCategory.TIME,
            "sysinfo": SyscallCategory.SYSINFO,
            "security": SyscallCategory.SECURITY,
            "debug": SyscallCategory.DEBUG,
            "misc": SyscallCategory.MISC,
        }

        if value in category_map:
            self.filter_category = category_map[value]
        else:
            # It's a comma-separated list of syscalls
            self.filtered_syscalls = set(value.split(","))

    def _should_trace_syscall(self, syscall_name: str) -> bool:
        """Check if a syscall should be traced based on filters.

        Args:
            syscall_name: Name of the syscall

        Returns:
            True if the syscall should be traced
        """
        if self.filter_category is not None:
            return self.registry.get_category(syscall_name) == self.filter_category
        if self.filtered_syscalls is not None:
            return syscall_name in self.filtered_syscalls

        # No filter - trace everything
        return True

    def _open_output(self) -> TextIO:
        """Open the output file or return stderr.

        Returns:
            File handle to write output to
        """
        handle = self.output_file.open("w") if self.output_file is not None else sys.stderr

        # Now that we have the output handle, create the appropriate formatter
        # Use colors if: not JSON mode, and output is a TTY
        use_colors = not self.json_output and handle.isatty()

        if self.json_output:
            self.formatter = JSONFormatter()
        else:
            self.formatter = ColorTextFormatter() if use_colors else TextFormatter()

        return handle

    def _write_event(self, event: SyscallEvent) -> None:
        """Write a syscall event to output.

        Args:
            event: The syscall event to write
        """
        # Always add to summary
        self.summary_formatter.add_event(event)

        # Skip writing individual events if summary-only mode
        if self.summary_only:
            return

        # Format and write (print is line-buffered by default)
        line = self.formatter.format(event)
        print(line, file=self.output_handle)

        # Ensure data is visible immediately for readers like tests
        if self.output_handle and self.output_file is not None:
            self.output_handle.flush()

    def spawn(self, command: list[str]) -> int:
        """Spawn a new process and trace its syscalls.

        Args:
            command: Command and arguments to execute

        Returns:
            Exit code of the traced process
        """
        if not command:
            msg = "Command cannot be empty"
            raise ValueError(msg)

        # Resolve binary path and check if it's SIP-protected
        binary_path = resolve_binary_path(command[0])
        if binary_path is None:
            msg = f"Binary not found: {command[0]}"
            raise FileNotFoundError(msg)

        if is_sip_protected(binary_path):
            raise SIPProtectedError(get_sip_error_message(binary_path))

        # Open output
        self.output_handle = self._open_output()

        try:
            # Create debugger
            debugger = self.lldb.SBDebugger.Create()
            debugger.SetAsync(False)  # noqa: FBT003

            # Create target
            target = debugger.CreateTarget(command[0])
            if not target:
                msg = f"Failed to create target for: {command[0]}"
                raise RuntimeError(msg)

            # Detect architecture
            arch = detect_architecture(target)
            if not arch:
                msg = f"Unsupported architecture: {target.GetTriple()}"
                raise RuntimeError(msg)
            self.arch = arch

            # Set breakpoints for syscalls
            self._set_syscall_breakpoints(target)

            # Launch process
            launch_info = self.lldb.SBLaunchInfo(command[1:] if len(command) > 1 else [])
            launch_info.SetWorkingDirectory(str(Path.cwd()))

            error = self.lldb.SBError()
            process = target.Launch(launch_info, error)

            if not process or not process.IsValid():
                msg = f"Failed to launch process: {error}"
                raise RuntimeError(msg)

            # Trace syscalls
            exit_code = self._trace_loop(process)

            # Write summary if needed
            if self.summary_only:
                summary = self.summary_formatter.format()
                print(summary, end="", file=self.output_handle)

            return exit_code

        finally:
            if self.output_handle and self.output_file is not None:
                self.output_handle.close()

    def _setup_debugger_and_attach(
        self, pid: int
    ) -> tuple[lldb.SBDebugger, lldb.SBTarget, lldb.SBProcess] | None:
        """Set up debugger and attach to process.

        Args:
            pid: Process ID to attach to

        Returns:
            Tuple of (debugger, target, process) or None on failure
        """
        debugger = self.lldb.SBDebugger.Create()
        debugger.SetAsync(False)  # noqa: FBT003

        target = debugger.CreateTarget("")
        if not target:
            return None

        error = self.lldb.SBError()
        process = target.AttachToProcessWithID(debugger.GetListener(), pid, error)

        if not process or not process.IsValid():
            return None

        arch = detect_architecture(target)
        if not arch:
            return None
        self.arch = arch

        return debugger, target, process

    def _setup_signal_handler(self) -> Any:
        """Set up signal handler for Ctrl+C.

        Returns:
            Old signal handler or None
        """

        def signal_handler(_signum: int, _frame: Any) -> None:
            self.interrupted = True

        with contextlib.suppress(ValueError):
            # Try to set signal handler (only works in main thread)
            return signal.signal(signal.SIGINT, signal_handler)
        return None

    def attach(self, pid: int) -> int:
        """Attach to an existing process and trace its syscalls.

        Args:
            pid: Process ID to attach to

        Returns:
            Exit code (0 for success, non-zero for error)
        """
        if pid <= 0:
            return 1

        self.output_handle = self._open_output()

        try:
            result = self._setup_debugger_and_attach(pid)
            if not result:
                return 1

            _debugger, target, process = result
            self._set_syscall_breakpoints(target)

            old_handler = self._setup_signal_handler()

            try:
                process.Continue()
                exit_code = self._trace_loop(process)
                process.Detach()
            finally:
                if old_handler is not None:
                    with contextlib.suppress(ValueError):
                        signal.signal(signal.SIGINT, old_handler)

            if self.summary_only:
                summary = self.summary_formatter.format()
                print(summary, end="", file=self.output_handle)

            return exit_code  # noqa: TRY300

        except Exception:  # noqa: BLE001
            return 1

        finally:
            if self.output_handle and self.output_file is not None:
                self.output_handle.close()

    def _set_syscall_breakpoints(self, target: lldb.SBTarget) -> None:
        """Set breakpoints on syscall entry points.

        Args:
            target: LLDB target
        """
        # Set breakpoints on all syscalls registered in the registry
        # We use plain function names (no underscores) which are the libc wrappers
        # that all programs call, regardless of compilation flags
        for syscall_def in self.registry.get_all_syscalls():
            target.BreakpointCreateByName(syscall_def.name)

    def _trace_loop(self, process: lldb.SBProcess) -> int:
        """Main tracing loop.

        Args:
            process: LLDB process

        Returns:
            Exit code of the process
        """
        while True:
            # Check if interrupted by signal
            if self.interrupted:
                return 0

            # Check process state
            state = process.GetState()

            if state == self.lldb.eStateExited:
                return process.GetExitStatus()  # type: ignore[no-any-return]
            if state == self.lldb.eStateStopped:
                # Handle breakpoint
                self._handle_stop(process)

                # Continue execution (unless interrupted)
                if not self.interrupted:
                    process.Continue()
            elif state in (
                self.lldb.eStateCrashed,
                self.lldb.eStateDetached,
                self.lldb.eStateUnloaded,
            ):
                return 1
            else:
                # Wait for state change
                time.sleep(0.01)

    def _handle_stop(self, process: lldb.SBProcess) -> None:
        """Handle a process stop (breakpoint hit).

        Args:
            process: LLDB process
        """
        thread = process.GetSelectedThread()
        if not thread:
            return

        frame = thread.GetSelectedFrame()
        if not frame:
            return

        # Get function name and PC to determine what kind of breakpoint this is
        function_name = frame.GetFunctionName()
        pc = frame.GetPC()
        thread_id = thread.GetThreadID()

        # Check if this is a return address breakpoint
        return_key = (thread_id, pc)
        if return_key in self.pending_syscalls:
            # This is a syscall return - capture return value
            self._handle_syscall_return(frame, thread_id, pc)
            return

        if not function_name:
            return

        # Strip leading underscores to get syscall name
        syscall_name = function_name.lstrip("_")

        # Check if this is a syscall we know about
        syscall_def = self.registry.lookup_by_name(syscall_name)
        if not syscall_def:
            return

        # Check if we should trace this syscall
        if not self._should_trace_syscall(syscall_name):
            return

        # This is a syscall entry - capture arguments and set return breakpoint
        self._handle_syscall_entry(frame, thread, process, syscall_name)

    def _handle_syscall_entry(
        self,
        frame: lldb.SBFrame,
        thread: lldb.SBThread,
        process: lldb.SBProcess,
        syscall_name: str,
    ) -> None:
        """Handle syscall entry - capture arguments and set return breakpoint.

        Args:
            frame: LLDB stack frame
            thread: LLDB thread
            process: LLDB process
            syscall_name: Name of the syscall
        """
        # Extract arguments (both decoded and raw values)
        args, raw_args = self._extract_args(frame, syscall_name)

        # Get return address using architecture-specific method
        return_address = self.arch.get_return_address(frame, process, self.lldb)
        if return_address is None:
            # Can't get return address, emit event without return value
            event = SyscallEvent(
                pid=process.GetProcessID(),
                syscall_name=syscall_name,
                args=args,
                return_value="?",
                timestamp=time.time(),
                raw_args=raw_args,
            )
            self._write_event(event)
            return

        # Create pending event with raw_args saved for exit-time decoding
        event = SyscallEvent(
            pid=process.GetProcessID(),
            syscall_name=syscall_name,
            args=args,
            return_value="?",
            timestamp=time.time(),
            raw_args=raw_args,
        )

        # Set one-shot breakpoint at return address
        target = process.GetTarget()
        bp = target.BreakpointCreateByAddress(return_address)
        bp.SetOneShot(True)  # Automatically deleted after first hit  # noqa: FBT003

        # Store pending event
        thread_id = thread.GetThreadID()
        self.pending_syscalls[(thread_id, return_address)] = event

    def _handle_syscall_return(
        self, frame: lldb.SBFrame, thread_id: int, return_address: int
    ) -> None:
        """Handle syscall return - capture return value and emit event.

        Args:
            frame: LLDB stack frame
            thread_id: Thread ID
            return_address: Return address PC
        """
        # Get the pending event
        return_key = (thread_id, return_address)
        event = self.pending_syscalls.pop(return_key, None)
        if not event:
            return

        # Extract return value from return register
        ret_reg = frame.FindRegister(self.arch.return_register)
        if ret_reg and ret_reg.IsValid():
            ret_value = ret_reg.GetValueAsUnsigned()
            # Convert to signed if negative (syscalls return -errno on error)
            if ret_value >= 0x8000000000000000:  # Sign bit set
                signed_ret = int(ret_value) - 0x10000000000000000
            else:
                signed_ret = int(ret_value)

            # Apply errno decoding if enabled and return is an error
            if not self.no_abbrev and signed_ret < 0:
                event.return_value = decode_errno(signed_ret)
            else:
                event.return_value = signed_ret
        else:
            event.return_value = "?"

        # Decode output parameters if syscall succeeded
        # Only decode output params if return value indicates success (>= 0)
        if isinstance(event.return_value, int) and event.return_value >= 0:
            syscall_def = self.registry.lookup_by_name(event.syscall_name)
            if syscall_def:
                self._decode_params_at_exit(frame, event, syscall_def.params)

        # Write the complete event
        self._write_event(event)

    def _extract_args(
        self, frame: lldb.SBFrame, syscall_name: str
    ) -> tuple[list[SyscallArg], list[int]]:
        """Extract syscall arguments from the stack frame.

        Returns:
            Tuple of (decoded_args, raw_values)
        """
        syscall_def = self.registry.lookup_by_name(syscall_name)
        if not syscall_def:
            return [], []

        thread = frame.GetThread()
        process = thread.GetProcess()
        arg_regs = self.arch.arg_registers

        # Use unified params system
        return self._extract_args_with_params(frame, process, syscall_def.params, arg_regs)

    def _extract_args_with_params(
        self,
        frame: lldb.SBFrame,
        process: lldb.SBProcess,
        params: list[Param],
        arg_regs: list[str],
    ) -> tuple[list[SyscallArg], list[int]]:
        """Extract args using the new unified Param system.

        Returns:
            Tuple of (decoded_args, raw_values) where raw_values are saved for exit-time decoding
        """
        # First, read all raw register values
        raw_values: list[int] = []
        for i in range(len(params)):
            if i >= len(arg_regs):
                raw_values.append(0)
                continue

            reg = frame.FindRegister(arg_regs[i])
            if not reg or not reg.IsValid():
                raw_values.append(0)
            else:
                raw_values.append(reg.GetValueAsUnsigned())

        # Now decode each argument using its Param
        args: list[SyscallArg] = []
        for i, param in enumerate(params):
            if i >= len(raw_values):
                args.append(UnknownArg())
                continue

            decoded = param.decode(
                tracer=self,
                process=process,
                raw_value=raw_values[i],
                all_args=raw_values,
                at_entry=True,
            )
            if decoded is not None:
                args.append(decoded)
            else:
                args.append(UnknownArg())

        return args, raw_values

    def _decode_params_at_exit(
        self, frame: lldb.SBFrame, event: SyscallEvent, params: list[Param]
    ) -> None:
        """Re-decode parameters at syscall exit (for OUT params).

        Uses raw_args saved at entry time, since argument registers are
        clobbered at exit time.
        """
        thread = frame.GetThread()
        process = thread.GetProcess()

        # Use saved raw values from entry time (NOT re-reading registers!)
        raw_values = event.raw_args

        # Re-decode parameters that need exit-time decoding
        for i, param in enumerate(params):
            if i >= len(event.args):
                continue
            if i >= len(raw_values):
                continue

            decoded = param.decode(
                tracer=self,
                process=process,
                raw_value=raw_values[i],
                all_args=raw_values,
                at_entry=False,
            )
            # Only update if decode returned something (not None)
            if decoded is not None:
                event.args[i] = decoded

    def _read_string(self, process: lldb.SBProcess, address: int, max_length: int = 4096) -> str:
        """Read a null-terminated string from process memory.

        Args:
            process: LLDB process
            address: Memory address to read from
            max_length: Maximum string length to read

        Returns:
            The string read from memory, or "?" if unable to read
        """
        if address == 0:
            return "NULL"

        # Read in small chunks to avoid crossing page boundaries
        # Page size on macOS is typically 16KB (0x4000)
        chunk_size = 256
        result_bytes = bytearray()
        current_address = address
        bytes_read = 0

        error = self.lldb.SBError()

        while bytes_read < max_length:
            # Read a chunk
            chunk = process.ReadMemory(
                current_address, min(chunk_size, max_length - bytes_read), error
            )

            if error.Fail():
                # If we haven't read anything yet, this is an error
                if bytes_read == 0:
                    return f"0x{address:x}"
                # Otherwise, just stop here
                break

            # Look for null terminator in this chunk
            try:
                null_pos = chunk.index(b"\x00")
                result_bytes.extend(chunk[:null_pos])
                break  # Found end of string
            except ValueError:
                # No null in this chunk, add it all and continue
                result_bytes.extend(chunk)
                bytes_read += len(chunk)
                current_address += len(chunk)

        # Decode the string, escaping invalid UTF-8 bytes
        if not result_bytes:
            return f"0x{address:x}"

        # Use backslashreplace to show \xNN for invalid bytes
        return result_bytes.decode("utf-8", errors="backslashreplace")
