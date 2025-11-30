"""Core syscall tracer using LLDB."""

from __future__ import annotations

import contextlib
import signal
import sys
import time
from dataclasses import dataclass, field
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
from strace_macos.syscalls.definitions import DecodeContext
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

# Syscalls that create child processes
FORK_SYSCALLS = {"fork", "vfork", "posix_spawn", "posix_spawnp"}


@dataclass
class Tracer:
    """System call tracer using LLDB."""

    # Configuration options
    output_file: Path | None = None
    json_output: bool = False
    summary_only: bool = False
    filter_expr: str | None = None
    no_abbrev: bool = False
    follow_forks: bool = False

    # Runtime state (initialized in __post_init__)
    lldb: Any = field(init=False)
    registry: SyscallRegistry = field(init=False)
    filtered_syscalls: set[str] | None = field(init=False)
    filter_category: SyscallCategory | None = field(init=False)
    summary_formatter: SummaryFormatter = field(init=False)
    output_handle: TextIO | None = field(init=False)
    formatter: JSONFormatter | TextFormatter | ColorTextFormatter = field(init=False)
    arch: Architecture = field(init=False)
    pending_syscalls: dict[tuple[int, int], SyscallEvent] = field(init=False)
    interrupted: bool = field(init=False)
    decode_ctx: DecodeContext | None = field(init=False, default=None)

    # Syscall parameter caches (for cross-parameter context sharing)
    sysctl_mib_cache: dict[int, list[int]] = field(init=False, default_factory=dict)
    sysctlbyname_cache: dict[int, str] = field(init=False, default_factory=dict)

    # Multi-process state for follow_forks
    child_pids_to_attach: list[int] = field(init=False, default_factory=list)
    traced_processes: dict[int, Any] = field(init=False, default_factory=dict)
    debugger: Any = field(init=False, default=None)

    def __post_init__(self) -> None:
        """Initialize runtime state after dataclass field assignment."""
        # Load LLDB
        self.lldb = load_lldb_module()

        # Create syscall registry
        self.registry = SyscallRegistry()

        # Parse filter expression
        self.filtered_syscalls = None
        self.filter_category = None
        if self.filter_expr:
            self._parse_filter(self.filter_expr)

        # Setup formatters
        self.summary_formatter = SummaryFormatter()
        self.output_handle = None

        # Track pending syscalls (entry without exit yet)
        # Key: (thread_id, return_address), Value: SyscallEvent with partial data
        self.pending_syscalls = {}

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

    def _setup_fork_interpose_env(self, launch_info: lldb.SBLaunchInfo) -> None:
        """Set up environment variables for fork interposition.

        Args:
            launch_info: LLDB launch info to configure
        """
        import os

        from strace_macos.interpose import get_child_stop_env

        # Get the interpose library environment
        interpose_env = get_child_stop_env()

        # Build environment with interpose vars added
        env_list = []
        for key, value in os.environ.items():
            env_list.append(f"{key}={value}")

        # Add/override interpose environment variables
        for key, value in interpose_env.items():
            env_list.append(f"{key}={value}")

        launch_info.SetEnvironmentEntries(env_list, True)  # noqa: FBT003

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

            # Store debugger for child attachment
            self.debugger = debugger

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

            # Set up environment for fork interposition if following forks
            if self.follow_forks:
                self._setup_fork_interpose_env(launch_info)

            error = self.lldb.SBError()
            process = target.Launch(launch_info, error)

            if not process or not process.IsValid():
                msg = f"Failed to launch process: {error}"
                raise RuntimeError(msg)

            # Create reusable decode context (avoids allocations in hot path)
            self.decode_ctx = DecodeContext(tracer=self, process=process)

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

            # Create reusable decode context (avoids allocations in hot path)
            self.decode_ctx = DecodeContext(tracer=self, process=process)

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

    def _attach_to_child(self, child_pid: int) -> lldb.SBProcess | None:
        """Attach to a child process.

        Args:
            child_pid: PID of the child process to attach to

        Returns:
            LLDB process for the child, or None on failure
        """
        if not self.debugger:
            return None

        # Create a new target for the child
        target = self.debugger.CreateTarget("")
        if not target:
            return None

        # Attach to the child
        error = self.lldb.SBError()
        child_process = target.AttachToProcessWithID(
            self.debugger.GetListener(), child_pid, error
        )

        if not child_process or not child_process.IsValid():
            return None

        # Set syscall breakpoints on the child
        self._set_syscall_breakpoints(target)

        # Store the process
        self.traced_processes[child_pid] = child_process

        return child_process

    def _trace_loop(self, process: lldb.SBProcess) -> int:
        """Main tracing loop.

        Args:
            process: LLDB process

        Returns:
            Exit code of the process
        """
        # Track the main process
        main_pid = process.GetProcessID()
        self.traced_processes[main_pid] = process

        while True:
            # Check if interrupted by signal
            if self.interrupted:
                return 0

            # Attach to any queued child processes
            if self.follow_forks:
                while self.child_pids_to_attach:
                    child_pid = self.child_pids_to_attach.pop(0)
                    child_process = self._attach_to_child(child_pid)
                    if child_process:
                        # Continue the child (it's stopped via SIGSTOP from interpose)
                        child_process.Continue()

            # Check all traced processes
            all_exited = True
            main_exit_code = 0

            for pid, proc in list(self.traced_processes.items()):
                state = proc.GetState()

                if state == self.lldb.eStateExited:
                    if pid == main_pid:
                        main_exit_code = proc.GetExitStatus()
                    # Remove exited process
                    del self.traced_processes[pid]
                    continue

                all_exited = False

                if state == self.lldb.eStateStopped:
                    # Handle breakpoint
                    self._handle_stop(proc)

                    # Continue execution (unless interrupted)
                    if not self.interrupted:
                        proc.Continue()
                elif state in (
                    self.lldb.eStateCrashed,
                    self.lldb.eStateDetached,
                    self.lldb.eStateUnloaded,
                ):
                    # Remove failed process
                    del self.traced_processes[pid]

            if all_exited or not self.traced_processes:
                return main_exit_code

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

        # Avoid duplicate tracing when wrapper branches to __implementation
        # Example: "kill" wrapper branches to "__kill" - only trace the wrapper
        # Check if we've already started tracing this syscall from a wrapper
        if function_name.startswith("__") and not syscall_def.name.startswith("__"):
            # We're at __foo but breakpoint name is foo
            # Check if we already have a pending syscall for this thread
            # If yes, this is a duplicate (wrapper already traced)
            # If no, this is the only symbol (no wrapper exists), so trace it
            thread_has_pending = any(key[0] == thread_id for key in self.pending_syscalls)
            if thread_has_pending:
                # Already tracing a syscall in this thread - this is a duplicate
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
        # Ensure decode context uses the current process (for multi-process)
        if self.decode_ctx is None:
            self.decode_ctx = DecodeContext(tracer=self, process=process)
        else:
            self.decode_ctx.process = process

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

            # Check if syscall has a custom return decoder
            syscall_def = self.registry.lookup_by_name(event.syscall_name)
            if syscall_def and syscall_def.return_decoder and signed_ret >= 0:
                # Use custom return decoder
                event.return_value = syscall_def.return_decoder(
                    signed_ret, event.raw_args, no_abbrev=self.no_abbrev
                )
            elif not self.no_abbrev and signed_ret < 0:
                # Apply errno decoding if enabled and return is an error
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
                self._decode_params_at_exit(event, syscall_def.params)

            # Queue child PID for attachment if following forks
            if self.follow_forks and event.syscall_name in FORK_SYSCALLS:
                child_pid = event.return_value
                # For posix_spawn, the child PID is in the first argument (output param)
                if event.syscall_name in ("posix_spawn", "posix_spawnp"):
                    # First arg is pid_t* - already decoded at exit
                    if event.args and isinstance(event.args[0], int):
                        child_pid = event.args[0]
                if child_pid > 0:
                    self.child_pids_to_attach.append(child_pid)

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
        return self._extract_args_with_params(
            frame, process, syscall_def.params, arg_regs, syscall_def.variadic_start
        )

    def _read_raw_arg_value(
        self,
        frame: lldb.SBFrame,
        process: lldb.SBProcess,
        arg_index: int,
        arg_regs: list[str],
        variadic_start: int | None,
    ) -> int:
        """Read a single raw argument value from register or stack.

        Returns the raw integer value of the argument at the given index.
        """
        # Check if this is a variadic argument
        if variadic_start is not None and arg_index >= variadic_start:
            variadic_index = arg_index - variadic_start
            value = self.arch.read_variadic_arg(frame, process, self.lldb, variadic_index)
            return 0 if value is None else value

        # Check if we've run out of registers
        if arg_index >= len(arg_regs):
            return 0

        # Read from register (normal case)
        reg = frame.FindRegister(arg_regs[arg_index])
        if not reg or not reg.IsValid():
            return 0
        return int(reg.GetValueAsUnsigned())

    def _decode_param_with_context(self, param: Param, raw_value: int) -> SyscallArg:
        """Decode a single parameter using the decode context.

        Returns the decoded SyscallArg or UnknownArg if decoding fails.
        """
        if not self.decode_ctx:
            return UnknownArg()

        self.decode_ctx.raw_value = raw_value
        decoded = param.decode(self.decode_ctx)
        return decoded if decoded is not None else UnknownArg()

    def _extract_args_with_params(
        self,
        frame: lldb.SBFrame,
        process: lldb.SBProcess,
        params: list[Param],
        arg_regs: list[str],
        variadic_start: int | None = None,
    ) -> tuple[list[SyscallArg], list[int]]:
        """Extract args using the new unified Param system.

        Args:
            frame: LLDB stack frame
            process: LLDB process
            params: List of Param decoders
            arg_regs: List of argument register names
            variadic_start: Index where variadic args start (passed on stack on ARM64)

        Returns:
            Tuple of (decoded_args, raw_values) where raw_values are saved for exit-time decoding
        """
        # First, read all raw register/stack values
        raw_values = [
            self._read_raw_arg_value(frame, process, i, arg_regs, variadic_start)
            for i in range(len(params))
        ]

        # Update context with per-syscall data (shared across all arguments)
        if self.decode_ctx:
            self.decode_ctx.all_args = raw_values
            self.decode_ctx.at_entry = True
            self.decode_ctx.return_value = None

        # Now decode each argument using its Param
        args = [
            self._decode_param_with_context(param, raw_values[i])
            if i < len(raw_values)
            else UnknownArg()
            for i, param in enumerate(params)
        ]

        return args, raw_values

    def _decode_params_at_exit(self, event: SyscallEvent, params: list[Param]) -> None:
        """Re-decode parameters at syscall exit (for OUT params).

        Uses raw_args saved at entry time, since argument registers are
        clobbered at exit time.
        """
        # Use saved raw values from entry time (NOT re-reading registers!)
        raw_values = event.raw_args

        # Update context with per-syscall data (shared across all arguments)
        if self.decode_ctx:
            self.decode_ctx.all_args = raw_values
            self.decode_ctx.at_entry = False
            self.decode_ctx.return_value = event.return_value

        # Re-decode parameters that need exit-time decoding
        for i, param in enumerate(params):
            if i >= len(event.args):
                continue
            if i >= len(raw_values):
                continue

            # Update per-argument field in context and decode
            if self.decode_ctx:
                self.decode_ctx.raw_value = raw_values[i]
                decoded = param.decode(self.decode_ctx)
            else:
                decoded = None

            # Only update if decode returned something (not None)
            if decoded is not None:
                event.args[i] = decoded
