"""Helper utilities for syscall test assertions.

This module provides reusable utilities to reduce code duplication across
syscall test files.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

# Add fixtures directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))
import helpers  # type: ignore[import-not-found]
from compile import get_test_executable  # type: ignore[import-not-found]


def run_strace_for_mode(
    mode: str,
    test_file: Path,
    additional_args: list[str] | None = None,
) -> tuple[int, list[dict[str, Any]]]:
    """Run strace with given mode and return exit code and syscalls.

    Args:
        mode: Test mode to pass to test executable (e.g., "--fd-ops", "--network")
        test_file: Path to this test file (use Path(__file__))
        additional_args: Additional args to pass to strace (e.g., ["-e", "trace=open"])

    Returns:
        Tuple of (exit_code, list of syscall dicts from JSON output)
    """
    test_executable = get_test_executable()
    python_path = "/usr/bin/python3"
    strace_module = str(test_file.parent.parent)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        output_file = Path(f.name)

    try:
        cmd = [
            python_path,
            "-m",
            "strace_macos",
            "--json",
            "-o",
            str(output_file),
        ]
        if additional_args:
            cmd.extend(additional_args)
        cmd.extend([str(test_executable), mode])

        result = subprocess.run(
            cmd,
            check=False,
            cwd=strace_module,
            capture_output=True,
            text=True,
        )

        exit_code = result.returncode
        syscalls = helpers.json_lines(output_file) if output_file.exists() else []
    finally:
        if output_file.exists():
            output_file.unlink()

    return exit_code, syscalls


def filter_syscalls(syscalls: list[dict[str, Any]], name: str) -> list[dict[str, Any]]:
    """Return all syscalls matching the given name.

    Args:
        syscalls: List of syscall dicts from JSON output
        name: Syscall name to filter for

    Returns:
        List of matching syscall dicts
    """
    return [sc for sc in syscalls if sc.get("syscall") == name]


def get_syscall_names(syscalls: list[dict[str, Any]]) -> list[str]:
    """Extract syscall names from list of syscall dicts.

    Args:
        syscalls: List of syscall dicts from JSON output

    Returns:
        List of syscall names
    """
    return [sc.get("syscall") for sc in syscalls]  # type: ignore[misc]


def assert_syscall_coverage(
    syscalls: list[dict[str, Any]],
    expected: set[str],
    min_count: int,
    category: str = "syscalls",
) -> None:
    """Assert minimum coverage of expected syscalls.

    Args:
        syscalls: List of syscall dicts from JSON output
        expected: Set of expected syscall names
        min_count: Minimum number of expected syscalls that must be captured
        category: Description of syscall category for error message

    Raises:
        AssertionError: If fewer than min_count expected syscalls are captured
    """
    syscall_names = get_syscall_names(syscalls)
    captured = expected & set(syscall_names)
    missing = expected - set(syscall_names)

    assert len(captured) >= min_count, (
        f"Should capture at least {min_count} {category}, got {len(captured)}.\n"
        f"Captured: {sorted(captured)}\n"
        f"Missing: {sorted(missing)}"
    )


def assert_min_call_count(
    calls: list[dict[str, Any]],
    min_count: int,
    syscall_name: str,
) -> None:
    """Assert minimum number of syscall occurrences.

    Args:
        calls: List of syscall dicts (pre-filtered for specific syscall)
        min_count: Minimum expected number of calls
        syscall_name: Name of syscall for error message

    Raises:
        AssertionError: If fewer than min_count calls are present
    """
    assert len(calls) >= min_count, (
        f"Should have at least {min_count} {syscall_name} calls, got {len(calls)}"
    )


def assert_arg_count(
    call: dict[str, Any],
    expected: int,
    syscall_name: str,
) -> None:
    """Assert syscall has expected number of arguments.

    Args:
        call: Single syscall dict
        expected: Expected number of arguments
        syscall_name: Name of syscall for error message

    Raises:
        AssertionError: If argument count doesn't match
    """
    actual = len(call["args"])
    assert actual == expected, f"{syscall_name} should have {expected} args, got {actual}"


def assert_arg_type(
    call: dict[str, Any],
    arg_index: int,
    expected_type: type,
    arg_name: str,
) -> None:
    """Assert argument has expected type.

    Args:
        call: Single syscall dict
        arg_index: Index of argument to check
        expected_type: Expected type (e.g., str, int, dict, list)
        arg_name: Name of argument for error message

    Raises:
        AssertionError: If argument type doesn't match
    """
    arg = call["args"][arg_index]
    assert isinstance(arg, expected_type), (
        f"{arg_name} should be {expected_type.__name__}, got {type(arg).__name__}"
    )


def assert_symbolic_value(
    call: dict[str, Any],
    arg_index: int,
    expected_symbols: str | list[str],
    arg_name: str,
) -> None:
    """Assert argument contains expected symbolic constant(s).

    Args:
        call: Single syscall dict
        arg_index: Index of argument to check
        expected_symbols: Single symbol or list of symbols that should be present
        arg_name: Name of argument for error message

    Raises:
        AssertionError: If expected symbol(s) not found in argument
    """
    arg_str = str(call["args"][arg_index])
    symbols = [expected_symbols] if isinstance(expected_symbols, str) else expected_symbols

    for symbol in symbols:
        assert symbol in arg_str, (
            f"{arg_name} should decode {symbol}, got {call['args'][arg_index]}"
        )


def assert_flag_present(
    calls: list[dict[str, Any]],
    arg_index: int,
    expected_flag: str,
    syscall_name: str,
) -> None:
    """Assert that at least one call contains the expected flag.

    Args:
        calls: List of syscall dicts (pre-filtered for specific syscall)
        arg_index: Index of flags argument
        expected_flag: Flag name to look for
        syscall_name: Name of syscall for error message

    Raises:
        AssertionError: If no calls contain the expected flag
    """
    flags_seen = set()
    for call in calls:
        flag_arg = call["args"][arg_index]
        if isinstance(flag_arg, str):
            flags_seen.add(flag_arg)
        elif isinstance(flag_arg, int):
            flags_seen.add(str(flag_arg))

    assert any(expected_flag in f for f in flags_seen), (
        f"{syscall_name} should have {expected_flag} flag, got flags: {flags_seen}"
    )


def collect_flags_from_calls(
    calls: list[dict[str, Any]],
    arg_index: int,
) -> set[str]:
    """Collect all unique flag values from calls.

    Args:
        calls: List of syscall dicts (pre-filtered for specific syscall)
        arg_index: Index of flags argument

    Returns:
        Set of unique flag values as strings
    """
    flags_seen = set()
    for call in calls:
        if len(call["args"]) > arg_index:
            flag_arg = call["args"][arg_index]
            if isinstance(flag_arg, str):
                flags_seen.add(flag_arg)
            elif isinstance(flag_arg, int):
                flags_seen.add(str(flag_arg))
    return flags_seen


def assert_struct_field(
    call: dict[str, Any],
    arg_index: int,
    field_name: str,
    syscall_name: str,
) -> dict[str, Any]:
    """Assert argument is a struct with expected field, return output dict.

    Args:
        call: Single syscall dict
        arg_index: Index of struct argument
        field_name: Name of field that should be present in struct
        syscall_name: Name of syscall for error message

    Returns:
        The struct's output dictionary

    Raises:
        AssertionError: If argument is not a struct or doesn't have expected field
    """
    arg = call["args"][arg_index]
    assert isinstance(arg, dict), (
        f"{syscall_name} arg[{arg_index}] should be decoded struct, got {type(arg)}"
    )
    assert "output" in arg, f"{syscall_name} should have 'output' key, got {arg}"
    fields: dict[str, Any] = arg["output"]
    assert field_name in fields, f"{syscall_name} should show {field_name} field, got {fields}"
    return fields


def assert_iovec_structure(
    call: dict[str, Any],
    arg_index: int,
    syscall_name: str,
    min_count: int = 1,
) -> list[dict[str, Any]]:
    """Assert argument is properly decoded iovec array, return iovecs.

    Args:
        call: Single syscall dict
        arg_index: Index of iovec argument
        syscall_name: Name of syscall for error message
        min_count: Minimum number of iovec elements expected

    Returns:
        List of iovec dicts

    Raises:
        AssertionError: If argument is not a properly structured iovec array
    """
    iov_arg = call["args"][arg_index]
    assert isinstance(iov_arg, list), (
        f"{syscall_name} iovec should be decoded as list, got {type(iov_arg)}"
    )
    assert len(iov_arg) >= min_count, (
        f"{syscall_name} should have at least {min_count} iovec elements, got {len(iov_arg)}"
    )

    # Verify first iovec has correct structure
    if iov_arg:
        iov = iov_arg[0]
        assert isinstance(iov, dict), (
            f"{syscall_name} iovec element should be a dict, got {type(iov)}"
        )
        assert "iov_base" in iov, f"{syscall_name} iovec should have iov_base, got {iov}"
        assert "iov_len" in iov, f"{syscall_name} iovec should have iov_len, got {iov}"

    return iov_arg


def assert_octal_mode(
    call: dict[str, Any],
    arg_index: int,
    syscall_name: str,
) -> None:
    """Assert argument is an octal mode string.

    Args:
        call: Single syscall dict
        arg_index: Index of mode argument
        syscall_name: Name of syscall for error message

    Raises:
        AssertionError: If argument is not an octal mode string
    """
    mode_arg = call["args"][arg_index]
    assert isinstance(mode_arg, str), f"{syscall_name} mode should be string, got {type(mode_arg)}"
    assert mode_arg.startswith("0"), f"{syscall_name} mode should be octal (0xxx), got {mode_arg}"


def assert_at_fdcwd(
    call: dict[str, Any],
    arg_index: int,
    syscall_name: str,
) -> None:
    """Assert argument is AT_FDCWD constant.

    Args:
        call: Single syscall dict
        arg_index: Index of dirfd argument
        syscall_name: Name of syscall for error message

    Raises:
        AssertionError: If argument is not AT_FDCWD
    """
    dirfd = call["args"][arg_index]
    assert "AT_FDCWD" in str(dirfd) or dirfd == -2, (
        f"{syscall_name} should use AT_FDCWD, got {dirfd}"
    )
