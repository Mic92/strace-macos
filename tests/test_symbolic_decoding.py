"""Integration tests for symbolic decoding of syscall arguments and return values."""

from __future__ import annotations

import re

from strace_macos.__main__ import main
from tests.base import StraceTestCase
from tests.fixtures import helpers


class TestSymbolicDecoding(StraceTestCase):
    """Test symbolic decoding of flags, modes, and errno values."""

    def test_open_flags_symbolic_decoding(self) -> None:
        """Test that open() flags are decoded symbolically (e.g., O_WRONLY|O_CREAT|O_TRUNC)."""
        output_file = self.temp_dir / "trace.txt"
        test_file = self.temp_dir / "test.txt"

        # Trace test executable with file operations (default text output)
        exit_code = main(
            [
                "-o",
                str(output_file),
                str(self.test_executable),
                "--file-ops",
                str(test_file),
            ]
        )

        assert exit_code == 0, "strace should exit with code 0"
        content = output_file.read_text()

        # Find open/openat calls using regex pattern
        open_pattern = r"open(?:at)?\([^)]+\)"
        open_calls = re.findall(open_pattern, content)
        assert len(open_calls) > 0, "Should find at least one open/openat call"

        # Check that at least one open call has symbolic flags (not just hex)
        # The test executable opens with O_WRONLY|O_CREAT|O_TRUNC (0x601)
        found_symbolic_flags = False
        for call in open_calls:
            # Look for symbolic flag names (O_WRONLY, O_CREAT, O_TRUNC, etc.)
            if re.search(r"O_\w+", call):
                found_symbolic_flags = True
                # Verify it's not showing raw hex for the common flags
                assert "0x601" not in call, f"Should use symbolic flags, not hex: {call}"
                break

        assert found_symbolic_flags, (
            f"Should find symbolic flags (O_WRONLY, O_CREAT, etc.) in open calls: {open_calls}"
        )

        # Verify variadic argument handling:
        # 1. open() with O_CREAT should have 3 arguments (path, flags, mode)
        # 2. open() without O_CREAT should have 2 arguments (path, flags) - no mode
        found_open_with_creat = False
        found_open_without_creat = False

        for call in open_calls:
            # Count comma-separated arguments
            # Extract arguments from open(arg1, arg2, ...)
            args_match = re.search(r"open(?:at)?\((.+)\)", call)
            if args_match:
                args_str = args_match.group(1)
                # Count arguments by splitting on commas (simple heuristic)
                # This works for our test case since strings don't contain commas
                arg_count = len([a.strip() for a in args_str.split(",") if a.strip()])

                if "O_CREAT" in call:
                    # With O_CREAT, should have mode argument (3 args for open, 4 for openat)
                    found_open_with_creat = True
                    if call.startswith("openat"):
                        assert arg_count == 4, (
                            f"openat with O_CREAT should have 4 args (dirfd, path, flags, mode), "
                            f"got {arg_count}: {call}"
                        )
                    else:
                        assert arg_count == 3, (
                            f"open with O_CREAT should have 3 args (path, flags, mode), "
                            f"got {arg_count}: {call}"
                        )
                elif "O_RDONLY" in call:
                    # Without O_CREAT, should NOT have mode argument (2 args for open, 3 for openat)
                    found_open_without_creat = True
                    if call.startswith("openat"):
                        assert arg_count == 3, (
                            f"openat without O_CREAT should have 3 args (dirfd, path, flags), "
                            f"got {arg_count}: {call}"
                        )
                    else:
                        assert arg_count == 2, (
                            f"open without O_CREAT should have 2 args (path, flags), "
                            f"got {arg_count}: {call}"
                        )

        assert found_open_with_creat, f"Should find open with O_CREAT in test output: {open_calls}"
        assert found_open_without_creat, (
            f"Should find open without O_CREAT (O_RDONLY) in test output: {open_calls}"
        )

    def test_no_abbrev_flag_disables_symbolic_decoding(self) -> None:
        """Test that --no-abbrev flag disables symbolic decoding and shows raw numbers."""
        output_file = self.temp_dir / "trace.txt"
        test_file = self.temp_dir / "test.txt"

        # Trace with --no-abbrev flag
        exit_code = main(
            [
                "--no-abbrev",
                "-o",
                str(output_file),
                str(self.test_executable),
                "--file-ops",
                str(test_file),
            ]
        )

        assert exit_code == 0, "strace should exit with code 0"
        content = output_file.read_text()

        # Find open/openat calls
        open_pattern = r"open(?:at)?\([^)]+\)"
        open_calls = re.findall(open_pattern, content)
        assert len(open_calls) > 0, "Should find at least one open/openat call"

        # Verify that symbolic decoding is disabled - should see hex values, not O_* constants
        found_raw_values = False
        for call in open_calls:
            # Should NOT have symbolic flags when --no-abbrev is used
            if re.search(r"0x[0-9a-fA-F]+", call) and not re.search(r"O_\w+", call):
                found_raw_values = True
                break

        assert found_raw_values, (
            f"With --no-abbrev, should show raw hex values (0x...), not symbolic (O_*): {open_calls}"
        )

    def test_stat_output_decoding(self) -> None:
        """Test that stat/fstat syscalls include decoded output data in JSON."""
        output_file = self.temp_dir / "trace.jsonl"
        test_file = self.temp_dir / "test.txt"

        # Create the test file so stat succeeds
        test_file.write_text("test content")

        # Trace test executable with JSON output
        exit_code = main(
            [
                "--json",
                "-o",
                str(output_file),
                str(self.test_executable),
                "--file-ops",
                str(test_file),
            ]
        )

        assert exit_code == 0, "strace should exit with code 0"
        syscalls = helpers.json_lines(output_file)
        assert len(syscalls) > 0, "Should capture syscalls"

        # Find stat/fstat calls that succeeded (return >= 0)
        stat_calls = [
            sc
            for sc in syscalls
            if sc["syscall"] in ("stat", "fstat", "stat64", "fstat64", "lstat", "lstat64")
            and isinstance(sc["return"], int)
            and sc["return"] >= 0
        ]

        if not stat_calls:
            self.skipTest("No successful stat calls found in output")

        # Check that at least one stat call has decoded st_mode in struct
        found_decoded_output = False
        for sc in stat_calls:
            # stat/fstat have struct stat as second argument (or first for fstat)
            for _i, arg in enumerate(sc["args"]):
                if isinstance(arg, dict) and "st_mode" in arg:
                    st_mode = arg["st_mode"]
                    # Should be decoded like "S_IFREG|0644" not just a number
                    if isinstance(st_mode, str) and ("S_IF" in st_mode or "|0" in st_mode):
                        found_decoded_output = True
                        break
            if found_decoded_output:
                break

        assert found_decoded_output, (
            f"stat syscalls should include decoded st_mode. Found: {stat_calls}"
        )

    def test_errno_return_value_formatting(self) -> None:
        """Test that error returns show errno from TLS.

        On macOS (BSD-style), syscalls return -1 on error and set errno in TLS.
        The tracer should read errno and show the actual error (e.g., ENOENT, EBADF).
        """
        output_file = self.temp_dir / "trace.txt"

        # Trace test executable with errno test mode
        exit_code = main(
            [
                "-o",
                str(output_file),
                str(self.test_executable),
                "--errno-test",
            ]
        )

        assert exit_code == 0, "strace should exit with code 0"
        content = output_file.read_text()

        # Find syscalls that should have failed (return -1)
        # Look for open, read, write, stat, access calls
        failed_syscalls = [line for line in content.split("\n") if " = -1" in line]

        assert len(failed_syscalls) > 0, f"Should find failed syscalls in output:\n{content}"

        # With errno reading enabled by default, should see actual errno names
        found_errno_decoding = False
        errno_names = ["ENOENT", "EBADF", "EINVAL"]

        for line in failed_syscalls:
            for errno_name in errno_names:
                if errno_name in line:
                    found_errno_decoding = True
                    break

        assert found_errno_decoding, (
            f"Should find errno names (ENOENT, EBADF, etc.) in failed syscalls. "
            f"Failed syscalls: {failed_syscalls}"
        )

    def test_errno_return_value_formatting_json(self) -> None:
        """Test that error returns show errno in JSON output."""
        output_file = self.temp_dir / "trace.jsonl"

        # Trace test executable with errno test mode and JSON output
        exit_code = main(
            [
                "--json",
                "-o",
                str(output_file),
                str(self.test_executable),
                "--errno-test",
            ]
        )

        assert exit_code == 0, "strace should exit with code 0"
        syscalls = helpers.json_lines(output_file)
        assert len(syscalls) > 0, "Should capture syscalls"

        # Find syscalls that failed (return starts with -1)
        failed_syscalls = [
            sc
            for sc in syscalls
            if isinstance(sc.get("return"), str) and sc.get("return", "").startswith("-1")
        ]

        # Debug: print all return values for open/read/write/stat/access
        debug_syscalls = [
            (sc.get("syscall"), sc.get("return"))
            for sc in syscalls
            if sc.get("syscall") in ("open", "read", "write", "stat", "access")
        ]

        assert len(failed_syscalls) > 0, (
            f"Should find failed syscalls in JSON output. "
            f"Debug syscalls with returns: {debug_syscalls}"
        )

        # Verify that failed syscalls show errno
        # and that errno is decoded from TLS
        found_errno_decoding = False
        errno_names = ["ENOENT", "EBADF", "EINVAL"]

        for sc in failed_syscalls:
            return_val = sc.get("return")
            if not return_val:
                continue

            # Check for actual errno names
            for errno_name in errno_names:
                if errno_name in return_val:
                    found_errno_decoding = True
                    break

        assert found_errno_decoding, (
            f"Should find errno names (ENOENT, EBADF, etc.) in JSON return values. "
            f"Failed syscalls: {[(sc.get('syscall'), sc.get('return')) for sc in failed_syscalls]}"
        )


if __name__ == "__main__":
    import unittest

    unittest.main()
