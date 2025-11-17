"""Integration tests for color output with PTY."""

from __future__ import annotations

import os
import pty
import select
import subprocess

from tests.base import StraceTestCase


class TestColorOutput(StraceTestCase):
    """Test color output when connected to a TTY."""

    def test_color_output_with_pty(self) -> None:
        """Test that ANSI color codes are present when output is a TTY."""
        # Use a PTY to simulate terminal output
        master_fd, slave_fd = pty.openpty()

        try:
            # Run strace-macos with stderr connected to the PTY slave
            process = subprocess.Popen(
                [
                    "/usr/bin/python3",
                    "-m",
                    "strace_macos",
                    "echo",
                    "hello",
                ],
                stderr=slave_fd,
                stdout=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                env=self.get_test_env(),
            )

            # Close slave in parent process (child has it)
            os.close(slave_fd)

            # Read output from master with timeout
            output_bytes = b""
            timeout = 10  # 10 second timeout

            while True:
                # Use select to wait for data with timeout
                ready, _, _ = select.select([master_fd], [], [], timeout)
                if not ready:
                    # No more data available
                    break

                try:
                    chunk = os.read(master_fd, 4096)
                    if not chunk:
                        break
                    output_bytes += chunk
                except OSError:
                    break

            process.wait(timeout=timeout)
            output = output_bytes.decode("utf-8", errors="replace")

            # Debug: print what we actually got
            if not output:
                self.fail(f"No output captured from PTY. Process exit code: {process.returncode}")

            # Verify ANSI color codes are present
            # Common ANSI escape sequences start with \033[
            assert "\x1b[" in output, (
                f"Output should contain ANSI color codes when connected to TTY. Got: {output[:200]!r}"
            )

            # Check for specific color codes we use
            # Bright cyan for syscall names: \033[1;36m
            assert "\x1b[1;36m" in output, "Should contain bright cyan color for syscall names"

            # Reset code: \033[0m
            assert "\x1b[0m" in output, "Should contain ANSI reset codes"

            # Check that we have syscall output (not just colors)
            # Should contain syscalls like write, close, etc.
            assert "write" in output or "close" in output or "read" in output, (
                f"Should contain actual syscall traces. Got: {output[:500]!r}"
            )

        finally:
            os.close(master_fd)

    def test_no_color_output_without_tty(self) -> None:
        """Test that NO color codes are present when output is not a TTY."""
        # Run with stderr redirected to a pipe (not a TTY)
        result = subprocess.run(
            [
                "/usr/bin/python3",
                "-m",
                "strace_macos",
                "echo",
                "hello",
            ],
            check=False,
            capture_output=True,
            text=True,
            env=self.get_test_env(),
        )

        # Verify NO ANSI color codes are present
        assert "\x1b[" not in result.stderr, (
            "Output should NOT contain ANSI color codes when not connected to TTY"
        )

        # But should still have syscall output
        assert "write(" in result.stderr or "close(" in result.stderr, (
            "Should still contain actual syscall traces"
        )

    def test_color_specific_argument_types(self) -> None:
        """Test that different argument types get different colors."""
        # Use a PTY to capture colored output
        master_fd, slave_fd = pty.openpty()

        try:
            # Run a command that will generate syscalls with different arg types
            # open() has: string (path), int (flags), int (mode)
            # write() has: int (fd), pointer (buf), size_t (count)
            process = subprocess.Popen(
                [
                    "/usr/bin/python3",
                    "-m",
                    "strace_macos",
                    "ls",
                    "/tmp",  # noqa: S108
                ],
                stderr=slave_fd,
                stdout=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                env=self.get_test_env(),
            )

            os.close(slave_fd)

            output_bytes = b""
            while True:
                try:
                    chunk = os.read(master_fd, 4096)
                    if not chunk:
                        break
                    output_bytes += chunk
                except OSError:
                    break

            process.wait()
            output = output_bytes.decode("utf-8", errors="replace")

            # Check for different color codes we use:
            # \033[0;33m - Yellow for strings
            # \033[0;35m - Magenta for numbers
            # \033[0;34m - Blue for pointers
            # \033[0;32m - Green for file descriptors
            # \033[1;36m - Bright cyan for syscall names

            # Should have syscall names (bright cyan)
            assert "\x1b[1;36m" in output, "Should have bright cyan for syscall names"

            # Should have at least one of: strings, numbers, or pointers
            has_typed_args = (
                "\033[0;33m" in output  # Yellow strings
                or "\033[0;35m" in output  # Magenta numbers
                or "\033[0;34m" in output  # Blue pointers
                or "\033[0;32m" in output  # Green FDs
            )
            assert has_typed_args, (
                "Should have color codes for typed arguments (strings/numbers/pointers/fds)"
            )

            # Should have return value colors (green for success or red for errors)
            has_return_colors = (
                "\033[1;32m" in output  # Bright green for success
                or "\033[1;31m" in output  # Bright red for errors
            )
            assert has_return_colors, "Should have color codes for return values"

        finally:
            os.close(master_fd)


if __name__ == "__main__":
    import unittest

    unittest.main()
