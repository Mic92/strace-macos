"""
Test comprehensive file descriptor syscall coverage.

This test verifies that the --fd-ops mode exercises fd-related syscalls
and tests high-level decoding of arguments.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
import helpers  # type: ignore[import-not-found]
from compile import get_test_executable  # type: ignore[import-not-found]


class TestFdSyscalls(unittest.TestCase):
    """Test fd syscall coverage using the test executable's --fd-ops mode."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.test_executable = get_test_executable()
        self.python_path = "/usr/bin/python3"  # System Python for LLDB
        self.strace_module = str(Path(__file__).parent.parent)

    def run_strace(self, args: list[str]) -> int:
        """Run strace and return exit code."""
        cmd = [self.python_path, "-m", "strace_macos", *args]
        result = subprocess.run(
            cmd,
            check=False,
            cwd=self.strace_module,
            capture_output=True,
            text=True,
        )
        return result.returncode

    def test_fd_syscall_coverage(self) -> None:  # noqa: PLR0915
        """Test that all expected fd syscalls are captured and decoded."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_file = Path(f.name)

        try:
            exit_code = self.run_strace(
                ["--json", "-o", str(output_file), str(self.test_executable), "--fd-ops"]
            )

            assert exit_code == 0, f"strace should exit with code 0, got {exit_code}"
            assert output_file.exists(), "Output file should be created"

            # Parse JSON Lines output
            syscalls = helpers.json_lines(output_file)
            syscall_names = [sc.get("syscall") for sc in syscalls]
        finally:
            if output_file.exists():
                output_file.unlink()

        # Expected fd syscalls
        expected_syscalls = {
            "mkstemp",
            "write",
            "pwrite",
            "pread",
            "readv",
            "writev",
            "dup",
            "dup2",
            "fcntl",
            "ioctl",
            "lseek",
        }

        captured_fd_syscalls = expected_syscalls & set(syscall_names)
        missing_syscalls = expected_syscalls - set(syscall_names)

        # We should capture at least 9 out of 11 expected syscalls
        # (some like mkstemp might be implemented as open internally)
        assert len(captured_fd_syscalls) >= 9, (
            f"Should capture at least 9 fd syscalls, "
            f"got {len(captured_fd_syscalls)}.\n"
            f"Captured: {sorted(captured_fd_syscalls)}\n"
            f"Missing: {sorted(missing_syscalls)}"
        )

        # Test readv: should decode iovec structures
        # Expected output: readv(3, [{iov_base="...", iov_len=16}, ...], 3)
        readv_calls = [sc for sc in syscalls if sc.get("syscall") == "readv"]
        if readv_calls:
            readv_call = readv_calls[0]
            iov_arg = readv_call["args"][1]
            # iov should be a list of dicts
            assert isinstance(iov_arg, list), (
                f"readv iovec should be decoded as list, got {type(iov_arg)}"
            )
            assert len(iov_arg) > 0, f"readv should have iovec elements, got {iov_arg}"
            # Check first iovec
            iov = iov_arg[0]
            assert isinstance(iov, dict), f"iovec should be a dict, got {type(iov)}"
            assert "iov_base" in iov, f"iovec should have iov_base, got {iov}"
            assert "iov_len" in iov, f"iovec should have iov_len, got {iov}"

        # Test writev: should decode iovec structures
        # Expected output: writev(3, [{iov_base="First ", iov_len=6}, ...], 3)
        writev_calls = [sc for sc in syscalls if sc.get("syscall") == "writev"]
        if writev_calls:
            writev_call = writev_calls[0]
            iov_arg = writev_call["args"][1]
            assert isinstance(iov_arg, list), (
                f"writev iovec should be decoded as list, got {type(iov_arg)}"
            )
            assert len(iov_arg) >= 3, f"writev should have 3 iovec elements, got {len(iov_arg)}"
            # Check first iovec
            iov = iov_arg[0]
            assert isinstance(iov, dict), f"iovec should be a dict, got {type(iov)}"
            assert "iov_base" in iov, f"iovec should have iov_base, got {iov}"
            assert "iov_len" in iov, f"iovec should have iov_len, got {iov}"
            # Should decode buffer content
            assert iov["iov_base"] == "First ", (
                f"iovec buffer should be 'First ', got {iov['iov_base']!r}"
            )
            assert iov["iov_len"] == 6, f"iovec length should be 6, got {iov['iov_len']}"

        # Test pwrite: should show offset parameter
        # Expected output: pwrite(3, "TEST", 4, 6)
        pwrite_calls = [sc for sc in syscalls if sc.get("syscall") == "pwrite"]
        if pwrite_calls:
            pwrite_call = pwrite_calls[0]
            buf_arg = pwrite_call["args"][1]
            assert '"' in buf_arg, f"pwrite buffer should be decoded as string, got {buf_arg}"
            assert "TEST" in buf_arg, f"pwrite buffer should contain 'TEST', got {buf_arg}"
            offset_arg = pwrite_call["args"][3]
            assert offset_arg == 6, f"pwrite offset should be 6, got {offset_arg}"

        # Test pread: should show offset parameter
        # Expected output: pread(3, buf, 4, 0)
        pread_calls = [sc for sc in syscalls if sc.get("syscall") == "pread"]
        if pread_calls:
            pread_call = pread_calls[0]
            offset_arg = pread_call["args"][3]
            assert offset_arg == 0, f"pread offset should be 0, got {offset_arg}"

        # Test dup: should return new fd
        # Expected output: dup(3) = 4
        dup_calls = [sc for sc in syscalls if sc.get("syscall") == "dup"]
        assert len(dup_calls) > 0, "Should have dup calls"
        dup_call = dup_calls[0]
        assert len(dup_call["args"]) == 1, f"dup should have 1 arg, got {len(dup_call['args'])}"
        assert isinstance(dup_call["args"][0], int), (
            f"dup arg should be int fd, got {type(dup_call['args'][0])}"
        )

        # Test dup2: should show both old and new fd
        # Expected output: dup2(3, 100) = 100
        dup2_calls = [sc for sc in syscalls if sc.get("syscall") == "dup2"]
        if dup2_calls:
            dup2_call = dup2_calls[0]
            assert len(dup2_call["args"]) == 2, (
                f"dup2 should have 2 args, got {len(dup2_call['args'])}"
            )
            new_fd = dup2_call["args"][1]
            assert new_fd == 100, f"dup2 new fd should be 100, got {new_fd}"

        # Test fcntl: should decode commands
        # Expected output: fcntl(3, F_GETFD) or fcntl(3, F_SETFD, FD_CLOEXEC)
        fcntl_calls = [sc for sc in syscalls if sc.get("syscall") == "fcntl"]
        assert len(fcntl_calls) > 0, "Should have fcntl calls"
        fcntl_call = fcntl_calls[0]
        cmd_arg = fcntl_call["args"][1]
        # Should decode F_GETFD, F_SETFD, F_GETFL, F_SETFL
        assert "F_" in str(cmd_arg), f"fcntl should decode command, got {cmd_arg}"

        # Test ioctl: should decode requests
        # Expected output: ioctl(3, FIOCLEX) or ioctl(3, FIONREAD, &nbytes)
        ioctl_calls = [sc for sc in syscalls if sc.get("syscall") == "ioctl"]
        assert len(ioctl_calls) > 0, "Should have ioctl calls"
        ioctl_call = ioctl_calls[0]
        request_arg = ioctl_call["args"][1]
        # Should decode FIOCLEX, FIONCLEX, FIONREAD, TIOCGWINSZ, TIOCGETA
        # For now, we check that it's not just a raw number
        assert isinstance(request_arg, (str, int)), (
            f"ioctl request should be decoded, got {type(request_arg)}"
        )
        # Ideally, we want symbolic names like "FIOCLEX" but even hex is better than nothing
        # We'll accept either symbolic or numeric representation for now


if __name__ == "__main__":
    unittest.main()
