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

        # Test fcntl: should decode commands and arguments properly
        fcntl_calls = [sc for sc in syscalls if sc.get("syscall") == "fcntl"]
        assert len(fcntl_calls) >= 4, f"Should have at least 4 fcntl calls, got {len(fcntl_calls)}"

        # F_GETFD: should have 2 args (no third arg)
        getfd_calls = [sc for sc in fcntl_calls if "F_GETFD" in str(sc["args"][1])]
        assert len(getfd_calls) > 0, "Should have fcntl F_GETFD calls"
        getfd_call = getfd_calls[0]
        assert len(getfd_call["args"]) == 2, (
            f"fcntl F_GETFD should have 2 args, got {len(getfd_call['args'])}: {getfd_call['args']}"
        )
        assert getfd_call["args"][1] == "F_GETFD", (
            f"fcntl cmd should be F_GETFD, got {getfd_call['args'][1]}"
        )

        # F_SETFD: should decode FD_CLOEXEC flags
        setfd_calls = [sc for sc in fcntl_calls if "F_SETFD" in str(sc["args"][1])]
        assert len(setfd_calls) > 0, "Should have fcntl F_SETFD calls"
        setfd_call = setfd_calls[0]
        assert len(setfd_call["args"]) == 3, (
            f"fcntl F_SETFD should have 3 args, got {len(setfd_call['args'])}"
        )
        flags_arg = setfd_call["args"][2]
        # Should decode FD_CLOEXEC flag
        assert "FD_CLOEXEC" in str(flags_arg) or flags_arg == 1, (
            f"fcntl F_SETFD should decode FD_CLOEXEC, got {flags_arg}"
        )

        # F_GETFL: should have 2 args and decode return value
        getfl_calls = [sc for sc in fcntl_calls if "F_GETFL" in str(sc["args"][1])]
        assert len(getfl_calls) > 0, "Should have fcntl F_GETFL calls"
        getfl_call = getfl_calls[0]
        assert len(getfl_call["args"]) == 2, (
            f"fcntl F_GETFL should have 2 args, got {len(getfl_call['args'])}: {getfl_call['args']}"
        )
        # Return value should decode O_* flags
        ret_val = getfl_call.get("return")
        if isinstance(ret_val, str):
            assert "O_" in ret_val, f"fcntl F_GETFL return should decode O_* flags, got {ret_val}"

        # F_SETFL: should decode O_* file status flags
        setfl_calls = [sc for sc in fcntl_calls if "F_SETFL" in str(sc["args"][1])]
        assert len(setfl_calls) > 0, "Should have fcntl F_SETFL calls"
        setfl_call = setfl_calls[0]
        assert len(setfl_call["args"]) == 3, (
            f"fcntl F_SETFL should have 3 args, got {len(setfl_call['args'])}"
        )
        flags_arg = setfl_call["args"][2]
        # Should decode O_* flags
        assert "O_" in str(flags_arg), f"fcntl F_SETFL should decode O_* flags, got {flags_arg}"

        # Test ioctl: should decode requests and data arguments
        ioctl_calls = [sc for sc in syscalls if sc.get("syscall") == "ioctl"]
        assert len(ioctl_calls) >= 2, f"Should have at least 2 ioctl calls, got {len(ioctl_calls)}"

        # FIOCLEX: should have 2 args (no data argument)
        fioclex_calls = [sc for sc in ioctl_calls if "FIOCLEX" in str(sc["args"][1])]
        assert len(fioclex_calls) > 0, "Should have ioctl FIOCLEX calls"
        fioclex_call = fioclex_calls[0]
        assert len(fioclex_call["args"]) == 2, (
            f"ioctl FIOCLEX should have 2 args, got {len(fioclex_call['args'])}: {fioclex_call['args']}"
        )

        # FIONCLEX: should have 2 args (no data argument)
        fionclex_calls = [sc for sc in ioctl_calls if "FIONCLEX" in str(sc["args"][1])]
        assert len(fionclex_calls) > 0, "Should have ioctl FIONCLEX calls"
        fionclex_call = fionclex_calls[0]
        assert len(fionclex_call["args"]) == 2, (
            f"ioctl FIONCLEX should have 2 args, got {len(fionclex_call['args'])}: {fionclex_call['args']}"
        )

        # FIONREAD: should decode int* as [value]
        fionread_calls = [sc for sc in ioctl_calls if "FIONREAD" in str(sc["args"][1])]
        assert len(fionread_calls) > 0, "Should have ioctl FIONREAD calls"
        fionread_call = fionread_calls[0]
        assert len(fionread_call["args"]) == 3, (
            f"ioctl FIONREAD should have 3 args, got {len(fionread_call['args'])}"
        )
        data_arg = fionread_call["args"][2]
        # Should be a list with single int value
        assert isinstance(data_arg, list), (
            f"ioctl FIONREAD data should be list, got {type(data_arg)}: {data_arg}"
        )
        assert len(data_arg) == 1, f"ioctl FIONREAD should have 1 value, got {len(data_arg)}"
        assert isinstance(data_arg[0], int), (
            f"ioctl FIONREAD value should be int, got {type(data_arg[0])}"
        )

        # TIOCGWINSZ: should decode struct winsize
        tiocgwinsz_calls = [sc for sc in ioctl_calls if "TIOCGWINSZ" in str(sc["args"][1])]
        assert len(tiocgwinsz_calls) > 0, "Should have ioctl TIOCGWINSZ calls"
        tiocgwinsz_call = tiocgwinsz_calls[0]
        assert len(tiocgwinsz_call["args"]) == 3, (
            f"ioctl TIOCGWINSZ should have 3 args, got {len(tiocgwinsz_call['args'])}"
        )
        data_arg = tiocgwinsz_call["args"][2]
        # Should be a dict with winsize fields
        assert isinstance(data_arg, dict), (
            f"ioctl TIOCGWINSZ data should be dict, got {type(data_arg)}"
        )
        # Check for struct winsize fields
        assert "output" in data_arg, f"TIOCGWINSZ should have output, got {data_arg}"
        winsize = data_arg["output"]
        assert "ws_row" in winsize, f"winsize should have ws_row, got {winsize}"
        assert "ws_col" in winsize, f"winsize should have ws_col, got {winsize}"

        # TIOCGETA: should decode struct termios
        tiocgeta_calls = [sc for sc in ioctl_calls if "TIOCGETA" in str(sc["args"][1])]
        assert len(tiocgeta_calls) > 0, "Should have ioctl TIOCGETA calls"
        tiocgeta_call = tiocgeta_calls[0]
        assert len(tiocgeta_call["args"]) == 3, (
            f"ioctl TIOCGETA should have 3 args, got {len(tiocgeta_call['args'])}"
        )
        data_arg = tiocgeta_call["args"][2]
        # Should be a dict with termios fields
        assert isinstance(data_arg, dict), (
            f"ioctl TIOCGETA data should be dict, got {type(data_arg)}"
        )
        # Check for struct termios output
        assert "output" in data_arg, f"TIOCGETA should have output, got {data_arg}"
        # Termios fields may vary, just check it's a dict
        assert isinstance(data_arg["output"], dict), (
            f"TIOCGETA output should be dict, got {type(data_arg['output'])}"
        )


if __name__ == "__main__":
    unittest.main()
