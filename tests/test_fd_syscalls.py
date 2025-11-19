"""
Test comprehensive file descriptor syscall coverage.

This test verifies that the --fd-ops mode exercises fd-related syscalls
and tests high-level decoding of arguments.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
import syscall_test_helpers as sth  # type: ignore[import-not-found]


class TestFdSyscalls(unittest.TestCase):
    """Test fd syscall coverage using the test executable's --fd-ops mode."""

    exit_code: int
    syscalls: list[dict]

    @classmethod
    def setUpClass(cls) -> None:
        """Run the test executable once and capture syscalls for all tests."""
        cls.exit_code, cls.syscalls = sth.run_strace_for_mode("--fd-ops", Path(__file__))

    def test_executable_exits_successfully(self) -> None:
        """Test that the executable runs without errors."""
        assert self.exit_code == 0, f"Test executable should exit with 0, got {self.exit_code}"

    def test_fd_syscall_coverage(self) -> None:  # noqa: PLR0915
        """Test that all expected fd syscalls are captured and decoded."""

        # Expected fd syscalls
        expected_syscalls = {
            "mkstemp",
            "write",
            "pwrite",
            "pread",
            "readv",
            "writev",
            "preadv",
            "pwritev",
            "dup",
            "dup2",
            "fcntl",
            "ioctl",
            "lseek",
        }

        # We should capture at least 11 out of 13 expected syscalls
        # (some like mkstemp might be implemented as open internally)
        sth.assert_syscall_coverage(self.syscalls, expected_syscalls, 11, "fd syscalls")

        # Test readv: should decode iovec structures
        # Expected output: readv(3, [{iov_base="...", iov_len=16}, ...], 3)
        readv_calls = sth.filter_syscalls(self.syscalls, "readv")
        sth.assert_min_call_count(readv_calls, 1, "readv")
        sth.assert_iovec_structure(readv_calls[0], 1, "readv")

        # Test writev: should decode iovec structures
        # Expected output: writev(3, [{iov_base="First ", iov_len=6}, ...], 3)
        writev_calls = sth.filter_syscalls(self.syscalls, "writev")
        sth.assert_min_call_count(writev_calls, 1, "writev")
        iovecs = sth.assert_iovec_structure(writev_calls[0], 1, "writev", min_count=3)
        # Should decode buffer content
        assert iovecs[0]["iov_base"] == "First ", (
            f"iovec buffer should be 'First ', got {iovecs[0]['iov_base']!r}"
        )
        assert iovecs[0]["iov_len"] == 6, f"iovec length should be 6, got {iovecs[0]['iov_len']}"

        # Test preadv: should decode iovec structures AND show offset parameter
        # Expected output: preadv(3, [{iov_base=..., iov_len=8}, {iov_base=..., iov_len=8}], 2, 0)
        preadv_calls = sth.filter_syscalls(self.syscalls, "preadv")
        sth.assert_min_call_count(preadv_calls, 1, "preadv")
        sth.assert_arg_count(preadv_calls[0], 4, "preadv")
        iovecs = sth.assert_iovec_structure(preadv_calls[0], 1, "preadv", min_count=2)
        # Check iovec structure
        assert iovecs[0]["iov_len"] == 8, (
            f"preadv iovec[0] length should be 8, got {iovecs[0]['iov_len']}"
        )
        assert iovecs[1]["iov_len"] == 8, (
            f"preadv iovec[1] length should be 8, got {iovecs[1]['iov_len']}"
        )
        # Check offset parameter (4th argument, index 3)
        offset_arg = preadv_calls[0]["args"][3]
        assert offset_arg == 0, f"preadv offset should be 0, got {offset_arg}"

        # Test pwritev: should decode iovec structures with buffer content AND show offset
        # Expected output: pwritev(3, [{iov_base="OVER", iov_len=4}, {iov_base="LAP", iov_len=3}], 2, 12)
        pwritev_calls = sth.filter_syscalls(self.syscalls, "pwritev")
        sth.assert_min_call_count(pwritev_calls, 1, "pwritev")
        sth.assert_arg_count(pwritev_calls[0], 4, "pwritev")
        iovecs = sth.assert_iovec_structure(pwritev_calls[0], 1, "pwritev", min_count=2)
        # Should decode buffer content for IN direction
        assert iovecs[0]["iov_base"] == "OVER", (
            f"pwritev iovec[0] buffer should be 'OVER', got {iovecs[0]['iov_base']!r}"
        )
        assert iovecs[0]["iov_len"] == 4, (
            f"pwritev iovec[0] length should be 4, got {iovecs[0]['iov_len']}"
        )
        assert iovecs[1]["iov_base"] == "LAP", (
            f"pwritev iovec[1] buffer should be 'LAP', got {iovecs[1]['iov_base']!r}"
        )
        assert iovecs[1]["iov_len"] == 3, (
            f"pwritev iovec[1] length should be 3, got {iovecs[1]['iov_len']}"
        )
        # Check offset parameter (4th argument, index 3)
        offset_arg = pwritev_calls[0]["args"][3]
        assert offset_arg == 12, f"pwritev offset should be 12, got {offset_arg}"

        # Test pwrite: should show offset parameter
        # Expected output: pwrite(3, "TEST", 4, 6)
        pwrite_calls = sth.filter_syscalls(self.syscalls, "pwrite")
        sth.assert_min_call_count(pwrite_calls, 1, "pwrite")
        pwrite_call = pwrite_calls[0]
        buf_arg = pwrite_call["args"][1]
        assert '"' in buf_arg, f"pwrite buffer should be decoded as string, got {buf_arg}"
        assert "TEST" in buf_arg, f"pwrite buffer should contain 'TEST', got {buf_arg}"
        offset_arg = pwrite_call["args"][3]
        assert offset_arg == 6, f"pwrite offset should be 6, got {offset_arg}"

        # Test pread: should show offset parameter
        # Expected output: pread(3, buf, 4, 0)
        pread_calls = sth.filter_syscalls(self.syscalls, "pread")
        sth.assert_min_call_count(pread_calls, 1, "pread")
        pread_call = pread_calls[0]
        offset_arg = pread_call["args"][3]
        assert offset_arg == 0, f"pread offset should be 0, got {offset_arg}"

        # Test dup: should return new fd
        # Expected output: dup(3) = 4
        dup_calls = sth.filter_syscalls(self.syscalls, "dup")
        sth.assert_min_call_count(dup_calls, 1, "dup")
        sth.assert_arg_count(dup_calls[0], 1, "dup")
        sth.assert_arg_type(dup_calls[0], 0, int, "dup fd")

        # Test dup2: should show both old and new fd
        # Expected output: dup2(3, 100) = 100
        dup2_calls = sth.filter_syscalls(self.syscalls, "dup2")
        sth.assert_min_call_count(dup2_calls, 1, "dup2")
        sth.assert_arg_count(dup2_calls[0], 2, "dup2")
        new_fd = dup2_calls[0]["args"][1]
        assert new_fd == 100, f"dup2 new fd should be 100, got {new_fd}"

        # Test fcntl: should decode commands and arguments properly
        fcntl_calls = sth.filter_syscalls(self.syscalls, "fcntl")
        sth.assert_min_call_count(fcntl_calls, 4, "fcntl")

        # F_GETFD: should have 2 args (no third arg)
        getfd_calls = [sc for sc in fcntl_calls if "F_GETFD" in str(sc["args"][1])]
        sth.assert_min_call_count(getfd_calls, 1, "fcntl F_GETFD")
        sth.assert_arg_count(getfd_calls[0], 2, "fcntl F_GETFD")
        sth.assert_symbolic_value(getfd_calls[0], 1, "F_GETFD", "fcntl cmd")

        # F_SETFD: should decode FD_CLOEXEC flags
        setfd_calls = [sc for sc in fcntl_calls if "F_SETFD" in str(sc["args"][1])]
        sth.assert_min_call_count(setfd_calls, 1, "fcntl F_SETFD")
        sth.assert_arg_count(setfd_calls[0], 3, "fcntl F_SETFD")
        flags_arg = setfd_calls[0]["args"][2]
        assert "FD_CLOEXEC" in str(flags_arg) or flags_arg == 1, (
            f"fcntl F_SETFD should decode FD_CLOEXEC, got {flags_arg}"
        )

        # F_GETFL: should have 2 args and decode return value
        getfl_calls = [sc for sc in fcntl_calls if "F_GETFL" in str(sc["args"][1])]
        sth.assert_min_call_count(getfl_calls, 1, "fcntl F_GETFL")
        sth.assert_arg_count(getfl_calls[0], 2, "fcntl F_GETFL")
        ret_val = getfl_calls[0].get("return")
        if isinstance(ret_val, str):
            assert "O_" in ret_val, f"fcntl F_GETFL return should decode O_* flags, got {ret_val}"

        # F_SETFL: should decode O_* file status flags
        setfl_calls = [sc for sc in fcntl_calls if "F_SETFL" in str(sc["args"][1])]
        sth.assert_min_call_count(setfl_calls, 1, "fcntl F_SETFL")
        sth.assert_arg_count(setfl_calls[0], 3, "fcntl F_SETFL")
        sth.assert_symbolic_value(setfl_calls[0], 2, "O_", "fcntl F_SETFL flags")

        # Test ioctl: should decode requests and data arguments
        ioctl_calls = sth.filter_syscalls(self.syscalls, "ioctl")
        sth.assert_min_call_count(ioctl_calls, 2, "ioctl")

        # FIOCLEX: should have 2 args (no data argument)
        fioclex_calls = [sc for sc in ioctl_calls if "FIOCLEX" in str(sc["args"][1])]
        sth.assert_min_call_count(fioclex_calls, 1, "ioctl FIOCLEX")
        sth.assert_arg_count(fioclex_calls[0], 2, "ioctl FIOCLEX")

        # FIONCLEX: should have 2 args (no data argument)
        fionclex_calls = [sc for sc in ioctl_calls if "FIONCLEX" in str(sc["args"][1])]
        sth.assert_min_call_count(fionclex_calls, 1, "ioctl FIONCLEX")
        sth.assert_arg_count(fionclex_calls[0], 2, "ioctl FIONCLEX")

        # FIONREAD: should decode int* as [value]
        fionread_calls = [sc for sc in ioctl_calls if "FIONREAD" in str(sc["args"][1])]
        sth.assert_min_call_count(fionread_calls, 1, "ioctl FIONREAD")
        sth.assert_arg_count(fionread_calls[0], 3, "ioctl FIONREAD")
        data_arg = fionread_calls[0]["args"][2]
        sth.assert_arg_type(fionread_calls[0], 2, list, "ioctl FIONREAD data")
        assert len(data_arg) == 1, f"ioctl FIONREAD should have 1 value, got {len(data_arg)}"
        assert isinstance(data_arg[0], int), (
            f"ioctl FIONREAD value should be int, got {type(data_arg[0])}"
        )

        # TIOCGWINSZ: should decode struct winsize
        tiocgwinsz_calls = [sc for sc in ioctl_calls if "TIOCGWINSZ" in str(sc["args"][1])]
        sth.assert_min_call_count(tiocgwinsz_calls, 1, "ioctl TIOCGWINSZ")
        sth.assert_arg_count(tiocgwinsz_calls[0], 3, "ioctl TIOCGWINSZ")
        winsize = sth.assert_struct_field(tiocgwinsz_calls[0], 2, "ws_row", "TIOCGWINSZ")
        assert "ws_col" in winsize, f"winsize should have ws_col, got {winsize}"

        # TIOCGETA: should decode struct termios
        tiocgeta_calls = [sc for sc in ioctl_calls if "TIOCGETA" in str(sc["args"][1])]
        sth.assert_min_call_count(tiocgeta_calls, 1, "ioctl TIOCGETA")
        sth.assert_arg_count(tiocgeta_calls[0], 3, "ioctl TIOCGETA")
        sth.assert_arg_type(tiocgeta_calls[0], 2, dict, "ioctl TIOCGETA data")
        # Check for struct termios output - termios fields are directly in the dict
        data_arg = tiocgeta_calls[0]["args"][2]
        assert isinstance(data_arg, dict), f"TIOCGETA output should be dict, got {type(data_arg)}"


if __name__ == "__main__":
    unittest.main()
