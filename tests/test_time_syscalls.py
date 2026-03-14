"""Tests for time syscalls."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
import syscall_test_helpers as sth  # type: ignore[import-not-found]


class TestTimeSyscalls(unittest.TestCase):
    """Test time syscall decoding."""

    exit_code: int
    syscalls: list[dict]

    @classmethod
    def setUpClass(cls) -> None:
        """Run the test executable once and capture syscalls for all tests."""
        cls.exit_code, cls.syscalls = sth.run_strace_for_mode("--time", Path(__file__))

    def test_executable_exits_successfully(self) -> None:
        """Test that the executable runs without errors."""
        assert self.exit_code == 0, f"Test executable should exit with 0, got {self.exit_code}"

    def test_time_coverage(self) -> None:
        """Test that expected time syscalls are captured."""
        expected_syscalls = {
            "gettimeofday",
            "settimeofday",
            "utimes",
            "futimes",
            "getitimer",
            "setitimer",
        }
        sth.assert_syscall_coverage(self.syscalls, expected_syscalls, 5, "time syscalls")

    def test_gettimeofday(self) -> None:
        """Test gettimeofday syscall parameter decodes."""
        gettimeofday_calls = sth.filter_syscalls(self.syscalls, "gettimeofday")
        sth.assert_min_call_count(gettimeofday_calls, 1, "gettimeofday")

        output = str(gettimeofday_calls)
        assert "tv_sec" in output, "missing tv_sec field in output"
        assert "tv_nsec" in output, "missing tv_nec field in output"
        assert "tz_minuteswest" in output, "missing tz_minuteswest field in output"
        assert "tz_dsttime" in output, "missing tz_dsttime field in output"

    def test_settimeofday(self) -> None:
        """Test settimeofday syscall parameter decodes."""
        settimeofday_calls = sth.filter_syscalls(self.syscalls, "settimeofday")
        sth.assert_min_call_count(settimeofday_calls, 1, "settimeofday")

        output = str(settimeofday_calls)
        assert "tv_sec" in output, "missing tv_sec field in output"
        assert "tv_nsec" in output, "missing tv_nec field in output"
        assert "tz_minuteswest" in output, "missing tz_minuteswest field in output"
        assert "tz_dsttime" in output, "missing tz_dsttime field in output"

    def _test_utimes(self) -> None:
        """Test utimes syscall parameter decodes."""
        print(self.syscalls)
        utimes_calls = sth.filter_syscalls(self.syscalls, "utimes")
        sth.assert_min_call_count(utimes_calls, 1, "utimes")

        print(utimes_calls)
        output = str(utimes_calls)
        assert "tv_sec" in output, "missing tv_sec field in output"
        assert "tv_usec" in output, "missing tv_usec field in output"

    def _test_futimes(self) -> None:
        """Test futimes syscall parameter decodes."""
        print(self.syscalls)
        futimes_calls = sth.filter_syscalls(self.syscalls, "futimes")
        sth.assert_min_call_count(futimes_calls, 1, "futimes")

    def _test_getitimer(self) -> None:
        """Test getitimer syscall parameter decodes."""
        print(self.syscalls)
        getitimer_calls = sth.filter_syscalls(self.syscalls, "getitimer")
        sth.assert_min_call_count(getitimer_calls, 1, "getitimer")

        print(getitimer_calls)

if __name__ == "__main__":
    unittest.main()
