"""
Test advanced process syscalls.

Tests coverage for:
- getpriority, setpriority (scheduling priority with PRIO_* constant decoding)
- getrlimit, setrlimit (resource limits with RLIMIT_* constants and struct rlimit decoding)
- getrusage (resource usage with RUSAGE_* constants and struct rusage decoding)

Note: The following syscalls have no public prototypes and are not included:
- proc_info, proc_info_extended_id, proc_trace_log, proc_uuid_policy, process_policy, proc_rlimit_control
- pid_suspend, pid_resume, pid_hibernate, pid_shutdown_sockets
- thread_selfid, thread_selfusage, gettid, settid, settid_with_pid
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
import syscall_test_helpers as sth  # type: ignore[import-not-found]


class TestProcessAdvanced(unittest.TestCase):
    """Test advanced process syscall decoding."""

    exit_code: int
    syscalls: list[dict]

    @classmethod
    def setUpClass(cls) -> None:
        """Run the test executable once and capture syscalls for all tests."""
        cls.exit_code, cls.syscalls = sth.run_strace_for_mode("--process-advanced", Path(__file__))

    def test_executable_exits_successfully(self) -> None:
        """Test that the executable runs without errors."""
        assert self.exit_code == 0, f"Test executable should exit with 0, got {self.exit_code}"

    def test_priority_syscalls(self) -> None:
        """Test getpriority/setpriority syscalls."""
        # Test getpriority
        getprio_calls = sth.filter_syscalls(self.syscalls, "getpriority")
        sth.assert_min_call_count(getprio_calls, 2, "getpriority")

        for call in getprio_calls:
            sth.assert_arg_count(call, 2, "getpriority")
            # First arg should be PRIO_* constant (symbolic)
            sth.assert_arg_type(call, 0, str, "getpriority which")
            which = call["args"][0]
            assert which in ["PRIO_PROCESS", "PRIO_PGRP", "PRIO_USER"], (
                f"getpriority which should be PRIO_* constant, got {which}"
            )
            # Second arg is int (pid/pgid/uid)
            sth.assert_arg_type(call, 1, int, "getpriority who")

        # Test setpriority
        setprio_calls = sth.filter_syscalls(self.syscalls, "setpriority")
        sth.assert_min_call_count(setprio_calls, 1, "setpriority")

        for call in setprio_calls:
            sth.assert_arg_count(call, 3, "setpriority")
            # First arg should be PRIO_* constant (symbolic)
            sth.assert_arg_type(call, 0, str, "setpriority which")
            which = call["args"][0]
            assert which in ["PRIO_PROCESS", "PRIO_PGRP", "PRIO_USER"], (
                f"setpriority which should be PRIO_* constant, got {which}"
            )
            # Second arg is int (pid/pgid/uid)
            sth.assert_arg_type(call, 1, int, "setpriority who")
            # Third arg is priority value
            sth.assert_arg_type(call, 2, int, "setpriority prio")

    def test_resource_limit_syscalls(self) -> None:
        """Test getrlimit/setrlimit syscalls with struct decoding."""
        # Test getrlimit
        getrlimit_calls = sth.filter_syscalls(self.syscalls, "getrlimit")
        sth.assert_min_call_count(getrlimit_calls, 5, "getrlimit")

        for call in getrlimit_calls:
            sth.assert_arg_count(call, 2, "getrlimit")
            # First arg should be RLIMIT_* constant (symbolic)
            sth.assert_arg_type(call, 0, str, "getrlimit resource")
            resource = call["args"][0]
            assert resource.startswith("RLIMIT_"), (
                f"getrlimit resource should be RLIMIT_* constant, got {resource}"
            )

            # Second arg should be struct with rlim_cur and rlim_max
            sth.assert_arg_type(call, 1, dict, "getrlimit rlp")
            rlim = call["args"][1]
            assert "rlim_cur" in rlim, "getrlimit should decode rlim_cur field"
            assert "rlim_max" in rlim, "getrlimit should decode rlim_max field"

            # Check for RLIM_INFINITY symbolic constant
            cur_val = rlim["rlim_cur"]
            max_val = rlim["rlim_max"]
            assert isinstance(cur_val, (int, str)), "rlim_cur should be int or 'RLIM_INFINITY'"
            assert isinstance(max_val, (int, str)), "rlim_max should be int or 'RLIM_INFINITY'"

        # Test setrlimit
        setrlimit_calls = sth.filter_syscalls(self.syscalls, "setrlimit")
        sth.assert_min_call_count(setrlimit_calls, 1, "setrlimit")

        for call in setrlimit_calls:
            sth.assert_arg_count(call, 2, "setrlimit")
            # First arg should be RLIMIT_* constant
            sth.assert_arg_type(call, 0, str, "setrlimit resource")
            resource = call["args"][0]
            assert resource.startswith("RLIMIT_"), (
                f"setrlimit resource should be RLIMIT_* constant, got {resource}"
            )

            # Second arg should be struct with rlim_cur and rlim_max
            sth.assert_arg_type(call, 1, dict, "setrlimit rlp")
            rlim = call["args"][1]
            assert "rlim_cur" in rlim, "setrlimit should decode rlim_cur field"
            assert "rlim_max" in rlim, "setrlimit should decode rlim_max field"

    def test_rusage_syscall(self) -> None:
        """Test getrusage syscall with struct decoding."""
        rusage_calls = sth.filter_syscalls(self.syscalls, "getrusage")
        sth.assert_min_call_count(rusage_calls, 2, "getrusage")

        for call in rusage_calls:
            sth.assert_arg_count(call, 2, "getrusage")
            # First arg should be RUSAGE_* constant
            sth.assert_arg_type(call, 0, str, "getrusage who")
            who = call["args"][0]
            assert who in ["RUSAGE_SELF", "RUSAGE_CHILDREN"], (
                f"getrusage who should be RUSAGE_* constant, got {who}"
            )

            # Second arg should be struct rusage with many fields
            sth.assert_arg_type(call, 1, dict, "getrusage usage")
            rusage = call["args"][1]

            # Check for key fields
            expected_fields = [
                "ru_maxrss",
                "ru_minflt",
                "ru_majflt",
                "ru_inblock",
                "ru_oublock",
                "ru_nvcsw",
                "ru_nivcsw",
            ]
            for field in expected_fields:
                assert field in rusage, f"getrusage should decode {field} field"

            # Check for time fields
            assert any(k.startswith("ru_utime") for k in rusage), (
                "getrusage should decode ru_utime fields"
            )
            assert any(k.startswith("ru_stime") for k in rusage), (
                "getrusage should decode ru_stime fields"
            )

    def test_syscall_coverage(self) -> None:
        """Test that we captured all expected process syscalls."""
        expected_syscalls = {
            # Priority
            "getpriority",
            "setpriority",
            # Resource limits
            "getrlimit",
            "setrlimit",
            "getrusage",
        }

        # We should capture all 5 of these syscalls
        # Note: proc_pidinfo() library wrapper doesn't generate traceable proc_info syscalls
        sth.assert_syscall_coverage(
            self.syscalls, expected_syscalls, 5, "advanced process syscalls"
        )


if __name__ == "__main__":
    unittest.main()
