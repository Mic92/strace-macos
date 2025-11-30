"""
Test following multiple processes with -f flag.

Tests that when -f (--follow-forks) is specified, strace-macos traces
syscalls from both parent and child processes after fork().

Without -f: Only parent process syscalls are traced
With -f: Both parent and child process syscalls are traced
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
import syscall_test_helpers as sth  # type: ignore[import-not-found]


class TestFollowMultipleProcesses(unittest.TestCase):
    """Test tracing of forked child processes with -f flag."""

    def test_without_follow_forks_only_parent_traced(self) -> None:
        """Without -f flag, only parent process syscalls are captured."""
        exit_code, syscalls = sth.run_strace_for_mode(
            "--follow-fork", Path(__file__)
        )

        assert exit_code == 0, f"Test executable should exit with 0, got {exit_code}"
        assert len(syscalls) > 0, "Should capture some syscalls"

        # Get all unique PIDs from captured syscalls
        pids = {sc.get("pid") for sc in syscalls if sc.get("pid") is not None}

        # Without -f, we should only see one PID (the parent)
        assert len(pids) == 1, (
            f"Without -f, should only see parent PID, but got {len(pids)} PIDs: {pids}"
        )

    def test_with_follow_forks_both_processes_traced(self) -> None:
        """With -f flag, both parent and child process syscalls are captured."""
        exit_code, syscalls = sth.run_strace_for_mode(
            "--follow-fork", Path(__file__), additional_args=["-f"]
        )

        assert exit_code == 0, f"Test executable should exit with 0, got {exit_code}"
        assert len(syscalls) > 0, "Should capture some syscalls"

        # Get all unique PIDs from captured syscalls
        pids = {sc.get("pid") for sc in syscalls if sc.get("pid") is not None}

        # With -f, we should see at least 2 PIDs (parent and child)
        assert len(pids) >= 2, (
            f"With -f, should see at least parent and child PIDs, but got {len(pids)} PIDs: {pids}. "
            f"Captured syscalls: {[sc.get('syscall') for sc in syscalls]}"
        )

    def test_child_getpid_captured_with_follow_forks(self) -> None:
        """With -f flag, child's getpid() call is captured with child's PID."""
        exit_code, syscalls = sth.run_strace_for_mode(
            "--follow-fork", Path(__file__), additional_args=["-f"]
        )

        assert exit_code == 0, f"Test executable should exit with 0, got {exit_code}"

        # Filter getpid syscalls
        getpid_calls = sth.filter_syscalls(syscalls, "getpid")

        # We should have at least 2 getpid calls (one from parent, one from child)
        assert len(getpid_calls) >= 2, (
            f"With -f, should have at least 2 getpid calls (parent + child), "
            f"got {len(getpid_calls)}"
        )

        # The getpid calls should return different values (different PIDs)
        returned_pids = {call.get("return") for call in getpid_calls}
        assert len(returned_pids) >= 2, (
            f"getpid() should return different values for parent and child, "
            f"got returns: {returned_pids}"
        )

    def test_child_syscalls_have_different_pid(self) -> None:
        """With -f flag, child syscalls are tagged with child's PID."""
        exit_code, syscalls = sth.run_strace_for_mode(
            "--follow-fork", Path(__file__), additional_args=["-f"]
        )

        assert exit_code == 0, f"Test executable should exit with 0, got {exit_code}"

        # Find fork call to get the child PID (return value of fork in parent)
        fork_calls = sth.filter_syscalls(syscalls, "fork")
        assert len(fork_calls) >= 1, "Should capture fork syscall"

        # The parent's fork() returns the child PID
        child_pid = fork_calls[0].get("return")
        assert isinstance(child_pid, int) and child_pid > 0, (
            f"fork() should return positive child PID, got {child_pid}"
        )

        # Find syscalls from the child (pid field matches child_pid)
        child_syscalls = [sc for sc in syscalls if sc.get("pid") == child_pid]
        assert len(child_syscalls) > 0, (
            f"Should have syscalls from child process (PID {child_pid}), "
            f"but found none. Available PIDs: {set(sc.get('pid') for sc in syscalls)}"
        )

        # Child should have called getpid
        child_getpid = [sc for sc in child_syscalls if sc.get("syscall") == "getpid"]
        assert len(child_getpid) >= 1, (
            f"Child (PID {child_pid}) should have called getpid, "
            f"child syscalls: {[sc.get('syscall') for sc in child_syscalls]}"
        )


if __name__ == "__main__":
    unittest.main()
