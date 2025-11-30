"""
Test following multiple processes with -f flag.

Tests that when -f (--follow-forks) is specified, strace-macos traces
syscalls from both parent and child processes after fork().
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
import syscall_test_helpers as sth  # type: ignore[import-not-found]


class TestFollowMultipleProcesses(unittest.TestCase):
    """Test tracing of forked child processes with -f flag."""

    def test_follow_forks_traces_child_process(self) -> None:
        """With -f flag, syscalls from both parent and child are captured."""
        exit_code, syscalls = sth.run_strace_for_mode(
            "--follow-fork", Path(__file__), additional_args=["-f"]
        )

        assert exit_code == 0, f"Test executable should exit with 0, got {exit_code}"

        # Get all unique PIDs from captured syscalls
        pids = {sc.get("pid") for sc in syscalls if sc.get("pid") is not None}

        # With -f, we should see at least 2 PIDs (parent and child)
        assert len(pids) >= 2, (
            f"With -f, should see parent and child PIDs, got {len(pids)}: {pids}"
        )


if __name__ == "__main__":
    unittest.main()
