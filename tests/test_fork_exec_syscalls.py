"""
Test fork/exec/spawn syscalls.

Tests coverage for:
- fork (simple fork with child exit)
- vfork (vfork with immediate _exit)
- execve (failure case with argv/envp decoding)
- posix_spawn (spawn with argv/envp decoding)
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
import syscall_test_helpers as sth  # type: ignore[import-not-found]


class TestForkExecSyscalls(unittest.TestCase):
    """Test fork/exec/spawn syscall decoding."""

    exit_code: int
    syscalls: list[dict]

    @classmethod
    def setUpClass(cls) -> None:
        """Run the test executable once and capture syscalls for all tests."""
        cls.exit_code, cls.syscalls = sth.run_strace_for_mode("--fork-exec", Path(__file__))

    def test_executable_exits_successfully(self) -> None:
        """Test that the executable runs without errors."""
        assert self.exit_code == 0, f"Test executable should exit with 0, got {self.exit_code}"

    def test_fork_exec_coverage(self) -> None:
        """Test that expected fork/exec/spawn syscalls are captured."""
        expected_syscalls = {
            "fork",
            "vfork",
            "execve",
            "posix_spawn",
        }

        # We should capture all 4 syscalls
        sth.assert_syscall_coverage(self.syscalls, expected_syscalls, 4, "fork/exec/spawn syscalls")

    def test_fork_syscall(self) -> None:
        """Test fork syscall is captured correctly."""
        fork_calls = sth.filter_syscalls(self.syscalls, "fork")

        # Should have at least one fork call
        sth.assert_min_call_count(fork_calls, 1, "fork")

        # fork() takes no arguments
        for call in fork_calls:
            sth.assert_arg_count(call, 0, "fork")

            # Return value should be a PID (integer > 0 for parent)
            # Note: we only see parent's return value, not child's
            assert isinstance(call["return"], int), "fork return should be int (PID)"

    def test_vfork_syscall(self) -> None:
        """Test vfork syscall is captured correctly."""
        vfork_calls = sth.filter_syscalls(self.syscalls, "vfork")

        # Should have at least one vfork call
        sth.assert_min_call_count(vfork_calls, 1, "vfork")

        # vfork() takes no arguments
        for call in vfork_calls:
            sth.assert_arg_count(call, 0, "vfork")

            # Return value should be a PID (integer > 0 for parent)
            assert isinstance(call["return"], int), "vfork return should be int (PID)"

    def test_execve_argv_decoding(self) -> None:
        """Test execve syscall with argv array decoding."""
        execve_calls = sth.filter_syscalls(self.syscalls, "execve")

        # Should have at least one execve call
        sth.assert_min_call_count(execve_calls, 1, "execve")

        for call in execve_calls:
            # Check arg count: path, argv, envp
            sth.assert_arg_count(call, 3, "execve")

            # First arg: path (string)
            sth.assert_arg_type(call, 0, str, "execve path")
            assert call["args"][0] == "/nonexistent/binary", "execve path should match"

            # Second arg: argv (array of strings)
            sth.assert_arg_type(call, 1, list, "execve argv")
            argv = call["args"][1]
            assert isinstance(argv, list), "argv should be a list"
            assert len(argv) >= 3, "argv should have at least 3 elements"
            assert argv[0] == "/nonexistent/binary", "argv[0] should be program name"
            assert argv[1] == "arg1", "argv[1] should be 'arg1'"
            assert argv[2] == "arg2", "argv[2] should be 'arg2'"

            # Third arg: envp (array of strings)
            sth.assert_arg_type(call, 2, list, "execve envp")
            envp = call["args"][2]
            assert isinstance(envp, list), "envp should be a list"
            assert len(envp) >= 2, "envp should have at least 2 elements"
            assert "VAR1=value1" in envp, "envp should contain VAR1=value1"
            assert "VAR2=value2" in envp, "envp should contain VAR2=value2"

            # Return value should be -1 (ENOENT) since path doesn't exist
            assert isinstance(call["return"], (int, str)), (
                "execve return should be int or error string"
            )

    def test_posix_spawn_argv_decoding(self) -> None:
        """Test posix_spawn syscall with argv array decoding."""
        spawn_calls = sth.filter_syscalls(self.syscalls, "posix_spawn")

        # Should have at least one posix_spawn call
        sth.assert_min_call_count(spawn_calls, 1, "posix_spawn")

        for call in spawn_calls:
            # Check arg count: pid, path, file_actions, attrp, argv, envp
            sth.assert_arg_count(call, 6, "posix_spawn")

            # First arg: pid pointer
            assert call["args"][0] is not None, "posix_spawn pid should not be None"

            # Second arg: path (string)
            sth.assert_arg_type(call, 1, str, "posix_spawn path")
            assert call["args"][1] == "/usr/bin/true", "posix_spawn path should match"

            # Third arg: file_actions (pointer, can be NULL)
            # Fourth arg: attrp (pointer, can be NULL)

            # Fifth arg: argv (array of strings)
            sth.assert_arg_type(call, 4, list, "posix_spawn argv")
            argv = call["args"][4]
            assert isinstance(argv, list), "argv should be a list"
            assert len(argv) >= 1, "argv should have at least 1 element"
            assert argv[0] == "/usr/bin/true", "argv[0] should be program name"
            if len(argv) > 1:
                assert argv[1] == "spawn_arg1", "argv[1] should be 'spawn_arg1'"

            # Sixth arg: envp (array of strings)
            sth.assert_arg_type(call, 5, list, "posix_spawn envp")
            envp = call["args"][5]
            assert isinstance(envp, list), "envp should be a list"
            assert len(envp) >= 1, "envp should have at least 1 element"
            assert "SPAWN_VAR=spawn_value" in envp, "envp should contain SPAWN_VAR=spawn_value"

            # Return value should be 0 on success
            assert call["return"] == 0, "posix_spawn should return 0 on success"


if __name__ == "__main__":
    unittest.main()
