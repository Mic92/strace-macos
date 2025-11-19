"""
Test process identity syscalls.

Tests coverage for:
- getpid, getppid (process IDs)
- getpgrp, getpgid, setpgid (process groups)
- getsid, setsid (sessions)
- getuid, geteuid, getgid, getegid (user/group IDs)
- setuid, seteuid, setgid, setegid (set user/group IDs)
- setreuid, setregid (set real and effective IDs)
- getgroups, setgroups (supplementary groups)
- initgroups (initialize group access list)
- getlogin, setlogin (login name)
- issetugid (setuid/setgid taint check)
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
import syscall_test_helpers as sth  # type: ignore[import-not-found]


class TestProcessIdentity(unittest.TestCase):
    """Test process identity syscall decoding."""

    exit_code: int
    syscalls: list[dict]

    @classmethod
    def setUpClass(cls) -> None:
        """Run the test executable once and capture syscalls for all tests."""
        cls.exit_code, cls.syscalls = sth.run_strace_for_mode("--process-identity", Path(__file__))

    def test_executable_exits_successfully(self) -> None:
        """Test that the executable runs without errors."""
        assert self.exit_code == 0, f"Test executable should exit with 0, got {self.exit_code}"

    def test_process_identity_coverage(self) -> None:
        """Test that expected process identity syscalls are captured."""
        # Expected syscalls from our test mode
        expected_syscalls = {
            "getpid",
            "getppid",
            "getpgrp",
            "getpgid",
            "setpgid",
            "getsid",
            "setsid",
            "getuid",
            "geteuid",
            "getgid",
            "getegid",
            "setuid",
            "seteuid",
            "setgid",
            "setegid",
            "setreuid",
            "setregid",
            "getgroups",
            "setgroups",
            "initgroups",
            "getlogin",
            "setlogin",
            "issetugid",
        }

        # We should capture at least 22 of these
        sth.assert_syscall_coverage(
            self.syscalls, expected_syscalls, 22, "process identity syscalls"
        )

    def test_initgroups_string_decoding(self) -> None:
        """Test that initgroups() properly decodes the username string argument."""
        initgroups_calls = sth.filter_syscalls(self.syscalls, "initgroups")

        # Should have initgroups calls
        sth.assert_min_call_count(initgroups_calls, 2, "initgroups")

        # Check that at least one call has a valid username string decoded
        valid_username_found = False
        for call in initgroups_calls:
            # initgroups has 4 args on macOS: name, basegid, groups, ngroups
            sth.assert_arg_count(call, 4, "initgroups")

            # First arg should be username string (decoded from pointer)
            sth.assert_arg_type(call, 0, str, "initgroups name")
            username = call["args"][0]

            # At least one call should have a real username (not "nonexistent_user_12345")
            if username != "nonexistent_user_12345" and len(username) > 0:
                valid_username_found = True

        assert valid_username_found, (
            "Should have at least one initgroups call with valid username decoded"
        )

    def test_argument_counts(self) -> None:
        """Test that syscalls have correct number of arguments."""
        # No-argument syscalls
        for syscall_name in [
            "getpid",
            "getppid",
            "getpgrp",
            "getuid",
            "geteuid",
            "getgid",
            "getegid",
            "setsid",
            "issetugid",
        ]:
            calls = sth.filter_syscalls(self.syscalls, syscall_name)
            for call in calls:
                sth.assert_arg_count(call, 0, syscall_name)

        # Single-argument syscalls
        for syscall_name in [
            "getpgid",
            "getsid",
            "setuid",
            "seteuid",
            "setgid",
            "setegid",
            "setlogin",
        ]:
            calls = sth.filter_syscalls(self.syscalls, syscall_name)
            for call in calls:
                sth.assert_arg_count(call, 1, syscall_name)

        # Two-argument syscalls
        for syscall_name in [
            "setpgid",
            "setreuid",
            "setregid",
            "getgroups",
            "setgroups",
            "getlogin",
        ]:
            calls = sth.filter_syscalls(self.syscalls, syscall_name)
            for call in calls:
                sth.assert_arg_count(call, 2, syscall_name)

        # Four-argument syscall (initgroups)
        initgroups_calls = sth.filter_syscalls(self.syscalls, "initgroups")
        for call in initgroups_calls:
            sth.assert_arg_count(call, 4, "initgroups")

    def test_setlogin_string_decoding(self) -> None:
        """Test that setlogin() properly decodes the string argument."""
        setlogin_calls = sth.filter_syscalls(self.syscalls, "setlogin")

        # Should have at least one setlogin call
        sth.assert_min_call_count(setlogin_calls, 1, "setlogin")

        # Check that the string argument is properly decoded
        for call in setlogin_calls:
            sth.assert_arg_count(call, 1, "setlogin")

            # First arg should be the username string
            sth.assert_arg_type(call, 0, str, "setlogin name")
            username = call["args"][0]
            assert username == "testuser", f"setlogin name should be 'testuser', got '{username}'"

    def test_issetugid_return_value(self) -> None:
        """Test that issetugid() returns valid boolean-ish values."""
        issetugid_calls = sth.filter_syscalls(self.syscalls, "issetugid")

        # Should have at least one issetugid call
        sth.assert_min_call_count(issetugid_calls, 1, "issetugid")

        # Check return values are 0 or 1
        for call in issetugid_calls:
            sth.assert_arg_count(call, 0, "issetugid")
            ret = call.get("return")
            assert ret is not None, "issetugid should have a return value"
            assert ret in [0, 1], f"issetugid should return 0 or 1, got {ret}"


if __name__ == "__main__":
    unittest.main()
