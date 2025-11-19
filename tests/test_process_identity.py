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

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
import helpers  # type: ignore[import-not-found]
from compile import get_test_executable  # type: ignore[import-not-found]


class TestProcessIdentity(unittest.TestCase):
    """Test process identity syscall decoding."""

    test_executable: Path
    python_path: str
    strace_module: str
    exit_code: int
    syscalls: list[dict]

    @classmethod
    def setUpClass(cls) -> None:
        """Run the test executable once and capture syscalls for all tests."""
        cls.test_executable = get_test_executable()
        cls.python_path = "/usr/bin/python3"
        cls.strace_module = str(Path(__file__).parent.parent)

        # Run strace once and capture output
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_file = Path(f.name)

        try:
            cmd = [
                cls.python_path,
                "-m",
                "strace_macos",
                "--json",
                "-o",
                str(output_file),
                str(cls.test_executable),
                "--process-identity",
            ]
            result = subprocess.run(
                cmd,
                check=False,
                cwd=cls.strace_module,
                capture_output=True,
                text=True,
            )

            cls.exit_code = result.returncode
            if output_file.exists():
                cls.syscalls = helpers.json_lines(output_file)
            else:
                cls.syscalls = []
        finally:
            if output_file.exists():
                output_file.unlink()

    def test_executable_exits_successfully(self) -> None:
        """Test that the executable runs without errors."""
        assert self.exit_code == 0, f"Test executable should exit with 0, got {self.exit_code}"

    def test_process_identity_coverage(self) -> None:
        """Test that expected process identity syscalls are captured."""
        syscall_names = [sc.get("syscall") for sc in self.syscalls]

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

        captured = expected_syscalls & set(syscall_names)
        missing = expected_syscalls - set(syscall_names)

        # We should capture all of these
        assert len(captured) >= 22, (
            f"Should capture at least 22 process identity syscalls, got {len(captured)}.\n"
            f"Captured: {sorted(captured)}\n"
            f"Missing: {sorted(missing)}"
        )

    def test_initgroups_string_decoding(self) -> None:
        """Test that initgroups() properly decodes the username string argument."""
        initgroups_calls = [sc for sc in self.syscalls if sc.get("syscall") == "initgroups"]

        # Should have initgroups calls
        assert len(initgroups_calls) >= 2, (
            f"Should have at least 2 initgroups calls, got {len(initgroups_calls)}"
        )

        # Check that at least one call has a valid username string decoded
        valid_username_found = False
        for call in initgroups_calls:
            # initgroups has 4 args on macOS: name, basegid, groups, ngroups
            assert len(call["args"]) == 4, f"initgroups should have 4 args, got {len(call['args'])}"

            # First arg should be username string (decoded from pointer)
            username = call["args"][0]
            assert isinstance(username, str), (
                f"initgroups name should be string, got {type(username)}"
            )

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
            calls = [sc for sc in self.syscalls if sc.get("syscall") == syscall_name]
            for call in calls:
                assert len(call["args"]) == 0, (
                    f"{syscall_name} should have 0 args, got {len(call['args'])}"
                )

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
            calls = [sc for sc in self.syscalls if sc.get("syscall") == syscall_name]
            for call in calls:
                assert len(call["args"]) == 1, (
                    f"{syscall_name} should have 1 arg, got {len(call['args'])}"
                )

        # Two-argument syscalls
        for syscall_name in [
            "setpgid",
            "setreuid",
            "setregid",
            "getgroups",
            "setgroups",
            "getlogin",
        ]:
            calls = [sc for sc in self.syscalls if sc.get("syscall") == syscall_name]
            for call in calls:
                assert len(call["args"]) == 2, (
                    f"{syscall_name} should have 2 args, got {len(call['args'])}"
                )

        # Four-argument syscall (initgroups)
        initgroups_calls = [sc for sc in self.syscalls if sc.get("syscall") == "initgroups"]
        for call in initgroups_calls:
            assert len(call["args"]) == 4, f"initgroups should have 4 args, got {len(call['args'])}"

    def test_setlogin_string_decoding(self) -> None:
        """Test that setlogin() properly decodes the string argument."""
        setlogin_calls = [sc for sc in self.syscalls if sc.get("syscall") == "setlogin"]

        # Should have at least one setlogin call
        assert len(setlogin_calls) >= 1, (
            f"Should have at least 1 setlogin call, got {len(setlogin_calls)}"
        )

        # Check that the string argument is properly decoded
        for call in setlogin_calls:
            assert len(call["args"]) == 1, f"setlogin should have 1 arg, got {len(call['args'])}"

            # First arg should be the username string
            username = call["args"][0]
            assert isinstance(username, str), (
                f"setlogin name should be string, got {type(username)}"
            )
            assert username == "testuser", f"setlogin name should be 'testuser', got '{username}'"

    def test_issetugid_return_value(self) -> None:
        """Test that issetugid() returns valid boolean-ish values."""
        issetugid_calls = [sc for sc in self.syscalls if sc.get("syscall") == "issetugid"]

        # Should have at least one issetugid call
        assert len(issetugid_calls) >= 1, (
            f"Should have at least 1 issetugid call, got {len(issetugid_calls)}"
        )

        # Check return values are 0 or 1
        for call in issetugid_calls:
            assert len(call["args"]) == 0, f"issetugid should have 0 args, got {len(call['args'])}"
            ret = call.get("return")
            assert ret is not None, "issetugid should have a return value"
            assert ret in [0, 1], f"issetugid should return 0 or 1, got {ret}"


if __name__ == "__main__":
    unittest.main()
