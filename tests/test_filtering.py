"""Integration tests for syscall filtering options."""

from __future__ import annotations

from strace_macos.__main__ import main
from tests.base import StraceTestCase
from tests.fixtures import helpers


class TestFiltering(StraceTestCase):
    """Test -e trace= filtering options."""

    def test_filter_specific_syscalls(self) -> None:
        """Test filtering for specific syscalls with -e trace=open,close."""
        output_file = self.temp_dir / "trace.jsonl"
        test_file = self.temp_dir / "test.txt"

        # Use spawn mode with test executable (avoids SIP issues with system binaries)
        exit_code = main(
            [
                "--json",
                "-o",
                str(output_file),
                "-e",
                "trace=open,close",
                str(self.test_executable),
                "--file-ops",
                str(test_file),
            ]
        )

        assert exit_code == 0, "strace should exit with code 0"

        # Verify filtering worked
        assert output_file.exists(), "Output file should be created"

        syscalls = helpers.json_lines(output_file)
        syscall_names = [sc["syscall"] for sc in syscalls]

        # Should see filtered syscalls
        assert "open" in syscall_names or "openat" in syscall_names, (
            "Should capture open/openat syscall"
        )
        assert "close" in syscall_names, "Should capture close syscall"

        # Should NOT see other syscalls
        assert "write" not in syscall_names, "Should NOT capture write syscall"
        assert "read" not in syscall_names, "Should NOT capture read syscall"

    def test_filter_syscall_class_file(self) -> None:
        """Test filtering by syscall class with -e trace=file."""
        output_file = self.temp_dir / "trace.jsonl"
        test_file = self.temp_dir / "test.txt"

        # Use spawn mode with test executable (avoids SIP issues with system binaries)
        exit_code = main(
            [
                "--json",
                "-o",
                str(output_file),
                "-e",
                "trace=file",
                str(self.test_executable),
                "--file-ops",
                str(test_file),
            ]
        )

        assert exit_code == 0, "strace should exit with code 0"

        # Verify file operations were traced
        assert output_file.exists(), "Output file should be created"

        syscalls = helpers.json_lines(output_file)
        syscall_names = [sc["syscall"] for sc in syscalls]

        # Should see file-related syscalls
        assert "open" in syscall_names or "openat" in syscall_names, (
            "Should capture file operations"
        )

    def test_filter_syscall_class_network(self) -> None:
        """Test filtering by syscall class with -e trace=network."""
        output_file = self.temp_dir / "trace.jsonl"

        # Use spawn mode with test executable (avoids SIP issues with system binaries)
        exit_code = main(
            [
                "--json",
                "-o",
                str(output_file),
                "-e",
                "trace=network",
                str(self.test_executable),
                "--network",
            ]
        )

        assert exit_code == 0, "strace should exit with code 0"

        # Verify network operations were traced
        assert output_file.exists(), "Output file should be created"

        syscalls = helpers.json_lines(output_file)
        syscall_names = [sc["syscall"] for sc in syscalls]

        # Should see network-related syscalls (connect may not be captured due to threading/timing)
        assert "socket" in syscall_names, "Should capture socket syscall"
        assert "bind" in syscall_names, "Should capture bind syscall"
        assert "sendto" in syscall_names or "socketpair" in syscall_names, (
            "Should capture network data syscalls"
        )


if __name__ == "__main__":
    import unittest

    unittest.main()
