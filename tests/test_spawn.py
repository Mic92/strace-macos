"""Integration tests for spawning and tracing new processes."""

from __future__ import annotations

import subprocess

from strace_macos.__main__ import main
from tests.base import StraceTestCase
from tests.fixtures import helpers


class TestSpawn(StraceTestCase):
    """Test spawning new processes and tracing them from start."""

    def test_spawn_simple_command(self) -> None:
        """Test spawning a simple command."""

        output_file = self.temp_dir / "trace.jsonl"

        # Trace test executable
        exit_code = main(
            [
                "--json",
                "-o",
                str(output_file),
                str(self.test_executable),
                "hello",
                "world",
            ]
        )

        assert exit_code == 0, "strace should exit with code 0"
        assert output_file.exists(), "Output file should be created"

        # Verify we captured syscalls
        syscalls = helpers.json_lines(output_file)
        assert len(syscalls) > 0, "Should capture some syscalls"

        # Verify JSON structure
        for sc in syscalls:
            assert helpers.verify_json_syscall_structure(sc), (
                f"Invalid JSON structure for syscall: {sc}"
            )

    def test_spawn_python_script_file_operations(self) -> None:
        """Test spawning a program that performs file I/O."""
        output_file = self.temp_dir / "trace.jsonl"
        test_file = self.temp_dir / "test.txt"

        # Trace the test executable with --file-ops flag
        exit_code = main(
            [
                "--json",
                "-o",
                str(output_file),
                str(self.test_executable),
                "--file-ops",
                str(test_file),
            ]
        )

        assert exit_code == 0, "Program should exit successfully"
        assert output_file.exists(), "Output file should be created"

        syscalls = helpers.json_lines(output_file)
        syscall_names = [sc["syscall"] for sc in syscalls]

        # Verify expected file I/O syscalls were captured
        assert "open" in syscall_names or "open_nocancel" in syscall_names, (
            "Should capture open syscall"
        )
        assert "write" in syscall_names or "write_nocancel" in syscall_names, (
            "Should capture write syscall"
        )
        assert "read" in syscall_names or "read_nocancel" in syscall_names, (
            "Should capture read syscall"
        )
        assert "close" in syscall_names or "close_nocancel" in syscall_names, (
            "Should capture close syscall"
        )
        assert "unlink" in syscall_names, "Should capture unlink syscall"

    def test_spawn_failing_command(self) -> None:
        """Test spawning a command that exits with non-zero status."""
        output_file = self.temp_dir / "trace.jsonl"

        # Trace test executable with --fail flag (exits with status 1)
        exit_code = main(
            [
                "--json",
                "-o",
                str(output_file),
                str(self.test_executable),
                "--fail",
            ]
        )

        # Should propagate non-zero exit code from traced process
        assert exit_code != 0, "Should propagate non-zero exit code from traced process"
        assert output_file.exists(), "Output file should still be created"

        # Should still capture syscalls even though command failed
        syscalls = helpers.json_lines(output_file)
        assert len(syscalls) > 0, "Should capture syscalls even on failure"

    def test_spawn_stdout_stderr_visible(self) -> None:
        """Test that traced process stdout/stderr is visible in output.

        Regression test for GitHub issue #48: LLDB was redirecting stdout/stderr
        to a pseudo-terminal, making traced process output invisible.
        """
        trace_output = self.temp_dir / "trace.jsonl"

        # Run strace in a subprocess so we can capture combined stdout/stderr
        result = subprocess.run(
            [
                "/usr/bin/python3",
                "-m",
                "strace_macos",
                "--json",
                "-o",
                str(trace_output),
                str(self.test_executable),
                "--stdio-test",
            ],
            capture_output=True,
            text=True,
            cwd=self.project_root,
            env=self.get_test_env(),
            check=False,
        )

        combined_output = result.stdout + result.stderr

        # Verify both stdout and stderr markers appear in the output
        assert "STDOUT_MARKER_12345" in combined_output, (
            f"Traced process stdout should be visible. Got: {combined_output[:500]}"
        )
        assert "STDERR_MARKER_67890" in combined_output, (
            f"Traced process stderr should be visible. Got: {combined_output[:500]}"
        )

        # Verify the trace completed successfully
        assert result.returncode == 0, f"strace should exit with code 0, got {result.returncode}"


if __name__ == "__main__":
    import unittest

    unittest.main()
