"""Tests for handling SIP-protected binaries."""

from __future__ import annotations

import contextlib
import io

from strace_macos.__main__ import main
from strace_macos.sip import is_sip_enabled
from tests.base import StraceTestCase


class TestSIPProtection(StraceTestCase):
    """Test handling of SIP-protected binaries."""

    def test_spawn_sip_protected_binary_stderr_message(self) -> None:
        """Test that spawning a SIP-protected binary outputs error to stderr when SIP is enabled."""
        # Skip test if SIP debugging restrictions are disabled (e.g., in CI environments)
        if not is_sip_enabled():
            self.skipTest("SIP debugging restrictions are disabled on this system")

        output_file = self.temp_dir / "trace.jsonl"

        # Capture stderr
        stderr_capture = io.StringIO()

        with contextlib.redirect_stderr(stderr_capture):
            exit_code = main(
                [
                    "--json",
                    "-o",
                    str(output_file),
                    "/bin/ls",
                    str(self.temp_dir),
                ]
            )

        stderr_output = stderr_capture.getvalue()

        # Should exit with error
        assert exit_code != 0, "strace should exit with non-zero code"

        # Stderr should contain informative error about SIP
        assert (
            "SIP" in stderr_output
            or "System Integrity Protection" in stderr_output
            or "protected" in stderr_output
        ), f"Error message should mention SIP or protection, got: {stderr_output}"
