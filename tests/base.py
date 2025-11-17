"""Base test case class for strace-macos tests."""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from tests.fixtures.compile import get_test_executable


class StraceTestCase(unittest.TestCase):
    """Base test case with common setup for strace-macos tests.

    Provides:
    - temp_dir: Temporary directory for test outputs and working files
    - test_executable: Path to compiled test executable (shared across all tests)
    - Automatic cleanup of temp_dir after test
    - Preservation and restoration of current working directory
    """

    def setUp(self) -> None:
        """Create temporary directory and preserve current directory."""
        self.temp_dir = Path(tempfile.mkdtemp(prefix="strace_test_"))
        self.addCleanup(lambda: shutil.rmtree(self.temp_dir, ignore_errors=True))

        # Store and restore original cwd
        self.orig_cwd = Path.cwd()
        self.addCleanup(lambda: os.chdir(self.orig_cwd) if self.orig_cwd.exists() else None)

        # Get test executable (compiled once, reused for all tests)
        self.test_executable = get_test_executable()

        # Store project root for PYTHONPATH
        self.project_root = Path(__file__).parent.parent

    def get_test_env(self) -> dict[str, str]:
        """Get environment dict with PYTHONPATH set to project root.

        Use this when spawning subprocess tests that need to import strace_macos.

        Returns:
            Environment dict with PYTHONPATH configured
        """
        env = os.environ.copy()
        env["PYTHONPATH"] = str(self.project_root)
        return env
