"""
Test memory management syscalls.

Tests coverage for:
- mmap (memory mapping with various flags and protections)
- munmap (unmapping memory)
- mprotect (changing memory protection)
- madvise (advising kernel on memory usage)
- msync (synchronizing memory with storage)
- mlock, munlock (locking/unlocking pages in memory)
- mincore (checking which pages are in memory)
- minherit (setting inheritance of memory regions)
- mlockall, munlockall (locking/unlocking all pages)
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
import syscall_test_helpers as sth  # type: ignore[import-not-found]


class TestMemorySyscalls(unittest.TestCase):
    """Test memory management syscall decoding."""

    exit_code: int
    syscalls: list[dict]

    @classmethod
    def setUpClass(cls) -> None:
        """Run the test executable once and capture syscalls for all tests."""
        cls.exit_code, cls.syscalls = sth.run_strace_for_mode("--memory", Path(__file__))

    def test_executable_exits_successfully(self) -> None:
        """Test that the executable runs without errors."""
        assert self.exit_code == 0, f"Test executable should exit with 0, got {self.exit_code}"

    def test_memory_coverage(self) -> None:
        """Test that all expected memory management syscalls are captured."""
        # Expected syscalls from our test mode (all should be traced even if they fail)
        expected_syscalls = {
            "mmap",
            "munmap",
            "mprotect",
            "madvise",
            "msync",
            "mlock",
            "munlock",
            "mincore",
            "minherit",
            "mlockall",
            "munlockall",
        }

        # We should capture all expected syscalls
        sth.assert_syscall_coverage(
            self.syscalls, expected_syscalls, len(expected_syscalls), "memory syscalls"
        )

        # Basic argument count checks
        mmap_calls = sth.filter_syscalls(self.syscalls, "mmap")
        sth.assert_min_call_count(mmap_calls, 5, "mmap")
        sth.assert_arg_count(mmap_calls[0], 6, "mmap")

        munmap_calls = sth.filter_syscalls(self.syscalls, "munmap")
        sth.assert_min_call_count(munmap_calls, 5, "munmap")
        sth.assert_arg_count(munmap_calls[0], 2, "munmap")

        mlock_calls = sth.filter_syscalls(self.syscalls, "mlock")
        munlock_calls = sth.filter_syscalls(self.syscalls, "munlock")
        sth.assert_min_call_count(mlock_calls, 1, "mlock")
        sth.assert_min_call_count(munlock_calls, 1, "munlock")

    def test_mmap_protection_flags(self) -> None:
        """Test that various PROT_* flags are properly decoded."""
        mmap_calls = sth.filter_syscalls(self.syscalls, "mmap")

        prot_flags_found = sth.collect_flags_from_calls(mmap_calls, 2)

        # Should see various protection combinations
        # At minimum: PROT_READ|PROT_WRITE, PROT_NONE, PROT_READ|PROT_WRITE|PROT_EXEC
        assert any("PROT_READ" in p and "PROT_WRITE" in p for p in prot_flags_found), (
            f"Should have PROT_READ|PROT_WRITE, got {prot_flags_found}"
        )
        assert any("PROT_NONE" in p for p in prot_flags_found), (
            f"Should have PROT_NONE, got {prot_flags_found}"
        )

    def test_mmap_map_flags(self) -> None:
        """Test that various MAP_* flags are properly decoded."""
        mmap_calls = sth.filter_syscalls(self.syscalls, "mmap")

        # Should see MAP_PRIVATE, MAP_ANON at minimum
        sth.assert_flag_present(mmap_calls, 3, "MAP_PRIVATE", "mmap")
        sth.assert_flag_present(mmap_calls, 3, "MAP_ANON", "mmap")
        # Should also see MAP_SHARED
        sth.assert_flag_present(mmap_calls, 3, "MAP_SHARED", "mmap")

    def test_mprotect_protection_flags(self) -> None:
        """Test mprotect() syscall with protection flag decoding."""
        mprotect_calls = sth.filter_syscalls(self.syscalls, "mprotect")

        sth.assert_min_call_count(mprotect_calls, 4, "mprotect")

        # Check we see different protection levels
        prot_values = sth.collect_flags_from_calls(mprotect_calls, 2)
        assert "PROT_READ" in prot_values, f"Should have PROT_READ, got {prot_values}"
        assert "PROT_NONE" in prot_values, f"Should have PROT_NONE, got {prot_values}"
        assert any("PROT_READ" in p and "PROT_WRITE" in p for p in prot_values), (
            f"Should have PROT_READ|PROT_WRITE, got {prot_values}"
        )

    def test_madvise_advice_constants(self) -> None:
        """Test madvise() syscall with advice constant decoding."""
        madvise_calls = sth.filter_syscalls(self.syscalls, "madvise")

        sth.assert_min_call_count(madvise_calls, 5, "madvise")

        # Check we see different advice values
        advice_values = sth.collect_flags_from_calls(madvise_calls, 2)
        expected_advice = {
            "MADV_NORMAL",
            "MADV_RANDOM",
            "MADV_SEQUENTIAL",
            "MADV_WILLNEED",
            "MADV_DONTNEED",
        }
        found_advice = expected_advice & advice_values
        assert len(found_advice) >= 3, (
            f"Should have at least 3 different MADV_ values, got {advice_values}"
        )

    def test_msync_flags(self) -> None:
        """Test msync() syscall with flag decoding."""
        msync_calls = sth.filter_syscalls(self.syscalls, "msync")

        sth.assert_min_call_count(msync_calls, 3, "msync")

        # Check we see different flag values
        flag_values = sth.collect_flags_from_calls(msync_calls, 2)
        expected_flags = {"MS_SYNC", "MS_ASYNC", "MS_INVALIDATE"}
        found_flags = expected_flags & flag_values
        assert len(found_flags) >= 2, (
            f"Should have at least 2 different MS_ flags, got {flag_values}"
        )

    def test_minherit_constants(self) -> None:
        """Test minherit() syscall with VM_INHERIT constant decoding."""
        minherit_calls = sth.filter_syscalls(self.syscalls, "minherit")

        sth.assert_min_call_count(minherit_calls, 3, "minherit")

        # Check we see different inheritance values
        inherit_values = sth.collect_flags_from_calls(minherit_calls, 2)
        expected_values = {"VM_INHERIT_SHARE", "VM_INHERIT_COPY", "VM_INHERIT_NONE"}
        found_values = expected_values & inherit_values
        assert len(found_values) >= 3, f"Should have all 3 VM_INHERIT values, got {inherit_values}"

    def test_mlockall_munlockall(self) -> None:
        """Test mlockall() and munlockall() syscalls."""
        mlockall_calls = sth.filter_syscalls(self.syscalls, "mlockall")
        munlockall_calls = sth.filter_syscalls(self.syscalls, "munlockall")

        # Should have multiple mlockall calls with different flags
        sth.assert_min_call_count(mlockall_calls, 3, "mlockall")

        # Check for MCL_CURRENT and MCL_FUTURE flags
        sth.assert_arg_count(mlockall_calls[0], 1, "mlockall")

        # Should see both MCL_CURRENT and MCL_FUTURE
        sth.assert_flag_present(mlockall_calls, 0, "MCL_CURRENT", "mlockall")
        sth.assert_flag_present(mlockall_calls, 0, "MCL_FUTURE", "mlockall")

        # Should have matching munlockall calls
        sth.assert_min_call_count(munlockall_calls, 3, "munlockall")


if __name__ == "__main__":
    unittest.main()
