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

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
import helpers  # type: ignore[import-not-found]
from compile import get_test_executable  # type: ignore[import-not-found]


class TestMemorySyscalls(unittest.TestCase):
    """Test memory management syscall decoding."""

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
                "--memory",
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

    def test_memory_coverage(self) -> None:
        """Test that all expected memory management syscalls are captured."""
        syscall_names = [sc.get("syscall") for sc in self.syscalls]

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

        captured = expected_syscalls & set(syscall_names)
        missing = expected_syscalls - set(syscall_names)

        # We should capture all expected syscalls
        assert len(captured) == len(expected_syscalls), (
            f"Should capture all {len(expected_syscalls)} memory syscalls, got {len(captured)}.\n"
            f"Captured: {sorted(captured)}\n"
            f"Missing: {sorted(missing)}"
        )

        # Basic argument count checks
        mmap_calls = [sc for sc in self.syscalls if sc.get("syscall") == "mmap"]
        assert len(mmap_calls) >= 5, f"Expected at least 5 mmap calls, got {len(mmap_calls)}"
        assert len(mmap_calls[0]["args"]) == 6, "mmap should have 6 args"

        munmap_calls = [sc for sc in self.syscalls if sc.get("syscall") == "munmap"]
        assert len(munmap_calls) >= 5, f"Expected at least 5 munmap calls, got {len(munmap_calls)}"
        assert len(munmap_calls[0]["args"]) == 2, "munmap should have 2 args"

        mlock_calls = [sc for sc in self.syscalls if sc.get("syscall") == "mlock"]
        munlock_calls = [sc for sc in self.syscalls if sc.get("syscall") == "munlock"]
        assert len(mlock_calls) >= 1, "Expected at least 1 mlock call"
        assert len(munlock_calls) >= 1, "Expected at least 1 munlock call"

    def test_mmap_protection_flags(self) -> None:
        """Test that various PROT_* flags are properly decoded."""
        mmap_calls = [sc for sc in self.syscalls if sc.get("syscall") == "mmap"]

        prot_flags_found = set()
        for call in mmap_calls:
            prot = str(call["args"][2])
            prot_flags_found.add(prot)

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
        mmap_calls = [sc for sc in self.syscalls if sc.get("syscall") == "mmap"]

        map_flags_found = set()
        for call in mmap_calls:
            flags = str(call["args"][3])
            map_flags_found.add(flags)

        # Should see MAP_PRIVATE, MAP_ANON at minimum
        assert any("MAP_PRIVATE" in f for f in map_flags_found), (
            f"Should have MAP_PRIVATE, got {map_flags_found}"
        )
        assert any("MAP_ANON" in f for f in map_flags_found), (
            f"Should have MAP_ANON, got {map_flags_found}"
        )
        # Should also see MAP_SHARED
        assert any("MAP_SHARED" in f for f in map_flags_found), (
            f"Should have MAP_SHARED, got {map_flags_found}"
        )

    def test_mprotect_protection_flags(self) -> None:
        """Test mprotect() syscall with protection flag decoding."""
        mprotect_calls = [sc for sc in self.syscalls if sc.get("syscall") == "mprotect"]

        assert len(mprotect_calls) >= 4, (
            f"Expected at least 4 mprotect calls, got {len(mprotect_calls)}"
        )

        # Check we see different protection levels
        prot_values = {str(call["args"][2]) for call in mprotect_calls}
        assert "PROT_READ" in prot_values, f"Should have PROT_READ, got {prot_values}"
        assert "PROT_NONE" in prot_values, f"Should have PROT_NONE, got {prot_values}"
        assert any("PROT_READ" in p and "PROT_WRITE" in p for p in prot_values), (
            f"Should have PROT_READ|PROT_WRITE, got {prot_values}"
        )

    def test_madvise_advice_constants(self) -> None:
        """Test madvise() syscall with advice constant decoding."""
        madvise_calls = [sc for sc in self.syscalls if sc.get("syscall") == "madvise"]

        assert len(madvise_calls) >= 5, (
            f"Expected at least 5 madvise calls, got {len(madvise_calls)}"
        )

        # Check we see different advice values
        advice_values = {str(call["args"][2]) for call in madvise_calls}
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
        msync_calls = [sc for sc in self.syscalls if sc.get("syscall") == "msync"]

        assert len(msync_calls) >= 3, f"Expected at least 3 msync calls, got {len(msync_calls)}"

        # Check we see different flag values
        flag_values = {str(call["args"][2]) for call in msync_calls}
        expected_flags = {"MS_SYNC", "MS_ASYNC", "MS_INVALIDATE"}
        found_flags = expected_flags & flag_values
        assert len(found_flags) >= 2, (
            f"Should have at least 2 different MS_ flags, got {flag_values}"
        )

    def test_minherit_constants(self) -> None:
        """Test minherit() syscall with VM_INHERIT constant decoding."""
        minherit_calls = [sc for sc in self.syscalls if sc.get("syscall") == "minherit"]

        assert len(minherit_calls) >= 3, (
            f"Expected at least 3 minherit calls, got {len(minherit_calls)}"
        )

        # Check we see different inheritance values
        inherit_values = {str(call["args"][2]) for call in minherit_calls}
        expected_values = {"VM_INHERIT_SHARE", "VM_INHERIT_COPY", "VM_INHERIT_NONE"}
        found_values = expected_values & inherit_values
        assert len(found_values) >= 3, f"Should have all 3 VM_INHERIT values, got {inherit_values}"

    def test_mlockall_munlockall(self) -> None:
        """Test mlockall() and munlockall() syscalls."""
        mlockall_calls = [sc for sc in self.syscalls if sc.get("syscall") == "mlockall"]
        munlockall_calls = [sc for sc in self.syscalls if sc.get("syscall") == "munlockall"]

        # Should have multiple mlockall calls with different flags
        assert len(mlockall_calls) >= 3, (
            f"Expected at least 3 mlockall calls, got {len(mlockall_calls)}"
        )

        # Check for MCL_CURRENT and MCL_FUTURE flags
        flags_seen = set()
        for call in mlockall_calls:
            assert len(call["args"]) == 1, f"mlockall should have 1 arg, got {len(call['args'])}"
            flag_arg = str(call["args"][0])
            flags_seen.add(flag_arg)

        # Should see both MCL_CURRENT and MCL_FUTURE
        assert any("MCL_CURRENT" in f for f in flags_seen), (
            f"Should have MCL_CURRENT flag, got flags: {flags_seen}"
        )
        assert any("MCL_FUTURE" in f for f in flags_seen), (
            f"Should have MCL_FUTURE flag, got flags: {flags_seen}"
        )

        # Should have matching munlockall calls
        assert len(munlockall_calls) >= 3, (
            f"Expected at least 3 munlockall calls, got {len(munlockall_calls)}"
        )


if __name__ == "__main__":
    unittest.main()
