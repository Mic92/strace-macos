"""
Test system information syscalls.

Tests coverage for:
- sysctl (BSD sysctl with MIB array)
- sysctlbyname (name-based sysctl interface)
- sysctlnametomib (convert sysctl name to MIB)
- getdtablesize (get max file descriptors)
- gethostuuid (get host UUID)
- getentropy (get random bytes)
- usrctl (user space control)
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
import syscall_test_helpers as sth  # type: ignore[import-not-found]


class TestSystemInfoSyscalls(unittest.TestCase):
    """Test system information syscall decoding."""

    exit_code: int
    syscalls: list[dict]

    @classmethod
    def setUpClass(cls) -> None:
        """Run the test executable once and capture syscalls for all tests."""
        cls.exit_code, cls.syscalls = sth.run_strace_for_mode("--sysinfo", Path(__file__))

    def test_executable_exits_successfully(self) -> None:
        """Test that the executable runs without errors."""
        assert self.exit_code == 0, f"Test executable should exit with 0, got {self.exit_code}"

    def test_sysinfo_coverage(self) -> None:
        """Test that all expected system info syscalls are captured."""
        # Expected syscalls from our test mode (all should be traced even if they fail)
        expected_syscalls = {
            "sysctl",
            "sysctlbyname",
            "getdtablesize",
            "gethostuuid",
            "getentropy",
            "usrctl",
        }

        # We should capture all expected syscalls
        sth.assert_syscall_coverage(
            self.syscalls, expected_syscalls, len(expected_syscalls), "system info syscalls"
        )

    def test_sysctl_basic(self) -> None:
        """Test sysctl() syscall with MIB array decoding."""
        sysctl_calls = sth.filter_syscalls(self.syscalls, "sysctl")

        # Should have at least 4 sysctl calls
        sth.assert_min_call_count(sysctl_calls, 4, "sysctl")

        # sysctl has 6 arguments: (int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen)
        sth.assert_arg_count(sysctl_calls[0], 6, "sysctl")

    def test_sysctlbyname_basic(self) -> None:
        """Test sysctlbyname() syscall with name string decoding."""
        sysctlbyname_calls = sth.filter_syscalls(self.syscalls, "sysctlbyname")

        # Should have at least 4 sysctlbyname calls
        sth.assert_min_call_count(sysctlbyname_calls, 4, "sysctlbyname")

        # sysctlbyname has 5 arguments: (const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen)
        # But we might see 6 due to variadic args - check for at least 5
        for call in sysctlbyname_calls[:2]:
            assert len(call["args"]) >= 5, (
                f"sysctlbyname should have at least 5 args, got {len(call['args'])}"
            )

    def test_sysctlbyname_names(self) -> None:
        """Test that sysctlbyname decodes sysctl names as strings, not raw pointers."""
        sysctlbyname_calls = sth.filter_syscalls(self.syscalls, "sysctlbyname")

        # First argument should be decoded as a string (containing "kern" or "hw"),
        # not a raw pointer (which would be all digits or hex like "0x16fdff048")
        test_calls = [
            c
            for c in sysctlbyname_calls
            if any(keyword in c["args"][0] for keyword in ["kern", "hw"])
        ]

        assert len(test_calls) >= 3, (
            f"Should have at least 3 sysctlbyname calls with decoded string names (kern/hw), got {len(test_calls)}. "
            f"If this fails, the first arg is likely showing as raw pointer instead of decoded string."
        )

    def test_getdtablesize(self) -> None:
        """Test getdtablesize() syscall (no arguments)."""
        getdtablesize_calls = sth.filter_syscalls(self.syscalls, "getdtablesize")

        # Should have exactly 1 call
        sth.assert_min_call_count(getdtablesize_calls, 1, "getdtablesize")

        # Should have 0 arguments
        sth.assert_arg_count(getdtablesize_calls[0], 0, "getdtablesize")

    def test_gethostuuid(self) -> None:
        """Test gethostuuid() syscall with UUID and timeout."""
        gethostuuid_calls = sth.filter_syscalls(self.syscalls, "gethostuuid")

        # Should have at least 2 calls
        sth.assert_min_call_count(gethostuuid_calls, 2, "gethostuuid")

        # gethostuuid has 2 arguments: (uuid_t uuid, const struct timespec *timeout)
        sth.assert_arg_count(gethostuuid_calls[0], 2, "gethostuuid")

    def test_getentropy(self) -> None:
        """Test getentropy() syscall with buffer and size."""
        getentropy_calls = sth.filter_syscalls(self.syscalls, "getentropy")

        # Should have at least 2 calls
        sth.assert_min_call_count(getentropy_calls, 2, "getentropy")

        # getentropy has 2 arguments: (void *buffer, size_t size)
        sth.assert_arg_count(getentropy_calls[0], 2, "getentropy")

        # Second argument should be the size - check we see different sizes
        sizes = [call["args"][1] for call in getentropy_calls]
        unique_sizes = set(sizes)
        assert len(unique_sizes) >= 2, f"Should have at least 2 different sizes, got {sizes}"

    def test_usrctl(self) -> None:
        """Test usrctl() syscall with flags."""
        usrctl_calls = sth.filter_syscalls(self.syscalls, "usrctl")

        # Should have exactly 1 call
        sth.assert_min_call_count(usrctl_calls, 1, "usrctl")

        # usrctl has 1 argument: (uint32_t flags)
        sth.assert_arg_count(usrctl_calls[0], 1, "usrctl")

    # === REGRESSION TESTS: Verify proper decoding ===

    def test_sysctl_decodes_mib_array(self) -> None:
        """REGRESSION: sysctl should decode MIB array with symbolic names.

        Current (BAD):  sysctl(0x16fdff640, 2, 0x16fdff540, 0x16fdff070, 0x0, 0)
        Expected (GOOD): sysctl([CTL_KERN, KERN_OSTYPE], 2, "Darwin", [7], NULL, 0)
        """
        sysctl_calls = sth.filter_syscalls(self.syscalls, "sysctl")
        assert len(sysctl_calls) >= 1, "Should have at least one sysctl call"

        first_call = sysctl_calls[0]
        first_arg = first_call["args"][0]

        # First arg MUST start with '[' to indicate array decoding
        assert first_arg.startswith("["), (
            f"sysctl first arg MUST be decoded as array [int, int, ...]. "
            f"Got: {first_arg}\n"
            f"Expected format: [CTL_KERN, KERN_OSTYPE] or [1, 1]"
        )

        # Should decode symbolic names for known CTL_* constants
        # Look for at least one call with symbolic names
        symbolic_calls = [c for c in sysctl_calls if "CTL_" in c["args"][0]]
        assert len(symbolic_calls) >= 1, (
            f"sysctl should decode MIB with symbolic names like CTL_KERN. "
            f"Found {len(sysctl_calls)} sysctl calls but none with CTL_* symbols. "
            f"First call: {first_arg}"
        )

    def test_sysctlbyname_decodes_size_pointer(self) -> None:
        """REGRESSION: sysctlbyname should decode size pointer as [size].

        Current (BAD):  sysctlbyname("kern.ostype", 6171915048, 0x16fdff048, 0x0, 0x0, 0)
        Expected (GOOD): sysctlbyname("kern.ostype", "Darwin", [7], NULL, 0)
        """
        sysctlbyname_calls = sth.filter_syscalls(self.syscalls, "sysctlbyname")
        assert len(sysctlbyname_calls) >= 1, "Should have at least one sysctlbyname call"

        # Get first call from our test (should have size pointer)
        call = sysctlbyname_calls[0]
        third_arg = call["args"][2]  # size_t *oldlenp

        # Third arg MUST be decoded as [size] or similar, showing it's a pointer to size
        assert third_arg.startswith("[") or "size" in third_arg.lower(), (
            f"sysctlbyname size pointer (arg 3) MUST be decoded as [size]. "
            f"Got: {third_arg}\n"
            f"Expected format: [7] or [256] or <size>"
        )

    def test_gethostuuid_decodes_uuid(self) -> None:
        """REGRESSION: gethostuuid should decode UUID as hex string or array.

        Current (BAD):  gethostuuid(0x16fdff1b8, 0x16fdff000)
        Expected (GOOD): gethostuuid([A1B2C3D4-...], {tv_sec=5, tv_nsec=0})
        """
        gethostuuid_calls = sth.filter_syscalls(self.syscalls, "gethostuuid")
        assert len(gethostuuid_calls) >= 1, "Should have at least one gethostuuid call"

        call = gethostuuid_calls[0]
        first_arg = call["args"][0]

        # First arg MUST show UUID in some decoded form (array or UUID format)
        # Could be: [A1B2...] or {uuid=...} or similar
        assert first_arg.startswith(("[", "{")) or "-" in first_arg, (
            f"gethostuuid UUID arg MUST be decoded (array/struct/UUID format). "
            f"Got: {first_arg}\n"
            f"Expected format: [A1B2C3D4-E5F6-7890-ABCD-EF1234567890] or {{uuid=...}}"
        )

    def test_gethostuuid_decodes_timespec(self) -> None:
        """REGRESSION: gethostuuid should decode timespec struct.

        Current (BAD):  gethostuuid(0x16fdff1b8, 0x16fdff000)
        Expected (GOOD): gethostuuid([...], {tv_sec=5, tv_nsec=0})
        """
        gethostuuid_calls = sth.filter_syscalls(self.syscalls, "gethostuuid")
        assert len(gethostuuid_calls) >= 1, "Should have at least one gethostuuid call"

        # Find a call with non-NULL timeout
        timeout_calls = []
        for c in gethostuuid_calls:
            arg1 = c["args"][1]
            # Check if it's a struct (dict) or a non-zero string
            if isinstance(arg1, dict) or (
                isinstance(arg1, str)
                and arg1 not in ("0", "NULL", "0x0")
                and not arg1.startswith("0x0")
            ):
                timeout_calls.append(c)

        assert len(timeout_calls) >= 1, (
            "Should have at least one gethostuuid call with non-NULL timeout. "
            f"Found {len(gethostuuid_calls)} total calls but none with non-NULL timeout."
        )

        call = timeout_calls[0]
        second_arg = call["args"][1]

        # Second arg MUST be a struct dict with tv_sec and tv_nsec
        assert isinstance(second_arg, dict), (
            f"gethostuuid timeout arg MUST be decoded as struct (dict). "
            f"Got type: {type(second_arg)}, value: {second_arg}"
        )
        assert "tv_sec" in second_arg, (
            f"gethostuuid timeout struct MUST have tv_sec field. "
            f"Got: {second_arg}\n"
            f"Expected format: {{tv_sec=5, tv_nsec=0}}"
        )
        assert "tv_nsec" in second_arg, (
            f"gethostuuid timeout struct MUST have tv_nsec field. "
            f"Got: {second_arg}\n"
            f"Expected format: {{tv_sec=5, tv_nsec=0}}"
        )


if __name__ == "__main__":
    unittest.main()
