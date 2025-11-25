"""
Test file metadata and permission syscalls.

Tests coverage for:
- access (check file accessibility)
- chmod, fchmod (change file permissions)
- chown, fchown (change file ownership)
- link, linkat (hard links)
- symlink, symlinkat, readlink, readlinkat (symbolic links)
- mkdir, mkdirat, rmdir (directory operations)
- rename, renameat (file renaming)
- unlinkat (extended unlink)
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
import syscall_test_helpers as sth  # type: ignore[import-not-found]


class TestFileMetadataSyscalls(unittest.TestCase):
    """Test file metadata and permission syscall decoding."""

    exit_code: int
    syscalls: list[dict]

    @classmethod
    def setUpClass(cls) -> None:
        """Run the test executable once and capture syscalls for all tests."""
        cls.exit_code, cls.syscalls = sth.run_strace_for_mode("--file-metadata", Path(__file__))

    def test_executable_exits_successfully(self) -> None:
        """Test that the executable runs without errors."""
        assert self.exit_code == 0, f"Test executable should exit with 0, got {self.exit_code}"

    def test_file_metadata_coverage(self) -> None:
        """Test that all expected file metadata syscalls are captured."""
        # Expected syscalls from our test mode
        expected_syscalls = {
            "access",
            "chmod",
            "fchmod",
            "chown",
            "fchown",
            "link",
            "linkat",
            "symlink",
            "symlinkat",
            "readlink",
            "readlinkat",
            "mkdir",
            "mkdirat",
            "rmdir",
            "rename",
            "renameat",
            "unlinkat",
        }

        # We should capture most of these (some might be optimized away)
        sth.assert_syscall_coverage(self.syscalls, expected_syscalls, 15, "file metadata syscalls")

    def test_access_mode_decoding(self) -> None:
        """Test access() syscall with mode flags decoding."""
        access_calls = sth.filter_syscalls(self.syscalls, "access")
        sth.assert_min_call_count(access_calls, 5, "access")

        # Check for various modes
        modes_found = sth.collect_flags_from_calls(access_calls, 1)

        # Should see F_OK, R_OK, W_OK, X_OK, and combinations
        assert any("F_OK" in m or m == "0" for m in modes_found), (
            f"Should have F_OK mode, got modes: {modes_found}"
        )
        assert any("R_OK" in m for m in modes_found), (
            f"Should have R_OK mode, got modes: {modes_found}"
        )

    def test_chmod_octal_mode_decoding(self) -> None:
        """Test chmod() and fchmod() with octal mode decoding."""
        # Check chmod calls
        chmod_calls = sth.filter_syscalls(self.syscalls, "chmod")
        sth.assert_min_call_count(chmod_calls, 3, "chmod")

        # Mode should be decoded as octal string like "0644"
        for call in chmod_calls:
            sth.assert_octal_mode(call, 1, "chmod")
            # Should be one of our test modes (includes directory chmod calls)
            mode_arg = call["args"][1]
            assert mode_arg in ["0644", "0755", "0700", "0600"], (
                f"Unexpected chmod mode: {mode_arg}"
            )

        # Check fchmod calls
        fchmod_calls = sth.filter_syscalls(self.syscalls, "fchmod")
        sth.assert_min_call_count(fchmod_calls, 2, "fchmod")

        for call in fchmod_calls:
            sth.assert_arg_type(call, 0, int, "fchmod fd")
            sth.assert_octal_mode(call, 1, "fchmod")

    def test_chown_arguments(self) -> None:
        """Test chown() and fchown() syscalls."""
        # Check chown calls
        chown_calls = sth.filter_syscalls(self.syscalls, "chown")
        sth.assert_min_call_count(chown_calls, 2, "chown")

        call = chown_calls[0]
        sth.assert_arg_count(call, 3, "chown")
        sth.assert_arg_type(call, 0, str, "chown path")
        sth.assert_arg_type(call, 1, int, "chown uid")
        sth.assert_arg_type(call, 2, int, "chown gid")

        # Check fchown calls
        fchown_calls = sth.filter_syscalls(self.syscalls, "fchown")
        sth.assert_min_call_count(fchown_calls, 2, "fchown")

        call = fchown_calls[0]
        sth.assert_arg_count(call, 3, "fchown")
        sth.assert_arg_type(call, 0, int, "fchown fd")
        sth.assert_arg_type(call, 1, int, "fchown uid")
        sth.assert_arg_type(call, 2, int, "fchown gid")

    def test_link_syscalls_arguments(self) -> None:
        """Test link() and linkat() for hard link creation."""
        # Check link calls
        link_calls = sth.filter_syscalls(self.syscalls, "link")
        sth.assert_min_call_count(link_calls, 1, "link")

        call = link_calls[0]
        sth.assert_arg_count(call, 2, "link")
        sth.assert_arg_type(call, 0, str, "link oldpath")
        sth.assert_arg_type(call, 1, str, "link newpath")

        # Check linkat calls
        linkat_calls = sth.filter_syscalls(self.syscalls, "linkat")
        sth.assert_min_call_count(linkat_calls, 1, "linkat")

        call = linkat_calls[0]
        sth.assert_arg_count(call, 5, "linkat")
        sth.assert_at_fdcwd(call, 0, "linkat olddirfd")

    def test_symlink_syscalls_arguments(self) -> None:
        """Test symlink(), symlinkat(), readlink(), and readlinkat()."""
        # Check symlink
        symlink_calls = sth.filter_syscalls(self.syscalls, "symlink")
        sth.assert_min_call_count(symlink_calls, 1, "symlink")

        call = symlink_calls[0]
        sth.assert_arg_count(call, 2, "symlink")
        sth.assert_arg_type(call, 0, str, "symlink target")
        sth.assert_arg_type(call, 1, str, "symlink linkpath")
        assert "/tmp/target" in call["args"][0], "symlink should reference target"  # noqa: S108

        # Check readlink
        readlink_calls = sth.filter_syscalls(self.syscalls, "readlink")
        sth.assert_min_call_count(readlink_calls, 1, "readlink")

        call = readlink_calls[0]
        sth.assert_arg_count(call, 3, "readlink")
        sth.assert_arg_type(call, 0, str, "readlink path")
        # buf should be decoded as output buffer
        assert isinstance(call["args"][1], (str, dict)), "readlink buf should be decoded"

        # Check symlinkat
        symlinkat_calls = sth.filter_syscalls(self.syscalls, "symlinkat")
        sth.assert_min_call_count(symlinkat_calls, 1, "symlinkat")

        call = symlinkat_calls[0]
        sth.assert_arg_count(call, 3, "symlinkat")
        sth.assert_at_fdcwd(call, 1, "symlinkat newdirfd")

        # Check readlinkat
        readlinkat_calls = sth.filter_syscalls(self.syscalls, "readlinkat")
        sth.assert_min_call_count(readlinkat_calls, 1, "readlinkat")

        call = readlinkat_calls[0]
        sth.assert_arg_count(call, 4, "readlinkat")
        sth.assert_at_fdcwd(call, 0, "readlinkat dirfd")

    def test_directory_syscalls_arguments(self) -> None:
        """Test mkdir(), rmdir(), mkdirat() with mode decoding."""
        # Check mkdir
        mkdir_calls = sth.filter_syscalls(self.syscalls, "mkdir")
        sth.assert_min_call_count(mkdir_calls, 2, "mkdir")

        for call in mkdir_calls:
            sth.assert_arg_count(call, 2, "mkdir")
            sth.assert_arg_type(call, 0, str, "mkdir path")
            sth.assert_octal_mode(call, 1, "mkdir")

        # Check mkdirat
        mkdirat_calls = sth.filter_syscalls(self.syscalls, "mkdirat")
        sth.assert_min_call_count(mkdirat_calls, 1, "mkdirat")

        call = mkdirat_calls[0]
        sth.assert_arg_count(call, 3, "mkdirat")
        sth.assert_at_fdcwd(call, 0, "mkdirat dirfd")
        sth.assert_octal_mode(call, 2, "mkdirat")

        # Check rmdir
        rmdir_calls = sth.filter_syscalls(self.syscalls, "rmdir")
        sth.assert_min_call_count(rmdir_calls, 6, "rmdir")

        for call in rmdir_calls:
            sth.assert_arg_count(call, 1, "rmdir")
            sth.assert_arg_type(call, 0, str, "rmdir path")

    def test_rename_syscalls_arguments(self) -> None:
        """Test rename() and renameat() syscalls."""
        # Check rename
        rename_calls = sth.filter_syscalls(self.syscalls, "rename")
        sth.assert_min_call_count(rename_calls, 1, "rename")

        call = rename_calls[0]
        sth.assert_arg_count(call, 2, "rename")
        sth.assert_arg_type(call, 0, str, "rename oldpath")
        sth.assert_arg_type(call, 1, str, "rename newpath")

        # Check renameat
        renameat_calls = sth.filter_syscalls(self.syscalls, "renameat")
        sth.assert_min_call_count(renameat_calls, 1, "renameat")

        call = renameat_calls[0]
        sth.assert_arg_count(call, 4, "renameat")
        sth.assert_at_fdcwd(call, 0, "renameat olddirfd")
        sth.assert_at_fdcwd(call, 2, "renameat newdirfd")

    def test_unlinkat_with_flags(self) -> None:
        """Test unlinkat() with AT_FDCWD and flags."""
        # Check unlinkat calls
        unlinkat_calls = sth.filter_syscalls(self.syscalls, "unlinkat")
        sth.assert_min_call_count(unlinkat_calls, 2, "unlinkat")

        for call in unlinkat_calls:
            sth.assert_arg_count(call, 3, "unlinkat")

            # Check dirfd is AT_FDCWD
            dirfd = call["args"][0]
            assert dirfd == "AT_FDCWD", f"unlinkat dirfd should be AT_FDCWD, got {dirfd}"

            # Check path is string
            sth.assert_arg_type(call, 1, str, "unlinkat path")

            # Check flags (either 0 or AT_REMOVEDIR string)
            flags = call["args"][2]
            assert flags in {"0", 0, "AT_REMOVEDIR"}, (
                f"unlinkat flags should be 0 or AT_REMOVEDIR, got {flags}"
            )

        # Verify we have at least one with AT_REMOVEDIR
        removedir_calls = [c for c in unlinkat_calls if c["args"][2] == "AT_REMOVEDIR"]
        sth.assert_min_call_count(removedir_calls, 1, "unlinkat with AT_REMOVEDIR flag")

    def test_chown_uid_gid_minus_one_regression(self) -> None:
        """Regression test for issue #11: uid/gid -1 should display as -1.

        When uid or gid is -1 (meaning "don't change"), it should be displayed as -1.
        The fixture uses: chown(path, -1, 1000) and fchown(fd, 1000, -1)
        """
        chown_calls = sth.filter_syscalls(self.syscalls, "chown")
        fchown_calls = sth.filter_syscalls(self.syscalls, "fchown")
        all_chown_calls = chown_calls + fchown_calls

        # Find calls where uid or gid is -1
        found_uid_minus_one = False
        found_gid_minus_one = False

        for call in all_chown_calls:
            if len(call.get("args", [])) >= 3:
                uid = call["args"][1]
                gid = call["args"][2]

                # Check for chown(path, -1, <gid>) - uid should be -1
                if uid == -1 and gid == 1000:
                    found_uid_minus_one = True

                # Check for fchown(fd, <uid>, -1) - gid should be -1
                if uid == 1000 and gid == -1:
                    found_gid_minus_one = True

        # The test fixture should have both cases
        assert found_uid_minus_one, "Test should have chown with uid=-1"
        assert found_gid_minus_one, "Test should have fchown with gid=-1"

    def test_readlink_shows_target_regression(self) -> None:
        """Regression test for issue #6: readlink should show the actual link target.

        readlink() and readlinkat() should decode the output buffer to show the
        symlink target path, not just the buffer pointer.
        The fixture creates: symlink("/tmp/target", ...) and symlink("/tmp/target2", ...)
        """
        readlink_calls = sth.filter_syscalls(self.syscalls, "readlink")
        sth.assert_min_call_count(readlink_calls, 1, "readlink")

        # Check that readlink shows the target path
        call = readlink_calls[0]
        buf = call["args"][1]
        assert isinstance(buf, str), f"readlink buf should be decoded as string, got {type(buf)}"
        assert "/tmp/target" in buf, (  # noqa: S108
            f"readlink should show symlink target '/tmp/target', got: {buf}"
        )

        # Check readlinkat
        readlinkat_calls = sth.filter_syscalls(self.syscalls, "readlinkat")
        sth.assert_min_call_count(readlinkat_calls, 1, "readlinkat")

        call = readlinkat_calls[0]
        buf = call["args"][2]
        assert isinstance(buf, str), f"readlinkat buf should be decoded as string, got {type(buf)}"
        assert "/tmp/target2" in buf, (  # noqa: S108
            f"readlinkat should show symlink target '/tmp/target2', got: {buf}"
        )


if __name__ == "__main__":
    unittest.main()
