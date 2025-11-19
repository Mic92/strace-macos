"""
Test file utilities syscalls.

Tests coverage for:
- flock (file locking)
- fsync, fdatasync (file synchronization)
- chdir, fchdir, chroot (directory changes)
- truncate, ftruncate (file size)
- utimes, futimes (file times)
- mkfifo, mkfifoat (named pipes)
- mknod, mknodat (special files)
- getattrlistat, getattrlistbulk, fchownat (extended attributes)
- clonefileat, fclonefileat (APFS clones)
- statfs, fstatfs, getfsstat (filesystem statistics)
- getxattr, fgetxattr, setxattr, fsetxattr, fremovexattr (extended attributes)
- fsctl, ffsctl, fsgetpath (filesystem control)
- copyfile, searchfs, exchangedata, undelete, revoke (special filesystem operations)
- getfh, fhopen (file handle operations)
- chflags, fchflags (file flags)
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
import syscall_test_helpers as sth  # type: ignore[import-not-found]


class TestFileUtilitiesSyscalls(unittest.TestCase):
    """Test file utilities syscall decoding."""

    exit_code: int
    syscalls: list[dict]

    @classmethod
    def setUpClass(cls) -> None:
        """Run the test executable once and capture syscalls for all tests."""
        cls.exit_code, cls.syscalls = sth.run_strace_for_mode("--file-utilities", Path(__file__))

    def test_executable_exits_successfully(self) -> None:
        """Test that the executable runs without errors."""
        assert self.exit_code == 0, f"Test executable should exit with 0, got {self.exit_code}"

    def test_file_utilities_coverage(self) -> None:
        """Test that expected file utilities syscalls are captured."""
        # Expected syscalls from our test mode
        expected_syscalls = {
            "flock",
            "fsync",
            "fdatasync",
            "chdir",
            "fchdir",
            "truncate",
            "ftruncate",
            "utimes",
            "futimes",
            "mkfifo",
            "mkfifoat",
            "mknod",
            "mknodat",
            "getattrlist",
            "fgetattrlist",
            "getattrlistat",
            "getattrlistbulk",
            "setattrlist",
            "fsetattrlist",
            "setattrlistat",
            "fchownat",
            # chroot will likely fail, but should still be captured
            # clonefileat/fclonefileat may fail but should be captured
        }

        # We should capture most of these
        sth.assert_syscall_coverage(self.syscalls, expected_syscalls, 19, "file utilities syscalls")

    def test_flock_operations(self) -> None:
        """Test flock() syscall with various lock types."""
        flock_calls = sth.filter_syscalls(self.syscalls, "flock")
        sth.assert_min_call_count(flock_calls, 5, "flock")

        # Check for different lock types
        operations_found = set()
        for call in flock_calls:
            op = call["args"][1]
            # op is a string like "LOCK_SH" or "LOCK_EX|LOCK_NB"
            if isinstance(op, str):
                # Split by | to get individual flags
                for flag in op.split("|"):
                    operations_found.add(flag)

        # Should see LOCK_SH, LOCK_EX, LOCK_UN, and LOCK_NB
        assert any("LOCK_SH" in op for op in operations_found), (
            f"Should have LOCK_SH operation, got operations: {operations_found}"
        )
        assert any("LOCK_EX" in op for op in operations_found), (
            f"Should have LOCK_EX operation, got operations: {operations_found}"
        )
        assert any("LOCK_UN" in op for op in operations_found), (
            f"Should have LOCK_UN operation, got operations: {operations_found}"
        )
        assert any("LOCK_NB" in op for op in operations_found), (
            f"Should have LOCK_NB flag, got operations: {operations_found}"
        )

    def test_sync_operations(self) -> None:
        """Test fsync() and fdatasync() syscalls."""
        fsync_calls = sth.filter_syscalls(self.syscalls, "fsync")
        fdatasync_calls = sth.filter_syscalls(self.syscalls, "fdatasync")

        sth.assert_min_call_count(fsync_calls, 2, "fsync")
        sth.assert_min_call_count(fdatasync_calls, 2, "fdatasync")

        # Both should have fd as first argument
        for call in fsync_calls:
            sth.assert_arg_type(call, 0, int, "fsync fd")
            assert call["args"][0] >= 0, "fsync fd should be valid"

        for call in fdatasync_calls:
            sth.assert_arg_type(call, 0, int, "fdatasync fd")
            assert call["args"][0] >= 0, "fdatasync fd should be valid"

    def test_directory_change_operations(self) -> None:
        """Test chdir(), fchdir(), chroot() syscalls."""
        chdir_calls = sth.filter_syscalls(self.syscalls, "chdir")
        fchdir_calls = sth.filter_syscalls(self.syscalls, "fchdir")
        chroot_calls = sth.filter_syscalls(self.syscalls, "chroot")

        # Should have chdir calls
        sth.assert_min_call_count(chdir_calls, 1, "chdir")
        call = chdir_calls[0]
        sth.assert_arg_type(call, 0, str, "chdir path")
        # Path should be valid directory path
        path = call["args"][0]
        assert path.startswith("/") or path in [".", ".."], (
            f"chdir path should be absolute or relative, got {path}"
        )

        # Should have fchdir calls
        sth.assert_min_call_count(fchdir_calls, 1, "fchdir")
        sth.assert_arg_type(fchdir_calls[0], 0, int, "fchdir fd")

        # chroot likely failed but should have been called
        sth.assert_min_call_count(chroot_calls, 1, "chroot")
        sth.assert_arg_type(chroot_calls[0], 0, str, "chroot path")

    def test_truncate_operations(self) -> None:
        """Test truncate() and ftruncate() syscalls."""
        truncate_calls = sth.filter_syscalls(self.syscalls, "truncate")
        ftruncate_calls = sth.filter_syscalls(self.syscalls, "ftruncate")

        sth.assert_min_call_count(truncate_calls, 3, "truncate")
        sth.assert_min_call_count(ftruncate_calls, 3, "ftruncate")

        # Check truncate arguments
        for call in truncate_calls:
            sth.assert_arg_type(call, 0, str, "truncate path")
            sth.assert_arg_type(call, 1, int, "truncate length")
            assert call["args"][1] >= 0, "truncate length should be non-negative"

        # Check ftruncate arguments
        for call in ftruncate_calls:
            sth.assert_arg_type(call, 0, int, "ftruncate fd")
            sth.assert_arg_type(call, 1, int, "ftruncate length")
            assert call["args"][1] >= 0, "ftruncate length should be non-negative"

    def test_time_modification_operations(self) -> None:
        """Test utimes() and futimes() syscalls."""
        utimes_calls = sth.filter_syscalls(self.syscalls, "utimes")
        futimes_calls = sth.filter_syscalls(self.syscalls, "futimes")

        sth.assert_min_call_count(utimes_calls, 2, "utimes")
        sth.assert_min_call_count(futimes_calls, 2, "futimes")

        # Check utimes arguments
        for call in utimes_calls:
            sth.assert_arg_type(call, 0, str, "utimes path")
            # Second arg is timeval pointer - can be NULL or pointer

        # Check futimes arguments
        for call in futimes_calls:
            sth.assert_arg_type(call, 0, int, "futimes fd")

    def test_special_file_creation(self) -> None:
        """Test mkfifo(), mkfifoat(), mknod(), mknodat() syscalls."""
        mkfifo_calls = sth.filter_syscalls(self.syscalls, "mkfifo")
        mkfifoat_calls = sth.filter_syscalls(self.syscalls, "mkfifoat")
        mknod_calls = sth.filter_syscalls(self.syscalls, "mknod")
        mknodat_calls = sth.filter_syscalls(self.syscalls, "mknodat")

        # Should have mkfifo
        sth.assert_min_call_count(mkfifo_calls, 1, "mkfifo")
        call = mkfifo_calls[0]
        sth.assert_arg_count(call, 2, "mkfifo")
        sth.assert_arg_type(call, 0, str, "mkfifo path")
        sth.assert_octal_mode(call, 1, "mkfifo")

        # Should have mkfifoat
        sth.assert_min_call_count(mkfifoat_calls, 1, "mkfifoat")
        call = mkfifoat_calls[0]
        sth.assert_arg_count(call, 3, "mkfifoat")
        # First arg should be AT_FDCWD or fd
        sth.assert_arg_type(call, 1, str, "mkfifoat path")
        sth.assert_octal_mode(call, 2, "mkfifoat")

        # Should have mknod (may fail without root)
        sth.assert_min_call_count(mknod_calls, 1, "mknod")
        call = mknod_calls[0]
        sth.assert_arg_count(call, 3, "mknod")
        sth.assert_arg_type(call, 0, str, "mknod path")
        sth.assert_octal_mode(call, 1, "mknod")
        sth.assert_arg_type(call, 2, int, "mknod dev")

        # Should have mknodat (may fail without root)
        sth.assert_min_call_count(mknodat_calls, 1, "mknodat")
        sth.assert_arg_count(mknodat_calls[0], 4, "mknodat")

    def test_getattrlistat(self) -> None:
        """Test getattrlistat() syscall."""
        getattrlistat_calls = sth.filter_syscalls(self.syscalls, "getattrlistat")

        # May or may not succeed, but should be called
        sth.assert_min_call_count(getattrlistat_calls, 1, "getattrlistat")
        # Expects: dirfd, path, attrlist, attrbuf, size, options
        sth.assert_arg_count(getattrlistat_calls[0], 6, "getattrlistat")

    def test_clone_operations(self) -> None:
        """Test clonefileat() and fclonefileat() syscalls with CLONE flags."""
        clonefileat_calls = sth.filter_syscalls(self.syscalls, "clonefileat")
        fclonefileat_calls = sth.filter_syscalls(self.syscalls, "fclonefileat")

        # These may fail if not on APFS or files don't exist, but should be invoked
        # We test multiple calls with different flags
        sth.assert_min_call_count(clonefileat_calls, 2, "clonefileat")

        # Expects: src_dirfd, src_name, dst_dirfd, dst_name, flags
        for call in clonefileat_calls:
            sth.assert_arg_count(call, 5, "clonefileat")

        flags_seen = sth.collect_flags_from_calls(clonefileat_calls, 4)
        # Should have tested different CLONE flags
        assert len(flags_seen) >= 2, (
            f"Should have multiple different CLONE flags, got: {flags_seen}"
        )

        sth.assert_min_call_count(fclonefileat_calls, 2, "fclonefileat")

        # Expects: srcfd, dst_dirfd, dst_name, flags
        for call in fclonefileat_calls:
            sth.assert_arg_count(call, 4, "fclonefileat")

        flags_seen = sth.collect_flags_from_calls(fclonefileat_calls, 3)
        # Should have tested CLONE_NOFOLLOW
        assert any("CLONE_NOFOLLOW" in f or "0x1" in f or "0x0001" in f for f in flags_seen), (
            f"Should have CLONE_NOFOLLOW flag, got flags: {flags_seen}"
        )

    def test_attribute_syscalls(self) -> None:
        """Test getattrlist/setattrlist family of syscalls."""
        getattrlist_calls = sth.filter_syscalls(self.syscalls, "getattrlist")
        fgetattrlist_calls = sth.filter_syscalls(self.syscalls, "fgetattrlist")
        setattrlist_calls = sth.filter_syscalls(self.syscalls, "setattrlist")
        fsetattrlist_calls = sth.filter_syscalls(self.syscalls, "fsetattrlist")
        getattrlistbulk_calls = sth.filter_syscalls(self.syscalls, "getattrlistbulk")
        fchownat_calls = sth.filter_syscalls(self.syscalls, "fchownat")

        # Should have getattrlist
        sth.assert_min_call_count(getattrlist_calls, 1, "getattrlist")
        call = getattrlist_calls[0]
        # Expects: path, attrlist, attrbuf, size, options
        sth.assert_arg_count(call, 5, "getattrlist")
        # Check attrlist struct is decoded
        fields = sth.assert_struct_field(call, 1, "commonattr", "getattrlist")
        # Should see ATTR_CMN_NAME or ATTR_CMN_OBJTYPE
        commonattr = str(fields["commonattr"])
        assert "ATTR_CMN" in commonattr, (
            f"commonattr should be decoded symbolically, got {commonattr}"
        )

        # Should have fgetattrlist
        sth.assert_min_call_count(fgetattrlist_calls, 1, "fgetattrlist")
        # Expects: fd, attrlist, attrbuf, size, options
        sth.assert_arg_count(fgetattrlist_calls[0], 5, "fgetattrlist")

        # Should have setattrlist
        sth.assert_min_call_count(setattrlist_calls, 1, "setattrlist")
        # Expects: path, attrlist, attrbuf, size, options
        sth.assert_arg_count(setattrlist_calls[0], 5, "setattrlist")

        # Should have fsetattrlist
        sth.assert_min_call_count(fsetattrlist_calls, 1, "fsetattrlist")
        # Expects: fd, attrlist, attrbuf, size, options
        sth.assert_arg_count(fsetattrlist_calls[0], 5, "fsetattrlist")

        # Should have getattrlistbulk
        sth.assert_min_call_count(getattrlistbulk_calls, 1, "getattrlistbulk")
        # Expects: dirfd, attrlist, attrbuf, size, options
        sth.assert_arg_count(getattrlistbulk_calls[0], 5, "getattrlistbulk")

        # Should have fchownat with flags
        sth.assert_min_call_count(fchownat_calls, 2, "fchownat")
        # Expects: dirfd, path, uid, gid, flags
        for call in fchownat_calls:
            sth.assert_arg_count(call, 5, "fchownat")

        flags_seen = sth.collect_flags_from_calls(fchownat_calls, 4)
        # Should have tested AT_SYMLINK_NOFOLLOW
        assert any(
            "AT_SYMLINK_NOFOLLOW" in f or "0x20" in f or "0x0020" in f for f in flags_seen
        ), f"Should have AT_SYMLINK_NOFOLLOW flag, got flags: {flags_seen}"

    def test_statfs_operations(self) -> None:
        """Test statfs family syscalls decode properly."""
        stat_calls = sth.filter_syscalls(self.syscalls, "statfs")
        fstat_calls = sth.filter_syscalls(self.syscalls, "fstatfs")
        getfsstat_calls = sth.filter_syscalls(self.syscalls, "getfsstat")

        sth.assert_min_call_count(stat_calls, 2, "statfs")
        for call in stat_calls:
            # Expects: path, statfs_struct
            sth.assert_arg_count(call, 2, "statfs")
            sth.assert_arg_type(call, 0, str, "statfs path")
            # Second arg should be struct (dict) or pointer
            assert isinstance(call["args"][1], (dict, str))

        sth.assert_min_call_count(fstat_calls, 1, "fstatfs")
        sth.assert_min_call_count(getfsstat_calls, 2, "getfsstat")

    def test_xattr_operations(self) -> None:
        """Test extended attribute syscalls decode properly."""
        getxattr_calls = sth.filter_syscalls(self.syscalls, "getxattr")
        fgetxattr_calls = sth.filter_syscalls(self.syscalls, "fgetxattr")
        setxattr_calls = sth.filter_syscalls(self.syscalls, "setxattr")
        fsetxattr_calls = sth.filter_syscalls(self.syscalls, "fsetxattr")
        fremovexattr_calls = sth.filter_syscalls(self.syscalls, "fremovexattr")

        # Should have getxattr with different flags
        sth.assert_min_call_count(getxattr_calls, 2, "getxattr")
        # Expects: path, name, value, size, position, options
        for call in getxattr_calls:
            sth.assert_arg_count(call, 6, "getxattr")

        # Check for XATTR_NOFOLLOW flag
        flags_seen = sth.collect_flags_from_calls(getxattr_calls, 5)
        # At least one should have XATTR_NOFOLLOW
        assert any("XATTR_NOFOLLOW" in f for f in flags_seen), (
            f"Should have XATTR_NOFOLLOW flag, got flags: {flags_seen}"
        )

        # Should have various xattr syscalls
        sth.assert_min_call_count(fgetxattr_calls, 1, "fgetxattr")
        sth.assert_min_call_count(setxattr_calls, 2, "setxattr")
        sth.assert_min_call_count(fsetxattr_calls, 1, "fsetxattr")
        sth.assert_min_call_count(fremovexattr_calls, 1, "fremovexattr")

    def test_fsctl_operations(self) -> None:
        """Test filesystem control syscalls decode properly."""
        fsctl_calls = sth.filter_syscalls(self.syscalls, "fsctl")
        ffsctl_calls = sth.filter_syscalls(self.syscalls, "ffsctl")
        fsgetpath_calls = sth.filter_syscalls(self.syscalls, "fsgetpath")

        sth.assert_min_call_count(fsctl_calls, 1, "fsctl")
        sth.assert_min_call_count(ffsctl_calls, 1, "ffsctl")
        sth.assert_min_call_count(fsgetpath_calls, 1, "fsgetpath")

    def test_copyfile_and_searchfs_operations(self) -> None:
        """Test copyfile and searchfs syscalls decode properly."""
        copyfile_calls = sth.filter_syscalls(self.syscalls, "copyfile")
        searchfs_calls = sth.filter_syscalls(self.syscalls, "searchfs")

        # Should have copyfile with different flags
        sth.assert_min_call_count(copyfile_calls, 2, "copyfile")
        # Expects: src, dst, state, flags
        for call in copyfile_calls:
            sth.assert_arg_count(call, 4, "copyfile")

        # Check for different flags (COPYFILE_DATA, COPYFILE_XATTR)
        flags_seen = sth.collect_flags_from_calls(copyfile_calls, 3)
        # Should have tested different flags
        assert any("COPYFILE_DATA" in f for f in flags_seen) or any(
            "COPYFILE_XATTR" in f for f in flags_seen
        ), f"Should have COPYFILE_DATA or COPYFILE_XATTR flag, got flags: {flags_seen}"

        # Should have searchfs with SRCHFS_MATCHFILES flag
        sth.assert_min_call_count(searchfs_calls, 1, "searchfs")
        # Expects: path, searchblock, nummatches, options, timeout, searchstate
        for call in searchfs_calls:
            sth.assert_arg_count(call, 6, "searchfs")

    def test_exchangedata_undelete_revoke(self) -> None:
        """Test exchangedata, undelete, and revoke syscalls."""
        exchangedata_calls = sth.filter_syscalls(self.syscalls, "exchangedata")
        undelete_calls = sth.filter_syscalls(self.syscalls, "undelete")
        revoke_calls = sth.filter_syscalls(self.syscalls, "revoke")

        sth.assert_min_call_count(exchangedata_calls, 1, "exchangedata")
        # undelete will fail on modern macOS but should be traced
        sth.assert_min_call_count(undelete_calls, 1, "undelete")
        sth.assert_min_call_count(revoke_calls, 1, "revoke")

    def test_file_handle_operations(self) -> None:
        """Test getfh() and fhopen() syscalls."""
        getfh_calls = sth.filter_syscalls(self.syscalls, "getfh")
        fhopen_calls = sth.filter_syscalls(self.syscalls, "fhopen")

        # getfh should be called at least once
        sth.assert_min_call_count(getfh_calls, 1, "getfh")
        # Expects: path, fhp
        call = getfh_calls[0]
        sth.assert_arg_count(call, 2, "getfh")
        sth.assert_arg_type(call, 0, str, "getfh path")
        # Second arg is a pointer to file handle buffer

        # fhopen is called if getfh succeeded (may fail for security reasons)
        if fhopen_calls:
            # Expects: fhp, flags
            call = fhopen_calls[0]
            sth.assert_arg_count(call, 2, "fhopen")
            # First arg is file handle pointer
            # Second arg should be flags (O_RDONLY in our test)

    def test_file_flags_operations(self) -> None:
        """Test chflags() and fchflags() syscalls."""
        chflags_calls = sth.filter_syscalls(self.syscalls, "chflags")
        fchflags_calls = sth.filter_syscalls(self.syscalls, "fchflags")

        # Should have multiple chflags calls (clearing and setting flags)
        sth.assert_min_call_count(chflags_calls, 3, "chflags")

        for call in chflags_calls:
            # Expects: path, flags
            sth.assert_arg_count(call, 2, "chflags")
            sth.assert_arg_type(call, 0, str, "chflags path")
            sth.assert_arg_type(call, 1, (int, str), "chflags flags")

        # Should have multiple fchflags calls
        sth.assert_min_call_count(fchflags_calls, 3, "fchflags")

        for call in fchflags_calls:
            # Expects: fd, flags
            sth.assert_arg_count(call, 2, "fchflags")
            sth.assert_arg_type(call, 0, int, "fchflags fd")
            sth.assert_arg_type(call, 1, (int, str), "fchflags flags")

        # Check that we tested UF_NODUMP flag (0x1)
        all_flags = sth.collect_flags_from_calls(chflags_calls, 1)
        all_flags.update(sth.collect_flags_from_calls(fchflags_calls, 1))

        # Should have 0 (clear flags) and UF_NODUMP (0x1 or symbolic)
        assert any(f in {"0", 0} for f in all_flags), (
            f"Should have flag value 0, got flags: {all_flags}"
        )
        # UF_NODUMP might be decoded symbolically or as 0x1
        assert any("UF_NODUMP" in str(f) or f in {1, "0x1", "0x0001"} for f in all_flags), (
            f"Should have UF_NODUMP flag, got flags: {all_flags}"
        )


if __name__ == "__main__":
    unittest.main()
