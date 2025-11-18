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


class TestFileUtilitiesSyscalls(unittest.TestCase):
    """Test file utilities syscall decoding."""

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
                "--file-utilities",
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

    def test_file_utilities_coverage(self) -> None:
        """Test that expected file utilities syscalls are captured."""
        syscall_names = [sc.get("syscall") for sc in self.syscalls]

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

        captured = expected_syscalls & set(syscall_names)
        missing = expected_syscalls - set(syscall_names)

        # We should capture most of these
        assert len(captured) >= 19, (
            f"Should capture at least 19 file utilities syscalls, got {len(captured)}.\n"
            f"Captured: {sorted(captured)}\n"
            f"Missing: {sorted(missing)}"
        )

    def test_flock_operations(self) -> None:
        """Test flock() syscall with various lock types."""
        flock_calls = [sc for sc in self.syscalls if sc.get("syscall") == "flock"]

        # Should have multiple flock calls
        assert len(flock_calls) >= 5, f"Expected at least 5 flock calls, got {len(flock_calls)}"

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
        fsync_calls = [sc for sc in self.syscalls if sc.get("syscall") == "fsync"]
        fdatasync_calls = [sc for sc in self.syscalls if sc.get("syscall") == "fdatasync"]

        # Should have fsync calls
        assert len(fsync_calls) >= 2, f"Expected at least 2 fsync calls, got {len(fsync_calls)}"

        # Should have fdatasync calls
        assert len(fdatasync_calls) >= 2, (
            f"Expected at least 2 fdatasync calls, got {len(fdatasync_calls)}"
        )

        # Both should have fd as first argument
        for call in fsync_calls:
            assert isinstance(call["args"][0], int), "fsync fd should be int"
            assert call["args"][0] >= 0, "fsync fd should be valid"

        for call in fdatasync_calls:
            assert isinstance(call["args"][0], int), "fdatasync fd should be int"
            assert call["args"][0] >= 0, "fdatasync fd should be valid"

    def test_directory_change_operations(self) -> None:
        """Test chdir(), fchdir(), chroot() syscalls."""
        chdir_calls = [sc for sc in self.syscalls if sc.get("syscall") == "chdir"]
        fchdir_calls = [sc for sc in self.syscalls if sc.get("syscall") == "fchdir"]
        chroot_calls = [sc for sc in self.syscalls if sc.get("syscall") == "chroot"]

        # Should have chdir calls
        if chdir_calls:
            call = chdir_calls[0]
            assert isinstance(call["args"][0], str), "chdir path should be string"
            # Path should be valid directory path
            path = call["args"][0]
            assert path.startswith("/") or path in [".", ".."], (
                f"chdir path should be absolute or relative, got {path}"
            )

        # Should have fchdir calls
        if fchdir_calls:
            call = fchdir_calls[0]
            assert isinstance(call["args"][0], int), "fchdir fd should be int"

        # chroot likely failed but should have been called
        if chroot_calls:
            call = chroot_calls[0]
            assert isinstance(call["args"][0], str), "chroot path should be string"

    def test_truncate_operations(self) -> None:
        """Test truncate() and ftruncate() syscalls."""
        truncate_calls = [sc for sc in self.syscalls if sc.get("syscall") == "truncate"]
        ftruncate_calls = [sc for sc in self.syscalls if sc.get("syscall") == "ftruncate"]

        # Should have truncate calls
        assert len(truncate_calls) >= 3, (
            f"Expected at least 3 truncate calls, got {len(truncate_calls)}"
        )

        # Should have ftruncate calls
        assert len(ftruncate_calls) >= 3, (
            f"Expected at least 3 ftruncate calls, got {len(ftruncate_calls)}"
        )

        # Check truncate arguments
        for call in truncate_calls:
            assert isinstance(call["args"][0], str), "truncate path should be string"
            assert isinstance(call["args"][1], int), "truncate length should be int"
            assert call["args"][1] >= 0, "truncate length should be non-negative"

        # Check ftruncate arguments
        for call in ftruncate_calls:
            assert isinstance(call["args"][0], int), "ftruncate fd should be int"
            assert isinstance(call["args"][1], int), "ftruncate length should be int"
            assert call["args"][1] >= 0, "ftruncate length should be non-negative"

    def test_time_modification_operations(self) -> None:
        """Test utimes() and futimes() syscalls."""
        utimes_calls = [sc for sc in self.syscalls if sc.get("syscall") == "utimes"]
        futimes_calls = [sc for sc in self.syscalls if sc.get("syscall") == "futimes"]

        # Should have utimes calls
        assert len(utimes_calls) >= 2, f"Expected at least 2 utimes calls, got {len(utimes_calls)}"

        # Should have futimes calls
        assert len(futimes_calls) >= 2, (
            f"Expected at least 2 futimes calls, got {len(futimes_calls)}"
        )

        # Check utimes arguments
        for call in utimes_calls:
            assert isinstance(call["args"][0], str), "utimes path should be string"
            # Second arg is timeval pointer - can be NULL or pointer

        # Check futimes arguments
        for call in futimes_calls:
            assert isinstance(call["args"][0], int), "futimes fd should be int"

    def test_special_file_creation(self) -> None:
        """Test mkfifo(), mkfifoat(), mknod(), mknodat() syscalls."""
        mkfifo_calls = [sc for sc in self.syscalls if sc.get("syscall") == "mkfifo"]
        mkfifoat_calls = [sc for sc in self.syscalls if sc.get("syscall") == "mkfifoat"]
        mknod_calls = [sc for sc in self.syscalls if sc.get("syscall") == "mknod"]
        mknodat_calls = [sc for sc in self.syscalls if sc.get("syscall") == "mknodat"]

        # Should have mkfifo
        if mkfifo_calls:
            call = mkfifo_calls[0]
            assert len(call["args"]) == 2, "mkfifo should have 2 args"
            assert isinstance(call["args"][0], str), "mkfifo path should be string"
            assert isinstance(call["args"][1], str), "mkfifo mode should be octal string"
            assert call["args"][1].startswith("0"), "mkfifo mode should be octal"

        # Should have mkfifoat
        if mkfifoat_calls:
            call = mkfifoat_calls[0]
            assert len(call["args"]) == 3, "mkfifoat should have 3 args"
            # First arg should be AT_FDCWD or fd
            assert isinstance(call["args"][1], str), "mkfifoat path should be string"
            assert isinstance(call["args"][2], str), "mkfifoat mode should be octal string"

        # Should have mknod (may fail without root)
        if mknod_calls:
            call = mknod_calls[0]
            assert len(call["args"]) == 3, "mknod should have 3 args"
            assert isinstance(call["args"][0], str), "mknod path should be string"
            assert isinstance(call["args"][1], str), "mknod mode should be octal string"
            assert isinstance(call["args"][2], int), "mknod dev should be int"

        # Should have mknodat (may fail without root)
        if mknodat_calls:
            call = mknodat_calls[0]
            assert len(call["args"]) == 4, "mknodat should have 4 args"

    def test_getattrlistat(self) -> None:
        """Test getattrlistat() syscall."""
        getattrlistat_calls = [sc for sc in self.syscalls if sc.get("syscall") == "getattrlistat"]

        # May or may not succeed, but should be called
        if getattrlistat_calls:
            call = getattrlistat_calls[0]
            # Expects: dirfd, path, attrlist, attrbuf, size, options
            assert len(call["args"]) == 6, (
                f"getattrlistat should have 6 args, got {len(call['args'])}"
            )

    def test_clone_operations(self) -> None:
        """Test clonefileat() and fclonefileat() syscalls with CLONE flags."""
        clonefileat_calls = [sc for sc in self.syscalls if sc.get("syscall") == "clonefileat"]
        fclonefileat_calls = [sc for sc in self.syscalls if sc.get("syscall") == "fclonefileat"]

        # These may fail if not on APFS or files don't exist, but should be invoked
        # We test multiple calls with different flags
        if clonefileat_calls:
            # Should have multiple clonefileat calls with different flags
            assert len(clonefileat_calls) >= 2, (
                f"Should have at least 2 clonefileat calls, got {len(clonefileat_calls)}"
            )

            flags_seen = set()
            for call in clonefileat_calls:
                # Expects: src_dirfd, src_name, dst_dirfd, dst_name, flags
                assert len(call["args"]) == 5, (
                    f"clonefileat should have 5 args, got {len(call['args'])}"
                )
                flag_arg = call["args"][4]
                if isinstance(flag_arg, str):
                    flags_seen.add(flag_arg)
                elif isinstance(flag_arg, int):
                    flags_seen.add(str(flag_arg))

            # Should have tested different CLONE flags
            assert len(flags_seen) >= 2, (
                f"Should have multiple different CLONE flags, got: {flags_seen}"
            )

        if fclonefileat_calls:
            # Should have multiple fclonefileat calls with different flags
            assert len(fclonefileat_calls) >= 2, (
                f"Should have at least 2 fclonefileat calls, got {len(fclonefileat_calls)}"
            )

            flags_seen = set()
            for call in fclonefileat_calls:
                # Expects: srcfd, dst_dirfd, dst_name, flags
                assert len(call["args"]) == 4, (
                    f"fclonefileat should have 4 args, got {len(call['args'])}"
                )
                flag_arg = call["args"][3]
                if isinstance(flag_arg, str):
                    flags_seen.add(flag_arg)
                elif isinstance(flag_arg, int):
                    flags_seen.add(str(flag_arg))

            # Should have tested CLONE_NOFOLLOW
            assert any("CLONE_NOFOLLOW" in f or "0x1" in f or "0x0001" in f for f in flags_seen), (
                f"Should have CLONE_NOFOLLOW flag, got flags: {flags_seen}"
            )

    def test_attribute_syscalls(self) -> None:
        """Test getattrlist/setattrlist family of syscalls."""
        getattrlist_calls = [sc for sc in self.syscalls if sc.get("syscall") == "getattrlist"]
        fgetattrlist_calls = [sc for sc in self.syscalls if sc.get("syscall") == "fgetattrlist"]
        setattrlist_calls = [sc for sc in self.syscalls if sc.get("syscall") == "setattrlist"]
        fsetattrlist_calls = [sc for sc in self.syscalls if sc.get("syscall") == "fsetattrlist"]
        getattrlistbulk_calls = [
            sc for sc in self.syscalls if sc.get("syscall") == "getattrlistbulk"
        ]
        fchownat_calls = [sc for sc in self.syscalls if sc.get("syscall") == "fchownat"]

        # Should have getattrlist
        if getattrlist_calls:
            call = getattrlist_calls[0]
            # Expects: path, attrlist, attrbuf, size, options
            assert len(call["args"]) == 5, (
                f"getattrlist should have 5 args, got {len(call['args'])}"
            )
            # Check attrlist struct is decoded
            attrlist_arg = call["args"][1]
            assert isinstance(attrlist_arg, dict), "attrlist should be decoded as dict"
            assert "output" in attrlist_arg, "attrlist should have 'output' field"
            fields = attrlist_arg["output"]
            assert "commonattr" in fields, "attrlist should have commonattr field"
            # Should see ATTR_CMN_NAME or ATTR_CMN_OBJTYPE
            commonattr = str(fields["commonattr"])
            assert "ATTR_CMN" in commonattr, (
                f"commonattr should be decoded symbolically, got {commonattr}"
            )

        # Should have fgetattrlist
        if fgetattrlist_calls:
            call = fgetattrlist_calls[0]
            # Expects: fd, attrlist, attrbuf, size, options
            assert len(call["args"]) == 5, (
                f"fgetattrlist should have 5 args, got {len(call['args'])}"
            )

        # Should have setattrlist
        if setattrlist_calls:
            call = setattrlist_calls[0]
            # Expects: path, attrlist, attrbuf, size, options
            assert len(call["args"]) == 5, (
                f"setattrlist should have 5 args, got {len(call['args'])}"
            )

        # Should have fsetattrlist
        if fsetattrlist_calls:
            call = fsetattrlist_calls[0]
            # Expects: fd, attrlist, attrbuf, size, options
            assert len(call["args"]) == 5, (
                f"fsetattrlist should have 5 args, got {len(call['args'])}"
            )

        # Should have getattrlistbulk
        if getattrlistbulk_calls:
            call = getattrlistbulk_calls[0]
            # Expects: dirfd, attrlist, attrbuf, size, options
            assert len(call["args"]) == 5, (
                f"getattrlistbulk should have 5 args, got {len(call['args'])}"
            )

        # Should have fchownat with flags
        assert len(fchownat_calls) >= 2, (
            f"Should have at least 2 fchownat calls, got {len(fchownat_calls)}"
        )
        if fchownat_calls:
            # Check for calls with different flags
            flags_seen = set()
            for call in fchownat_calls:
                # Expects: dirfd, path, uid, gid, flags
                assert len(call["args"]) == 5, (
                    f"fchownat should have 5 args, got {len(call['args'])}"
                )
                flag_arg = call["args"][4]
                if isinstance(flag_arg, str):
                    flags_seen.add(flag_arg)
                elif isinstance(flag_arg, int):
                    flags_seen.add(str(flag_arg))

            # Should have tested AT_SYMLINK_NOFOLLOW
            assert any(
                "AT_SYMLINK_NOFOLLOW" in f or "0x20" in f or "0x0020" in f for f in flags_seen
            ), f"Should have AT_SYMLINK_NOFOLLOW flag, got flags: {flags_seen}"

    def test_statfs_operations(self) -> None:
        """Test statfs family syscalls decode properly."""
        stat_calls = [sc for sc in self.syscalls if sc.get("syscall") == "statfs"]
        fstat_calls = [sc for sc in self.syscalls if sc.get("syscall") == "fstatfs"]
        getfsstat_calls = [sc for sc in self.syscalls if sc.get("syscall") == "getfsstat"]

        # Should have statfs calls
        assert len(stat_calls) >= 2, f"Should have at least 2 statfs calls, got {len(stat_calls)}"
        for call in stat_calls:
            # Expects: path, statfs_struct
            assert len(call["args"]) == 2, f"statfs should have 2 args, got {len(call['args'])}"
            # First arg should be a path string
            assert isinstance(call["args"][0], str)
            # Second arg should be struct (dict) or pointer
            assert isinstance(call["args"][1], (dict, str))

        # Should have fstatfs calls
        assert len(fstat_calls) >= 1, f"Should have at least 1 fstatfs call, got {len(fstat_calls)}"

        # Should have getfsstat calls
        assert len(getfsstat_calls) >= 2, (
            f"Should have at least 2 getfsstat calls, got {len(getfsstat_calls)}"
        )

    def test_xattr_operations(self) -> None:
        """Test extended attribute syscalls decode properly."""
        getxattr_calls = [sc for sc in self.syscalls if sc.get("syscall") == "getxattr"]
        fgetxattr_calls = [sc for sc in self.syscalls if sc.get("syscall") == "fgetxattr"]
        setxattr_calls = [sc for sc in self.syscalls if sc.get("syscall") == "setxattr"]
        fsetxattr_calls = [sc for sc in self.syscalls if sc.get("syscall") == "fsetxattr"]
        fremovexattr_calls = [sc for sc in self.syscalls if sc.get("syscall") == "fremovexattr"]

        # Should have getxattr with different flags
        assert len(getxattr_calls) >= 2, (
            f"Should have at least 2 getxattr calls, got {len(getxattr_calls)}"
        )
        if getxattr_calls:
            # Check for XATTR_NOFOLLOW flag
            flags_seen = set()
            for call in getxattr_calls:
                # Expects: path, name, value, size, position, options
                assert len(call["args"]) == 6, (
                    f"getxattr should have 6 args, got {len(call['args'])}"
                )
                flag_arg = call["args"][5]
                if isinstance(flag_arg, str):
                    flags_seen.add(flag_arg)

            # At least one should have XATTR_NOFOLLOW
            assert any("XATTR_NOFOLLOW" in f for f in flags_seen), (
                f"Should have XATTR_NOFOLLOW flag, got flags: {flags_seen}"
            )

        # Should have various xattr syscalls
        assert len(fgetxattr_calls) >= 1
        assert len(setxattr_calls) >= 2  # Multiple calls with different flags
        assert len(fsetxattr_calls) >= 1
        assert len(fremovexattr_calls) >= 1

    def test_fsctl_operations(self) -> None:
        """Test filesystem control syscalls decode properly."""
        fsctl_calls = [sc for sc in self.syscalls if sc.get("syscall") == "fsctl"]
        ffsctl_calls = [sc for sc in self.syscalls if sc.get("syscall") == "ffsctl"]
        fsgetpath_calls = [sc for sc in self.syscalls if sc.get("syscall") == "fsgetpath"]

        # Should have fsctl
        assert len(fsctl_calls) >= 1, f"Should have at least 1 fsctl call, got {len(fsctl_calls)}"

        # Should have ffsctl
        assert len(ffsctl_calls) >= 1, (
            f"Should have at least 1 ffsctl call, got {len(ffsctl_calls)}"
        )

        # Should have fsgetpath
        assert len(fsgetpath_calls) >= 1, (
            f"Should have at least 1 fsgetpath call, got {len(fsgetpath_calls)}"
        )

    def test_copyfile_and_searchfs_operations(self) -> None:
        """Test copyfile and searchfs syscalls decode properly."""
        copyfile_calls = [sc for sc in self.syscalls if sc.get("syscall") == "copyfile"]
        searchfs_calls = [sc for sc in self.syscalls if sc.get("syscall") == "searchfs"]

        # Should have copyfile with different flags
        assert len(copyfile_calls) >= 2, (
            f"Should have at least 2 copyfile calls, got {len(copyfile_calls)}"
        )
        if copyfile_calls:
            # Check for different flags (COPYFILE_DATA, COPYFILE_XATTR)
            flags_seen = set()
            for call in copyfile_calls:
                # Expects: src, dst, state, flags
                assert len(call["args"]) == 4, (
                    f"copyfile should have 4 args, got {len(call['args'])}"
                )
                flag_arg = call["args"][3]
                if isinstance(flag_arg, str):
                    flags_seen.add(flag_arg)

            # Should have tested different flags
            assert any("COPYFILE_DATA" in f for f in flags_seen) or any(
                "COPYFILE_XATTR" in f for f in flags_seen
            ), f"Should have COPYFILE_DATA or COPYFILE_XATTR flag, got flags: {flags_seen}"

        # Should have searchfs with SRCHFS_MATCHFILES flag
        assert len(searchfs_calls) >= 1, (
            f"Should have at least 1 searchfs call, got {len(searchfs_calls)}"
        )
        if searchfs_calls:
            for call in searchfs_calls:
                # Expects: path, searchblock, nummatches, options, timeout, searchstate
                assert len(call["args"]) == 6, (
                    f"searchfs should have 6 args, got {len(call['args'])}"
                )

    def test_exchangedata_undelete_revoke(self) -> None:
        """Test exchangedata, undelete, and revoke syscalls."""
        exchangedata_calls = [sc for sc in self.syscalls if sc.get("syscall") == "exchangedata"]
        undelete_calls = [sc for sc in self.syscalls if sc.get("syscall") == "undelete"]
        revoke_calls = [sc for sc in self.syscalls if sc.get("syscall") == "revoke"]

        # Should have exchangedata
        assert len(exchangedata_calls) >= 1, (
            f"Should have at least 1 exchangedata call, got {len(exchangedata_calls)}"
        )

        # Should have undelete (will fail on modern macOS but should be traced)
        assert len(undelete_calls) >= 1, (
            f"Should have at least 1 undelete call, got {len(undelete_calls)}"
        )

        # Should have revoke
        assert len(revoke_calls) >= 1, (
            f"Should have at least 1 revoke call, got {len(revoke_calls)}"
        )


if __name__ == "__main__":
    unittest.main()
