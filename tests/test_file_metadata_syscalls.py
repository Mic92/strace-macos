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

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
import helpers  # type: ignore[import-not-found]
from compile import get_test_executable  # type: ignore[import-not-found]


class TestFileMetadataSyscalls(unittest.TestCase):
    """Test file metadata and permission syscall decoding."""

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
                "--file-metadata",
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

    def test_file_metadata_coverage(self) -> None:
        """Test that all expected file metadata syscalls are captured."""
        syscall_names = [sc.get("syscall") for sc in self.syscalls]

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

        captured = expected_syscalls & set(syscall_names)
        missing = expected_syscalls - set(syscall_names)

        # We should capture most of these (some might be optimized away)
        assert len(captured) >= 15, (
            f"Should capture at least 15 file metadata syscalls, got {len(captured)}.\n"
            f"Captured: {sorted(captured)}\n"
            f"Missing: {sorted(missing)}"
        )

    def test_access_mode_decoding(self) -> None:
        """Test access() syscall with mode flags decoding."""
        access_calls = [sc for sc in self.syscalls if sc.get("syscall") == "access"]

        # Should have at least 5 access calls
        assert len(access_calls) >= 5, f"Expected at least 5 access calls, got {len(access_calls)}"

        # Check for various modes
        modes_found = set()
        for call in access_calls:
            mode = call["args"][1]
            modes_found.add(str(mode))

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
        chmod_calls = [sc for sc in self.syscalls if sc.get("syscall") == "chmod"]
        if chmod_calls:
            # Mode should be decoded as octal string like "0644"
            for call in chmod_calls:
                mode_arg = call["args"][1]
                assert isinstance(mode_arg, str), (
                    f"chmod mode should be string, got {type(mode_arg)}"
                )
                assert mode_arg.startswith("0"), (
                    f"chmod mode should be octal (0xxx), got {mode_arg}"
                )
                # Should be one of our test modes
                assert mode_arg in ["0644", "0755", "0600"], f"Unexpected chmod mode: {mode_arg}"

        # Check fchmod calls
        fchmod_calls = [sc for sc in self.syscalls if sc.get("syscall") == "fchmod"]
        if fchmod_calls:
            for call in fchmod_calls:
                # First arg should be fd (int)
                fd_arg = call["args"][0]
                assert isinstance(fd_arg, int), f"fchmod fd should be int, got {type(fd_arg)}"
                # Second arg should be octal mode
                mode_arg = call["args"][1]
                assert isinstance(mode_arg, str), (
                    f"fchmod mode should be string, got {type(mode_arg)}"
                )
                assert mode_arg.startswith("0"), f"fchmod mode should be octal, got {mode_arg}"

    def test_chown_arguments(self) -> None:
        """Test chown() and fchown() syscalls."""
        # Check chown calls
        chown_calls = [sc for sc in self.syscalls if sc.get("syscall") == "chown"]
        if chown_calls:
            call = chown_calls[0]
            # Should have 3 args: path, uid, gid
            assert len(call["args"]) == 3, f"chown should have 3 args, got {len(call['args'])}"
            path_arg = call["args"][0]
            uid_arg = call["args"][1]
            gid_arg = call["args"][2]
            assert isinstance(path_arg, str), f"chown path should be string, got {type(path_arg)}"
            assert isinstance(uid_arg, int), f"chown uid should be int, got {type(uid_arg)}"
            assert isinstance(gid_arg, int), f"chown gid should be int, got {type(gid_arg)}"

        # Check fchown calls
        fchown_calls = [sc for sc in self.syscalls if sc.get("syscall") == "fchown"]
        if fchown_calls:
            call = fchown_calls[0]
            # Should have 3 args: fd, uid, gid
            assert len(call["args"]) == 3, f"fchown should have 3 args, got {len(call['args'])}"
            fd_arg = call["args"][0]
            uid_arg = call["args"][1]
            gid_arg = call["args"][2]
            assert isinstance(fd_arg, int), f"fchown fd should be int, got {type(fd_arg)}"
            assert isinstance(uid_arg, int), f"fchown uid should be int, got {type(uid_arg)}"
            assert isinstance(gid_arg, int), f"fchown gid should be int, got {type(gid_arg)}"

    def test_link_syscalls_arguments(self) -> None:
        """Test link() and linkat() for hard link creation."""
        # Check link calls
        link_calls = [sc for sc in self.syscalls if sc.get("syscall") == "link"]
        if link_calls:
            call = link_calls[0]
            # Should have 2 args: oldpath, newpath
            assert len(call["args"]) == 2, f"link should have 2 args, got {len(call['args'])}"
            assert isinstance(call["args"][0], str), "link oldpath should be string"
            assert isinstance(call["args"][1], str), "link newpath should be string"

        # Check linkat calls
        linkat_calls = [sc for sc in self.syscalls if sc.get("syscall") == "linkat"]
        if linkat_calls:
            call = linkat_calls[0]
            # Should have 5 args: olddirfd, oldpath, newdirfd, newpath, flags
            assert len(call["args"]) == 5, f"linkat should have 5 args, got {len(call['args'])}"
            # Check AT_FDCWD is decoded
            olddirfd = call["args"][0]
            assert "AT_FDCWD" in str(olddirfd) or olddirfd == -2, (
                f"linkat olddirfd should be AT_FDCWD, got {olddirfd}"
            )

    def test_symlink_syscalls_arguments(self) -> None:
        """Test symlink(), symlinkat(), readlink(), and readlinkat()."""
        # Check symlink
        symlink_calls = [sc for sc in self.syscalls if sc.get("syscall") == "symlink"]
        if symlink_calls:
            call = symlink_calls[0]
            # Should have 2 args: target, linkpath
            assert len(call["args"]) == 2, f"symlink should have 2 args, got {len(call['args'])}"
            assert isinstance(call["args"][0], str), "symlink target should be string"
            assert isinstance(call["args"][1], str), "symlink linkpath should be string"
            assert "/tmp/target" in call["args"][0], "symlink should reference target"  # noqa: S108

        # Check readlink
        readlink_calls = [sc for sc in self.syscalls if sc.get("syscall") == "readlink"]
        if readlink_calls:
            call = readlink_calls[0]
            # Should have 3 args: path, buf, bufsize
            assert len(call["args"]) == 3, f"readlink should have 3 args, got {len(call['args'])}"
            assert isinstance(call["args"][0], str), "readlink path should be string"
            # buf should be decoded as output buffer
            assert isinstance(call["args"][1], (str, dict)), "readlink buf should be decoded"

        # Check symlinkat
        symlinkat_calls = [sc for sc in self.syscalls if sc.get("syscall") == "symlinkat"]
        if symlinkat_calls:
            call = symlinkat_calls[0]
            # Should have 3 args: target, newdirfd, linkpath
            assert len(call["args"]) == 3, f"symlinkat should have 3 args, got {len(call['args'])}"
            assert "AT_FDCWD" in str(call["args"][1]) or call["args"][1] == -2, (
                f"symlinkat should use AT_FDCWD, got {call['args'][1]}"
            )

        # Check readlinkat
        readlinkat_calls = [sc for sc in self.syscalls if sc.get("syscall") == "readlinkat"]
        if readlinkat_calls:
            call = readlinkat_calls[0]
            # Should have 4 args: dirfd, path, buf, bufsize
            assert len(call["args"]) == 4, f"readlinkat should have 4 args, got {len(call['args'])}"
            assert "AT_FDCWD" in str(call["args"][0]) or call["args"][0] == -2, (
                f"readlinkat should use AT_FDCWD, got {call['args'][0]}"
            )

    def test_directory_syscalls_arguments(self) -> None:
        """Test mkdir(), rmdir(), mkdirat() with mode decoding."""
        # Check mkdir
        mkdir_calls = [sc for sc in self.syscalls if sc.get("syscall") == "mkdir"]
        assert len(mkdir_calls) >= 2, f"Should have at least 2 mkdir calls, got {len(mkdir_calls)}"

        for call in mkdir_calls:
            # Should have 2 args: path, mode
            assert len(call["args"]) == 2, f"mkdir should have 2 args, got {len(call['args'])}"
            path_arg = call["args"][0]
            mode_arg = call["args"][1]
            assert isinstance(path_arg, str), f"mkdir path should be string, got {type(path_arg)}"
            assert isinstance(mode_arg, str), f"mkdir mode should be string, got {type(mode_arg)}"
            # Mode should be octal
            assert mode_arg.startswith("0"), f"mkdir mode should be octal, got {mode_arg}"

        # Check mkdirat
        mkdirat_calls = [sc for sc in self.syscalls if sc.get("syscall") == "mkdirat"]
        if mkdirat_calls:
            call = mkdirat_calls[0]
            # Should have 3 args: dirfd, path, mode
            assert len(call["args"]) == 3, f"mkdirat should have 3 args, got {len(call['args'])}"
            dirfd = call["args"][0]
            assert "AT_FDCWD" in str(dirfd) or dirfd == -2, (
                f"mkdirat should use AT_FDCWD, got {dirfd}"
            )
            mode_arg = call["args"][2]
            assert isinstance(mode_arg, str), f"mkdirat mode should be string, got {type(mode_arg)}"
            assert mode_arg.startswith("0"), f"mkdirat mode should be octal, got {mode_arg}"

        # Check rmdir
        rmdir_calls = [sc for sc in self.syscalls if sc.get("syscall") == "rmdir"]
        assert len(rmdir_calls) >= 3, f"Should have at least 3 rmdir calls, got {len(rmdir_calls)}"

        for call in rmdir_calls:
            # Should have 1 arg: path
            assert len(call["args"]) == 1, f"rmdir should have 1 arg, got {len(call['args'])}"
            assert isinstance(call["args"][0], str), "rmdir path should be string"

    def test_rename_syscalls_arguments(self) -> None:
        """Test rename() and renameat() syscalls."""
        # Check rename
        rename_calls = [sc for sc in self.syscalls if sc.get("syscall") == "rename"]
        if rename_calls:
            call = rename_calls[0]
            # Should have 2 args: oldpath, newpath
            assert len(call["args"]) == 2, f"rename should have 2 args, got {len(call['args'])}"
            assert isinstance(call["args"][0], str), "rename oldpath should be string"
            assert isinstance(call["args"][1], str), "rename newpath should be string"

        # Check renameat
        renameat_calls = [sc for sc in self.syscalls if sc.get("syscall") == "renameat"]
        if renameat_calls:
            call = renameat_calls[0]
            # Should have 4 args: olddirfd, oldpath, newdirfd, newpath
            assert len(call["args"]) == 4, f"renameat should have 4 args, got {len(call['args'])}"
            assert "AT_FDCWD" in str(call["args"][0]) or call["args"][0] == -2, (
                f"renameat olddirfd should be AT_FDCWD, got {call['args'][0]}"
            )
            assert "AT_FDCWD" in str(call["args"][2]) or call["args"][2] == -2, (
                f"renameat newdirfd should be AT_FDCWD, got {call['args'][2]}"
            )

    def test_unlinkat_with_flags(self) -> None:
        """Test unlinkat() with AT_FDCWD and flags."""
        # Check unlinkat calls
        unlinkat_calls = [sc for sc in self.syscalls if sc.get("syscall") == "unlinkat"]
        assert len(unlinkat_calls) >= 2, (
            f"Should have at least 2 unlinkat calls, got {len(unlinkat_calls)}"
        )

        for call in unlinkat_calls:
            # Should have 3 args: dirfd, path, flags
            assert len(call["args"]) == 3, f"unlinkat should have 3 args, got {len(call['args'])}"

            # Check dirfd is AT_FDCWD
            dirfd = call["args"][0]
            assert dirfd == "AT_FDCWD", f"unlinkat dirfd should be AT_FDCWD, got {dirfd}"

            # Check path is string
            assert isinstance(call["args"][1], str), "unlinkat path should be string"

            # Check flags (either 0 or AT_REMOVEDIR string)
            flags = call["args"][2]
            assert flags in {"0", 0, "AT_REMOVEDIR"}, (
                f"unlinkat flags should be 0 or AT_REMOVEDIR, got {flags}"
            )

        # Verify we have at least one with AT_REMOVEDIR
        removedir_calls = [c for c in unlinkat_calls if c["args"][2] == "AT_REMOVEDIR"]
        assert len(removedir_calls) >= 1, "Should have at least one unlinkat with AT_REMOVEDIR flag"


if __name__ == "__main__":
    unittest.main()
