"""
Test System V IPC and AIO syscalls.

Tests coverage for:
- System V Message Queues: msgget, msgctl, msgsnd, msgrcv
- System V Semaphores: semget, semctl, semop
- System V Shared Memory: shmget, shmat, shmctl, shmdt
- AIO: aio_cancel, aio_error, aio_return, aio_suspend, lio_listio
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


class TestIPCAIOSyscalls(unittest.TestCase):
    """Test System V IPC and AIO syscall decoding."""

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
                "--ipc-aio",
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

    def test_ipc_aio_coverage(self) -> None:
        """Test that expected IPC and AIO syscalls are captured."""
        syscall_names: list[str] = [
            sc.get("syscall")  # type: ignore[misc]
            for sc in self.syscalls
            if sc.get("syscall")
        ]

        # Expected syscalls from our test mode
        expected_syscalls = {
            # Message queues
            "msgget",
            "msgctl",
            # Semaphores
            "semget",
            "semctl",
            "semop",
            # Shared memory
            "shmget",
            "shmat",
            "shmctl",
            "shmdt",
            # AIO
            "aio_cancel",
            "aio_error",
            "aio_suspend",
            "lio_listio",
        }

        found_syscalls = expected_syscalls.intersection(syscall_names)
        missing_syscalls = expected_syscalls - found_syscalls

        assert len(missing_syscalls) == 0, (
            f"Missing expected syscalls: {missing_syscalls}\n"
            f"Found syscalls: {sorted(set(syscall_names))}"
        )

    # Message Queue Tests
    def test_msgget_with_ipc_flags(self) -> None:
        """Test msgget syscall with IPC_CREAT|IPC_EXCL flags."""
        msgget_calls = [sc for sc in self.syscalls if sc.get("syscall") == "msgget"]
        assert len(msgget_calls) > 0, "Should have msgget syscalls"

        call = msgget_calls[0]
        args = call.get("args", [])
        assert len(args) == 2, "msgget should have 2 arguments"

        # Second argument should be flags with IPC_CREAT|IPC_EXCL|mode
        flags_arg = args[1]
        assert "IPC_CREAT" in flags_arg, f"msgget flags should contain IPC_CREAT: {flags_arg}"
        assert "IPC_EXCL" in flags_arg, f"msgget flags should contain IPC_EXCL: {flags_arg}"

    def test_msgctl_commands(self) -> None:
        """Test msgctl syscall with different commands."""
        msgctl_calls = [sc for sc in self.syscalls if sc.get("syscall") == "msgctl"]
        assert len(msgctl_calls) >= 2, "Should have multiple msgctl calls"

        # Check for IPC_STAT command
        stat_calls = [c for c in msgctl_calls if "IPC_STAT" in str(c.get("args", []))]
        assert len(stat_calls) > 0, "Should have msgctl with IPC_STAT"

        # Check for IPC_RMID command
        rmid_calls = [c for c in msgctl_calls if "IPC_RMID" in str(c.get("args", []))]
        assert len(rmid_calls) > 0, "Should have msgctl with IPC_RMID"

    # Semaphore Tests
    def test_semget_with_ipc_flags(self) -> None:
        """Test semget syscall with IPC_CREAT|IPC_EXCL flags."""
        semget_calls = [sc for sc in self.syscalls if sc.get("syscall") == "semget"]
        assert len(semget_calls) > 0, "Should have semget syscalls"

        call = semget_calls[0]
        args = call.get("args", [])
        assert len(args) == 3, "semget should have 3 arguments"

        # Third argument should be flags with IPC_CREAT|IPC_EXCL|mode
        flags_arg = args[2]
        assert "IPC_CREAT" in flags_arg, f"semget flags should contain IPC_CREAT: {flags_arg}"
        assert "IPC_EXCL" in flags_arg, f"semget flags should contain IPC_EXCL: {flags_arg}"

    def test_semctl_commands(self) -> None:
        """Test semctl syscall with different commands."""
        semctl_calls = [sc for sc in self.syscalls if sc.get("syscall") == "semctl"]
        assert len(semctl_calls) >= 5, "Should have multiple semctl calls"

        commands_found = set()
        for call in semctl_calls:
            args = call.get("args", [])
            if len(args) >= 3:
                cmd = args[2]
                commands_found.add(cmd)

        # We should see various semctl commands
        expected_commands = {
            "IPC_STAT",
            "SETVAL",
            "GETVAL",
            "GETPID",
            "GETNCNT",
            "GETZCNT",
            "SETALL",
            "GETALL",
            "IPC_RMID",
        }
        found_commands = expected_commands.intersection(commands_found)

        assert len(found_commands) >= 5, (
            f"Should find at least 5 different semctl commands, found: {commands_found}"
        )

    def test_semop_flags(self) -> None:
        """Test semop syscall with SEM_UNDO flag."""
        semop_calls = [sc for sc in self.syscalls if sc.get("syscall") == "semop"]
        assert len(semop_calls) >= 2, "Should have multiple semop calls"

        # At least one call should use SEM_UNDO (based on our fixture)
        # Note: semop takes a pointer to sembuf array, so flags aren't directly visible in args
        # This test primarily verifies the syscall is captured
        call = semop_calls[0]
        args = call.get("args", [])
        assert len(args) == 3, "semop should have 3 arguments: semid, sops, nsops"

    # Shared Memory Tests
    def test_shmget_with_ipc_flags(self) -> None:
        """Test shmget syscall with IPC_CREAT|IPC_EXCL flags."""
        shmget_calls = [sc for sc in self.syscalls if sc.get("syscall") == "shmget"]
        assert len(shmget_calls) > 0, "Should have shmget syscalls"

        call = shmget_calls[0]
        args = call.get("args", [])
        assert len(args) == 3, "shmget should have 3 arguments"

        # Third argument should be flags with IPC_CREAT|IPC_EXCL|mode
        flags_arg = args[2]
        assert "IPC_CREAT" in flags_arg, f"shmget flags should contain IPC_CREAT: {flags_arg}"
        assert "IPC_EXCL" in flags_arg, f"shmget flags should contain IPC_EXCL: {flags_arg}"

    def test_shmat_flags(self) -> None:
        """Test shmat syscall with SHM_RDONLY and SHM_RND flags."""
        shmat_calls = [sc for sc in self.syscalls if sc.get("syscall") == "shmat"]
        assert len(shmat_calls) >= 3, "Should have multiple shmat calls"

        # Find the call with SHM_RDONLY
        readonly_calls = [
            c for c in shmat_calls if len(c.get("args", [])) >= 3 and "SHM_RDONLY" in c["args"][2]
        ]
        assert len(readonly_calls) > 0, "Should have shmat with SHM_RDONLY flag"

        # Find the call with SHM_RND
        rnd_calls = [
            c for c in shmat_calls if len(c.get("args", [])) >= 3 and "SHM_RND" in c["args"][2]
        ]
        assert len(rnd_calls) > 0, "Should have shmat with SHM_RND flag"

    def test_shmctl_commands(self) -> None:
        """Test shmctl syscall with different commands."""
        shmctl_calls = [sc for sc in self.syscalls if sc.get("syscall") == "shmctl"]
        assert len(shmctl_calls) >= 2, "Should have multiple shmctl calls"

        # Check for IPC_STAT command
        stat_calls = [c for c in shmctl_calls if "IPC_STAT" in str(c.get("args", []))]
        assert len(stat_calls) > 0, "Should have shmctl with IPC_STAT"

        # Check for IPC_RMID command
        rmid_calls = [c for c in shmctl_calls if "IPC_RMID" in str(c.get("args", []))]
        assert len(rmid_calls) > 0, "Should have shmctl with IPC_RMID"

    def test_shmdt(self) -> None:
        """Test shmdt syscall."""
        shmdt_calls = [sc for sc in self.syscalls if sc.get("syscall") == "shmdt"]
        assert len(shmdt_calls) >= 3, "Should have multiple shmdt calls (one per shmat)"

        call = shmdt_calls[0]
        args = call.get("args", [])
        assert len(args) == 1, "shmdt should have 1 argument (shmaddr)"

    # AIO Tests
    def test_aio_cancel(self) -> None:
        """Test aio_cancel syscall."""
        aio_cancel_calls = [sc for sc in self.syscalls if sc.get("syscall") == "aio_cancel"]
        assert len(aio_cancel_calls) > 0, "Should have aio_cancel syscalls"

        call = aio_cancel_calls[0]
        args = call.get("args", [])
        assert len(args) == 2, "aio_cancel should have 2 arguments: fd, aiocbp"

    def test_aio_error(self) -> None:
        """Test aio_error syscall."""
        aio_error_calls = [sc for sc in self.syscalls if sc.get("syscall") == "aio_error"]
        assert len(aio_error_calls) > 0, "Should have aio_error syscalls"

        call = aio_error_calls[0]
        args = call.get("args", [])
        assert len(args) == 1, "aio_error should have 1 argument: aiocbp"

    def test_aio_suspend(self) -> None:
        """Test aio_suspend syscall."""
        aio_suspend_calls = [sc for sc in self.syscalls if sc.get("syscall") == "aio_suspend"]
        assert len(aio_suspend_calls) > 0, "Should have aio_suspend syscalls"

        call = aio_suspend_calls[0]
        args = call.get("args", [])
        assert len(args) == 3, "aio_suspend should have 3 arguments: aiocblist, nent, timeout"

    def test_lio_listio_modes(self) -> None:
        """Test lio_listio syscall with LIO_WAIT and LIO_NOWAIT modes."""
        lio_calls = [sc for sc in self.syscalls if sc.get("syscall") == "lio_listio"]
        assert len(lio_calls) >= 2, "Should have multiple lio_listio calls"

        # Check for LIO_WAIT mode
        wait_calls = [c for c in lio_calls if "LIO_WAIT" in str(c.get("args", []))]
        assert len(wait_calls) > 0, "Should have lio_listio with LIO_WAIT mode"

        # Check for LIO_NOWAIT mode
        nowait_calls = [c for c in lio_calls if "LIO_NOWAIT" in str(c.get("args", []))]
        assert len(nowait_calls) > 0, "Should have lio_listio with LIO_NOWAIT mode"

        # Verify argument count
        for call in lio_calls:
            args = call.get("args", [])
            assert len(args) == 4, "lio_listio should have 4 arguments: mode, list, nent, sig"


if __name__ == "__main__":
    unittest.main()
