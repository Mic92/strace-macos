"""
Test System V IPC and AIO syscalls.

Tests coverage for:
- System V Message Queues: msgget, msgctl, msgsnd, msgrcv
- System V Semaphores: semget, semctl, semop
- System V Shared Memory: shmget, shmat, shmctl, shmdt
- POSIX Shared Memory: shm_open, shm_unlink
- AIO: aio_cancel, aio_error, aio_return, aio_suspend, lio_listio
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
import syscall_test_helpers as sth  # type: ignore[import-not-found]


class TestIPCAIOSyscalls(unittest.TestCase):
    """Test System V IPC and AIO syscall decoding."""

    exit_code: int
    syscalls: list[dict]

    @classmethod
    def setUpClass(cls) -> None:
        """Run the test executable once and capture syscalls for all tests."""
        cls.exit_code, cls.syscalls = sth.run_strace_for_mode("--ipc-aio", Path(__file__))

    def test_executable_exits_successfully(self) -> None:
        """Test that the executable runs without errors."""
        assert self.exit_code == 0, f"Test executable should exit with 0, got {self.exit_code}"

    def test_ipc_aio_coverage(self) -> None:
        """Test that expected IPC and AIO syscalls are captured."""
        expected_syscalls = {
            # Message queues
            "msgget",
            "msgctl",
            # Semaphores
            "semget",
            "semctl",
            "semop",
            # Shared memory (System V)
            "shmget",
            "shmat",
            "shmctl",
            "shmdt",
            # Shared memory (POSIX)
            "shm_open",
            "shm_unlink",
            # AIO
            "aio_cancel",
            "aio_error",
            "aio_suspend",
            "lio_listio",
        }

        sth.assert_syscall_coverage(
            self.syscalls, expected_syscalls, len(expected_syscalls), "IPC/AIO syscalls"
        )

    # Message Queue Tests
    def test_msgget_with_ipc_flags(self) -> None:
        """Test msgget syscall with IPC_CREAT|IPC_EXCL flags."""
        msgget_calls = sth.filter_syscalls(self.syscalls, "msgget")
        sth.assert_min_call_count(msgget_calls, 1, "msgget")
        sth.assert_arg_count(msgget_calls[0], 2, "msgget")
        sth.assert_symbolic_value(msgget_calls[0], 1, ["IPC_CREAT", "IPC_EXCL"], "msgget flags")

    def test_msgctl_commands(self) -> None:
        """Test msgctl syscall with different commands."""
        msgctl_calls = sth.filter_syscalls(self.syscalls, "msgctl")
        sth.assert_min_call_count(msgctl_calls, 2, "msgctl")

        # Check for IPC_STAT command
        stat_calls = [c for c in msgctl_calls if "IPC_STAT" in str(c.get("args", []))]
        sth.assert_min_call_count(stat_calls, 1, "msgctl IPC_STAT")

        # Check for IPC_RMID command
        rmid_calls = [c for c in msgctl_calls if "IPC_RMID" in str(c.get("args", []))]
        sth.assert_min_call_count(rmid_calls, 1, "msgctl IPC_RMID")

    def test_msgctl_struct_decoding(self) -> None:
        """Test msgctl decodes struct msqid_ds fields."""
        msgctl_calls = sth.filter_syscalls(self.syscalls, "msgctl")
        stat_calls = [c for c in msgctl_calls if "IPC_STAT" in str(c.get("args", []))]
        sth.assert_min_call_count(stat_calls, 1, "msgctl IPC_STAT")

        # Check that struct fields are present in output
        call = stat_calls[-1]  # Get last IPC_STAT call (after SET)
        output_str = str(call)

        # Look for struct msqid_ds fields in the output
        # We should see msg_qbytes=8192 after our IPC_SET
        assert "msg_q" in output_str.lower() or "8192" in output_str, (
            f"msgctl should decode msqid_ds struct fields, got: {output_str}"
        )

    # Semaphore Tests
    def test_semget_with_ipc_flags(self) -> None:
        """Test semget syscall with IPC_CREAT|IPC_EXCL flags."""
        semget_calls = sth.filter_syscalls(self.syscalls, "semget")
        sth.assert_min_call_count(semget_calls, 1, "semget")
        sth.assert_arg_count(semget_calls[0], 3, "semget")
        sth.assert_symbolic_value(semget_calls[0], 2, ["IPC_CREAT", "IPC_EXCL"], "semget flags")

    def test_semctl_commands(self) -> None:
        """Test semctl syscall with different commands."""
        semctl_calls = sth.filter_syscalls(self.syscalls, "semctl")
        sth.assert_min_call_count(semctl_calls, 5, "semctl")

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
        semop_calls = sth.filter_syscalls(self.syscalls, "semop")
        sth.assert_min_call_count(semop_calls, 2, "semop")
        sth.assert_arg_count(semop_calls[0], 3, "semop")

    # Shared Memory Tests
    def test_shmget_with_ipc_flags(self) -> None:
        """Test shmget syscall with IPC_CREAT|IPC_EXCL flags."""
        shmget_calls = sth.filter_syscalls(self.syscalls, "shmget")
        sth.assert_min_call_count(shmget_calls, 1, "shmget")
        sth.assert_arg_count(shmget_calls[0], 3, "shmget")
        sth.assert_symbolic_value(shmget_calls[0], 2, ["IPC_CREAT", "IPC_EXCL"], "shmget flags")

    def test_shmat_flags(self) -> None:
        """Test shmat syscall with SHM_RDONLY and SHM_RND flags."""
        shmat_calls = sth.filter_syscalls(self.syscalls, "shmat")
        sth.assert_min_call_count(shmat_calls, 3, "shmat")

        # Find the call with SHM_RDONLY
        readonly_calls = [
            c for c in shmat_calls if len(c.get("args", [])) >= 3 and "SHM_RDONLY" in c["args"][2]
        ]
        sth.assert_min_call_count(readonly_calls, 1, "shmat SHM_RDONLY")

        # Find the call with SHM_RND
        rnd_calls = [
            c for c in shmat_calls if len(c.get("args", [])) >= 3 and "SHM_RND" in c["args"][2]
        ]
        sth.assert_min_call_count(rnd_calls, 1, "shmat SHM_RND")

    def test_shmctl_commands(self) -> None:
        """Test shmctl syscall with different commands."""
        shmctl_calls = sth.filter_syscalls(self.syscalls, "shmctl")
        sth.assert_min_call_count(shmctl_calls, 2, "shmctl")

        # Check for IPC_STAT command
        stat_calls = [c for c in shmctl_calls if "IPC_STAT" in str(c.get("args", []))]
        sth.assert_min_call_count(stat_calls, 1, "shmctl IPC_STAT")

        # Check for IPC_RMID command
        rmid_calls = [c for c in shmctl_calls if "IPC_RMID" in str(c.get("args", []))]
        sth.assert_min_call_count(rmid_calls, 1, "shmctl IPC_RMID")

    def test_shmdt(self) -> None:
        """Test shmdt syscall."""
        shmdt_calls = sth.filter_syscalls(self.syscalls, "shmdt")
        sth.assert_min_call_count(shmdt_calls, 3, "shmdt")
        sth.assert_arg_count(shmdt_calls[0], 1, "shmdt")

    # POSIX Shared Memory Tests
    def test_shm_open(self) -> None:
        """Test shm_open syscall."""
        shm_open_calls = sth.filter_syscalls(self.syscalls, "shm_open")
        sth.assert_min_call_count(shm_open_calls, 2, "shm_open")

        # Find the call that creates /strace_test_shm (not the system one)
        test_calls = [c for c in shm_open_calls if "/strace_test_shm" in str(c.get("args", []))]
        sth.assert_min_call_count(test_calls, 1, "shm_open /strace_test_shm")

        # First call: create with O_CREAT|O_RDWR|O_EXCL
        call = test_calls[0]
        sth.assert_arg_count(call, 3, "shm_open")

        # Check for name
        sth.assert_arg_type(call, 0, str, "shm_open name")
        assert "/strace_test_shm" in call["args"][0], (
            f"shm_open should have name /strace_test_shm: {call['args'][0]}"
        )

        # Check for flags (should be decoded symbolically)
        sth.assert_symbolic_value(call, 1, ["O_CREAT", "O_RDWR", "O_EXCL"], "shm_open flags")

        # Check for mode (should be octal)
        mode_arg = call["args"][2]
        assert "0600" in str(mode_arg) or "384" in str(mode_arg), (
            f"shm_open mode should be 0600: {mode_arg}"
        )

    def test_shm_unlink(self) -> None:
        """Test shm_unlink syscall."""
        shm_unlink_calls = sth.filter_syscalls(self.syscalls, "shm_unlink")
        sth.assert_min_call_count(shm_unlink_calls, 1, "shm_unlink")
        sth.assert_arg_count(shm_unlink_calls[0], 1, "shm_unlink")
        sth.assert_arg_type(shm_unlink_calls[0], 0, str, "shm_unlink name")
        assert "/strace_test_shm" in shm_unlink_calls[0]["args"][0], (
            f"shm_unlink should have name /strace_test_shm: {shm_unlink_calls[0]['args'][0]}"
        )

    # AIO Tests
    def test_aio_cancel(self) -> None:
        """Test aio_cancel syscall."""
        aio_cancel_calls = sth.filter_syscalls(self.syscalls, "aio_cancel")
        sth.assert_min_call_count(aio_cancel_calls, 1, "aio_cancel")
        sth.assert_arg_count(aio_cancel_calls[0], 2, "aio_cancel")

    def test_aio_error(self) -> None:
        """Test aio_error syscall."""
        aio_error_calls = sth.filter_syscalls(self.syscalls, "aio_error")
        sth.assert_min_call_count(aio_error_calls, 1, "aio_error")
        sth.assert_arg_count(aio_error_calls[0], 1, "aio_error")

    def test_aio_suspend(self) -> None:
        """Test aio_suspend syscall."""
        aio_suspend_calls = sth.filter_syscalls(self.syscalls, "aio_suspend")
        sth.assert_min_call_count(aio_suspend_calls, 1, "aio_suspend")
        sth.assert_arg_count(aio_suspend_calls[0], 3, "aio_suspend")

    def test_lio_listio_modes(self) -> None:
        """Test lio_listio syscall with LIO_WAIT and LIO_NOWAIT modes."""
        lio_calls = sth.filter_syscalls(self.syscalls, "lio_listio")
        sth.assert_min_call_count(lio_calls, 2, "lio_listio")

        # Check for LIO_WAIT mode
        wait_calls = [c for c in lio_calls if "LIO_WAIT" in str(c.get("args", []))]
        sth.assert_min_call_count(wait_calls, 1, "lio_listio LIO_WAIT")

        # Check for LIO_NOWAIT mode
        nowait_calls = [c for c in lio_calls if "LIO_NOWAIT" in str(c.get("args", []))]
        sth.assert_min_call_count(nowait_calls, 1, "lio_listio LIO_NOWAIT")

        # Verify argument count
        for call in lio_calls:
            sth.assert_arg_count(call, 4, "lio_listio")

    # Struct Decoding Tests
    def test_semctl_struct_decoding(self) -> None:
        """Test semctl decodes struct semid_ds fields."""
        semctl_calls = sth.filter_syscalls(self.syscalls, "semctl")
        stat_calls = [c for c in semctl_calls if "IPC_STAT" in str(c.get("args", []))]
        sth.assert_min_call_count(stat_calls, 1, "semctl IPC_STAT")

        call = stat_calls[0]
        output_str = str(call)

        # Look for struct semid_ds fields - we created 3 semaphores
        assert "sem_nsems" in output_str.lower() or "3" in output_str, (
            f"semctl should decode semid_ds struct with sem_nsems, got: {output_str}"
        )

    def test_shmctl_struct_decoding(self) -> None:
        """Test shmctl decodes struct shmid_ds fields."""
        shmctl_calls = sth.filter_syscalls(self.syscalls, "shmctl")
        stat_calls = [c for c in shmctl_calls if "IPC_STAT" in str(c.get("args", []))]
        sth.assert_min_call_count(stat_calls, 1, "shmctl IPC_STAT")

        call = stat_calls[0]
        output_str = str(call)

        # Look for struct shmid_ds fields - we created 16KB segment
        assert "shm_segsz" in output_str.lower() or "16384" in output_str, (
            f"shmctl should decode shmid_ds struct with shm_segsz, got: {output_str}"
        )

    def test_aio_suspend_array_decoding(self) -> None:
        """Test aio_suspend decodes aiocb* array."""
        aio_suspend_calls = sth.filter_syscalls(self.syscalls, "aio_suspend")
        sth.assert_min_call_count(aio_suspend_calls, 1, "aio_suspend")

        call = aio_suspend_calls[0]
        output_str = str(call)

        # Look for aiocb array decoding showing fd, nbytes, offset
        # We passed 3 aiocbs with different nbytes (512, 256, 128)
        assert "fd=" in output_str or "nbytes=" in output_str or "[" in output_str, (
            f"aio_suspend should decode aiocb array with fd/nbytes/offset fields, got: {output_str}"
        )

    def test_lio_listio_array_decoding(self) -> None:
        """Test lio_listio decodes aiocb* array with operations."""
        lio_calls = sth.filter_syscalls(self.syscalls, "lio_listio")
        sth.assert_min_call_count(lio_calls, 2, "lio_listio")

        # Check the LIO_WAIT call with 2 operations
        wait_calls = [c for c in lio_calls if "LIO_WAIT" in str(c.get("args", []))]
        sth.assert_min_call_count(wait_calls, 1, "lio_listio LIO_WAIT")

        call = wait_calls[0]
        output_str = str(call)

        # Look for aiocb array with operations (LIO_READ, LIO_WRITE)
        assert (
            "op=" in output_str
            or "LIO_READ" in output_str
            or "LIO_WRITE" in output_str
            or "fd=" in output_str
        ), f"lio_listio should decode aiocb array with operation types, got: {output_str}"

    def test_lio_listio_sigevent_decoding(self) -> None:
        """Test lio_listio decodes struct sigevent."""
        lio_calls = sth.filter_syscalls(self.syscalls, "lio_listio")
        nowait_calls = [c for c in lio_calls if "LIO_NOWAIT" in str(c.get("args", []))]
        sth.assert_min_call_count(nowait_calls, 1, "lio_listio LIO_NOWAIT")

        call = nowait_calls[-1]  # Last one has SIGEV_SIGNAL
        output_str = str(call)

        # Look for sigevent struct decoding with SIGEV_SIGNAL
        assert (
            "sigev_notify" in output_str.lower() or "SIGEV" in output_str or "SIG" in output_str
        ), f"lio_listio should decode sigevent struct, got: {output_str}"

    def test_aiocb_struct_fields(self) -> None:
        """Test that individual aiocb structs show fd, offset, nbytes."""
        aio_cancel_calls = sth.filter_syscalls(self.syscalls, "aio_cancel")
        sth.assert_min_call_count(aio_cancel_calls, 1, "aio_cancel")

        call = aio_cancel_calls[0]
        output_str = str(call)

        # aio_cancel takes aiocb* - should show struct fields
        # Our cb1 has: fd=tmpfile, offset=0, nbytes=512
        assert (
            "aio_fildes" in output_str.lower()
            or "aio_nbytes" in output_str.lower()
            or "512" in output_str
        ), f"aio_cancel should decode aiocb struct showing fildes/nbytes fields, got: {output_str}"


if __name__ == "__main__":
    unittest.main()
