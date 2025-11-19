"""Tests for signal handling syscalls."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
import syscall_test_helpers as sth  # type: ignore[import-not-found]


class TestSignalSyscalls(unittest.TestCase):
    """Test signal handling syscall decoding."""

    exit_code: int
    syscalls: list[dict]

    @classmethod
    def setUpClass(cls) -> None:
        """Run the test executable once and capture syscalls for all tests."""
        cls.exit_code, cls.syscalls = sth.run_strace_for_mode("--signal", Path(__file__))

    def test_executable_exits_successfully(self) -> None:
        """Test that the executable runs without errors."""
        assert self.exit_code == 0, f"Test executable should exit with 0, got {self.exit_code}"

    def test_signal_coverage(self) -> None:
        """Test that expected signal syscalls are captured.

        Note: sigwait and sigsuspend are omitted because they are blocking
        syscalls that require complex synchronization to test properly.
        """
        expected_syscalls = {
            "kill",
            "sigaction",
            "sigprocmask",
            "sigpending",
            "sigaltstack",
            "pthread_kill",
            "pthread_sigmask",
        }
        sth.assert_syscall_coverage(self.syscalls, expected_syscalls, 7, "signal syscalls")

    def test_kill_signal_constants(self) -> None:
        """Test kill syscall decodes signal number constants."""
        kill_calls = sth.filter_syscalls(self.syscalls, "kill")
        sth.assert_min_call_count(kill_calls, 3, "kill")

        # Check for specific signals we send
        output = str(kill_calls)
        assert "SIGCONT" in output, "Should have kill with SIGCONT"
        assert "SIGUSR1" in output, "Should have kill with SIGUSR1"

    def test_sigaction_signal_constants(self) -> None:
        """Test sigaction decodes signal number constants."""
        sigaction_calls = sth.filter_syscalls(self.syscalls, "sigaction")
        sth.assert_min_call_count(sigaction_calls, 5, "sigaction")

        output = str(sigaction_calls)
        assert "SIGUSR1" in output, "Should have sigaction for SIGUSR1"
        assert "SIGUSR2" in output, "Should have sigaction for SIGUSR2"
        assert "SIGPIPE" in output, "Should have sigaction for SIGPIPE"

    def test_sigaction_struct_decoding(self) -> None:
        """Test sigaction decodes struct sigaction with SA_* flags."""
        sigaction_calls = sth.filter_syscalls(self.syscalls, "sigaction")
        output = str(sigaction_calls)

        # We use SA_RESTART, SA_SIGINFO, SA_NODEFER, SA_RESETHAND in our test
        has_flags = (
            "SA_RESTART" in output
            or "SA_SIGINFO" in output
            or "SA_NODEFER" in output
            or "SA_RESETHAND" in output
        )
        assert has_flags, f"sigaction should decode SA_* flags, got: {output}"

    def test_sigprocmask_how_constants(self) -> None:
        """Test sigprocmask decodes 'how' parameter constants."""
        sigprocmask_calls = sth.filter_syscalls(self.syscalls, "sigprocmask")
        sth.assert_min_call_count(sigprocmask_calls, 4, "sigprocmask")

        output = str(sigprocmask_calls)
        assert "SIG_BLOCK" in output, "Should have SIG_BLOCK"
        assert "SIG_SETMASK" in output, "Should have SIG_SETMASK"
        assert "SIG_UNBLOCK" in output, "Should have SIG_UNBLOCK"

    def test_sigprocmask_sigset_decoding(self) -> None:
        """Test sigprocmask decodes sigset_t showing signal names."""
        sigprocmask_calls = sth.filter_syscalls(self.syscalls, "sigprocmask")
        output = str(sigprocmask_calls)

        # We block/unblock SIGUSR1, SIGUSR2, SIGTERM, SIGINT in our test
        has_signals = (
            "SIGUSR1" in output or "SIGUSR2" in output or "SIGTERM" in output or "SIGINT" in output
        )
        assert has_signals, f"sigprocmask should decode signals in sigset_t, got: {output}"

    def test_sigpending_traced(self) -> None:
        """Test sigpending syscall is traced."""
        sigpending_calls = sth.filter_syscalls(self.syscalls, "sigpending")
        sth.assert_min_call_count(sigpending_calls, 1, "sigpending")

    def test_sigaltstack_struct_decoding(self) -> None:
        """Test sigaltstack decodes stack_t structure."""
        sigaltstack_calls = sth.filter_syscalls(self.syscalls, "sigaltstack")
        sth.assert_min_call_count(sigaltstack_calls, 3, "sigaltstack")

        output = str(sigaltstack_calls)
        # Look for SS_DISABLE flag we use
        has_stack_info = (
            "ss_sp" in output.lower()
            or "ss_size" in output.lower()
            or "SS_DISABLE" in output
            or "SIGSTKSZ" in output
        )
        assert has_stack_info, f"sigaltstack should decode stack_t struct, got: {output}"

    def test_pthread_kill_signal_constants(self) -> None:
        """Test pthread_kill decodes signal constants."""
        pthread_kill_calls = sth.filter_syscalls(self.syscalls, "pthread_kill")
        sth.assert_min_call_count(pthread_kill_calls, 3, "pthread_kill")

        output = str(pthread_kill_calls)
        has_signals = "SIGCONT" in output or "SIGUSR1" in output
        assert has_signals, f"pthread_kill should decode signal numbers, got: {output}"

    def test_pthread_sigmask_how_constants(self) -> None:
        """Test pthread_sigmask decodes 'how' parameter."""
        pthread_sigmask_calls = sth.filter_syscalls(self.syscalls, "pthread_sigmask")
        sth.assert_min_call_count(pthread_sigmask_calls, 4, "pthread_sigmask")

        output = str(pthread_sigmask_calls)
        has_how = "SIG_BLOCK" in output or "SIG_SETMASK" in output or "SIG_UNBLOCK" in output
        assert has_how, f"pthread_sigmask should decode 'how' constant, got: {output}"


if __name__ == "__main__":
    unittest.main()
