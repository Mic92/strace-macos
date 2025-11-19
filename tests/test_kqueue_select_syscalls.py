"""Tests for kqueue, kevent, select, pselect, and poll syscalls."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
import syscall_test_helpers as sth  # type: ignore[import-not-found]


class TestKqueueSelectSyscalls(unittest.TestCase):
    """Test kqueue, kevent, select, pselect, and poll syscall decoding."""

    exit_code: int
    syscalls: list[dict]

    @classmethod
    def setUpClass(cls) -> None:
        """Run the test executable once and capture syscalls for all tests."""
        cls.exit_code, cls.syscalls = sth.run_strace_for_mode("--kqueue-select", Path(__file__))

    def test_executable_exits_successfully(self) -> None:
        """Test that the executable runs without errors."""
        assert self.exit_code == 0, f"Test executable should exit with 0, got {self.exit_code}"

    def test_kqueue_select_coverage(self) -> None:
        """Test that expected kqueue/select syscalls are captured.

        Note: *_nocancel variants are omitted (no public prototypes).
        kevent_id, kevent_qos, kqueue_workloop_ctl, guarded_kqueue_np are omitted (no public prototypes).
        """
        expected_syscalls = {
            "kqueue",
            "kevent",
            "kevent64",
            "select",
            "pselect",
            "poll",
        }
        sth.assert_syscall_coverage(self.syscalls, expected_syscalls, 6, "kqueue/select syscalls")

    # ==========================================================================
    # Kqueue Tests
    # ==========================================================================

    def test_kqueue_traced(self) -> None:
        """Test kqueue() syscall is traced.

        Expected output:
        kqueue() = 3
        """
        kqueue_calls = sth.filter_syscalls(self.syscalls, "kqueue")
        sth.assert_min_call_count(kqueue_calls, 1, "kqueue")

    def test_kevent_decodes_filters_and_flags(self) -> None:
        """Test kevent decodes filter types, event flags, and filter-specific flags.

        Expected output should include:
        - Filter types: EVFILT_READ, EVFILT_WRITE, EVFILT_VNODE, EVFILT_TIMER
        - Event flags: EV_ADD, EV_ENABLE, EV_ONESHOT, EV_CLEAR, EV_DELETE, EV_DISABLE
        - Filter-specific flags (fflags): NOTE_WRITE, NOTE_DELETE, NOTE_USECONDS
        - Timespec timeout: tv_sec, tv_nsec

        Example:
        kevent(3, [{ident=4, filter=EVFILT_READ, flags=EV_ADD|EV_ENABLE, ...},
                   {filter=EVFILT_VNODE, flags=EV_ADD|EV_ENABLE|EV_CLEAR, fflags=NOTE_WRITE|NOTE_DELETE, ...},
                   {filter=EVFILT_TIMER, flags=EV_ADD|EV_ENABLE, fflags=NOTE_USECONDS, data=500000, ...}],
              4, NULL, 0, {tv_sec=0, tv_nsec=0})
        """
        kevent_calls = sth.filter_syscalls(self.syscalls, "kevent")
        sth.assert_min_call_count(kevent_calls, 3, "kevent")

        output = str(kevent_calls)

        # Check filter type decoding (EVFILT_*)
        has_filters = (
            "EVFILT_READ" in output
            or "EVFILT_WRITE" in output
            or "EVFILT_VNODE" in output
            or "EVFILT_TIMER" in output
        )
        assert has_filters, f"kevent should decode EVFILT_* filter constants, got: {output}"

        # Check event flags decoding (EV_*)
        has_ev_flags = (
            "EV_ADD" in output
            or "EV_ENABLE" in output
            or "EV_ONESHOT" in output
            or "EV_CLEAR" in output
            or "EV_DELETE" in output
            or "EV_DISABLE" in output
        )
        assert has_ev_flags, f"kevent should decode EV_* event flags, got: {output}"

        # Check filter-specific flags decoding (NOTE_*)
        has_note_flags = (
            "NOTE_WRITE" in output or "NOTE_DELETE" in output or "NOTE_USECONDS" in output
        )
        assert has_note_flags, f"kevent should decode NOTE_* filter-specific flags, got: {output}"

        # Check timespec decoding
        has_timespec = "tv_sec" in output and "tv_nsec" in output
        assert has_timespec, f"kevent should decode struct timespec timeout, got: {output}"

    def test_kevent64_traced(self) -> None:
        """Test kevent64 syscall is traced.

        Expected output:
        kevent64(3, [{filter=EVFILT_READ, flags=EV_ADD|EV_ENABLE, ...}], 2, ...)
        """
        kevent64_calls = sth.filter_syscalls(self.syscalls, "kevent64")
        sth.assert_min_call_count(kevent64_calls, 2, "kevent64")

    # ==========================================================================
    # Select Tests
    # ==========================================================================

    def test_select_timeval_timeout(self) -> None:
        """Test select uses struct timeval (not timespec).

        Expected output:
        select(6, [4], [5], [], {tv_sec=0, tv_usec=100000}) = 2 (in [4], out [5])

        Key distinction: select uses timeval with tv_usec (microseconds),
        while pselect uses timespec with tv_nsec (nanoseconds).
        """
        select_calls = sth.filter_syscalls(self.syscalls, "select")
        sth.assert_min_call_count(select_calls, 3, "select")

        output = str(select_calls)
        # select must use tv_usec, NOT tv_nsec
        has_timeval = "tv_sec" in output and "tv_usec" in output
        assert has_timeval, f"select should decode struct timeval (tv_usec), got: {output}"

    # ==========================================================================
    # Pselect Tests
    # ==========================================================================

    def test_pselect_timespec_timeout(self) -> None:
        """Test pselect uses struct timespec (not timeval).

        Expected output:
        pselect(6, [4], [5], NULL, {tv_sec=0, tv_nsec=100000000}, NULL) = 2 (in [4], out [5])

        Key distinction: pselect uses timespec with tv_nsec (nanoseconds),
        while select uses timeval with tv_usec (microseconds).
        """
        pselect_calls = sth.filter_syscalls(self.syscalls, "pselect")
        sth.assert_min_call_count(pselect_calls, 3, "pselect")

        output = str(pselect_calls)
        # pselect must use tv_nsec, NOT tv_usec
        has_timespec = "tv_sec" in output and "tv_nsec" in output
        assert has_timespec, f"pselect should decode struct timespec (tv_nsec), got: {output}"

    # ==========================================================================
    # Poll Tests
    # ==========================================================================

    def test_poll_event_flags(self) -> None:
        """Test poll decodes event flags (POLLIN, POLLOUT, etc.).

        Expected output should include:
        poll([{fd=4, events=POLLIN}], 1, 100) = 1 ([{fd=4, revents=POLLIN}])
        poll([{fd=4, events=POLLIN|POLLPRI}, {fd=5, events=POLLOUT}], 2, 50) = 2
        poll([{fd=4, events=POLLERR|POLLHUP}], 1, 0) = ...
        """
        poll_calls = sth.filter_syscalls(self.syscalls, "poll")
        sth.assert_min_call_count(poll_calls, 4, "poll")

        output = str(poll_calls)
        # We use POLLIN, POLLOUT, POLLPRI, POLLERR, POLLHUP in our test
        has_events = (
            "POLLIN" in output
            or "POLLOUT" in output
            or "POLLPRI" in output
            or "POLLERR" in output
            or "POLLHUP" in output
        )
        assert has_events, f"poll should decode POLL* event flags, got: {output}"


if __name__ == "__main__":
    unittest.main()
