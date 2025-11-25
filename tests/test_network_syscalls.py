"""
Test comprehensive network syscall coverage.

This test verifies that the --network mode exercises most socket-related syscalls.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
import syscall_test_helpers as sth  # type: ignore[import-not-found]


class TestNetworkSyscalls(unittest.TestCase):
    """Test network syscall coverage using the test executable's --network mode."""

    exit_code: int
    syscalls: list[dict]

    @classmethod
    def setUpClass(cls) -> None:
        """Run the test executable once and capture syscalls for all tests."""
        cls.exit_code, cls.syscalls = sth.run_strace_for_mode("--network", Path(__file__))

    def test_executable_exits_successfully(self) -> None:
        """Test that the executable runs without errors."""
        assert self.exit_code == 0, f"Test executable should exit with 0, got {self.exit_code}"

    def test_network_syscall_coverage(self) -> None:  # noqa: PLR0915
        """Test that all expected network syscalls are captured and decoded."""

        # Expected network syscalls - we capture 12+ out of 15 reliably
        expected_syscalls = {
            "socketpair",
            "socket",
            "bind",
            "listen",
            "accept",
            "connect",
            "sendto",
            "recvfrom",
            "sendmsg",
            "recvmsg",
            "shutdown",
            "getsockname",
            "getpeername",
            "getsockopt",
            "setsockopt",  # May not always be captured due to timing/inlining
        }

        # We should capture at least 12 out of 15 expected syscalls
        sth.assert_syscall_coverage(self.syscalls, expected_syscalls, 12, "network syscalls")

        # Verify symbolic decoders are working correctly
        # Test socketpair(domain, type, protocol, sv)
        socketpair_calls = sth.filter_syscalls(self.syscalls, "socketpair")
        sth.assert_min_call_count(socketpair_calls, 1, "socketpair")
        sth.assert_symbolic_value(socketpair_calls[0], 0, "AF_UNIX", "socketpair domain")
        sth.assert_symbolic_value(socketpair_calls[0], 1, "SOCK_STREAM", "socketpair type")

        # Test socket(domain, type, protocol)
        socket_calls = sth.filter_syscalls(self.syscalls, "socket")
        sth.assert_min_call_count(socket_calls, 1, "socket")
        sth.assert_symbolic_value(socket_calls[0], 0, "AF_", "socket domain")
        sth.assert_symbolic_value(socket_calls[0], 1, "SOCK_", "socket type")

        # Test shutdown(sockfd, how)
        shutdown_calls = sth.filter_syscalls(self.syscalls, "shutdown")
        sth.assert_min_call_count(shutdown_calls, 1, "shutdown")
        sth.assert_symbolic_value(shutdown_calls[0], 1, "SHUT_", "shutdown how")

        # Test getsockopt(sockfd, level, optname, optval, optlen)
        getsockopt_calls = sth.filter_syscalls(self.syscalls, "getsockopt")
        sth.assert_min_call_count(getsockopt_calls, 1, "getsockopt")
        sth.assert_symbolic_value(getsockopt_calls[0], 1, "SOL_SOCKET", "getsockopt level")
        sth.assert_symbolic_value(getsockopt_calls[0], 2, "SO_", "getsockopt optname")

        # Test setsockopt(sockfd, level, optname, optval, optlen)
        setsockopt_calls = sth.filter_syscalls(self.syscalls, "setsockopt")
        sth.assert_min_call_count(setsockopt_calls, 1, "setsockopt")
        sth.assert_symbolic_value(setsockopt_calls[0], 1, "SOL_SOCKET", "setsockopt level")
        sth.assert_symbolic_value(setsockopt_calls[0], 2, "SO_KEEPALIVE", "setsockopt optname")

        # Test bind: should decode sockaddr structure
        # Expected output: bind(3, {sa_family=AF_UNIX, sun_path="/tmp/strace_test.12345"}, 106)
        bind_calls = sth.filter_syscalls(self.syscalls, "bind")
        sth.assert_min_call_count(bind_calls, 1, "bind")
        addr_fields = sth.assert_struct_field(bind_calls[0], 1, "sa_family", "bind")
        # For Unix sockets, should show sun_path
        assert "sun_path" in addr_fields or "AF_UNIX" in str(addr_fields), (
            f"bind should decode sockaddr, got {addr_fields}"
        )

        # Test sendto: should decode buffer contents and flags
        # Expected output: sendto(3, "test", 4, 0, NULL, 0)
        sendto_calls = sth.filter_syscalls(self.syscalls, "sendto")
        sth.assert_min_call_count(sendto_calls, 1, "sendto")
        buf_arg = sendto_calls[0]["args"][1]
        assert '"' in buf_arg, f"sendto buffer should be decoded as string, got {buf_arg}"
        assert "test" in buf_arg, f"sendto buffer should contain 'test', got {buf_arg}"

        # Flags should already be decoded with current decode_msg_flags
        flags_arg = sendto_calls[0]["args"][3]
        assert flags_arg == "0" or "MSG_" in flags_arg, (
            f"sendto flags should be decoded, got {flags_arg}"
        )

        # Test recvfrom: should decode buffer contents and flags
        recvfrom_calls = sth.filter_syscalls(self.syscalls, "recvfrom")
        sth.assert_min_call_count(recvfrom_calls, 1, "recvfrom")
        flags_arg = recvfrom_calls[0]["args"][3]
        assert flags_arg == "0" or "MSG_" in flags_arg, (
            f"recvfrom flags should be decoded, got {flags_arg}"
        )

        # Test sendmsg: should decode msghdr structure
        # Expected output: sendmsg(3, {msg_name=NULL, msg_iov=[...], ...}, 0)
        sendmsg_calls = sth.filter_syscalls(self.syscalls, "sendmsg")
        sth.assert_min_call_count(sendmsg_calls, 1, "sendmsg")
        msg_fields = sth.assert_struct_field(sendmsg_calls[0], 1, "msg_iov", "sendmsg")
        # msg_iov should be a list of iovec dicts
        assert isinstance(msg_fields["msg_iov"], list), (
            f"msg_iov should be a list, got {type(msg_fields['msg_iov'])}"
        )
        assert len(msg_fields["msg_iov"]) > 0, (
            f"msg_iov should have elements, got {msg_fields['msg_iov']}"
        )
        # Check first iovec
        iov = msg_fields["msg_iov"][0]
        assert "iov_base" in iov, f"iovec should have iov_base, got {iov}"
        assert "iov_len" in iov, f"iovec should have iov_len, got {iov}"
        # iov_base should be a plain string without quotes (quotes are added by JSON serialization)
        assert iov["iov_base"] == "msg", (
            f"iovec buffer should be 'msg' (without quotes), got {iov['iov_base']!r}"
        )
        assert iov["iov_len"] == 3, f"iovec length should be 3, got {iov['iov_len']}"

        # Test getsockname: should decode sockaddr
        getsockname_calls = sth.filter_syscalls(self.syscalls, "getsockname")
        sth.assert_min_call_count(getsockname_calls, 1, "getsockname")
        sth.assert_struct_field(getsockname_calls[0], 1, "sa_family", "getsockname")

        # Test getpeername: should decode sockaddr
        getpeername_calls = sth.filter_syscalls(self.syscalls, "getpeername")
        sth.assert_min_call_count(getpeername_calls, 1, "getpeername")
        sth.assert_struct_field(getpeername_calls[0], 1, "sa_family", "getpeername")

        # Test accept: should decode sockaddr
        accept_calls = sth.filter_syscalls(self.syscalls, "accept")
        sth.assert_min_call_count(accept_calls, 1, "accept")
        sth.assert_struct_field(accept_calls[0], 1, "sa_family", "accept")

    def test_sendmsg_recvmsg_formatting_regression(self) -> None:
        """Regression test for issue #3: sendmsg/recvmsg should use C struct syntax.

        The output should be: msg_iov=[{iov_base="msg", iov_len=3}]
        """
        # Test sendmsg
        sendmsg_calls = sth.filter_syscalls(self.syscalls, "sendmsg")
        sth.assert_min_call_count(sendmsg_calls, 1, "sendmsg")

        msg_fields = sth.assert_struct_field(sendmsg_calls[0], 1, "msg_iov", "sendmsg")
        iov = msg_fields["msg_iov"][0]

        # In JSON output, iov_base should be a plain string "msg"
        assert iov["iov_base"] == "msg", (
            f"sendmsg iov_base should be 'msg', got {iov['iov_base']!r}"
        )
        assert iov["iov_len"] == 3, f"sendmsg iov_len should be 3, got {iov['iov_len']}"

        # Test recvmsg
        recvmsg_calls = sth.filter_syscalls(self.syscalls, "recvmsg")
        sth.assert_min_call_count(recvmsg_calls, 1, "recvmsg")

        msg_fields = sth.assert_struct_field(recvmsg_calls[0], 1, "msg_iov", "recvmsg")
        iov = msg_fields["msg_iov"][0]

        # Verify iov_base is properly decoded as a string
        assert isinstance(iov["iov_base"], str), (
            f"recvmsg iov_base should be a string, got {type(iov['iov_base'])}"
        )

    def test_af_inet_byte_order_regression(self) -> None:
        """Regression test for issue #4: AF_INET addresses should show 127.0.0.1."""
        bind_calls = sth.filter_syscalls(self.syscalls, "bind")
        sth.assert_min_call_count(bind_calls, 1, "bind")

        # Find the AF_INET bind call (there should be at least one)
        inet_bind = None
        for call in bind_calls:
            addr_fields = sth.assert_struct_field(call, 1, "sa_family", "bind")
            if addr_fields.get("sa_family") == "AF_INET":
                inet_bind = call
                break

        assert inet_bind is not None, "Should have at least one AF_INET bind call"

        addr_fields = sth.assert_struct_field(inet_bind, 1, "sin_addr", "bind AF_INET")
        sin_addr = addr_fields.get("sin_addr", "")

        # Should contain 127.0.0.1
        assert "127.0.0.1" in sin_addr, f"AF_INET bind should show 127.0.0.1, got {sin_addr}"

    def test_socketpair_shows_fds_regression(self) -> None:
        """Regression test for issue #18: socketpair should show created FD pair.

        socketpair() should decode the sv[2] output parameter to show the two
        file descriptors created, formatted as [fd1, fd2].
        """
        socketpair_calls = sth.filter_syscalls(self.syscalls, "socketpair")
        sth.assert_min_call_count(socketpair_calls, 1, "socketpair")

        call = socketpair_calls[0]
        sv = call["args"][3]

        # Should be a string like "[3, 4]" showing the two FDs
        assert isinstance(sv, str), f"socketpair sv should be decoded as string, got {type(sv)}"
        assert sv.startswith("["), f"socketpair sv should start with '[', got: {sv}"
        assert sv.endswith("]"), f"socketpair sv should end with ']', got: {sv}"
        assert "," in sv, f"socketpair sv should contain two FDs separated by comma, got: {sv}"


if __name__ == "__main__":
    unittest.main()
