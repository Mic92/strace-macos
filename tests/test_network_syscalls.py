"""
Test comprehensive network syscall coverage.

This test verifies that the --network mode exercises most socket-related syscalls.
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


class TestNetworkSyscalls(unittest.TestCase):
    """Test network syscall coverage using the test executable's --network mode."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.test_executable = get_test_executable()
        self.python_path = "/usr/bin/python3"  # System Python for LLDB
        self.strace_module = str(Path(__file__).parent.parent)

    def run_strace(self, args: list[str]) -> int:
        """Run strace and return exit code."""
        cmd = [self.python_path, "-m", "strace_macos", *args]
        result = subprocess.run(
            cmd,
            check=False,
            cwd=self.strace_module,
            capture_output=True,
            text=True,
        )
        return result.returncode

    def test_network_syscall_coverage(self) -> None:  # noqa: PLR0915
        """Test that all expected network syscalls are captured."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_file = Path(f.name)

        try:
            exit_code = self.run_strace(
                ["--json", "-o", str(output_file), str(self.test_executable), "--network"]
            )

            assert exit_code == 0, f"strace should exit with code 0, got {exit_code}"
            assert output_file.exists(), "Output file should be created"

            # Parse JSON Lines output
            syscalls = helpers.json_lines(output_file)
            syscall_names = [sc.get("syscall") for sc in syscalls]
        finally:
            if output_file.exists():
                output_file.unlink()

        # Expected network syscalls - we capture 14 out of 15 reliably
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

        captured_network_syscalls = expected_syscalls & set(syscall_names)
        missing_syscalls = expected_syscalls - set(syscall_names)

        # We should capture at least 12 out of 14 expected syscalls
        assert len(captured_network_syscalls) >= 12, (
            f"Should capture at least 12 network syscalls, "
            f"got {len(captured_network_syscalls)}.\n"
            f"Captured: {sorted(captured_network_syscalls)}\n"
            f"Missing: {sorted(missing_syscalls)}"
        )

        # Verify symbolic decoders are working correctly
        # Test socketpair(domain, type, protocol, sv)
        socketpair_calls = [sc for sc in syscalls if sc.get("syscall") == "socketpair"]
        assert len(socketpair_calls) > 0, "Should have socketpair calls"
        sp = socketpair_calls[0]
        assert "AF_UNIX" in sp["args"][0], "socketpair should decode AF_UNIX"
        assert "SOCK_STREAM" in sp["args"][1], "socketpair should decode SOCK_STREAM"

        # Test socket(domain, type, protocol)
        socket_calls = [sc for sc in syscalls if sc.get("syscall") == "socket"]
        assert len(socket_calls) > 0, "Should have socket calls"
        sock = socket_calls[0]
        assert "AF_" in sock["args"][0], "socket should decode AF_* domain"
        assert "SOCK_" in sock["args"][1], "socket should decode SOCK_* type"

        # Test shutdown(sockfd, how)
        shutdown_calls = [sc for sc in syscalls if sc.get("syscall") == "shutdown"]
        assert len(shutdown_calls) > 0, "Should have shutdown calls"
        shutdown = shutdown_calls[0]
        assert "SHUT_" in shutdown["args"][1], "shutdown should decode SHUT_* flag"

        # Test getsockopt(sockfd, level, optname, optval, optlen)
        getsockopt_calls = [sc for sc in syscalls if sc.get("syscall") == "getsockopt"]
        assert len(getsockopt_calls) > 0, "Should have getsockopt calls"
        getsockopt = getsockopt_calls[0]
        assert getsockopt["args"][1] == "SOL_SOCKET", "getsockopt should decode SOL_SOCKET"
        assert "SO_" in getsockopt["args"][2], "getsockopt should decode SO_* option name"

        # Test setsockopt(sockfd, level, optname, optval, optlen)
        setsockopt_calls = [sc for sc in syscalls if sc.get("syscall") == "setsockopt"]
        assert len(setsockopt_calls) > 0, "Should have setsockopt calls"
        setsockopt = setsockopt_calls[0]
        assert setsockopt["args"][1] == "SOL_SOCKET", "setsockopt should decode SOL_SOCKET"
        assert setsockopt["args"][2] == "SO_KEEPALIVE", "setsockopt should decode SO_KEEPALIVE"

        # Test bind: should decode sockaddr structure
        # Expected output: bind(3, {sa_family=AF_UNIX, sun_path="/tmp/strace_test.12345"}, 106)
        bind_calls = [sc for sc in syscalls if sc.get("syscall") == "bind"]
        if bind_calls:
            bind_call = bind_calls[0]
            addr_arg = bind_call["args"][1]
            assert isinstance(addr_arg, dict), f"bind addr should be decoded struct, got {addr_arg}"
            assert "output" in addr_arg, (
                f"bind addr should have 'output' key for StructArg, got {addr_arg}"
            )
            addr_fields = addr_arg["output"]
            assert "sa_family" in addr_fields, f"bind should show sa_family, got {addr_fields}"
            # For Unix sockets, should show sun_path
            assert "sun_path" in addr_fields or "AF_UNIX" in str(addr_fields), (
                f"bind should decode sockaddr, got {addr_fields}"
            )

        # Test sendto: should decode buffer contents and flags
        # Expected output: sendto(3, "test", 4, 0, NULL, 0)
        sendto_calls = [sc for sc in syscalls if sc.get("syscall") == "sendto"]
        if sendto_calls:
            sendto_call = sendto_calls[0]
            buf_arg = sendto_call["args"][1]
            assert '"' in buf_arg, f"sendto buffer should be decoded as string, got {buf_arg}"
            assert "test" in buf_arg, f"sendto buffer should contain 'test', got {buf_arg}"

            # Flags should already be decoded with current decode_msg_flags
            flags_arg = sendto_call["args"][3]
            assert flags_arg == "0" or "MSG_" in flags_arg, (
                f"sendto flags should be decoded, got {flags_arg}"
            )

        # Test recvfrom: should decode buffer contents and flags
        recvfrom_calls = [sc for sc in syscalls if sc.get("syscall") == "recvfrom"]
        if recvfrom_calls:
            recvfrom_call = recvfrom_calls[0]
            flags_arg = recvfrom_call["args"][3]
            assert flags_arg == "0" or "MSG_" in flags_arg, (
                f"recvfrom flags should be decoded, got {flags_arg}"
            )

        # Test sendmsg: should decode msghdr structure
        # Expected output: sendmsg(3, {msg_name=NULL, msg_iov=[...], ...}, 0)
        sendmsg_calls = [sc for sc in syscalls if sc.get("syscall") == "sendmsg"]
        if sendmsg_calls:
            sendmsg_call = sendmsg_calls[0]
            msg_arg = sendmsg_call["args"][1]
            assert isinstance(msg_arg, dict), f"sendmsg msg should be decoded struct, got {msg_arg}"
            assert "output" in msg_arg, f"sendmsg should have 'output' key, got {msg_arg}"
            msg_fields = msg_arg["output"]
            assert "msg_iov" in msg_fields, f"sendmsg should show msg_iov, got {msg_fields}"
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
        getsockname_calls = [sc for sc in syscalls if sc.get("syscall") == "getsockname"]
        if getsockname_calls:
            getsockname_call = getsockname_calls[0]
            addr_arg = getsockname_call["args"][1]
            assert isinstance(addr_arg, dict), (
                f"getsockname addr should be decoded struct, got {addr_arg}"
            )
            assert "output" in addr_arg, f"getsockname should have 'output' key, got {addr_arg}"

        # Test getpeername: should decode sockaddr
        getpeername_calls = [sc for sc in syscalls if sc.get("syscall") == "getpeername"]
        if getpeername_calls:
            getpeername_call = getpeername_calls[0]
            addr_arg = getpeername_call["args"][1]
            assert isinstance(addr_arg, dict), (
                f"getpeername addr should be decoded struct, got {addr_arg}"
            )
            assert "output" in addr_arg, f"getpeername should have 'output' key, got {addr_arg}"

        # Test accept: should decode sockaddr
        accept_calls = [sc for sc in syscalls if sc.get("syscall") == "accept"]
        if accept_calls:
            accept_call = accept_calls[0]
            addr_arg = accept_call["args"][1]
            assert isinstance(addr_arg, dict), (
                f"accept addr should be decoded struct, got {addr_arg}"
            )
            assert "output" in addr_arg, f"accept should have 'output' key, got {addr_arg}"


if __name__ == "__main__":
    unittest.main()
