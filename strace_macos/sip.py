"""Utilities for detecting SIP (System Integrity Protection) on macOS."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def resolve_binary_path(path: str | Path) -> Path | None:
    """Resolve a binary path to its absolute location.

    Args:
        path: Path or command name to resolve

    Returns:
        Absolute path to the binary, or None if not found
    """
    path_str = str(path)

    # If it's already an absolute path, just resolve it
    if Path(path_str).is_absolute():
        return Path(path_str).resolve()

    # Otherwise, search in PATH
    resolved = shutil.which(path_str)
    if resolved:
        return Path(resolved).resolve()

    # Try treating it as a relative path
    if Path(path_str).exists():
        return Path(path_str).resolve()

    return None


def is_sip_enabled() -> bool:
    """Check if System Integrity Protection (SIP) is enabled on this system.

    Returns:
        True if SIP is enabled, False if disabled or cannot determine
    """
    try:
        result = subprocess.run(
            ["csrutil", "status"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        # Output format: "System Integrity Protection status: enabled." or "disabled."
        # Check for "Debugging Restrictions: enabled" which is what prevents debugging
        output = result.stdout.lower()
        if "debugging restrictions: enabled" in output:
            return True
        # Fallback: check overall status
        return "status: enabled" in output  # noqa: TRY300
    except (subprocess.TimeoutExpired, FileNotFoundError):
        # If csrutil isn't available, assume SIP is enabled (safer default)
        return True


def is_sip_protected(binary_path: Path) -> bool:
    """Check if a binary is protected by macOS System Integrity Protection (SIP).

    This checks the binary itself for platform binary flags rather than
    relying on path-based heuristics.

    Args:
        binary_path: Absolute path to the binary to check

    Returns:
        True if the binary is SIP-protected
    """
    # If SIP debugging restrictions are disabled, nothing is protected
    if not is_sip_enabled():
        return False

    # Check using codesign for platform binary identifier
    # Platform binaries (part of macOS) have "Platform identifier" and cannot be debugged when SIP is enabled
    try:
        result = subprocess.run(  # noqa: S603
            ["codesign", "-dvvv", str(binary_path)],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        output = result.stderr  # codesign outputs to stderr
        # Look for "Platform identifier=" which indicates an Apple platform binary
        # Adhoc-signed (user-compiled) binaries have "Signature=adhoc" and no platform identifier
        if "platform identifier=" in output.lower():
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        # If codesign isn't available, assume not protected
        pass

    return False


def get_sip_error_message(path: str | Path) -> str:
    """Get a helpful error message for SIP-protected binaries.

    Args:
        path: Path to the SIP-protected binary

    Returns:
        Error message explaining the issue and suggesting alternatives
    """
    return (
        f"Cannot trace '{path}': binary is protected by System Integrity Protection (SIP).\n"
        "SIP prevents debugging system binaries in /bin, /sbin, /usr/bin, /System, etc.\n\n"
        "Alternatives:\n"
        "  - Use binaries from Homebrew: /usr/local/bin/* or /opt/homebrew/bin/*\n"
        "  - Use binaries from Nix: /nix/store/*\n"
        "  - Compile your own binary and place it in /tmp or ~/\n"
        "  - Disable SIP (not recommended): csrutil disable (requires reboot)"
    )
