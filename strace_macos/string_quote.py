"""String quoting utilities for safely displaying buffer data.

This module implements string quoting similar to strace, filtering out
non-printable characters and escaping special characters appropriately.
"""

from __future__ import annotations


def is_printable(c: int) -> bool:
    """Check if a character is printable ASCII.

    Args:
        c: Character code (0-255)

    Returns:
        True if the character is printable (space through ~)
    """
    return 0x20 <= c < 0x7F  # Space (32) through ~ (126)


def quote_string(data: bytes, max_length: int = 32) -> str:  # noqa: C901
    """Quote and escape a byte string for safe terminal output.

    This function implements string quoting similar to strace:
    - Printable ASCII characters (0x20-0x7E) are shown as-is
    - Special whitespace characters are escaped: \\t, \\n, \\r, \\v, \\f
    - Backslash and quotes are escaped: \\\\, \\"
    - Other non-printable characters are escaped as octal: \\ooo

    Args:
        data: The byte data to quote
        max_length: Maximum number of bytes to display before truncating

    Returns:
        Escaped string representation (without surrounding quotes)
    """
    if not data:
        return ""

    display_data = data[:max_length]
    suffix = "..." if len(data) > max_length else ""
    result = []

    for i, byte in enumerate(display_data):
        # Handle special escape sequences first
        if byte == ord('"'):
            result.append('\\"')
        elif byte == ord("\\"):
            result.append("\\\\")
        elif byte == ord("\t"):
            result.append("\\t")
        elif byte == ord("\n"):
            result.append("\\n")
        elif byte == ord("\r"):
            result.append("\\r")
        elif byte == ord("\v"):
            result.append("\\v")
        elif byte == ord("\f"):
            result.append("\\f")
        # Check if printable
        elif is_printable(byte):
            result.append(chr(byte))
        # Non-printable: use octal escape
        # Use 3-digit octal if next char is a digit, otherwise minimal
        elif i + 1 < len(display_data) and 48 <= display_data[i + 1] <= 55:  # '0' to '7'
            # Need full 3-digit octal to avoid ambiguity
            result.append(f"\\{byte:03o}")
        else:
            # Can use minimal octal representation
            result.append(f"\\{byte:o}")

    return "".join(result) + suffix
