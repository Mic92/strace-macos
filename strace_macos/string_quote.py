"""String quoting utilities for safely displaying buffer data.

This module implements string quoting similar to strace, filtering out
non-printable characters and escaping special characters appropriately.
"""

from __future__ import annotations

# Mapping of special bytes to their escape sequences
_ESCAPE_MAP = {
    ord('"'): '\\"',
    ord("\\"): "\\\\",
    ord("\t"): "\\t",
    ord("\n"): "\\n",
    ord("\r"): "\\r",
    ord("\v"): "\\v",
    ord("\f"): "\\f",
}


def is_printable(c: int) -> bool:
    """Check if a character is printable ASCII.

    Args:
        c: Character code (0-255)

    Returns:
        True if the character is printable (space through ~)
    """
    return 0x20 <= c < 0x7F  # Space (32) through ~ (126)


def _escape_byte(byte: int, next_byte: int | None) -> str:
    """Escape a single byte for terminal output.

    Args:
        byte: The byte to escape
        next_byte: The next byte in the sequence (or None if last byte)

    Returns:
        Escaped string representation of the byte
    """
    # Check if it's a special character with predefined escape
    if byte in _ESCAPE_MAP:
        return _ESCAPE_MAP[byte]

    # Check if printable
    if is_printable(byte):
        return chr(byte)

    # Non-printable: use octal escape
    # Use 3-digit octal if next char is a digit 0-7, otherwise minimal
    if next_byte is not None and 48 <= next_byte <= 55:  # '0' to '7'
        # Need full 3-digit octal to avoid ambiguity
        return f"\\{byte:03o}"

    # Can use minimal octal representation
    return f"\\{byte:o}"


def quote_string(data: bytes, max_length: int = 32) -> str:
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
        next_byte = display_data[i + 1] if i + 1 < len(display_data) else None
        result.append(_escape_byte(byte, next_byte))

    return "".join(result) + suffix
