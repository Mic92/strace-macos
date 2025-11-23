"""Tests for string_quote module."""

import sys
import unittest
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from strace_macos.string_quote import is_printable, quote_string  # noqa: E402


class TestIsPrintable(unittest.TestCase):
    """Test the is_printable function."""

    def test_printable_characters(self) -> None:
        """Test that printable ASCII characters are recognized."""
        # Space through tilde (0x20-0x7E)
        for c in range(0x20, 0x7F):
            with self.subTest(c=c, char=chr(c)):
                self.assertTrue(is_printable(c), f"Character {c} ({chr(c)!r}) should be printable")

    def test_non_printable_characters(self) -> None:
        """Test that non-printable characters are recognized."""
        # Control characters (0x00-0x1F)
        for c in range(0x00, 0x20):
            with self.subTest(c=c):
                self.assertFalse(is_printable(c), f"Control character {c} should not be printable")

        # DEL and above (0x7F-0xFF)
        for c in range(0x7F, 0x100):
            with self.subTest(c=c):
                self.assertFalse(is_printable(c), f"Character {c} should not be printable")


class TestQuoteString(unittest.TestCase):
    """Test the quote_string function."""

    def test_empty_string(self) -> None:
        """Test that empty data returns empty string."""
        self.assertEqual(quote_string(b""), "")

    def test_simple_text(self) -> None:
        """Test simple printable ASCII text."""
        self.assertEqual(quote_string(b"hello"), "hello")
        self.assertEqual(quote_string(b"Hello, World!"), "Hello, World!")
        self.assertEqual(quote_string(b"test123"), "test123")

    def test_special_escapes(self) -> None:
        """Test that special characters are properly escaped."""
        self.assertEqual(quote_string(b"hello\nworld"), "hello\\nworld")
        self.assertEqual(quote_string(b"hello\tworld"), "hello\\tworld")
        self.assertEqual(quote_string(b"hello\rworld"), "hello\\rworld")
        self.assertEqual(quote_string(b"hello\vworld"), "hello\\vworld")
        self.assertEqual(quote_string(b"hello\fworld"), "hello\\fworld")

    def test_quote_and_backslash_escapes(self) -> None:
        """Test that quotes and backslashes are escaped."""
        self.assertEqual(quote_string(b'say "hello"'), 'say \\"hello\\"')
        self.assertEqual(quote_string(b"path\\to\\file"), "path\\\\to\\\\file")
        self.assertEqual(quote_string(b'test\\"quote'), 'test\\\\\\"quote')

    def test_null_byte(self) -> None:
        """Test that null bytes are escaped as octal."""
        self.assertEqual(quote_string(b"hello\x00world"), "hello\\0world")

    def test_control_characters(self) -> None:
        """Test that control characters are escaped as octal."""
        # SOH (Start of Heading)
        self.assertEqual(quote_string(b"\x01"), "\\1")
        # STX (Start of Text)
        self.assertEqual(quote_string(b"\x02"), "\\2")
        # BEL (Bell)
        self.assertEqual(quote_string(b"\x07"), "\\7")
        # Multiple control characters
        self.assertEqual(quote_string(b"\x01\x02\x03"), "\\1\\2\\3")

    def test_del_character(self) -> None:
        """Test that DEL (0x7F) is escaped as octal."""
        self.assertEqual(quote_string(b"test\x7f"), "test\\177")

    def test_high_bytes(self) -> None:
        """Test that bytes >= 0x80 are escaped as octal."""
        self.assertEqual(quote_string(b"\x80"), "\\200")
        self.assertEqual(quote_string(b"\xff"), "\\377")
        self.assertEqual(quote_string(b"\x80\x81\x82"), "\\200\\201\\202")

    def test_octal_ambiguity(self) -> None:
        """Test that octal escapes use 3 digits when followed by a digit."""
        # When followed by a digit 0-7, must use 3-digit octal
        self.assertEqual(quote_string(b"\x01" + b"0"), "\\0010")
        self.assertEqual(quote_string(b"\x01" + b"7"), "\\0017")
        # When followed by 8 or 9, can use minimal octal
        self.assertEqual(quote_string(b"\x01" + b"8"), "\\18")
        self.assertEqual(quote_string(b"\x01" + b"9"), "\\19")
        # When followed by non-digit, can use minimal octal
        self.assertEqual(quote_string(b"\x01a"), "\\1a")

    def test_mixed_content(self) -> None:
        """Test strings with mixed printable and non-printable characters."""
        self.assertEqual(quote_string(b"hello\x00\x01world"), "hello\\0\\1world")
        self.assertEqual(quote_string(b"test\n\t\x00end"), "test\\n\\t\\0end")
        self.assertEqual(quote_string(b"a\x01b\x02c\x03"), "a\\1b\\2c\\3")

    def test_truncation(self) -> None:
        """Test that long strings are truncated with ellipsis."""
        long_data = b"x" * 100
        result = quote_string(long_data, max_length=10)
        self.assertEqual(result, "x" * 10 + "...")

        # Test truncation with special characters
        long_data_with_escapes = b"hello\nworld" * 10
        result = quote_string(long_data_with_escapes, max_length=8)
        # First 8 bytes: "hello\nwo"
        self.assertTrue(result.endswith("..."))

    def test_realistic_buffers(self) -> None:
        """Test realistic buffer content similar to what strace might encounter."""
        # HTTP request fragment
        http = b"GET / HTTP/1.1\r\nHost: example.com\r\n"
        expected = "GET / HTTP/1.1\\r\\nHost: example.com\\r\\n"
        self.assertEqual(quote_string(http, max_length=100), expected)

        # Binary data with mixed content
        binary = b"PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        # \r -> \r, \n -> \n, \x1a -> \32, \n -> \n, \x00 (4 times) -> \0, \r -> \r
        result = quote_string(binary)
        self.assertIn("PNG\\r\\n", result)
        self.assertIn("IHDR", result)


if __name__ == "__main__":
    unittest.main()
