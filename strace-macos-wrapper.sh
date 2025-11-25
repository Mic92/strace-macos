#!/bin/sh
# Wrapper script to run strace-macos with system Python
# This ensures LLDB bindings work even inside Nix devShells

# Use Command Line Tools Python directly (most reliable, works in Nix devShells)
# xcrun is unreliable because Nix sets DEVELOPER_DIR and pollutes PATH
PYTHON_PATH="/Library/Developer/CommandLineTools/usr/bin/python3"

if [ ! -x "$PYTHON_PATH" ]; then
    echo "Error: System Python not found at $PYTHON_PATH" >&2
    echo "" >&2
    echo "strace-macos requires Xcode Command Line Tools to be installed." >&2
    echo "Please install them with:" >&2
    echo "  xcode-select --install" >&2
    exit 1
fi

# Set PYTHONPATH to find strace_macos module (replaced by Nix build)
export PYTHONPATH="@PYTHONPATH@"

# Execute strace-macos with system Python
exec "$PYTHON_PATH" -m strace_macos "$@"
