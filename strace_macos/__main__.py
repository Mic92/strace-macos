"""CLI entry point for strace-macos."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from strace_macos.exceptions import StraceError


def main(argv: list[str] | None = None) -> int:
    """Main entry point for strace-macos.

    Args:
        argv: Command-line arguments (default: sys.argv[1:])

    Returns:
        Exit code (0 for success, non-zero for error)
    """
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description="Trace system calls on macOS using LLDB",
        prog="strace-macos",
    )

    # Output options
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Write output to file instead of stderr",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON Lines format (default: strace-compatible text)",
    )
    parser.add_argument(
        "-c",
        "--summary-only",
        action="store_true",
        help="Count time, calls, and errors for each syscall and report summary",
    )
    parser.add_argument(
        "--no-abbrev",
        action="store_true",
        help="Print raw values without symbolic decoding (no abbreviation)",
    )

    # Filtering options
    parser.add_argument(
        "-e",
        "--expr",
        dest="filter_expr",
        help="Filter expression (e.g., 'trace=open,close' or 'trace=file')",
    )

    # Attach or spawn
    parser.add_argument(
        "-p",
        "--attach",
        dest="pid",
        type=int,
        help="Attach to process with given PID",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Command and arguments to trace",
    )

    args = parser.parse_args(argv)

    # Validate: must specify either -p or command
    if args.pid is None and not args.command:
        parser.error("Must specify either -p PID or COMMAND")
    if args.pid is not None and args.command:
        parser.error("Cannot specify both -p PID and COMMAND")

    # Import tracer here to avoid loading LLDB until needed
    from strace_macos.tracer import Tracer  # noqa: PLC0415

    try:
        # Create tracer
        tracer = Tracer(
            output_file=args.output,
            json_output=args.json,
            summary_only=args.summary_only,
            filter_expr=args.filter_expr,
            no_abbrev=args.no_abbrev,
        )

        # Run trace
        if args.pid is not None:
            return tracer.attach(args.pid)
        return tracer.spawn(args.command)
    except StraceError as e:
        # User-facing errors: print message without stack trace
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except StraceError as e:
        # User-facing errors: print message without stack trace
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
