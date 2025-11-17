# Contributing to strace-macos

Thank you for your interest in contributing to strace-macos! This document provides guidelines and information for contributors.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Code Style](#code-style)
- [Testing](#testing)
- [Architecture Overview](#architecture-overview)
- [Adding New Syscalls](#adding-new-syscalls)
- [Submitting Changes](#submitting-changes)

## Getting Started

### Prerequisites

- macOS 12+ (Monterey or later)
- Apple Silicon (ARM64) or Intel (x86_64)
- Xcode Command Line Tools
- System Python 3.9+ (`/usr/bin/python3`)

### Fork and Clone

```bash
# Fork the repository on GitHub (https://github.com/Mic92/strace-macos), then clone your fork
git clone https://github.com/YOUR-USERNAME/strace-macos
cd strace-macos
```

## Development Environment

Development tools can be installed via:
- Nix: `nix profile install nixpkgs#ruff nixpkgs#mypy`
- Homebrew: `brew install ruff mypy`
- pip: `/usr/bin/python3 -m pip install --user ruff mypy`

## Code Style

This project uses strict code quality tools to maintain consistency.

### Formatting and Linting

We use [ruff](https://docs.astral.sh/ruff/) for both linting and formatting:

```bash
# Format all code (with Nix)
nix fmt

# Or manually
ruff format .
ruff check --fix .
```

### Type Checking

We use [mypy](https://mypy.readthedocs.io/) with strict settings:

```bash
mypy .
```

**Note**: LLDB types are not available in the Nix build environment, so we use `type: ignore` comments for LLDB-related type errors. This is acceptable.

### Code Quality Guidelines

1. **Type hints**: All functions must have complete type annotations
2. **Docstrings**: Public functions and classes should have docstrings
3. **Keyword-only arguments**: Use `*` for boolean/optional parameters to avoid boolean traps
4. **Error handling**: Prefer explicit error handling over silent failures
5. **Comments**: Explain *why*, not *what* - the code should be self-explanatory

### Ruff Configuration

Key rules we follow (see `pyproject.toml`):

- `select = ["ALL"]` - Enable all rules by default
- Exceptions:
  - `S101` allowed in tests (assertions are standard in tests)
  - `S603` allowed in tests (subprocess with controlled inputs)
  - `FBT` ignored (we use keyword-only args instead)
  - `PLR2004` ignored (syscall numbers are naturally magic)

Example of good code style:

```python
def decode_flags(
    value: int,
    *,  # Force keyword-only arguments
    no_abbrev: bool = False,
) -> str:
    """Decode file flags to symbolic representation.

    Args:
        value: Integer flag value
        no_abbrev: If True, return raw hex instead of symbols

    Returns:
        Symbolic flag string like "O_RDONLY|O_CREAT" or hex "0x601"
    """
    if no_abbrev:
        return f"0x{value:x}"

    # Implementation...
```

## Testing

### Running Tests

Tests **must** use macOS system Python because LLDB bindings only work with it:

```bash
# Run all tests
/usr/bin/python3 -m unittest discover tests/ -v

# Run specific test file
/usr/bin/python3 -m unittest tests/test_spawn.py -v

# Run specific test case
/usr/bin/python3 -m unittest tests.test_spawn.TestSpawn.test_spawn_simple_command -v

# Use the test runner script
/usr/bin/python3 ./run_tests.py
```

### Writing Tests

All tests should:

1. Inherit from `StraceTestCase` base class
2. Use the compiled test executable for controlled behavior
3. Clean up resources in `tearDown` or using context managers
4. Include docstrings explaining what they test
5. Use descriptive assertion messages

Example test structure:

```python
class TestMyFeature(StraceTestCase):
    """Test suite for my new feature."""

    def test_basic_functionality(self) -> None:
        """Test that basic feature works correctly."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as output_file:
            exit_code = main([
                "--json",
                "-o", output_file.name,
                str(self.test_executable),
            ])

            assert exit_code == 0, "strace should exit successfully"

            # Parse and verify output
            syscalls = helpers.json_lines(Path(output_file.name))
            assert len(syscalls) > 0, "Should capture syscalls"
```

### Test Organization

- `tests/test_spawn.py` - Process spawning tests
- `tests/test_attach.py` - Process attachment tests
- `tests/test_filtering.py` - Syscall filtering tests
- `tests/test_output_formats.py` - Output format tests
- `tests/test_statistics.py` - Summary statistics tests
- `tests/test_symbolic_decoding.py` - Argument decoding tests
- `tests/fixtures/` - Test helper utilities and compiled test programs

## Architecture Overview

### Core Components

```
strace_macos/
├── __main__.py          # CLI entry point
├── tracer.py            # Main Tracer class (syscall capture loop)
├── arch.py              # Architecture-specific code (ARM64/x86_64)
├── lldb_loader.py       # LLDB module loading
└── syscalls/
    ├── registry.py      # Syscall definitions registry
    ├── formatters.py    # Output formatters (JSON, text, color)
    ├── definitions/     # Syscall definitions by category
    ├── symbols/         # Symbolic decoders (flags, errno, etc.)
    └── struct_decoders/ # Struct decoders (stat, etc.)
```

### Key Classes

- **Tracer**: Main class that manages LLDB debugger, sets breakpoints, captures syscalls
- **Architecture**: Abstract base for architecture-specific register access
- **SyscallRegistry**: Manages syscall definitions and lookup
- **Formatters**: Convert syscall events to output formats (JSON/text/color)

### How It Works

1. **Setup**: LLDB creates a debugger and target process
2. **Breakpoints**: Set breakpoints at syscall entry (`__syscall`) and return points
3. **Capture**: When breakpoint hits, read registers to get syscall number and arguments
4. **Decode**: Look up syscall definition and decode arguments symbolically
5. **Format**: Convert to output format and write to stdout/file
6. **Continue**: Resume process and repeat

## Adding New Syscalls

### Step 1: Define the Syscall

Add to appropriate file in `strace_macos/syscalls/definitions/`:

```python
# In strace_macos/syscalls/definitions/file.py

from strace_macos.syscalls import numbers
from strace_macos.syscalls.definitions import SyscallDef
from strace_macos.syscalls.symbols import decode_flags, decode_errno

RENAMEAT_SYSCALL = SyscallDef(
    name="renameat",
    number=numbers.SYS_renameat,
    args=[
        ("fromfd", "int", None),
        ("from", "const char *", None),
        ("tofd", "int", None),
        ("to", "const char *", None),
    ],
    return_type="int",
    decode_return=decode_errno,
)
```

### Step 2: Register the Syscall

Add to the category list:

```python
FILE_SYSCALLS = [
    OPEN_SYSCALL,
    OPENAT_SYSCALL,
    RENAMEAT_SYSCALL,  # Add here
    # ...
]
```

### Step 3: Add Symbol Decoders (if needed)

If the syscall has flags or special arguments:

```python
# In strace_macos/syscalls/symbols/file.py

def decode_renameat_flags(value: int) -> str | None:
    """Decode renameat flags."""
    if value == 0:
        return None

    flags = []
    if value & RENAME_SWAP:
        flags.append("RENAME_SWAP")
    # ... more flags

    return "|".join(flags) if flags else None
```

Then use it in the syscall definition:

```python
args=[
    ("fromfd", "int", None),
    ("from", "const char *", None),
    ("tofd", "int", None),
    ("to", "const char *", None),
    ("flags", "int", decode_renameat_flags),  # Add decoder
],
```

### Step 4: Add Tests

Create tests that verify the syscall is captured correctly:

```python
def test_renameat_capture(self) -> None:
    """Test that renameat syscalls are captured."""
    # Test implementation
```

## Submitting Changes

### Commit Messages

Write clear commit messages following this format:

```
Short summary (50 chars or less)

More detailed explanation if needed. Explain WHY the change
is being made, not WHAT is changing (the diff shows that).

- Bullet points are fine
- Reference issues: Fixes #123
```

### Pull Request Process

1. **Create a branch**: `git checkout -b feature/my-feature`

2. **Make changes**: Follow the code style guidelines

3. **Test**: Ensure all tests pass
   ```bash
   /usr/bin/python3 ./run_tests.py
   ```

4. **Format**: Run code formatter
   ```bash
   nix fmt
   ```

5. **Commit**: Write a clear commit message

6. **Push**: `git push origin feature/my-feature`

7. **Open PR**: Create a pull request on GitHub with:
   - Clear description of changes
   - Reference to related issues
   - Test results
   - Example output if applicable

### PR Checklist

Before submitting, ensure:

- [ ] All tests pass
- [ ] Code is formatted (`nix fmt` or `ruff format`)
- [ ] No linting errors (`ruff check`)
- [ ] Type checking passes (`mypy`)
- [ ] New features have tests
- [ ] Documentation is updated if needed
- [ ] Commit messages are clear

## Getting Help

- **Issues**: Open an issue on GitHub for bugs or feature requests
- **Discussions**: Use GitHub Discussions for questions

## Code of Conduct

Be respectful and constructive. We're all here to make strace-macos better.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
