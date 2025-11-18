# strace-macos

A system call tracer for macOS using the LLDB debugger API.

**Status**: Beta - Core functionality works, but some features are still in development.

## Features

- **Works with SIP enabled** - Unlike `dtruss`, doesn't require disabling System Integrity Protection
- **Pure Python implementation** - No kernel extensions or compiled components
- **Multiple output formats** - JSON Lines and strace-compatible text output
- **Syscall filtering** - Filter by syscall name or category (`-e trace=file`, `-e trace=network`)
- **Symbolic decoding** - Automatically decodes flags, error codes, and struct fields
- **Color output** - Syntax highlighting when output is a TTY
- **Summary statistics** - Time/call/error counts with `-c`

## Installation

### With Nix Flakes

```bash
# Run directly
nix run github:Mic92/strace-macos -- ls

# Install to profile
nix profile install github:Mic92/strace-macos
```

### Manual Installation

strace-macos requires macOS system Python (has LLDB bindings):

```bash
# Install directly from GitHub
/usr/bin/python3 -m pip install --user git+https://github.com/Mic92/strace-macos

# Then run (if ~/Library/Python/3.x/bin is in PATH)
strace /usr/local/bin/git status  # or any homebrew-installed binary

# Or run directly from repository without installing
git clone https://github.com/Mic92/strace-macos
cd strace-macos
/usr/bin/python3 -m strace_macos /usr/local/bin/git status
```

## Usage

### Trace a command

```bash
# Basic usage (use non-system binaries like homebrew or nix-installed)
strace /usr/local/bin/git status

# Output to file
strace -o trace.txt /usr/local/bin/git status

# JSON output
strace --json /usr/local/bin/git status > trace.jsonl

# Filter syscalls by name
strace -e trace=open,close /usr/local/bin/git status

# Filter by category*
strace -e trace=file /usr/local/bin/git status    # All file operations
strace -e trace=network /usr/local/bin/curl https://example.com   # Network syscalls only
strace -e trace=process /usr/local/bin/git status # Process lifecycle syscalls
```

\* See [Syscall Filtering](#syscall-filtering) for all supported categories.

### Attach to running process

```bash
strace -p 1234
```

### Summary statistics

```bash
strace -c /usr/local/bin/git status
# % time     seconds  usecs/call     calls    errors syscall
# ------ ----------- ----------- --------- --------- ----------------
#  45.23    0.001234          12       103           read
#  32.10    0.000876           8       110           write
#  ...
```

## Syscall Filtering

strace-macos supports filtering syscalls by name or category using the `-e trace=` option.

### Filter by Syscall Name

Specify one or more syscall names separated by commas:

```bash
strace -e trace=open,close,read,write /usr/local/bin/git status
```

### Filter by Category

Use predefined categories to trace groups of related syscalls:

| Category | Description | Example Syscalls |
|----------|-------------|------------------|
| `file` | File operations | open, close, read, write, stat, unlink |
| `network` | Network operations | socket, connect, send, recv, bind |
| `process` | Process lifecycle | fork, exec, wait, exit, kill |
| `memory` | Memory management | mmap, munmap, brk, mprotect |
| `signal` | Signal handling | signal, sigaction, sigprocmask, kill |
| `ipc` | Inter-process communication | pipe, shm_open, msgget, semop |
| `thread` | Thread operations | pthread_create, bsdthread_register |
| `time` | Time and timers | gettimeofday, setitimer, utimes |
| `sysinfo` | System information | sysctl, getpid, getuid, uname |
| `security` | Security/MAC operations | \_\_mac_\*, csops, csrctl |
| `debug` | Debugging and tracing | ptrace, kdebug_trace, panic_with_data |
| `misc` | Miscellaneous syscalls | ioctl, fcntl, kqueue, connectx |

Example:

```bash
# Trace only file operations
strace -e trace=file /usr/local/bin/git status

# Trace only network syscalls
strace -e trace=network /usr/local/bin/curl https://example.com

# Trace process management syscalls
strace -e trace=process /usr/local/bin/git status
```

### Comparison with Linux strace

| Feature | Linux strace | strace-macos |
|---------|-------------|--------------|
| Filter by syscall name | ✅ `-e trace=open,close` | ✅ `-e trace=open,close` |
| Filter by category | ✅ `-e trace=file` | ✅ `-e trace=file` |
| Negation (`!`) | ✅ `-e trace=!open` | ❌ Not yet |
| Regex filtering | ✅ `-e trace=/^open/` | ❌ Not yet |
| Path filtering | ✅ `-P /etc/passwd` | ❌ Not yet |
| FD filtering | ✅ `-e trace-fd=3` | ❌ Not yet |
| `%desc` category | ✅ FD-related syscalls | ❌ Not yet |
| Percent prefix | ✅ `%file` or `file` | ⚠️ Only `file` |

## Requirements

- macOS 12+ (Monterey or later)
- Apple Silicon (ARM64) - **primary platform**
- Intel (x86_64) - **work in progress**
- Xcode Command Line Tools (for LLDB)
- System Python (`/usr/bin/python3`)

**Important**: Must use macOS system Python - LLDB bindings don't work with Homebrew/pyenv/Nix Python.

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for:

- Development environment setup
- Code style guidelines
- Testing instructions
- How to add new syscalls
- Pull request process

**Current Status**: 3/13 tests passing (spawn functionality working)

## Architecture

```
strace-macos (Python CLI)
    ↓
LLDB Python API
    ↓
debugserver (macOS debugging APIs)
    ↓
Target Process
```

The tracer uses LLDB's Python bindings to:
1. Set breakpoints at syscall entry/exit points
2. Read CPU registers to extract syscall arguments
3. Decode arguments symbolically (flags, errno, structs)
4. Format output in strace-compatible or JSON format

## Implementation Status

**Working**:
- Spawn and trace new processes ✅
- Attach to running processes ✅
- Basic syscall capture (entry/exit) ✅
- Argument decoding (integers, strings, pointers, buffers, iovecs) ✅
- Symbolic flag decoding (O_RDONLY, etc.) ✅
- Error code decoding (ENOENT, etc.) ✅
- Struct decoding (stat, sockaddr, msghdr, etc.) ✅
- Syscall filtering by name and category ✅
- Summary statistics (`-c`) ✅
- JSON and text output formats ✅
- Color output with syntax highlighting ✅

**Planned**:
- Multi-threaded process support
- Follow forks (`-f`)
- Negation filtering (`-e trace=!open`)
- Regex filtering (`-e trace=/^open/`)
- Path-based filtering (`-P /path`)
- FD-based filtering (`-e trace-fd=3`)
- String truncation control (`-s`)
- Relative/absolute timestamps (`-t`, `-tt`, `-ttt`)

## Why not dtruss?

macOS ships with `dtruss`, a DTrace-based syscall tracer. However:

- Requires disabling System Integrity Protection (SIP)
- Doesn't work on modern macOS versions without workarounds
- Limited filtering capabilities
- No symbolic decoding of arguments

strace-macos works with SIP enabled and provides richer output.

## Comparison with Linux strace

strace-macos aims for compatibility with Linux strace where possible:

| Feature | Linux strace | strace-macos |
|---------|-------------|--------------|
| Basic tracing | ✅ | ✅ |
| Attach to PID | ✅ | ✅ |
| Syscall filtering* | ✅ | ✅ |
| Summary stats | ✅ | ✅ |
| Follow forks | ✅ | ⏳ |
| Symbolic decoding | ✅ | ✅ |
| JSON output | ❌ | ✅ |
| Color output | ❌ | ✅ |

\* See [Syscall Filtering](#syscall-filtering) for detailed feature comparison.

## License

MIT License - see LICENSE file for details.

## Author

Jörg Thalheim <joerg@thalheim.io>

## Need commercial support or customization?

For commercial support, please contact [Mic92](https://github.com/Mic92/) at
joerg@thalheim.io or reach out to [Numtide](https://numtide.com/contact/).

## See Also

- [CONTRIBUTING.md](CONTRIBUTING.md) - Development and contribution guide
- [tests/README.md](tests/README.md) - Test suite documentation
