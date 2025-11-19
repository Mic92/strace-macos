# macOS strace Syscall Test Coverage

Legend:
- [x] = Has explicit test coverage
- [ ] = Not yet tested

---

## File I/O Syscalls (162 total)

### Basic File Operations
- [x] open (with variadic arg handling)
- [x] openat (with variadic arg handling)
- [x] close
- [x] close_nocancel
- [x] read
- [x] read_nocancel
- [x] write
- [x] write_nocancel
- [x] unlink
- [x] unlinkat (with AT_FDCWD and AT_REMOVEDIR flag decoding)

### File Descriptor Operations
- [x] dup
- [x] dup2
- [x] lseek
- [x] pread
- [x] pread_nocancel
- [ ] preadv
- [ ] preadv_nocancel
- [x] pwrite
- [x] pwrite_nocancel
- [ ] pwritev
- [ ] pwritev_nocancel
- [x] readv (with iovec decoding)
- [x] readv_nocancel
- [x] writev (with iovec decoding)
- [x] writev_nocancel

### File Status & Metadata
- [x] stat
- [x] stat64
- [ ] stat_extended
- [ ] stat64_extended
- [x] fstat
- [x] fstat64
- [ ] fstat_extended
- [ ] fstat64_extended
- [x] lstat
- [x] lstat64
- [ ] lstat_extended
- [ ] lstat64_extended
- [x] access (with F_OK, R_OK, W_OK, X_OK flag decoding)
- [x] chmod (with octal mode decoding)
- [ ] chmod_extended
- [x] chown
- [x] fchmod (with octal mode decoding)
- [ ] fchmod_extended
- [x] fchown
- [x] fchownat (with AT_SYMLINK_NOFOLLOW flag decoding)
- [x] getattrlist (with attrlist struct and ATTR_* flag decoding)
- [x] getattrlistat (with attrlist struct and ATTR_* flag decoding)
- [x] getattrlistbulk (with attrlist struct and ATTR_* flag decoding)
- [x] fgetattrlist (with attrlist struct and ATTR_* flag decoding)
- [x] setattrlist (with attrlist struct and ATTR_* flag decoding)
- [x] setattrlistat (with attrlist struct and ATTR_* flag decoding)
- [x] fsetattrlist (with attrlist struct and ATTR_* flag decoding)

### Extended Attributes
- [x] getxattr (with XATTR_* flag decoding)
- [x] fgetxattr (with XATTR_* flag decoding)
- [x] setxattr (with XATTR_* flag decoding)
- [x] fsetxattr (with XATTR_* flag decoding)
- [x] fremovexattr (with XATTR_* flag decoding)

### File System Operations
- [x] link
- [x] linkat (with AT_FDCWD decoding)
- [x] symlink
- [x] symlinkat (with AT_FDCWD decoding)
- [x] readlink
- [x] readlinkat (with AT_FDCWD decoding)
- [x] rename
- [x] renameat (with AT_FDCWD decoding)
- [ ] renameatx_np
- [x] mkdir (with octal mode decoding)
- [ ] mkdir_extended
- [x] mkdirat (with AT_FDCWD and octal mode decoding)
- [x] rmdir
- [x] mkfifo (with octal mode decoding)
- [ ] mkfifo_extended
- [x] mkfifoat (with AT_FDCWD and octal mode decoding)
- [x] mknod (with octal mode and dev_t decoding)
- [x] mknodat (with AT_FDCWD, octal mode, and dev_t decoding)

### Directory Operations
- [x] chdir
- [x] fchdir
- [x] chroot
- [ ] getdirentries
- [ ] getdirentries64
- [ ] getdirentriesattr

### File Locking & Synchronization
- [x] flock (with LOCK_SH, LOCK_EX, LOCK_UN, LOCK_NB flag decoding)
- [x] fsync
- [x] fsync_nocancel
- [x] fdatasync
- [x] msync
- [x] msync_nocancel

### File Control & Special Operations
- [x] ioctl (FIOCLEX, FIONCLEX, FIONREAD, TIOCGWINSZ, TIOCGETA)
- [x] fcntl (F_GETFD, F_SETFD, F_GETFL, F_SETFL with flag decoding)
- [x] fcntl_nocancel
- [x] truncate
- [x] ftruncate
- [x] utimes
- [x] futimes

### Mount & File System Management
- [ ] mount
- [ ] unmount
- [ ] fmount
- [x] statfs (with struct statfs decoding)
- [ ] statfs64
- [x] fstatfs (with struct statfs decoding)
- [ ] fstatfs64
- [x] getfsstat (with MNT_* flag decoding)
- [ ] getfsstat64

### Guarded File Descriptors
- [ ] guarded_open_np
- [ ] guarded_open_dprotected_np
- [ ] guarded_close_np
- [ ] guarded_write_np
- [ ] guarded_pwrite_np
- [ ] guarded_writev_np
- [ ] changefdguard_np

### Protected/Extended Open
- [ ] open_extended
- [ ] open_nocancel
- [ ] open_dprotected_np
- [ ] openat_nocancel
- [ ] openat_dprotected_np
- [ ] openbyid_np

### File System Control & Special
- [x] fsctl
- [x] ffsctl
- [x] fsgetpath
- [ ] fsgetpath_ext
- [x] searchfs (with fssearchblock struct and SRCHFS_* flag decoding)
- [x] copyfile (with COPYFILE_* flag decoding)
- [x] clonefileat (tested earlier with CLONE_* flags)
- [x] exchangedata
- [ ] delete (conflicts with C++ keyword - skipped)
- [x] undelete
- [x] revoke
- [ ] getfh
- [ ] fhopen

### Shared Memory File Operations
- [ ] shm_open
- [ ] shm_unlink

### Quota & Audit
- [ ] quotactl
- [ ] acct
- [ ] audit
- [ ] auditon
- [ ] auditctl

### Miscellaneous File Operations
- [ ] chflags
- [ ] fchflags
- [ ] mremap_encrypted
- [ ] nfssvc
- [x] mkstemp (tested via test_fd_ops)
- [x] mkdtemp

---

## Process Management Syscalls (75 total)

### Process Lifecycle
- [ ] fork
- [ ] vfork
- [ ] execve
- [ ] __mac_execve
- [ ] posix_spawn
- [ ] exit
- [ ] wait4
- [ ] wait4_nocancel
- [ ] waitid
- [ ] waitid_nocancel

### Process Identity
- [x] getpid
- [x] getppid
- [x] getpgrp
- [x] getpgid
- [x] setpgid
- [x] getsid
- [x] setsid
- [x] getuid
- [x] geteuid
- [x] getgid
- [x] getegid
- [x] setuid
- [x] seteuid
- [x] setgid
- [x] setegid
- [x] setreuid
- [x] setregid
- [x] getgroups
- [x] setgroups
- [x] initgroups (with username string decoding)

### Process Priority & Resources
- [ ] getpriority
- [ ] setpriority
- [ ] getrlimit
- [ ] setrlimit
- [ ] getrusage
- [ ] proc_rlimit_control

### Process Information & Control
- [ ] proc_info
- [ ] proc_info_extended_id
- [ ] proc_trace_log
- [ ] proc_uuid_policy
- [ ] process_policy
- [ ] pid_suspend
- [ ] pid_resume
- [ ] pid_hibernate
- [ ] pid_shutdown_sockets

### Thread Management
- [ ] bsdthread_create
- [ ] bsdthread_register
- [ ] bsdthread_terminate
- [ ] bsdthread_ctl
- [ ] thread_selfid
- [ ] thread_selfusage
- [ ] gettid
- [ ] settid
- [ ] settid_with_pid

### Login & Session
- [ ] getlogin
- [ ] setlogin
- [ ] issetugid

### Semaphore Operations (POSIX)
- [ ] sem_wait
- [ ] sem_wait_nocancel
- [ ] sem_trywait
- [ ] __semwait_signal
- [ ] __semwait_signal_nocancel

### Signal Waiting
- [ ] __sigwait
- [ ] __sigwait_nocancel

### Thread-specific Directory
- [ ] __pthread_chdir
- [ ] __pthread_fchdir

### Task & Coalition
- [ ] coalition
- [ ] coalition_info
- [ ] coalition_ledger
- [ ] coalition_policy_get
- [ ] coalition_policy_set
- [ ] task_inspect_for_pid

### Work Queue & Lock
- [ ] workq_kernreturn
- [ ] ulock_wait
- [ ] ulock_wait2

### SFI (Selective Forced Idle)
- [ ] sfi_pidctl

### MAC (Mandatory Access Control) Process
- [ ] __mac_get_pid
- [ ] __mac_get_proc
- [ ] __mac_set_proc

---

## Network Syscalls (33 total)

### Socket Creation
- [x] socket
- [x] socketpair
- [ ] socket_delegate

### Socket Connection
- [x] connect
- [ ] connect_nocancel
- [ ] connectx
- [ ] disconnectx
- [x] bind
- [x] listen
- [x] accept
- [ ] accept_nocancel

### Socket I/O
- [x] sendto (with buffer and flags decoding)
- [x] sendto_nocancel
- [x] sendmsg (with msghdr and iovec decoding)
- [x] sendmsg_nocancel
- [ ] sendmsg_x
- [x] recvfrom (with flags decoding)
- [x] recvfrom_nocancel
- [x] recvmsg (with msghdr decoding)
- [x] recvmsg_nocancel
- [ ] recvmsg_x

### Socket Control & Information
- [x] getsockname (with sockaddr decoding)
- [x] getpeername (with sockaddr decoding)
- [x] getsockopt (with level and option decoding)
- [x] setsockopt (with level and option decoding)
- [x] shutdown (with SHUT_* flag decoding)
- [ ] peeloff

### Network Control & Policy
- [ ] necp_client_action
- [ ] necp_match_policy
- [ ] necp_open
- [ ] necp_session_action
- [ ] netagent_trigger
- [ ] net_qos_guideline

---

## Memory Management Syscalls (16 total)

- [x] mmap (with PROT_* and MAP_* flag decoding)
- [x] munmap
- [x] mprotect (with PROT_* flag decoding)
- [x] msync (with MS_* flag decoding)
- [x] __msync_nocancel
- [x] madvise (with MADV_* constant decoding)
- [x] mincore
- [x] minherit (with VM_INHERIT_* constant decoding)
- [x] mlock
- [x] munlock
- [x] mlockall (with MCL_* flag decoding)
- [x] munlockall
- [ ] mremap_encrypted (no public header/linkable symbol)
- [ ] shared_region_check_np (no public linkable symbol)
- [ ] shared_region_map_and_slide_2_np (no public header)
- [ ] vm_pressure_monitor (no public header)

---

## IPC/Kqueue/Psynch Syscalls (48 total)

### Kqueue & Event Management
- [ ] kqueue
- [ ] guarded_kqueue_np
- [ ] kevent
- [ ] kevent64
- [ ] kevent_id
- [ ] kevent_qos
- [ ] kqueue_workloop_ctl

### Select & Poll
- [ ] select
- [ ] select_nocancel
- [ ] pselect
- [ ] pselect_nocancel
- [ ] poll
- [ ] poll_nocancel

### System V Message Queues
- [x] msgget - with IPC_CREAT|IPC_EXCL|mode flags
- [x] msgctl - with IPC_STAT, IPC_SET, IPC_RMID commands and struct msqid_ds
- [x] msgsnd - with IPC_NOWAIT|MSG_NOERROR flags
- [x] msgsnd_nocancel - with flags
- [x] msgrcv - with IPC_NOWAIT|MSG_NOERROR flags
- [x] msgrcv_nocancel - with flags
- [ ] msgsys (legacy multiplexer, basic decoding only, rarely used)

### System V Semaphores
- [x] semget - with IPC_CREAT|IPC_EXCL|mode flags
- [x] semctl - with GETNCNT, GETPID, GETVAL, GETALL, GETZCNT, SETVAL, SETALL, IPC_STAT, IPC_SET, IPC_RMID commands and struct semid_ds
- [x] semop - with SEM_UNDO flag and struct sembuf array
- [ ] semsys (legacy multiplexer, basic decoding only, rarely used)

### System V Shared Memory
- [x] shmget - with IPC_CREAT|IPC_EXCL|mode flags
- [x] shmat - with SHM_RDONLY, SHM_RND flags
- [x] shmctl - with IPC_STAT, IPC_SET, IPC_RMID commands and struct shmid_ds
- [x] shmdt
- [ ] shmsys (legacy multiplexer, basic decoding only, rarely used)

### Psynch (pthread synchronization primitives)
- [ ] psynch_mutexwait
- [ ] psynch_mutexdrop
- [ ] psynch_cvwait
- [ ] psynch_cvsignal
- [ ] psynch_cvbroad
- [ ] psynch_rw_rdlock
- [ ] psynch_rw_wrlock
- [ ] psynch_rw_unlock
- [ ] psynch_rw_unlock2
- [ ] psynch_rw_longrdlock
- [ ] psynch_rw_upgrade
- [ ] psynch_rw_downgrade
- [ ] psynch_rw_yieldwrlock

### AIO (Asynchronous I/O)
- [x] aio_cancel - with file descriptor and struct aiocb decoding
- [x] aio_error - with struct aiocb decoding
- [x] aio_return - with struct aiocb decoding
- [x] aio_suspend - with aiocb pointer array decoding showing fd, nbytes, offset, opcode
- [x] aio_suspend_nocancel - with aiocb pointer array
- [x] lio_listio - with LIO_WAIT/LIO_NOWAIT modes, aiocb array decoding, and struct sigevent

### Miscellaneous
- [ ] peeloff
- [ ] ulock_wake

---

## Signal Handling Syscalls (13 total)

- [ ] sigaction
- [ ] sigprocmask
- [ ] sigpending
- [ ] sigsuspend
- [ ] sigsuspend_nocancel
- [ ] sigaltstack
- [ ] sigreturn
- [ ] kill
- [ ] __pthread_kill
- [ ] __pthread_sigmask
- [ ] __disable_threadsignal
- [ ] __sigwait
- [ ] __sigwait_nocancel

---

## Debug/Tracing Syscalls (15 total)

- [ ] ptrace
- [ ] kdebug_trace
- [ ] kdebug_trace64
- [ ] kdebug_trace_string
- [ ] kdebug_typefilter
- [ ] stack_snapshot_with_config
- [ ] microstackshot
- [ ] log_data
- [ ] abort_with_payload
- [ ] terminate_with_payload
- [ ] os_fault_with_payload
- [ ] panic_with_data
- [ ] objc_bp_assist_cfg_np
- [ ] debug_syscall_reject
- [ ] debug_syscall_reject_config

---

## Security/MAC Syscalls (11 total)

- [ ] __mac_execve
- [ ] __mac_get_fd
- [ ] __mac_get_file
- [ ] __mac_get_link
- [ ] __mac_get_pid
- [ ] __mac_get_proc
- [ ] __mac_set_fd
- [ ] __mac_set_file
- [ ] __mac_set_link
- [ ] __mac_set_proc
- [ ] __mac_syscall
- [ ] __mac_mount
- [ ] __mac_getfsstat
- [ ] csops
- [ ] csrctl

---

## System Info Syscalls (12 total)

- [ ] sysctl
- [ ] sysctlbyname
- [ ] getdtablesize
- [ ] gethostuuid
- [ ] getentropy
- [ ] kas_info
- [ ] ledger
- [ ] memorystatus_available_memory
- [ ] memorystatus_control
- [ ] telemetry
- [ ] usrctl
- [ ] work_interval_ctl

---

## Thread Management Syscalls (10 total)

- [ ] bsdthread_create
- [ ] bsdthread_register
- [ ] bsdthread_terminate
- [ ] bsdthread_ctl
- [ ] thread_selfid
- [ ] thread_selfusage
- [ ] __pthread_canceled
- [ ] __pthread_markcancel
- [ ] __pthread_chdir
- [ ] __pthread_fchdir

---

## Time/Timer Syscalls (7 total)

- [ ] gettimeofday
- [ ] settimeofday
- [ ] adjtime
- [ ] getitimer
- [ ] setitimer
- [x] utimes
- [x] futimes
- [ ] ntp_adjtime
- [ ] ntp_gettime

---

## Miscellaneous Syscalls (15 total)

- [ ] syscall
- [ ] sync
- [ ] reboot
- [ ] swapon
- [ ] acct
- [ ] crossarch_trap
- [ ] fileport_makefd
- [ ] fileport_makeport
- [ ] map_with_linking_np
- [ ] necp_open
- [ ] oslog_coproc
- [ ] oslog_coproc_reg
- [ ] tracker_action

---

## Test Coverage Summary

### Completely Untested Areas
- IPC mechanisms (message queues, semaphores, shared memory)
- Kqueue/kevent operations
- Psynch operations (pthread synchronization)
- Signal handling (beyond basic capture)
- Debug/tracing syscalls
- Security/MAC syscalls
- System information queries (sysctl, sysctlbyname)
- Thread management
- Time/timer operations (gettimeofday, setitimer, etc.)
- Process lifecycle (fork, execve, wait4)
- All *_extended variants (stat_extended, mkdir_extended, etc.)
- Directory reading (getdirentries, getdirentries64)
- Some guarded file descriptors (guarded_open_np, etc.)
- Protected/extended open variants (open_dprotected_np, etc.)

### Priority Test Candidates (Remaining)
1. **Process**: fork, execve, wait4, getpid, getuid/geteuid (high-priority fundamentals)
2. **Kqueue**: kqueue, kevent (modern macOS event notification)
3. **Signal**: sigaction, sigprocmask, kill (important for process control)
4. **Extended I/O**: preadv, pwritev (iovec variants of pread/pwrite)
5. **Time**: gettimeofday, setitimer, getitimer (commonly used in profiling)
6. **Directory reading**: getdirentries64 (commonly used directory iteration)
