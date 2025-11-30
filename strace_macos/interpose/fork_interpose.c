/*
 * DYLD interposition library for fork/spawn tracing.
 *
 * This library intercepts fork, vfork, and posix_spawn to make child
 * processes stop (SIGSTOP) immediately after creation, allowing a
 * debugger to attach before the child continues execution.
 *
 * Usage: DYLD_INSERT_LIBRARIES=/path/to/libfork_interpose.dylib command
 *
 * Build: clang -dynamiclib -o libfork_interpose.dylib fork_interpose.c
 */

#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* DYLD interposition macro */
#define DYLD_INTERPOSE(_replacement, _original)                                \
  __attribute__((used)) static struct {                                        \
    const void *replacement;                                                   \
    const void *original;                                                      \
  } _interpose_##_original __attribute__((section("__DATA,__interpose"))) = {  \
      (const void *)(unsigned long)&_replacement,                              \
      (const void *)(unsigned long)&_original};

/* Environment variable to signal child to stop */
#define STRACE_CHILD_STOP_ENV "STRACE_MACOS_CHILD_STOP"

/* Check if we should stop the child */
static int should_child_stop(void) {
  const char *val = getenv(STRACE_CHILD_STOP_ENV);
  return val != NULL && strcmp(val, "1") == 0;
}

/* Interposed fork */
pid_t interposed_fork(void) {
  pid_t pid = fork();

  if (pid == 0 && should_child_stop()) {
    /* Child process: stop ourselves so debugger can attach */
    raise(SIGSTOP);
  }

  return pid;
}

/* Interposed vfork - treat like fork for safety */
pid_t interposed_vfork(void) {
  /* vfork is tricky - child shares parent's stack until exec.
   * We use fork() instead for safety, which is slower but correct. */
  pid_t pid = fork();

  if (pid == 0 && should_child_stop()) {
    raise(SIGSTOP);
  }

  return pid;
}

/* Interposed posix_spawn */
int interposed_posix_spawn(pid_t *restrict pid, const char *restrict path,
                           const posix_spawn_file_actions_t *file_actions,
                           const posix_spawnattr_t *restrict attrp,
                           char *const argv[restrict],
                           char *const envp[restrict]) {
  int result;
  pid_t child_pid;

  /* Call the real posix_spawn */
  result = posix_spawn(&child_pid, path, file_actions, attrp, argv, envp);

  if (result == 0 && should_child_stop()) {
    /* Send SIGSTOP to the spawned child */
    kill(child_pid, SIGSTOP);
  }

  if (pid != NULL) {
    *pid = child_pid;
  }

  return result;
}

/* Interposed posix_spawnp */
int interposed_posix_spawnp(pid_t *restrict pid, const char *restrict file,
                            const posix_spawn_file_actions_t *file_actions,
                            const posix_spawnattr_t *restrict attrp,
                            char *const argv[restrict],
                            char *const envp[restrict]) {
  int result;
  pid_t child_pid;

  result = posix_spawnp(&child_pid, file, file_actions, attrp, argv, envp);

  if (result == 0 && should_child_stop()) {
    kill(child_pid, SIGSTOP);
  }

  if (pid != NULL) {
    *pid = child_pid;
  }

  return result;
}

/* Register interpositions */
DYLD_INTERPOSE(interposed_fork, fork)
DYLD_INTERPOSE(interposed_vfork, vfork)
DYLD_INTERPOSE(interposed_posix_spawn, posix_spawn)
DYLD_INTERPOSE(interposed_posix_spawnp, posix_spawnp)
