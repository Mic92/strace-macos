/*
 * Fork/exec operations mode
 * Tests: fork, vfork, execve (failure), posix_spawn
 */

#ifndef MODE_FORK_EXEC_H
#define MODE_FORK_EXEC_H

#include <errno.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Main mode that tests all fork/exec/spawn syscalls */
int mode_fork_exec(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  pid_t pid;
  int status;

  /* === TEST FORK === */
  pid = fork();
  if (pid < 0) {
    perror("fork failed");
    return 1;
  }
  if (pid == 0) {
    /* Child process - exit syscall (only visible with -f flag) */
    exit(42);
  }
  /* Parent - wait for child */
  waitpid(pid, &status, 0);

  /* === TEST VFORK === */
  pid = vfork();
  if (pid < 0) {
    perror("vfork failed");
    return 1;
  }
  if (pid == 0) {
    /* Child - must use _exit, not exit */
    _exit(0);
  }
  /* Parent - wait for child */
  waitpid(pid, &status, 0);

  /* === TEST EXECVE (FAILURE) === */
  /* Try to execute non-existent file - should fail with ENOENT */
  char *test_argv[] = {"/nonexistent/binary", "arg1", "arg2", NULL};
  char *test_envp[] = {"VAR1=value1", "VAR2=value2", NULL};

  int ret = execve("/nonexistent/binary", test_argv, test_envp);

  /* If we get here, execve failed (which is expected) */
  if (ret < 0) {
    /* Expected failure - just continue */
    if (errno != ENOENT) {
      perror("execve failed with unexpected error");
      return 1;
    }
  } else {
    /* Should never reach here */
    fprintf(stderr, "execve unexpectedly succeeded\n");
    return 1;
  }

  /* === TEST POSIX_SPAWN === */
  pid_t child_pid;
  char *spawn_argv[] = {"/usr/bin/true", "spawn_arg1", NULL};
  char *spawn_envp[] = {"SPAWN_VAR=spawn_value", NULL};

  ret = posix_spawn(&child_pid, "/usr/bin/true", NULL, NULL, spawn_argv,
                    spawn_envp);

  if (ret != 0) {
    fprintf(stderr, "posix_spawn failed: %s\n", strerror(ret));
    return 1;
  }

  /* Wait for spawned child to complete */
  waitpid(child_pid, &status, 0);

  return 0;
}

#endif /* MODE_FORK_EXEC_H */
