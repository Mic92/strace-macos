/*
 * Follow fork test mode
 * Tests tracing of child processes when -f flag is used.
 *
 * Parent forks, child calls getpid() and writes to pipe,
 * parent reads from pipe and waits for child.
 */

#ifndef MODE_FOLLOW_FORK_H
#define MODE_FOLLOW_FORK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int mode_follow_fork(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  int pipefd[2];
  pid_t pid;
  int status;

  /* Create pipe for parent-child communication */
  if (pipe(pipefd) < 0) {
    perror("pipe failed");
    return 1;
  }

  /* Fork child process */
  pid = fork();
  if (pid < 0) {
    perror("fork failed");
    return 1;
  }

  if (pid == 0) {
    /* === CHILD PROCESS === */
    close(pipefd[0]); /* Close read end */

    /* Call getpid() - this will show child's PID in trace */
    pid_t child_pid = getpid();

    /* Write child's PID to pipe (so test can verify) */
    char buf[32];
    int len = snprintf(buf, sizeof(buf), "%d", child_pid);
    write(pipefd[1], buf, len);
    close(pipefd[1]);

    /* Exit with distinctive code */
    _exit(42);
  }

  /* === PARENT PROCESS === */
  close(pipefd[1]); /* Close write end */

  /* Call getpid() - this will show parent's PID in trace */
  pid_t parent_pid = getpid();
  (void)parent_pid; /* Avoid unused variable warning */

  /* Read child's PID from pipe */
  char buf[32];
  ssize_t n = read(pipefd[0], buf, sizeof(buf) - 1);
  if (n > 0) {
    buf[n] = '\0';
  }
  close(pipefd[0]);

  /* Wait for child */
  waitpid(pid, &status, 0);

  return 0;
}

#endif /* MODE_FOLLOW_FORK_H */
