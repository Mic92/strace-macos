/*
 * Miscellaneous modes
 */

#ifndef MODE_MISC_H
#define MODE_MISC_H

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

extern volatile int keep_running;
extern void sigterm_handler(int sig);

int mode_long_running(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  /* Setup signal handler */
  signal(SIGTERM, sigterm_handler);

  /* Write ready marker */
  write(STDOUT_FILENO, "READY\n", 6);

  while (keep_running) {
    /* Generate syscalls - do file operations */
    int fd = open("/tmp/strace_long_running_test.txt",
                  O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
      write(fd, "test\n", 5);
      close(fd);
    }
    unlink("/tmp/strace_long_running_test.txt");

    usleep(500000); /* 0.5 seconds */
  }

  return 0;
}

int mode_fail(int argc, char *argv[]) {
  (void)argc;
  (void)argv;
  return 1;
}

int mode_stdio_test(int argc, char *argv[]) {
  (void)argc;
  (void)argv;
  /* Write unique markers to both stdout and stderr */
  fprintf(stdout, "STDOUT_MARKER_12345\n");
  fflush(stdout);
  fprintf(stderr, "STDERR_MARKER_67890\n");
  fflush(stderr);
  return 0;
}

int mode_default(int argc, char *argv[]) {
  /* Print all arguments */
  for (int i = 0; i < argc; i++) {
    printf("%s\n", argv[i]);
  }
  return 0;
}

#endif /* MODE_MISC_H */
