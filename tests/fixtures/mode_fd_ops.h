/*
 * File descriptor operations modes
 * Comprehensive testing of fd-related syscalls
 */

#ifndef MODE_FD_OPS_H
#define MODE_FD_OPS_H

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <termios.h>
#include <unistd.h>

int mode_fd_ops(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  /* Create a secure temporary file */
  char tmpfile[] = "/tmp/strace_fd_test.XXXXXX";
  int fd = mkstemp(tmpfile);
  if (fd < 0) {
    return 1;
  }

  /* 1. write - write initial data */
  const char *data = "Hello World\n";
  write(fd, data, strlen(data));

  /* 2. pwrite - write at specific offset */
  const char *pdata = "TEST";
  pwrite(fd, pdata, 4, 6);

  /* 3. writev - write multiple buffers */
  struct iovec iov_write[3];
  const char *msg1 = "First ";
  const char *msg2 = "Second ";
  const char *msg3 = "Third\n";
  iov_write[0].iov_base = (void *)msg1;
  iov_write[0].iov_len = strlen(msg1);
  iov_write[1].iov_base = (void *)msg2;
  iov_write[1].iov_len = strlen(msg2);
  iov_write[2].iov_base = (void *)msg3;
  iov_write[2].iov_len = strlen(msg3);
  writev(fd, iov_write, 3);

  /* 4. pread - read from specific offset */
  char pbuf[32];
  pread(fd, pbuf, 4, 0);

  /* 5. readv - read into multiple buffers */
  lseek(fd, 0, SEEK_SET);
  char buf1[16], buf2[16], buf3[16];
  struct iovec iov_read[3];
  iov_read[0].iov_base = buf1;
  iov_read[0].iov_len = sizeof(buf1);
  iov_read[1].iov_base = buf2;
  iov_read[1].iov_len = sizeof(buf2);
  iov_read[2].iov_base = buf3;
  iov_read[2].iov_len = sizeof(buf3);
  readv(fd, iov_read, 3);

  /* 6. dup - duplicate file descriptor */
  int fd2 = dup(fd);
  if (fd2 >= 0) {
    /* 7. dup2 - duplicate to specific fd */
    int fd3 = dup2(fd, 100);
    if (fd3 >= 0) {
      close(fd3);
    }
    close(fd2);
  }

  /* 8. fcntl - get/set file descriptor flags */
  int flags = fcntl(fd, F_GETFD);
  if (flags >= 0) {
    // Call fcntl through a variable to force proper register loading
    int cloexec_value = FD_CLOEXEC;
    fcntl(fd, F_SETFD, cloexec_value);  // Explicitly set FD_CLOEXEC for testing
  }

  /* 9. fcntl - get/set file status flags */
  flags = fcntl(fd, F_GETFL);
  if (flags >= 0) {
    fcntl(fd, F_SETFL, O_RDWR | O_APPEND);  // Explicitly set flags for testing
  }

  /* 10. ioctl - test with FIOCLEX (set close-on-exec) */
  ioctl(fd, FIOCLEX);

  /* 11. ioctl - test with FIONCLEX (clear close-on-exec) */
  ioctl(fd, FIONCLEX);

  /* 12. ioctl - test FIONREAD (get bytes available to read) */
  int nbytes = 0;
  ioctl(fd, FIONREAD, &nbytes);

  /* Test ioctl with stdout (tty operations) */
  struct winsize ws;
  /* 13. ioctl - TIOCGWINSZ (get window size) */
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
    /* Successfully got window size */
  }

  /* Test with stderr for additional coverage */
  /* 14. ioctl - TIOCGETA (get terminal attributes) - macOS specific */
  struct termios term;
  ioctl(STDERR_FILENO, TIOCGETA, &term);

  /* Clean up */
  close(fd);
  unlink(tmpfile);

  return 0;
}

#endif /* MODE_FD_OPS_H */
