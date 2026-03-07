/*
 * Errno test mode - generates syscalls that fail with various errors
 */

#ifndef MODE_ERRNO_TEST_H
#define MODE_ERRNO_TEST_H

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int mode_errno_test(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  /* Try to open non-existent file - will fail with ENOENT */
  int fd = open("/tmp/this_file_definitely_does_not_exist_12345.txt", O_RDONLY);
  if (fd == -1) {
    /* Expected to fail */
  }

  /* Try to read from invalid fd - will fail with EBADF */
  char buf[10];
  ssize_t ret = read(999, buf, sizeof(buf));
  if (ret == -1) {
    /* Expected to fail */
  }

  /* Try to write to invalid fd - will fail with EBADF */
  ret = write(999, "test", 4);
  if (ret == -1) {
    /* Expected to fail */
  }

  /* Try to stat non-existent file - will fail with ENOENT */
  struct stat st;
  int stat_ret = stat("/tmp/nonexistent_file_54321.txt", &st);
  if (stat_ret == -1) {
    /* Expected to fail */
  }

  /* Try to access non-existent file - will fail with ENOENT */
  int access_ret = access("/tmp/another_nonexistent_file_99999.txt", R_OK);
  if (access_ret == -1) {
    /* Expected to fail */
  }

  return 0;
}

#endif /* MODE_ERRNO_TEST_H */
