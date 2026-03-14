/*
 * time syscalls mode
 * Tests: gettimeofday
 */

#ifndef MODE_TIME_H
#define MODE_TIME_H

#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

int mode_time(int argc, char *argv[]) {
  (void)argc; /* Unused parameter */
  (void)argv; /* Unused parameter */

  // we don't actually want to run if this is launched as root; 
  // we want the settimeofday/adjtime calls to fail, rather than
  // actually set the time
  if (getuid() == 0) {
      fprintf(stderr, "cowardly refusing to run as root\n");
      return -1;
  }

  /* === gettimeofday() - get date and time === */
  {
      struct timeval tv;
      struct timezone tz;
      gettimeofday(&tv, &tz);
  }

  /* === settimeofday() - set date and time === */
  {
      struct timeval tv = {100, 200};
      struct timezone tz = {-60, 1};
      settimeofday(&tv, &tz);
  }

  const char* tempfile = "/tmp/strace_futimes_test.txt";

  /* === futimes() === */
  {
      int fd = open(tempfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
      if (fd < 0) {
          fprintf(stderr, "couldn't create tempfile for time tests\n");
          return -1;
      }

      struct timeval tv[2] = {{999, 888}, {777, 666}};
      futimes(fd, tv);
      close(fd);
  }

  /* === utimes() === */
  {
      struct timeval tv[2] = {{123, 456}, {654, 321}};
      utimes(tempfile, tv);
  }

  unlink(tempfile);

  /* === adjtime() === */
  {
      struct timeval delta = {1, 2};
      struct timeval olddelta = {0, 0};
      adjtime(&delta, &olddelta);
  }
  
  /* === getitimer() === */
  {
      struct itimerval itv;
      getitimer(ITIMER_VIRTUAL, &itv);
  }

  /* === setitimer() === */
  {
      struct itimerval value = {{1,2}, {0,0}};
      struct itimerval ovalue;
      setitimer(ITIMER_VIRTUAL, &value, &ovalue);
  }

  return 0;
}

#endif /* MODE_TIME_H */

