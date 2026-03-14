/*
 * time syscalls mode
 * Tests: gettimeofday
 */

#ifndef MODE_TIME_H
#define MODE_TIME_H

#include <stdio.h>
#include <sys/time.h>

int mode_time(int argc, char *argv[]) {
  (void)argc; /* Unused parameter */
  (void)argv; /* Unused parameter */

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

  /* === utimes() === */
  {
      struct timeval tv[2];
      utimes("somefile", tv);
  }

  printf("DPNE\n");
  return 0;
}

#endif /* MODE_TIME_H */
