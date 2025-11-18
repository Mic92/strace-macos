/*
 * Memory management operations mode
 * Tests: mmap, munmap, mprotect, madvise, msync, mlock, munlock
 */

#ifndef MODE_MEMORY_H
#define MODE_MEMORY_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int mode_memory(int argc, char *argv[]) {
  void *addr;
  size_t page_size = getpagesize();
  size_t map_size = page_size * 4;  /* 4 pages */
  int fd = -1;

  /* Test mmap with anonymous memory, different protection flags */

  /* Anonymous private mapping with read+write */
  addr = mmap(NULL, map_size, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_ANON, -1, 0);
  if (addr != MAP_FAILED) {
    /* Write some data */
    memset(addr, 0xAA, page_size);

    /* Test mprotect - change to read-only */
    mprotect(addr, page_size, PROT_READ);

    /* Test mprotect - change to read+write */
    mprotect(addr, page_size, PROT_READ | PROT_WRITE);

    /* Test mprotect - change to no access */
    mprotect(addr, page_size, PROT_NONE);

    /* Test mprotect - back to read+write */
    mprotect(addr, page_size, PROT_READ | PROT_WRITE);

    /* Test madvise with various hints */
    madvise(addr, map_size, MADV_NORMAL);
    madvise(addr, map_size, MADV_RANDOM);
    madvise(addr, map_size, MADV_SEQUENTIAL);
    madvise(addr, map_size, MADV_WILLNEED);
    madvise(addr, map_size, MADV_DONTNEED);

    /* Test msync - flush to disk (no-op for anon, but tests syscall) */
    msync(addr, map_size, MS_SYNC);
    msync(addr, map_size, MS_ASYNC);
    msync(addr, map_size, MS_INVALIDATE);

    /* Test mlock - lock pages in memory */
    mlock(addr, page_size);

    /* Test munlock - unlock pages */
    munlock(addr, page_size);

    /* Clean up */
    munmap(addr, map_size);
  }

  /* Test mmap with different flag combinations */

  /* Shared anonymous mapping */
  addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
              MAP_SHARED | MAP_ANON, -1, 0);
  if (addr != MAP_FAILED) {
    munmap(addr, page_size);
  }

  /* Private anonymous mapping with PROT_EXEC (for testing JIT scenarios) */
  addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE | PROT_EXEC,
              MAP_PRIVATE | MAP_ANON, -1, 0);
  if (addr != MAP_FAILED) {
    munmap(addr, page_size);
  }

  /* Test MAP_FIXED (risky, but useful for testing) */
  /* First allocate a region */
  void *hint = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANON, -1, 0);
  if (hint != MAP_FAILED) {
    /* Then map over it with MAP_FIXED */
    addr = mmap(hint, page_size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
    if (addr != MAP_FAILED) {
      munmap(addr, page_size);
    }
  }

  /* Test mmap with PROT_NONE */
  addr = mmap(NULL, page_size, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
  if (addr != MAP_FAILED) {
    munmap(addr, page_size);
  }

  /* Test larger mappings for alignment testing */
  addr = mmap(NULL, page_size * 16, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_ANON, -1, 0);
  if (addr != MAP_FAILED) {
    /* Partial munmap at the end */
    munmap((char *)addr + (page_size * 12), page_size * 4);
    /* munmap the rest */
    munmap(addr, page_size * 12);
  }

  return 0;
}

#endif /* MODE_MEMORY_H */
