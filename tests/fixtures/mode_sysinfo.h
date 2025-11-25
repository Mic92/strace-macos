/*
 * System information operations mode
 * Tests: sysctl, sysctlbyname, sysctlnametomib, getdtablesize,
 *        gethostuuid, getentropy, usrctl
 */

#ifndef MODE_SYSINFO_H
#define MODE_SYSINFO_H

#include <gethostuuid.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/reboot.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <unistd.h>
#include <uuid/uuid.h>

int mode_sysinfo(int argc, char *argv[]) {
  (void)argc; /* Unused parameter */
  (void)argv; /* Unused parameter */

  /* === sysctl() - BSD sysctl interface === */

  /* Test 1: Get kern.ostype (string) */
  {
    int mib[2] = {CTL_KERN, KERN_OSTYPE};
    char ostype[256];
    size_t len = sizeof(ostype);
    sysctl(mib, 2, ostype, &len, NULL, 0);
  }

  /* Test 2: Get kern.hostname (string) */
  {
    int mib[2] = {CTL_KERN, KERN_HOSTNAME};
    char hostname[256];
    size_t len = sizeof(hostname);
    sysctl(mib, 2, hostname, &len, NULL, 0);
  }

  /* Test 3: Get hw.ncpu (integer) */
  {
    int mib[2] = {CTL_HW, HW_NCPU};
    int ncpu;
    size_t len = sizeof(ncpu);
    sysctl(mib, 2, &ncpu, &len, NULL, 0);
  }

  /* Test 4: Query size first (NULL buffer) */
  {
    int mib[2] = {CTL_KERN, KERN_OSTYPE};
    size_t len = 0;
    sysctl(mib, 2, NULL, &len, NULL, 0);
    /* Now len contains the required size */
  }

  /* === sysctlbyname() - Name-based sysctl interface === */

  /* Test 1: Get kern.ostype by name */
  {
    char ostype[256];
    size_t len = sizeof(ostype);
    sysctlbyname("kern.ostype", ostype, &len, NULL, 0);
  }

  /* Test 2: Get kern.hostname by name */
  {
    char hostname[256];
    size_t len = sizeof(hostname);
    sysctlbyname("kern.hostname", hostname, &len, NULL, 0);
  }

  /* Test 3: Get hw.ncpu by name */
  {
    int ncpu;
    size_t len = sizeof(ncpu);
    sysctlbyname("hw.ncpu", &ncpu, &len, NULL, 0);
  }

  /* Test 4: Query size first with NULL buffer */
  {
    size_t len = 0;
    sysctlbyname("kern.ostype", NULL, &len, NULL, 0);
  }

  /* === sysctlnametomib() - Convert name to MIB === */

  /* Test 1: Convert kern.ostype to MIB */
  {
    int mib[CTL_MAXNAME];
    size_t mib_len = CTL_MAXNAME;
    sysctlnametomib("kern.ostype", mib, &mib_len);
    /* Can now use mib with sysctl() */
  }

  /* Test 2: Convert kern.hostname to MIB */
  {
    int mib[CTL_MAXNAME];
    size_t mib_len = CTL_MAXNAME;
    sysctlnametomib("kern.hostname", mib, &mib_len);
  }

  /* === getdtablesize() - Get max file descriptors === */

  /* Test 1: Get max file descriptors for current process */
  {
    int max_fds = getdtablesize();
    (void)max_fds;
  }

  /* === gethostuuid() - Get host UUID === */

  /* Test 1: Get host UUID with timeout */
  {
    uuid_t uuid;
    struct timespec timeout = {5, 0}; /* 5 seconds timeout */
    gethostuuid(uuid, &timeout);
  }

  /* Test 2: Get host UUID with NULL timeout */
  {
    uuid_t uuid;
    gethostuuid(uuid, NULL);
  }

  /* === getentropy() - Get random bytes === */

  /* Test 1: Get 32 bytes of entropy */
  {
    char buf[32];
    getentropy(buf, sizeof(buf));
  }

  /* Test 2: Get 256 bytes of entropy (max allowed) */
  {
    char buf[256];
    getentropy(buf, sizeof(buf));
  }

  /* === usrctl() - User space control === */

  /* Test 1: Query usrctl flags (read-only operation) */
  {
    /* USRCTL_USER_SHUTDOWN_READ = 0 (query current state) */
    usrctl(0);
  }

  return 0;
}

#endif /* MODE_SYSINFO_H */
