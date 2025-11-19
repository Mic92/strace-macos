/*
 * Advanced process operations mode
 * Tests: proc_info, proc_info_extended_id, proc_trace_log, proc_uuid_policy,
 *        process_policy, pid_suspend, pid_resume, pid_hibernate,
 *        pid_shutdown_sockets, getpriority, setpriority, getrlimit, setrlimit,
 *        getrusage, proc_rlimit_control, thread_selfid, thread_selfusage,
 *        gettid, settid, settid_with_pid
 */

#ifndef MODE_PROCESS_ADVANCED_H
#define MODE_PROCESS_ADVANCED_H

#include <errno.h>
#include <libproc.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/proc_info.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

int mode_process_advanced(int argc, char *argv[]) {
  (void)argc; /* Unused parameter */
  (void)argv; /* Unused parameter */

  pid_t pid = getpid();
  int ret;

  /* === PRIORITY TESTS === */

  /* Test getpriority() - get scheduling priority */
  errno = 0;
  int prio = getpriority(PRIO_PROCESS, 0);
  if (prio == -1 && errno != 0) {
    perror("getpriority(PRIO_PROCESS, 0) failed");
  }

  /* Test with PRIO_PGRP */
  errno = 0;
  prio = getpriority(PRIO_PGRP, 0);
  if (prio == -1 && errno != 0) {
    perror("getpriority(PRIO_PGRP, 0) failed");
  }

  /* Test with PRIO_USER */
  errno = 0;
  prio = getpriority(PRIO_USER, getuid());
  if (prio == -1 && errno != 0) {
    perror("getpriority(PRIO_USER) failed");
  }

  /* Test setpriority() - set scheduling priority
   * Try to set to current value (should succeed without root) */
  if (setpriority(PRIO_PROCESS, 0, 0) < 0) {
    /* May fail depending on current priority and permissions */
  }

  /* Test with PRIO_PGRP */
  if (setpriority(PRIO_PGRP, 0, 0) < 0) {
    /* May fail depending on permissions */
  }

  /* === RESOURCE LIMIT TESTS === */

  struct rlimit rlim;

  /* Test getrlimit() - get resource limits */
  if (getrlimit(RLIMIT_CPU, &rlim) < 0) {
    perror("getrlimit(RLIMIT_CPU) failed");
  }

  if (getrlimit(RLIMIT_FSIZE, &rlim) < 0) {
    perror("getrlimit(RLIMIT_FSIZE) failed");
  }

  if (getrlimit(RLIMIT_DATA, &rlim) < 0) {
    perror("getrlimit(RLIMIT_DATA) failed");
  }

  if (getrlimit(RLIMIT_STACK, &rlim) < 0) {
    perror("getrlimit(RLIMIT_STACK) failed");
  }

  if (getrlimit(RLIMIT_CORE, &rlim) < 0) {
    perror("getrlimit(RLIMIT_CORE) failed");
  }

  if (getrlimit(RLIMIT_AS, &rlim) < 0) {
    perror("getrlimit(RLIMIT_AS) failed");
  }

  if (getrlimit(RLIMIT_NOFILE, &rlim) < 0) {
    perror("getrlimit(RLIMIT_NOFILE) failed");
  }

  if (getrlimit(RLIMIT_NPROC, &rlim) < 0) {
    perror("getrlimit(RLIMIT_NPROC) failed");
  }

  /* Test setrlimit() - set resource limits
   * Try setting to current values (should succeed) */
  struct rlimit current_nofile;
  if (getrlimit(RLIMIT_NOFILE, &current_nofile) == 0) {
    /* Try to set RLIMIT_NOFILE to current value */
    if (setrlimit(RLIMIT_NOFILE, &current_nofile) < 0) {
      /* May fail depending on hard limit */
    }
  }

  /* Test with RLIMIT_CORE */
  struct rlimit core_limit = {0, 0}; /* Disable core dumps */
  if (setrlimit(RLIMIT_CORE, &core_limit) < 0) {
    perror("setrlimit(RLIMIT_CORE) failed");
  }

  /* === RESOURCE USAGE TESTS === */

  struct rusage usage;

  /* Test getrusage() - get resource usage */
  if (getrusage(RUSAGE_SELF, &usage) < 0) {
    perror("getrusage(RUSAGE_SELF) failed");
  }

  if (getrusage(RUSAGE_CHILDREN, &usage) < 0) {
    perror("getrusage(RUSAGE_CHILDREN) failed");
  }

  /* === PROC_INFO TESTS === */

  /* Test proc_info() with PROC_PIDTBSDINFO - get BSD process info */
  struct proc_bsdinfo bsdinfo;
  ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsdinfo, sizeof(bsdinfo));
  if (ret <= 0) {
    perror("proc_pidinfo(PROC_PIDTBSDINFO) failed");
  }

  /* Test with PROC_PIDTASKINFO - get task info */
  struct proc_taskinfo taskinfo;
  ret = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &taskinfo, sizeof(taskinfo));
  if (ret <= 0) {
    perror("proc_pidinfo(PROC_PIDTASKINFO) failed");
  }

  /* Test with PROC_PIDTASKALLINFO - get both BSD and task info */
  struct proc_taskallinfo taskallinfo;
  ret = proc_pidinfo(pid, PROC_PIDTASKALLINFO, 0, &taskallinfo,
                     sizeof(taskallinfo));
  if (ret <= 0) {
    perror("proc_pidinfo(PROC_PIDTASKALLINFO) failed");
  }

  /* Test with PROC_PIDPATHINFO - get path to executable */
  char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
  ret = proc_pidinfo(pid, PROC_PIDPATHINFO, 0, pathbuf, sizeof(pathbuf));
  if (ret <= 0) {
    perror("proc_pidinfo(PROC_PIDPATHINFO) failed");
  }

  /* Test proc_pidpath() - another way to get the path */
  ret = proc_pidpath(pid, pathbuf, sizeof(pathbuf));
  if (ret <= 0) {
    perror("proc_pidpath failed");
  }

  /* === THREAD TESTS === */

  /* Test pthread_threadid_np() - get thread ID (public API) */
  uint64_t thread_id = 0;
  ret = pthread_threadid_np(NULL, &thread_id);
  if (ret != 0) {
    perror("pthread_threadid_np failed");
  }

  /* Note: thread_selfid, thread_selfusage, gettid, settid, settid_with_pid
   * have no public prototypes/wrappers - skipped */

  /* Note: pid_suspend, pid_resume, pid_hibernate, pid_shutdown_sockets
   * have no public prototypes - skipped */

  /* Note: proc_trace_log, proc_uuid_policy, process_policy, proc_rlimit_control,
   * proc_info_extended_id have no public prototypes - skipped */

  return 0;
}

#endif /* MODE_PROCESS_ADVANCED_H */
