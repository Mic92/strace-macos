/*
 * Process identity operations mode
 * Tests: getpid, getppid, getpgrp, getpgid, setpgid, getsid, setsid,
 *        getuid, geteuid, getgid, getegid, setuid, seteuid, setgid, setegid,
 *        setreuid, setregid, getgroups, setgroups, initgroups,
 *        getlogin, setlogin, issetugid
 */

#ifndef MODE_PROCESS_IDENTITY_H
#define MODE_PROCESS_IDENTITY_H

#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int mode_process_identity(int argc, char *argv[]) {
  (void)argc; /* Unused parameter */
  (void)argv; /* Unused parameter */

  pid_t pid, ppid, pgrp, pgid, sid;
  uid_t uid, euid, new_uid;
  gid_t gid, egid, new_gid;
  gid_t groups[32];
  int ngroups;

  /* === PROCESS ID TESTS === */

  /* Test getpid() - get current process ID */
  pid = getpid();
  if (pid < 0) {
    perror("getpid failed");
  }

  /* Test getppid() - get parent process ID */
  ppid = getppid();
  if (ppid < 0) {
    perror("getppid failed");
  }

  /* === PROCESS GROUP TESTS === */

  /* Test getpgrp() - get process group ID (no arguments) */
  pgrp = getpgrp();
  if (pgrp < 0) {
    perror("getpgrp failed");
  }

  /* Test getpgid() - get process group ID of a process */
  pgid = getpgid(0); /* 0 means current process */
  if (pgid < 0) {
    perror("getpgid(0) failed");
  }

  /* Test getpgid() with actual pid */
  pgid = getpgid(pid);
  if (pgid < 0) {
    perror("getpgid(pid) failed");
  }

  /* Test setpgid() - set process group ID
   * setpgid(0, 0) sets the calling process's process group ID to its own PID
   * This will likely fail if we're a session leader, but tests the syscall */
  if (setpgid(0, 0) < 0) {
    /* Expected to fail in many cases, but we still test it */
  }

  /* Test setpgid() with specific pid and pgid
   * This will likely fail without proper permissions, but tests the syscall */
  if (setpgid(pid, pgrp) < 0) {
    /* Expected to fail, but we test the syscall */
  }

  /* === SESSION TESTS === */

  /* Test getsid() - get session ID */
  sid = getsid(0); /* 0 means current process */
  if (sid < 0) {
    perror("getsid(0) failed");
  }

  /* Test getsid() with actual pid */
  sid = getsid(pid);
  if (sid < 0) {
    perror("getsid(pid) failed");
  }

  /* Test setsid() - create a new session
   * This will fail if we're already a process group leader, but tests the
   * syscall Note: We don't actually want to succeed here in most cases, as it
   * would detach from the terminal */
  if (setsid() < 0) {
    /* Expected to fail if already a session leader, but we test the syscall */
  }

  /* === USER ID TESTS === */

  /* Test getuid() - get real user ID */
  uid = getuid();
  /* getuid() always succeeds on macOS */

  /* Test geteuid() - get effective user ID */
  euid = geteuid();
  /* geteuid() always succeeds on macOS */

  /* === GROUP ID TESTS === */

  /* Test getgid() - get real group ID */
  gid = getgid();
  /* getgid() always succeeds on macOS */

  /* Test getegid() - get effective group ID */
  egid = getegid();
  /* getegid() always succeeds on macOS */

  /* === SET USER ID TESTS === */

  /* Test setuid() - set real and effective user ID
   * This will fail unless we're root, but tests the syscall */
  new_uid = uid; /* Try to set to current uid (should succeed) */
  if (setuid(new_uid) < 0) {
    /* May fail if not root, but we test the syscall */
  }

  /* Test seteuid() - set effective user ID
   * This will fail unless we're root, but tests the syscall */
  if (seteuid(euid) < 0) {
    /* May fail if not root, but we test the syscall */
  }

  /* === SET GROUP ID TESTS === */

  /* Test setgid() - set real and effective group ID
   * This will fail unless we're root, but tests the syscall */
  new_gid = gid; /* Try to set to current gid (should succeed) */
  if (setgid(new_gid) < 0) {
    /* May fail if not root, but we test the syscall */
  }

  /* Test setegid() - set effective group ID
   * This will fail unless we're root, but tests the syscall */
  if (setegid(egid) < 0) {
    /* May fail if not root, but we test the syscall */
  }

  /* === SET REAL AND EFFECTIVE IDS === */

  /* Test setreuid() - set real and effective user IDs
   * Pass -1 to leave a value unchanged */
  if (setreuid(-1, -1) < 0) {
    /* Setting to -1 should succeed (no change) */
  }

  /* Try setting to current values */
  if (setreuid(uid, euid) < 0) {
    /* May fail if not root */
  }

  /* Test setregid() - set real and effective group IDs
   * Pass -1 to leave a value unchanged */
  if (setregid(-1, -1) < 0) {
    /* Setting to -1 should succeed (no change) */
  }

  /* Try setting to current values */
  if (setregid(gid, egid) < 0) {
    /* May fail if not root */
  }

  /* === SUPPLEMENTARY GROUPS TESTS === */

  /* Test getgroups() - get supplementary group IDs
   * First call with ngroups=0 to get the count */
  ngroups = getgroups(0, NULL);
  if (ngroups < 0) {
    perror("getgroups(0) failed");
    ngroups = 0;
  }

  /* Now get the actual groups (limited to our buffer size) */
  if (ngroups > 0) {
    int groups_to_get = ngroups < 32 ? ngroups : 32;
    ngroups = getgroups(groups_to_get, groups);
    if (ngroups < 0) {
      perror("getgroups failed");
      ngroups = 0;
    }
  }

  /* Test setgroups() - set supplementary group IDs
   * This will fail unless we're root, but tests the syscall
   * Try to set to current groups */
  if (ngroups > 0) {
    if (setgroups(ngroups, groups) < 0) {
      /* Expected to fail if not root, but we test the syscall */
    }
  }

  /* Test setgroups with empty list (will also fail if not root) */
  if (setgroups(0, NULL) < 0) {
    /* Expected to fail if not root */
  }

  /* Test initgroups() - initialize the group access list
   * This syscall initializes the supplementary group access list by reading
   * /etc/group This will likely fail unless we're root, but tests the syscall
   */

  /* Get current username for initgroups */
  char username[256];
  struct passwd *pwd = getpwuid(uid);
  if (pwd != NULL) {
    snprintf(username, sizeof(username), "%s", pwd->pw_name);

    /* Test initgroups() with current username and primary gid */
    if (initgroups(username, gid) < 0) {
      /* Expected to fail if not root, but we test the syscall */
    }

    /* Test initgroups() with different gid */
    if (initgroups(username, egid) < 0) {
      /* Expected to fail if not root */
    }
  }

  /* Test with a non-existent username (should fail) */
  if (initgroups("nonexistent_user_12345", gid) < 0) {
    /* Expected to fail */
  }

  /* === LOGIN NAME TESTS === */

  /* Test getlogin() - get login name
   * Returns the login name of the user associated with the session */
  char login_buf[256];
  char *login_name = getlogin();
  if (login_name != NULL) {
    /* getlogin() succeeded */
  }

  /* Test getlogin_r() - reentrant version
   * Gets login name into provided buffer */
  if (getlogin_r(login_buf, sizeof(login_buf)) == 0) {
    /* Successfully got login name */
  }

  /* Test setlogin() - set login name
   * This will fail unless we're root, but tests the syscall */
  if (setlogin("testuser") < 0) {
    /* Expected to fail if not root */
  }

  /* === SETUID PROGRAM TESTS === */

  /* Test issetugid() - check if process was tainted by setuid/setgid
   * Returns 1 if the process was made setuid/setgid as result of execve,
   * or if it has changed any of its UIDs/GIDs since it began execution.
   * This is important for security-sensitive operations. */
  int is_tainted = issetugid();
  (void)is_tainted; /* Use the value to avoid warnings */

  return 0;
}

#endif /* MODE_PROCESS_IDENTITY_H */
