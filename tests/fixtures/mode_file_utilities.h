/*
 * File utilities operations mode
 * Tests: flock, fsync, fdatasync, chdir, fchdir, chroot,
 *        truncate, ftruncate, utimes, futimes,
 *        mkfifo, mkfifoat, mknod, mknodat,
 *        getattrlist, fgetattrlist, getattrlistat, getattrlistbulk,
 *        setattrlist, fsetattrlist, setattrlistat, fchownat,
 *        clonefileat, fclonefileat
 */

#ifndef MODE_FILE_UTILITIES_H
#define MODE_FILE_UTILITIES_H

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/clonefile.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

int mode_file_utilities(int argc, char *argv[]) {
  (void)argc; /* Unused parameter */
  (void)argv; /* Unused parameter */
  int fd1, fd2, dirfd;
  char temp_template1[256];
  char temp_template2[256];
  char temp_dir_template[256];
  char test_file1[256];
  char test_file2[256];
  char test_dir[256];
  char fifo_path[256];
  char fifo_at_path[256];
  char device_path[256];
  char device_at_path[256];
  char cwd_backup[1024];
  struct timeval times[2];

  /* Get current directory for restoration later */
  if (getcwd(cwd_backup, sizeof(cwd_backup)) == NULL) {
    perror("getcwd failed");
    return 1;
  }

  /* Create test files and directory using mkstemp/mkdtemp */
  strcpy(temp_template1, "/tmp/test_file1_XXXXXX");
  fd1 = mkstemp(temp_template1);
  strcpy(test_file1, temp_template1);

  strcpy(temp_template2, "/tmp/test_file2_XXXXXX");
  fd2 = mkstemp(temp_template2);
  strcpy(test_file2, temp_template2);

  strcpy(temp_dir_template, "/tmp/test_dir_XXXXXX");
  if (mkdtemp(temp_dir_template) == NULL) {
    perror("mkdtemp failed");
    return 1;
  }
  strcpy(test_dir, temp_dir_template);

  if (fd1 < 0 || fd2 < 0) {
    perror("mkstemp failed");
    return 1;
  }

  /* Write some data to test files */
  write(fd1, "test data for truncation and sync\n", 34);
  write(fd2, "test data 2\n", 12);

  /* === FILE LOCKING TESTS === */

  /* Test flock() with different operations */
  flock(fd1, LOCK_SH);              /* Shared lock */
  flock(fd1, LOCK_UN);              /* Unlock */
  flock(fd1, LOCK_EX);              /* Exclusive lock */
  flock(fd1, LOCK_UN);              /* Unlock */
  flock(fd1, LOCK_EX | LOCK_NB);    /* Non-blocking exclusive */
  flock(fd1, LOCK_UN);              /* Unlock */
  flock(fd2, LOCK_SH | LOCK_NB);    /* Non-blocking shared */

  /* === SYNC TESTS === */

  /* Test fsync() to flush file data to disk */
  fsync(fd1);
  fsync(fd2);

  /* Test fdatasync() - sync data but not necessarily metadata */
  fdatasync(fd1);
  fdatasync(fd2);

  /* Unlock the second file */
  flock(fd2, LOCK_UN);

  /* === DIRECTORY CHANGE TESTS === */

  /* Test chdir() - change to /tmp */
  chdir("/tmp");

  /* Open test directory for fchdir() */
  dirfd = open(test_dir, O_RDONLY | O_DIRECTORY);
  if (dirfd >= 0) {
    /* Test fchdir() - change directory via fd */
    fchdir(dirfd);

    /* Change back using chdir */
    chdir(cwd_backup);
    close(dirfd);
  }

  /* Test chroot() - will likely fail without root, but tests the syscall */
  chroot("/tmp");
  /* Note: Can't easily recover from chroot without being root, but that's ok
   * for testing */

  /* === TRUNCATE TESTS === */

  /* Test truncate() - truncate file to specific size */
  truncate(test_file1, 10);  /* Truncate to 10 bytes */
  truncate(test_file1, 100); /* Extend to 100 bytes */
  truncate(test_file1, 0);   /* Truncate to empty */

  /* Test ftruncate() - truncate via file descriptor */
  ftruncate(fd1, 5);   /* Truncate to 5 bytes */
  ftruncate(fd1, 50);  /* Extend to 50 bytes */
  ftruncate(fd1, 0);   /* Truncate to empty */

  /* === TIME MODIFICATION TESTS === */

  /* Set up timeval structures for utimes/futimes */
  times[0].tv_sec = 1000000000;  /* Access time */
  times[0].tv_usec = 0;
  times[1].tv_sec = 1000000000;  /* Modification time */
  times[1].tv_usec = 0;

  /* Test utimes() - set file access and modification times */
  utimes(test_file2, times);

  /* Different times */
  times[0].tv_sec = 1500000000;
  times[1].tv_sec = 1500000000;
  utimes(test_file2, times);

  /* Test futimes() - set times via file descriptor */
  futimes(fd2, times);

  /* Set to current time (NULL) */
  utimes(test_file2, NULL);
  futimes(fd2, NULL);

  /* === SPECIAL FILE CREATION TESTS === */

  /* Test mkfifo() - create named pipe */
  snprintf(fifo_path, sizeof(fifo_path), "%s/test_fifo", test_dir);
  mkfifo(fifo_path, 0644);

  /* Test mkfifoat() - create named pipe at directory */
  dirfd = open(test_dir, O_RDONLY | O_DIRECTORY);
  if (dirfd >= 0) {
    mkfifoat(dirfd, "test_fifo_at", 0600);
    snprintf(fifo_at_path, sizeof(fifo_at_path), "%s/test_fifo_at", test_dir);
  }

  /* Test mknod() - create special file (character device)
   * Will likely fail without root, but tests the syscall
   * Using makedev(1, 3) which would be /dev/null on many systems */
  snprintf(device_path, sizeof(device_path), "%s/test_device", test_dir);
  mknod(device_path, S_IFCHR | 0666, makedev(1, 3));

  /* Test mknodat() - create special file at directory */
  if (dirfd >= 0) {
    mknodat(dirfd, "test_device_at", S_IFCHR | 0666, makedev(1, 5));
    snprintf(device_at_path, sizeof(device_at_path), "%s/test_device_at",
             test_dir);
    close(dirfd);
  }

  /* === ADDITIONAL *AT SYSCALLS === */

  /* Test getattrlistat() - get attributes at directory */
  /* Note: This syscall is complex and may not work without proper setup,
   * but it tests the syscall invocation */
  dirfd = open(test_dir, O_RDONLY | O_DIRECTORY);
  if (dirfd >= 0) {
    struct attrlist attr_list;
    char attr_buf[1024];

    memset(&attr_list, 0, sizeof(attr_list));
    attr_list.bitmapcount = ATTR_BIT_MAP_COUNT;
    attr_list.commonattr = ATTR_CMN_NAME | ATTR_CMN_OBJTYPE;

    /* getattrlistat(dirfd, path, attrlist, attrbuf, size, options) */
    getattrlistat(dirfd, "test_fifo", &attr_list, attr_buf, sizeof(attr_buf),
                  0);

    /* Test setattrlistat() - set attributes at directory */
    struct timespec ts = {0};
    attr_list.commonattr = ATTR_CMN_MODTIME;
    setattrlistat(dirfd, "test_fifo", &attr_list, &ts, sizeof(ts), 0);

    close(dirfd);
  }

  /* Test clonefileat() - clone file between directories with various flags */
  /* This is a macOS-specific syscall for APFS copy-on-write clones */
  dirfd = open(test_dir, O_RDONLY | O_DIRECTORY);
  if (dirfd >= 0) {
    int src_dirfd = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (src_dirfd >= 0) {
      /* Test with no flags */
      clonefileat(src_dirfd, "test_file1_clone_src", dirfd,
                  "test_file1_clone_dst", 0);
      /* Test with CLONE_NOFOLLOW */
      clonefileat(src_dirfd, "test_file1_clone_src2", dirfd,
                  "test_file1_clone_dst2", CLONE_NOFOLLOW);
      /* Test with CLONE_NOOWNERCOPY */
      clonefileat(src_dirfd, "test_file1_clone_src3", dirfd,
                  "test_file1_clone_dst3", CLONE_NOOWNERCOPY);
      close(src_dirfd);
    }
    close(dirfd);
  }

  /* Test fclonefileat() - clone file from fd to directory with flags */
  /* fclonefileat(srcfd, dst_dirfd, dst_name, flags) */
  dirfd = open(test_dir, O_RDONLY | O_DIRECTORY);
  if (dirfd >= 0 && fd1 >= 0) {
    fclonefileat(fd1, dirfd, "test_file1_fclone", 0);
    fclonefileat(fd1, dirfd, "test_file1_fclone2", CLONE_NOFOLLOW);
    close(dirfd);
  }

  /* === ATTRIBUTE SYSCALLS === */

  /* Test getattrlist() - get attributes of a file */
  {
    struct attrlist alist;
    char attrbuf[1024];
    memset(&alist, 0, sizeof(alist));
    alist.bitmapcount = ATTR_BIT_MAP_COUNT;
    alist.commonattr = ATTR_CMN_NAME | ATTR_CMN_OBJTYPE;
    getattrlist(test_file1, &alist, attrbuf, sizeof(attrbuf), 0);
  }

  /* Test fgetattrlist() - get attributes via fd */
  if (fd2 >= 0) {
    struct attrlist alist;
    char attrbuf[1024];
    memset(&alist, 0, sizeof(alist));
    alist.bitmapcount = ATTR_BIT_MAP_COUNT;
    alist.commonattr = ATTR_CMN_NAME | ATTR_CMN_OBJTYPE;
    fgetattrlist(fd2, &alist, attrbuf, sizeof(attrbuf), 0);
  }

  /* Test setattrlist() - set attributes of a file */
  {
    struct attrlist alist;
    struct timespec ts = {0};
    memset(&alist, 0, sizeof(alist));
    alist.bitmapcount = ATTR_BIT_MAP_COUNT;
    alist.commonattr = ATTR_CMN_MODTIME;
    setattrlist(test_file1, &alist, &ts, sizeof(ts), 0);
  }

  /* Test fsetattrlist() - set attributes via fd */
  if (fd2 >= 0) {
    struct attrlist alist;
    struct timespec ts = {0};
    memset(&alist, 0, sizeof(alist));
    alist.bitmapcount = ATTR_BIT_MAP_COUNT;
    alist.commonattr = ATTR_CMN_MODTIME;
    fsetattrlist(fd2, &alist, &ts, sizeof(ts), 0);
  }

  /* Test fchownat() - change ownership at directory with various flags */
  dirfd = open(test_dir, O_RDONLY | O_DIRECTORY);
  if (dirfd >= 0) {
    fchownat(dirfd, "test_fifo", 1000, 1000, 0);
    fchownat(dirfd, "test_fifo", 1000, 1000, AT_SYMLINK_NOFOLLOW);
    close(dirfd);
  }

  /* Test getattrlistbulk() - bulk get attributes */
  dirfd = open(test_dir, O_RDONLY | O_DIRECTORY);
  if (dirfd >= 0) {
    struct attrlist alist;
    char attrbuf[4096];
    memset(&alist, 0, sizeof(alist));
    alist.bitmapcount = ATTR_BIT_MAP_COUNT;
    alist.commonattr = ATTR_CMN_NAME | ATTR_CMN_OBJTYPE;
    getattrlistbulk(dirfd, &alist, attrbuf, sizeof(attrbuf), 0);
    close(dirfd);
  }

  /* === CLEANUP === */

  close(fd1);
  close(fd2);

  /* Remove special files (may fail if creation failed) */
  unlink(device_at_path);
  unlink(device_path);
  unlink(fifo_at_path);
  unlink(fifo_path);

  /* Remove regular test files */
  unlink(test_file1);
  unlink(test_file2);

  /* Remove test directory */
  rmdir(test_dir);

  return 0;
}

#endif /* MODE_FILE_UTILITIES_H */
