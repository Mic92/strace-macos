/*
 * File metadata operations mode
 * Tests: access, chmod, fchmod, chown, fchown, link, linkat,
 *        symlink, symlinkat, readlink, readlinkat,
 *        mkdir, mkdirat, rmdir, rename, renameat, unlinkat
 */

#ifndef MODE_FILE_METADATA_H
#define MODE_FILE_METADATA_H

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int mode_file_metadata(int argc, char *argv[]) {
  char buf[256];
  int fd;
  char temp_template[256];
  char chmod_file[256];
  char fchmod_file[256];
  char link_src[256];
  char link_dst1[256];
  char link_dst2[256];
  char symlink1[256];
  char symlink2[256];
  char rename_src[256];
  char rename_dst[256];
  char renameat_src[256];
  char renameat_dst[256];
  char unlinkat_file[256];
  char dir1[256];
  char dir2[256];
  char dir_at[256];
  char unlinkat_dir[256];

  /* Test access() with various modes */
  access("/tmp", F_OK);        /* Check existence */
  access("/tmp", R_OK);        /* Check read permission */
  access("/tmp", W_OK);        /* Check write permission */
  access("/tmp", X_OK);        /* Check execute permission */
  access("/tmp", R_OK | W_OK); /* Check read+write */

  /* Create test files using mkstemp for safe temp file creation */

  /* Test chmod() with various modes */
  strcpy(temp_template, "/tmp/test_chmod_XXXXXX");
  fd = mkstemp(temp_template);
  strcpy(chmod_file, temp_template);
  close(fd);
  chmod(chmod_file, 0644);
  chmod(chmod_file, 0755);
  chmod(chmod_file, 0600);

  /* Test fchmod() */
  strcpy(temp_template, "/tmp/test_fchmod_XXXXXX");
  fd = mkstemp(temp_template);
  strcpy(fchmod_file, temp_template);
  if (fd >= 0) {
    fchmod(fd, 0600);
    fchmod(fd, 0755);
    close(fd);
  }

  /* Test chown() and fchown() - will likely fail without root, but tests
   * syscall */
  chown(chmod_file, 1000, 1000);
  chown(chmod_file, -1, 1000); /* Keep owner, change group */

  fd = open(fchmod_file, O_RDONLY);
  if (fd >= 0) {
    fchown(fd, 1000, 1000);
    fchown(fd, 1000, -1); /* Change owner, keep group */
    close(fd);
  }

  /* Test link() and linkat() */
  strcpy(temp_template, "/tmp/test_link_src_XXXXXX");
  fd = mkstemp(temp_template);
  strcpy(link_src, temp_template);
  close(fd);

  snprintf(link_dst1, sizeof(link_dst1), "%s.link1", link_src);
  snprintf(link_dst2, sizeof(link_dst2), "%s.link2", link_src);

  link(link_src, link_dst1);
  linkat(AT_FDCWD, link_src, AT_FDCWD, link_dst2, 0);

  /* Test symlink() and readlink() */
  strcpy(temp_template, "/tmp/test_symlink_XXXXXX");
  fd = mkstemp(temp_template);
  close(fd);
  unlink(temp_template); /* Remove the file, we'll create symlink */
  strcpy(symlink1, temp_template);

  symlink("/tmp/target", symlink1);
  readlink(symlink1, buf, sizeof(buf));

  /* Test symlinkat() and readlinkat() */
  strcpy(temp_template, "/tmp/test_symlink2_XXXXXX");
  fd = mkstemp(temp_template);
  close(fd);
  unlink(temp_template);
  strcpy(symlink2, temp_template);

  symlinkat("/tmp/target2", AT_FDCWD, symlink2);
  readlinkat(AT_FDCWD, symlink2, buf, sizeof(buf));

  /* Test mkdir() and mkdirat() with various modes */
  strcpy(temp_template, "/tmp/test_dir1_XXXXXX");
  mkdtemp(temp_template); /* Creates directory atomically */
  strcpy(dir1, temp_template);

  /* Test mkdir() explicitly with different modes */
  char mkdir_test1[256];
  snprintf(mkdir_test1, sizeof(mkdir_test1), "%s/subdir1", dir1);
  mkdir(mkdir_test1, 0755);

  char mkdir_test2[256];
  snprintf(mkdir_test2, sizeof(mkdir_test2), "%s/subdir2", dir1);
  mkdir(mkdir_test2, 0700);

  strcpy(temp_template, "/tmp/test_dir2_XXXXXX");
  mkdtemp(temp_template);
  strcpy(dir2, temp_template);

  strcpy(temp_template, "/tmp/test_dir_at_XXXXXX");
  mkdtemp(temp_template);
  strcpy(dir_at, temp_template);

  /* Test mkdirat() explicitly */
  int dirfd_for_mkdir = open(dir2, O_RDONLY | O_DIRECTORY);
  if (dirfd_for_mkdir >= 0) {
    mkdirat(dirfd_for_mkdir, "subdir_at", 0755);
    close(dirfd_for_mkdir);
  }

  /* Test rename() and renameat() */
  strcpy(temp_template, "/tmp/test_rename_src_XXXXXX");
  fd = mkstemp(temp_template);
  strcpy(rename_src, temp_template);
  close(fd);
  snprintf(rename_dst, sizeof(rename_dst), "%s.renamed", rename_src);
  rename(rename_src, rename_dst);

  strcpy(temp_template, "/tmp/test_renameat_src_XXXXXX");
  fd = mkstemp(temp_template);
  strcpy(renameat_src, temp_template);
  close(fd);
  snprintf(renameat_dst, sizeof(renameat_dst), "%s.renamed", renameat_src);
  renameat(AT_FDCWD, renameat_src, AT_FDCWD, renameat_dst);

  /* Test unlinkat() with file (flags=0) */
  strcpy(temp_template, "/tmp/test_unlinkat_XXXXXX");
  fd = mkstemp(temp_template);
  strcpy(unlinkat_file, temp_template);
  close(fd);
  unlinkat(AT_FDCWD, unlinkat_file, 0);

  /* Test unlinkat() with directory (flags=AT_REMOVEDIR) */
  strcpy(temp_template, "/tmp/test_unlinkat_dir_XXXXXX");
  mkdtemp(temp_template);
  strcpy(unlinkat_dir, temp_template);
  chmod(unlinkat_dir, 0755); /* Ensure correct permissions */
  unlinkat(AT_FDCWD, unlinkat_dir, AT_REMOVEDIR);

  /* Test rmdir() - clean up subdirectories first */
  char cleanup_path[256];
  snprintf(cleanup_path, sizeof(cleanup_path), "%s/subdir_at", dir2);
  rmdir(cleanup_path);
  snprintf(cleanup_path, sizeof(cleanup_path), "%s/subdir2", dir1);
  rmdir(cleanup_path);
  snprintf(cleanup_path, sizeof(cleanup_path), "%s/subdir1", dir1);
  rmdir(cleanup_path);

  rmdir(dir_at);
  rmdir(dir2);
  rmdir(dir1);

  /* Cleanup all test files */
  unlink(symlink2);
  unlink(symlink1);
  unlink(link_dst2);
  unlink(link_dst1);
  unlink(link_src);
  unlink(renameat_dst);
  unlink(rename_dst);
  unlink(fchmod_file);
  unlink(chmod_file);

  return 0;
}

#endif /* MODE_FILE_METADATA_H */
