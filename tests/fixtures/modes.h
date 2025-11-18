/*
 * Mode definitions for test executable
 */

#ifndef MODES_H
#define MODES_H

/* Mode handler function type */
typedef int (*mode_handler_t)(int argc, char *argv[]);

/* Mode definition structure */
typedef struct {
  const char *name;
  mode_handler_t handler;
  const char *description;
} test_mode_t;

/* Mode handlers - defined in separate files */
int mode_file_ops(int argc, char *argv[]);
int mode_file_ops_loop(int argc, char *argv[]);
int mode_fd_ops(int argc, char *argv[]);
int mode_network(int argc, char *argv[]);
int mode_network_loop(int argc, char *argv[]);
int mode_long_running(int argc, char *argv[]);
int mode_fail(int argc, char *argv[]);
int mode_default(int argc, char *argv[]);

/* Global mode registry */
static const test_mode_t modes[] = {
    {"--file-ops", mode_file_ops, "Perform basic file operations"},
    {"--file-ops-loop", mode_file_ops_loop,
     "Loop file operations for attach testing"},
    {"--fd-ops", mode_fd_ops, "Perform fd operations (readv/writev/dup/fcntl/ioctl)"},
    {"--network", mode_network, "Perform basic network operations"},
    {"--network-loop", mode_network_loop,
     "Loop network operations for attach testing"},
    {"--long-running", mode_long_running,
     "Long-running process for attach testing"},
    {"--fail", mode_fail, "Exit with non-zero status"},
    {NULL, mode_default, "Default mode: print args"},
};

#endif /* MODES_H */
