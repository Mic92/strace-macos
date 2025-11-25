/*
 * Simple test executable for strace-macos tests.
 * This avoids issues with debugging system binaries on macOS.
 */

#include "mode_fd_ops.h"
#include "mode_file_metadata.h"
#include "mode_file_ops.h"
#include "mode_file_utilities.h"
#include "mode_fork_exec.h"
#include "mode_ipc_aio.h"
#include "mode_kqueue_select.h"
#include "mode_memory.h"
#include "mode_misc.h"
#include "mode_network.h"
#include "mode_process_identity.h"
#include "mode_process_advanced.h"
#include "mode_signal.h"
#include "modes.h"
#include <string.h>

int main(int argc, char *argv[]) {
  /* If no arguments, use default mode */
  if (argc < 2) {
    return mode_default(argc, argv);
  }

  /* Find matching mode */
  for (const test_mode_t *mode = modes; mode->name != NULL; mode++) {
    if (strcmp(argv[1], mode->name) == 0) {
      return mode->handler(argc, argv);
    }
  }

  /* No match found, use default */
  return mode_default(argc, argv);
}
