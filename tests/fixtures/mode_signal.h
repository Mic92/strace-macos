#ifndef MODE_SIGNAL_H
#define MODE_SIGNAL_H

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Signal handler for testing */
static void test_signal_handler(int signo) {
  /* Do nothing - just for testing signal handling */
  (void)signo;
}

/* Signal handler with siginfo for testing */
static void test_sigaction_handler(int signo, siginfo_t *info, void *context) {
  /* Do nothing - just for testing sigaction */
  (void)signo;
  (void)info;
  (void)context;
}

int mode_signal(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  /* ==========================================================================
   * Signal Action Setup - sigaction()
   * ==========================================================================
   * Set up handlers FIRST before sending any signals
   */
  {
    struct sigaction new_action, old_action;

    /* sigaction - set up SIGUSR1 handler with SA_RESTART */
    memset(&new_action, 0, sizeof(new_action));
    new_action.sa_handler = test_signal_handler;
    sigemptyset(&new_action.sa_mask);
    new_action.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &new_action, &old_action);

    /* sigaction - set up SIGUSR2 handler with SA_SIGINFO and SA_NODEFER */
    memset(&new_action, 0, sizeof(new_action));
    new_action.sa_sigaction = test_sigaction_handler;
    sigemptyset(&new_action.sa_mask);
    sigaddset(&new_action.sa_mask, SIGINT);  /* Block SIGINT during handler */
    new_action.sa_flags = SA_SIGINFO | SA_NODEFER | SA_RESETHAND;
    sigaction(SIGUSR2, &new_action, &old_action);

    /* sigaction - set to SIG_IGN */
    memset(&new_action, 0, sizeof(new_action));
    new_action.sa_handler = SIG_IGN;
    sigemptyset(&new_action.sa_mask);
    new_action.sa_flags = 0;
    sigaction(SIGPIPE, &new_action, NULL);

    /* sigaction - set to SIG_DFL */
    memset(&new_action, 0, sizeof(new_action));
    new_action.sa_handler = SIG_DFL;
    sigemptyset(&new_action.sa_mask);
    new_action.sa_flags = 0;
    sigaction(SIGPIPE, &new_action, NULL);

    /* sigaction - query current handler without changing */
    sigaction(SIGINT, NULL, &old_action);
  }

  /* ==========================================================================
   * Basic Signal Sending - kill()
   * ==========================================================================
   */
  {
    pid_t pid = getpid();

    /* kill - send SIGCONT to self (harmless) */
    kill(pid, SIGCONT);

    /* kill - send null signal (check if process exists) */
    kill(pid, 0);

    /* kill - send SIGUSR1 to self (will be caught by handler we just set up) */
    kill(pid, SIGUSR1);
  }

  /* ==========================================================================
   * Signal Masking - sigprocmask()
   * ==========================================================================
   */
  {
    sigset_t new_mask, old_mask, pending_mask;

    /* sigprocmask - SIG_BLOCK: add signals to blocked set */
    sigemptyset(&new_mask);
    sigaddset(&new_mask, SIGUSR1);
    sigaddset(&new_mask, SIGUSR2);
    sigprocmask(SIG_BLOCK, &new_mask, &old_mask);

    /* sigprocmask - SIG_SETMASK: replace entire signal mask */
    sigemptyset(&new_mask);
    sigaddset(&new_mask, SIGTERM);
    sigaddset(&new_mask, SIGINT);
    sigprocmask(SIG_SETMASK, &new_mask, &old_mask);

    /* sigprocmask - SIG_UNBLOCK: remove signals from blocked set */
    sigemptyset(&new_mask);
    sigaddset(&new_mask, SIGTERM);
    sigprocmask(SIG_UNBLOCK, &new_mask, &old_mask);

    /* sigprocmask - query current mask without changing (NULL new_mask) */
    sigprocmask(SIG_BLOCK, NULL, &old_mask);

    /* sigpending - get set of pending signals */
    sigpending(&pending_mask);
  }

  /* ==========================================================================
   * Alternate Signal Stack - sigaltstack()
   * ==========================================================================
   */
  {
    stack_t new_stack, old_stack;
    char stack_buffer[SIGSTKSZ];

    /* sigaltstack - set up alternate signal stack */
    memset(&new_stack, 0, sizeof(new_stack));
    new_stack.ss_sp = stack_buffer;
    new_stack.ss_size = SIGSTKSZ;
    new_stack.ss_flags = 0;
    sigaltstack(&new_stack, &old_stack);

    /* sigaltstack - query current stack without changing */
    sigaltstack(NULL, &old_stack);

    /* sigaltstack - disable alternate stack with SS_DISABLE */
    memset(&new_stack, 0, sizeof(new_stack));
    new_stack.ss_flags = SS_DISABLE;
    sigaltstack(&new_stack, NULL);
  }

  /* ==========================================================================
   * Thread Signal Operations - pthread_kill(), pthread_sigmask()
   * ==========================================================================
   */
  {
    pthread_t self_thread = pthread_self();
    sigset_t new_mask, old_mask;

    /* pthread_kill - send SIGCONT to self thread */
    pthread_kill(self_thread, SIGCONT);

    /* pthread_kill - send null signal to check thread validity */
    pthread_kill(self_thread, 0);

    /* pthread_kill - send SIGUSR1 to self thread */
    pthread_kill(self_thread, SIGUSR1);

    /* pthread_sigmask - SIG_BLOCK: block signals in this thread */
    sigemptyset(&new_mask);
    sigaddset(&new_mask, SIGUSR1);
    sigaddset(&new_mask, SIGUSR2);
    pthread_sigmask(SIG_BLOCK, &new_mask, &old_mask);

    /* pthread_sigmask - SIG_SETMASK: set thread signal mask */
    sigemptyset(&new_mask);
    sigaddset(&new_mask, SIGPIPE);
    pthread_sigmask(SIG_SETMASK, &new_mask, &old_mask);

    /* pthread_sigmask - SIG_UNBLOCK: unblock signals */
    sigemptyset(&new_mask);
    sigaddset(&new_mask, SIGPIPE);
    pthread_sigmask(SIG_UNBLOCK, &new_mask, &old_mask);

    /* pthread_sigmask - query without changing */
    pthread_sigmask(SIG_BLOCK, NULL, &old_mask);
  }

  /* Note: sigwait() and sigsuspend() are blocking syscalls that require
   * complex synchronization to test properly (e.g., using threads or alarm()).
   * We skip them here to keep the test simple and non-blocking.
   * The other 7 signal syscalls provide good coverage of signal handling. */

  return 0;
}

#endif /* MODE_SIGNAL_H */
