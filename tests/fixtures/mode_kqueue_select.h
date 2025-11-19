#ifndef MODE_KQUEUE_SELECT_H
#define MODE_KQUEUE_SELECT_H

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/event.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

int mode_kqueue_select(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  /* Create pipes for testing I/O events */
  int pipe_fds[2];
  if (pipe(pipe_fds) < 0) {
    perror("pipe");
    return 1;
  }
  int read_fd = pipe_fds[0];
  int write_fd = pipe_fds[1];

  /* Make write fd have data available to read (for select/poll tests) */
  write(write_fd, "test", 4);

  /* ==========================================================================
   * Kqueue & Event Management
   * ==========================================================================
   */
  {
    int kq;
    struct kevent changelist[4], eventlist[4];
    struct timespec timeout;

    /* kqueue - create a new kernel event queue */
    kq = kqueue();
    if (kq < 0) {
      perror("kqueue");
      goto cleanup_pipes;
    }

    /* kevent - register events to monitor */
    /* Monitor read_fd for EVFILT_READ with EV_ADD|EV_ENABLE */
    EV_SET(&changelist[0], read_fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0,
           NULL);

    /* Monitor write_fd for EVFILT_WRITE with EV_ADD|EV_ONESHOT */
    EV_SET(&changelist[1], write_fd, EVFILT_WRITE, EV_ADD | EV_ONESHOT, 0, 0,
           NULL);

    /* Monitor write_fd for EVFILT_WRITE with EV_ADD|EV_CLEAR */
    EV_SET(&changelist[2], write_fd, EVFILT_WRITE,
           EV_ADD | EV_ENABLE | EV_CLEAR, 0, 0, NULL);

    /* Set up a timer event for 500ms with EV_ADD|EV_ENABLE */
    EV_SET(&changelist[3], 1, EVFILT_TIMER, EV_ADD | EV_ENABLE, NOTE_USECONDS,
           500000, NULL);

    /* kevent - register 4 events, don't wait for events (nevents=0)
     * Expected output:
     * kevent(3, [{ident=4, filter=EVFILT_READ, flags=EV_ADD|EV_ENABLE, ...},
     *            {ident=5, filter=EVFILT_WRITE, flags=EV_ADD|EV_ONESHOT, ...},
     *            {ident=5, filter=EVFILT_VNODE,
     * flags=EV_ADD|EV_ENABLE|EV_CLEAR, fflags=NOTE_WRITE|NOTE_DELETE, ...},
     *            {ident=1, filter=EVFILT_TIMER, flags=EV_ADD|EV_ENABLE,
     * fflags=NOTE_USECONDS, data=500000, ...}], 4, NULL, 0, {tv_sec=0,
     * tv_nsec=0}) = 0
     */
    timeout.tv_sec = 0;
    timeout.tv_nsec = 0;
    if (kevent(kq, changelist, 4, NULL, 0, &timeout) < 0) {
      perror("kevent register");
      close(kq);
      goto cleanup_pipes;
    }

    /* kevent - wait for events with timeout
     * Expected output:
     * kevent(3, NULL, 0, [{ident=5, filter=EVFILT_WRITE, flags=...,
     * revents=...}, ...], 4, {tv_sec=0, tv_nsec=100000000}) = 1 (or 2)
     */
    timeout.tv_sec = 0;
    timeout.tv_nsec = 100000000; /* 100ms */
    kevent(kq, NULL, 0, eventlist, 4, &timeout);

    /* kevent - delete an event with EV_DELETE */
    EV_SET(&changelist[0], 1, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
    kevent(kq, changelist, 1, NULL, 0, NULL);

    /* kevent - disable event with EV_DISABLE */
    EV_SET(&changelist[0], read_fd, EVFILT_READ, EV_DISABLE, 0, 0, NULL);
    kevent(kq, changelist, 1, NULL, 0, NULL);

    /* kevent64 - 64-bit version with extended fields */
#ifdef __DARWIN_UNIX03
    struct kevent64_s changelist64[2], eventlist64[2];

    /* kevent64 - register event with 64-bit identifiers */
    memset(&changelist64[0], 0, sizeof(changelist64[0]));
    changelist64[0].ident = read_fd;
    changelist64[0].filter = EVFILT_READ;
    changelist64[0].flags = EV_ADD | EV_ENABLE;
    changelist64[0].fflags = 0;
    changelist64[0].data = 0;
    changelist64[0].udata = 0;

    memset(&changelist64[1], 0, sizeof(changelist64[1]));
    changelist64[1].ident = write_fd;
    changelist64[1].filter = EVFILT_WRITE;
    changelist64[1].flags = EV_ADD | EV_ONESHOT;
    changelist64[1].fflags = 0;
    changelist64[1].data = 0;
    changelist64[1].udata = 0;

    timeout.tv_sec = 0;
    timeout.tv_nsec = 0;
    kevent64(kq, changelist64, 2, NULL, 0, 0, &timeout);

    /* kevent64 - wait for events */
    timeout.tv_sec = 0;
    timeout.tv_nsec = 50000000; /* 50ms */
    kevent64(kq, NULL, 0, eventlist64, 2, 0, &timeout);
#endif

    close(kq);
  }

  /* ==========================================================================
   * Select & Poll
   * ==========================================================================
   */
  {
    fd_set readfds, writefds, exceptfds;
    struct timeval tv_timeout;
    struct timespec ts_timeout;
    int maxfd = (read_fd > write_fd ? read_fd : write_fd) + 1;

    /* select - monitor read_fd for reading, write_fd for writing */
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_ZERO(&exceptfds);
    FD_SET(read_fd, &readfds);
    FD_SET(write_fd, &writefds);

    tv_timeout.tv_sec = 0;
    tv_timeout.tv_usec = 100000; /* 100ms */
    select(maxfd, &readfds, &writefds, &exceptfds, &tv_timeout);

    /* select - with NULL timeout (non-blocking poll) */
    FD_ZERO(&readfds);
    FD_SET(read_fd, &readfds);
    select(maxfd, &readfds, NULL, NULL, NULL);

    /* select - monitor multiple fds for reading */
    FD_ZERO(&readfds);
    FD_SET(read_fd, &readfds);
    FD_SET(write_fd, &readfds);
    tv_timeout.tv_sec = 0;
    tv_timeout.tv_usec = 50000; /* 50ms */
    select(maxfd, &readfds, NULL, NULL, &tv_timeout);

    /* pselect - like select but with nanosecond precision and sigmask */
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_SET(read_fd, &readfds);
    FD_SET(write_fd, &writefds);

    ts_timeout.tv_sec = 0;
    ts_timeout.tv_nsec = 100000000; /* 100ms */
    pselect(maxfd, &readfds, &writefds, NULL, &ts_timeout, NULL);

    /* pselect - with empty signal mask */
    sigset_t empty_mask;
    sigemptyset(&empty_mask);
    FD_ZERO(&readfds);
    FD_SET(read_fd, &readfds);
    ts_timeout.tv_sec = 0;
    ts_timeout.tv_nsec = 50000000; /* 50ms */
    pselect(maxfd, &readfds, NULL, NULL, &ts_timeout, &empty_mask);

    /* pselect - with NULL timeout (block indefinitely - but we know fd is
     * ready) */
    FD_ZERO(&readfds);
    FD_SET(read_fd, &readfds);
    pselect(maxfd, &readfds, NULL, NULL, NULL, NULL);
  }

  /* ==========================================================================
   * Poll
   * ==========================================================================
   */
  {
    struct pollfd fds[3];

    /* poll - monitor read_fd for POLLIN */
    fds[0].fd = read_fd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    poll(fds, 1, 100); /* 100ms timeout */

    /* poll - monitor multiple fds with different events */
    fds[0].fd = read_fd;
    fds[0].events = POLLIN | POLLPRI;
    fds[0].revents = 0;

    fds[1].fd = write_fd;
    fds[1].events = POLLOUT;
    fds[1].revents = 0;

    poll(fds, 2, 50); /* 50ms timeout */

    /* poll - with -1 timeout (infinite) but fd is ready */
    fds[0].fd = read_fd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    poll(fds, 1, -1);

    /* poll - with 0 timeout (non-blocking) */
    fds[0].fd = read_fd;
    fds[0].events = POLLIN | POLLOUT;
    fds[0].revents = 0;

    fds[1].fd = write_fd;
    fds[1].events = POLLOUT;
    fds[1].revents = 0;

    poll(fds, 2, 0);

    /* poll - monitor for error conditions */
    fds[0].fd = read_fd;
    fds[0].events = POLLERR | POLLHUP;
    fds[0].revents = 0;
    poll(fds, 1, 0);
  }

cleanup_pipes:
  close(read_fd);
  close(write_fd);

  return 0;
}

#endif /* MODE_KQUEUE_SELECT_H */
