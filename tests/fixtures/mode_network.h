/*
 * Network operations modes
 * Comprehensive testing of socket syscalls using Unix domain sockets
 */

#ifndef MODE_NETWORK_H
#define MODE_NETWORK_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

extern volatile int keep_running;
extern void sigterm_handler(int sig);

/* Shared state for client/server synchronization */
typedef struct {
  pthread_mutex_t mutex;
  pthread_cond_t cond;
  int server_ready;
  struct sockaddr_un addr;
} client_server_sync_t;

/* Thread function for client connection */
static void *client_thread(void *arg) {
  client_server_sync_t *sync = (client_server_sync_t *)arg;

  /* Wait for server to be ready */
  pthread_mutex_lock(&sync->mutex);
  while (!sync->server_ready) {
    pthread_cond_wait(&sync->cond, &sync->mutex);
  }
  pthread_mutex_unlock(&sync->mutex);

  int client_sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (client_sock >= 0) {
    /* connect - connect to server */
    connect(client_sock, (struct sockaddr *)&sync->addr, sizeof(sync->addr));
    close(client_sock);
  }

  return NULL;
}

int mode_network(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  int sv[2];
  char buf[128];
  struct sockaddr_storage peer_addr;
  socklen_t addr_len;
  int opt = 1;
  struct msghdr msg;
  struct iovec iov;

  /* 1. socketpair - create connected Unix socket pair */
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
    /* 2. getsockname - get socket address */
    addr_len = sizeof(peer_addr);
    getsockname(sv[0], (struct sockaddr *)&peer_addr, &addr_len);

    /* 3. getpeername - get peer address */
    addr_len = sizeof(peer_addr);
    getpeername(sv[0], (struct sockaddr *)&peer_addr, &addr_len);

    /* 4. getsockopt - get socket options */
    addr_len = sizeof(opt);
    getsockopt(sv[0], SOL_SOCKET, SO_TYPE, &opt, &addr_len);

    /* 5. setsockopt - set socket options */
    opt = 1;
    setsockopt(sv[0], SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));

    /* 6. sendto - send data (works even on connected socket) */
    sendto(sv[0], "test", 4, 0, NULL, 0);

    /* 7. recvfrom - receive data */
    addr_len = sizeof(peer_addr);
    recvfrom(sv[1], buf, sizeof(buf), 0, (struct sockaddr *)&peer_addr,
             &addr_len);

    /* 8. sendmsg - send message with control data */
    memset(&msg, 0, sizeof(msg));
    iov.iov_base = (void *)"msg";
    iov.iov_len = 3;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    sendmsg(sv[0], &msg, 0);

    /* 9. recvmsg - receive message with control data */
    memset(&msg, 0, sizeof(msg));
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    recvmsg(sv[1], &msg, 0);

    /* 10. shutdown - shutdown one direction */
    shutdown(sv[0], SHUT_WR);

    close(sv[0]);
    close(sv[1]);
  }

  /* Test bind/listen/accept with Unix domain socket using threads */
  int listen_sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (listen_sock >= 0) {
    client_server_sync_t sync;
    pthread_mutex_init(&sync.mutex, NULL);
    pthread_cond_init(&sync.cond, NULL);
    sync.server_ready = 0;

    memset(&sync.addr, 0, sizeof(sync.addr));
    sync.addr.sun_family = AF_UNIX;
    snprintf(sync.addr.sun_path, sizeof(sync.addr.sun_path),
             "/tmp/strace_test.%d", getpid());

    /* 11. bind - bind socket to address */
    if (bind(listen_sock, (struct sockaddr *)&sync.addr, sizeof(sync.addr)) ==
        0) {
      /* 12. listen - mark socket as passive */
      if (listen(listen_sock, 1) == 0) {
        /* Start client thread */
        pthread_t thread;
        pthread_create(&thread, NULL, client_thread, &sync);

        /* Signal that server is ready */
        pthread_mutex_lock(&sync.mutex);
        sync.server_ready = 1;
        pthread_cond_signal(&sync.cond);
        pthread_mutex_unlock(&sync.mutex);

        /* Server: accept connection */
        addr_len = sizeof(peer_addr);
        /* 14. accept - accept connection */
        int conn =
            accept(listen_sock, (struct sockaddr *)&peer_addr, &addr_len);
        if (conn >= 0) {
          close(conn);
        }

        /* Wait for client thread */
        pthread_join(thread, NULL);
      }
      unlink(sync.addr.sun_path);
    }

    pthread_mutex_destroy(&sync.mutex);
    pthread_cond_destroy(&sync.cond);
    close(listen_sock);
  }

  /* Test with INET socket for additional coverage */
  int inet_sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (inet_sock >= 0) {
    struct sockaddr_in inet_addr;
    memset(&inet_addr, 0, sizeof(inet_addr));
    inet_addr.sin_family = AF_INET;
    inet_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    inet_addr.sin_port = 0; /* Let kernel choose port */

    /* Additional bind test with INET */
    bind(inet_sock, (struct sockaddr *)&inet_addr, sizeof(inet_addr));

    /* Test disconnectx if we want (macOS specific) - will likely fail but
     * exercises the syscall */
    /* Note: disconnectx requires specific setup, skipping for now */

    close(inet_sock);
  }

  return 0;
}

int mode_network_loop(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  /* Setup signal handler */
  signal(SIGTERM, sigterm_handler);

  /* Write ready marker */
  write(STDOUT_FILENO, "READY\n", 6);

  while (keep_running) {
    int sv[2];
    char buf[32];

    /* Repeatedly exercise socket operations */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
      sendto(sv[0], "x", 1, 0, NULL, 0);
      recvfrom(sv[1], buf, sizeof(buf), 0, NULL, NULL);
      shutdown(sv[0], SHUT_RDWR);
      close(sv[0]);
      close(sv[1]);
    }

    /* Small sleep */
    usleep(100000); /* 0.1 seconds */
  }

  return 0;
}

#endif /* MODE_NETWORK_H */
