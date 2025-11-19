/*
 * System V IPC and AIO operations mode
 * Tests: Message queues (msgget, msgctl, msgsnd, msgrcv)
 *        Semaphores (semget, semctl, semop)
 *        Shared memory (shmget, shmat, shmctl, shmdt)
 *        AIO (aio_cancel, aio_error, aio_return, aio_suspend, lio_listio)
 */

#ifndef MODE_IPC_AIO_H
#define MODE_IPC_AIO_H

#include <aio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <unistd.h>

/* shmat() returns this value on failure */
/* NOLINTBEGIN(performance-no-int-to-ptr) */
#define SHMAT_FAILED ((void *)-1)
/* NOLINTEND(performance-no-int-to-ptr) */

int mode_ipc_aio(int argc, char *argv[]) {
  (void)argc; /* Unused parameter */
  (void)argv; /* Unused parameter */
  int result = 0;

  /* System V Message Queues */
  {
    key_t key = IPC_PRIVATE;
    int msgid;
    struct msqid_ds buf;

    /* msgget - create message queue with specific permissions */
    msgid = msgget(key, IPC_CREAT | IPC_EXCL | 0600);
    if (msgid >= 0) {
      /* msgctl - IPC_STAT (reads current queue status) */
      memset(&buf, 0, sizeof(buf));
      msgctl(msgid, IPC_STAT, &buf);
      /* After IPC_STAT, buf.msg_qnum should be 0 (no messages),
       * buf.msg_qbytes should be system default */

      /* msgctl - IPC_SET (modify queue bytes limit) */
      buf.msg_qbytes = 8192; /* Set to 8KB */
      msgctl(msgid, IPC_SET, &buf);

      /* msgctl - IPC_STAT again to verify the change */
      memset(&buf, 0, sizeof(buf));
      msgctl(msgid, IPC_STAT, &buf);
      /* Now buf.msg_qbytes should be 8192 */

      /* msgsnd/msgrcv would normally be used here, but they require
       * struct msgbuf and may block. We'll skip actual send/recv
       * to keep the test simple and non-blocking. */

      /* msgctl - IPC_RMID (remove queue) */
      msgctl(msgid, IPC_RMID, NULL);
    }
  }

  /* System V Semaphores */
  {
    key_t key = IPC_PRIVATE;
    int semid;
    struct semid_ds buf;
    union semun {
      int val;
      struct semid_ds *buf;
      unsigned short *array;
    } arg;

    /* semget - create semaphore set with 3 semaphores */
    semid = semget(key, 3, IPC_CREAT | IPC_EXCL | 0600);
    if (semid >= 0) {
      /* semctl - IPC_STAT (reads current semaphore set status) */
      memset(&buf, 0, sizeof(buf));
      arg.buf = &buf;
      semctl(semid, 0, IPC_STAT, arg);
      /* After IPC_STAT, buf.sem_nsems should be 3 */

      /* semctl - SETVAL (set semaphore 0 to value 5) */
      arg.val = 5;
      semctl(semid, 0, SETVAL, arg);

      /* semctl - GETVAL (read back the value) */
      int val = semctl(semid, 0, GETVAL, arg);
      (void)val; /* Suppress unused warning - val should be 5 */

      /* semctl - GETPID (get PID of last operation) */
      semctl(semid, 0, GETPID, arg);

      /* semctl - GETNCNT (get number of processes waiting for value to
       * increase) */
      semctl(semid, 0, GETNCNT, arg);

      /* semctl - GETZCNT (get number of processes waiting for value to be zero)
       */
      semctl(semid, 0, GETZCNT, arg);

      /* semop - increment semaphore with SEM_UNDO flag */
      struct sembuf sop;
      sop.sem_num = 0;
      sop.sem_op = 1; /* increment by 1 */
      sop.sem_flg = IPC_NOWAIT | SEM_UNDO;
      semop(semid, &sop, 1);

      /* semop - decrement semaphore */
      sop.sem_op = -1; /* decrement by 1 */
      sop.sem_flg = IPC_NOWAIT;
      semop(semid, &sop, 1);

      /* semctl - SETALL (set all 3 semaphore values at once) */
      unsigned short vals[3] = {10, 20, 30};
      arg.array = vals;
      semctl(semid, 0, SETALL, arg);

      /* semctl - GETALL (read all values back) */
      unsigned short getvals[3];
      arg.array = getvals;
      semctl(semid, 0, GETALL, arg);
      /* getvals should now be {10, 20, 30} */

      /* semctl - IPC_RMID (remove semaphore set) */
      semctl(semid, 0, IPC_RMID, arg);
    }
  }

  /* System V Shared Memory */
  {
    key_t key = IPC_PRIVATE;
    int shmid;
    void *shmaddr;
    struct shmid_ds buf;

    /* shmget - create shared memory segment (16KB) */
    shmid = shmget(key, 16384, IPC_CREAT | IPC_EXCL | 0600);
    if (shmid >= 0) {
      /* shmctl - IPC_STAT (get initial status) */
      memset(&buf, 0, sizeof(buf));
      shmctl(shmid, IPC_STAT, &buf);
      /* buf.shm_segsz should be 16384, shm_nattch should be 0 */

      /* shmat - attach with default address (read/write) */
      shmaddr = shmat(shmid, NULL, 0);
      if (shmaddr != SHMAT_FAILED) {
        /* Write some test data */
        memcpy(shmaddr, "test_data_123", 13);

        /* shmctl - IPC_STAT (should show 1 attachment) */
        memset(&buf, 0, sizeof(buf));
        shmctl(shmid, IPC_STAT, &buf);
        /* buf.shm_nattch should be 1 now */

        /* shmdt - detach */
        shmdt(shmaddr);
      }

      /* shmat - attach read-only */
      shmaddr = shmat(shmid, NULL, SHM_RDONLY);
      if (shmaddr != SHMAT_FAILED) {
        /* Can read but not write */
        shmdt(shmaddr);
      }

      /* shmat - attach with SHM_RND (round address) */
      shmaddr = shmat(shmid, NULL, SHM_RND);
      if (shmaddr != SHMAT_FAILED) {
        shmdt(shmaddr);
      }

      /* shmctl - IPC_STAT final check */
      memset(&buf, 0, sizeof(buf));
      shmctl(shmid, IPC_STAT, &buf);
      /* buf.shm_nattch should be 0 again, shm_segsz still 16384 */

      /* shmctl - IPC_RMID (remove segment) */
      shmctl(shmid, IPC_RMID, NULL);
    }
  }

  /* AIO (Asynchronous I/O) */
  {
    /* Create a temporary file for AIO testing */
    char tmpfile[] = "/tmp/strace_aio_test_XXXXXX";
    int fd = mkstemp(tmpfile);
    if (fd >= 0) {
      char buf1[512];
      char buf2[256];
      char buf3[128];
      memset(buf1, 'A', sizeof(buf1));
      memset(buf2, 'B', sizeof(buf2));
      memset(buf3, 'C', sizeof(buf3));

      /* Write some initial data */
      write(fd, buf1, sizeof(buf1));

      /* Prepare aiocb structures with different parameters */
      struct aiocb cb1, cb2, cb3;

      /* cb1: read 512 bytes from offset 0 */
      memset(&cb1, 0, sizeof(cb1));
      cb1.aio_fildes = fd;
      cb1.aio_offset = 0;
      cb1.aio_buf = buf1;
      cb1.aio_nbytes = 512;
      cb1.aio_reqprio = 0;
      cb1.aio_sigevent.sigev_notify = SIGEV_NONE;
      cb1.aio_lio_opcode = LIO_READ;

      /* cb2: write 256 bytes at offset 1024 */
      memset(&cb2, 0, sizeof(cb2));
      cb2.aio_fildes = fd;
      cb2.aio_offset = 1024;
      cb2.aio_buf = buf2;
      cb2.aio_nbytes = 256;
      cb2.aio_reqprio = 0;
      cb2.aio_sigevent.sigev_notify = SIGEV_NONE; /* Don't send real signals */
      cb2.aio_sigevent.sigev_signo = 0;
      cb2.aio_lio_opcode = LIO_WRITE;

      /* cb3: no operation */
      memset(&cb3, 0, sizeof(cb3));
      cb3.aio_fildes = fd;
      cb3.aio_offset = 2048;
      cb3.aio_buf = buf3;
      cb3.aio_nbytes = 128;
      cb3.aio_reqprio = 0;
      cb3.aio_sigevent.sigev_notify = SIGEV_NONE;
      cb3.aio_lio_opcode = LIO_NOP;

      /* aio_cancel - try to cancel cb1 (nothing to cancel yet) */
      aio_cancel(fd, &cb1);

      /* aio_error - check error status of cb1 */
      aio_error(&cb1);

      /* aio_return - get return status of cb1 (not started, so undefined) */
      /* Commented out because calling aio_return on non-started operation
       * may cause issues */
      /* aio_return(&cb1); */

      /* aio_suspend - suspend with array of 3 aiocbs */
      const struct aiocb *cblist[3] = {&cb1, &cb2, &cb3};
      struct timespec timeout = {0, 1000000}; /* 1ms */
      aio_suspend(cblist, 3, &timeout);

      /* lio_listio - LIO_WAIT mode with 2 operations (READ and WRITE) */
      struct aiocb *list_wait[2] = {&cb1, &cb2};
      lio_listio(LIO_WAIT, list_wait, 2, NULL);

      /* lio_listio - LIO_NOWAIT mode with 3 operations including NOP */
      struct aiocb *list_nowait[3] = {&cb1, &cb2, &cb3};
      struct sigevent sig_event;
      memset(&sig_event, 0, sizeof(sig_event));
      sig_event.sigev_notify = SIGEV_NONE; /* Don't send real signals */
      sig_event.sigev_signo = 0;
      lio_listio(LIO_NOWAIT, list_nowait, 3, &sig_event);

      /* Clean up */
      close(fd);
      unlink(tmpfile);
    }
  }

  return result;
}

#endif /* MODE_IPC_AIO_H */
