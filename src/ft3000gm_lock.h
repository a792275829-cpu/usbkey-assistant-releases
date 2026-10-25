#ifndef FT3000GM_LOCK_H
#define FT3000GM_LOCK_H
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Per-user lock shared by every one-shot helper. The OS releases it on exit. */
static int acquire_device_lock(void) {
    char path[128];
    snprintf(path, sizeof(path), "/tmp/gdpower-ft3000gm-%lu.lock", (unsigned long)getuid());
    int fd = open(path, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    struct stat info;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != getuid() ||
        (info.st_mode & 0777) != 0600 || info.st_nlink != 1) {
        close(fd); return -1;
    }
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        if (flock(fd, LOCK_EX | LOCK_NB) == 0) return fd;
        if (errno != EWOULDBLOCK && errno != EINTR) break;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec >= 12) break;
        const struct timespec pause = { .tv_sec = 0, .tv_nsec = 50000000 };
        nanosleep(&pause, NULL);
    }
    close(fd);
    return -1;
}
#endif
