/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>

#include "macro.h"

int close_nointr(int fd);
int safe_close(int fd);

FILE* safe_fclose(FILE *f);
DIR* safe_closedir(DIR *f);

static inline void closep(int *fd) {
        safe_close(*fd);
}

static inline void fclosep(FILE **f) {
        safe_fclose(*f);
}

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(FILE*, pclose, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(DIR*, closedir, NULL);

#define _cleanup_close_ _cleanup_(closep)
#define _cleanup_fclose_ _cleanup_(fclosep)
#define _cleanup_pclose_ _cleanup_(pclosep)
#define _cleanup_closedir_ _cleanup_(closedirp)
#define _cleanup_close_pair_ _cleanup_(close_pairp)

int fd_get_path(int fd, char **ret);

/* Like TAKE_PTR() but for file descriptors, resetting them to -EBADF */
#define TAKE_FD(fd) TAKE_GENERIC(fd, int, -EBADF)

/* Like free_and_replace(), but for file descriptors */
#define close_and_replace(a, b)                 \
        ({                                      \
                int *_fdp_ = &(a);              \
                safe_close(*_fdp_);             \
                *_fdp_ = TAKE_FD(b);            \
                0;                              \
        })

int fd_reopen(int fd, int flags);
int fd_reopen_condition(int fd, int flags, int mask, int *ret_new_fd);
int fd_is_opath(int fd);

int path_is_root_at(int dir_fd, const char *path);

/* The maximum length a buffer for a /proc/self/fd/<fd> path needs */
#define PROC_FD_PATH_MAX \
        (STRLEN("/proc/self/fd/") + DECIMAL_STR_MAX(int))

static inline char *format_proc_fd_path(char buf[static PROC_FD_PATH_MAX], int fd) {
        assert(buf);
        assert(fd >= 0);
        snprintf(buf, PROC_FD_PATH_MAX, "/proc/self/fd/%i", fd);
        return buf;
}

#define FORMAT_PROC_FD_PATH(fd) \
        format_proc_fd_path((char[PROC_FD_PATH_MAX]) {}, (fd))
