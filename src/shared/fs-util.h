/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "lock-util.h"

#define MODE_INVALID ((mode_t) -1)

int readlinkat_malloc(int fd, const char *p, char **ret);

int chmod_and_chown_at(int dir_fd, const char *path, mode_t mode, uid_t uid, gid_t gid);
int fchmod_and_chown_with_fallback(int fd, const char *path, mode_t mode, uid_t uid, gid_t gid);

int fchmod_opath(int fd, mode_t m);

int tmp_dir(const char **ret);
int var_tmp_dir(const char **ret);

static inline char* unlink_and_free(char *p) {
        if (!p)
                return NULL;

        (void) unlink(p);
        return mfree(p);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(char*, unlink_and_free);

int open_parent_at(int dir_fd, const char *path, int flags, mode_t mode);

typedef enum XOpenFlags {
        XO_LABEL     = 1 << 0,
} XOpenFlags;

int xopenat(int dir_fd, const char *path, int open_flags, XOpenFlags xopen_flags, mode_t mode);
int xopenat_lock(int dir_fd, const char *path, int open_flags, XOpenFlags xopen_flags, mode_t mode, LockType locktype, int operation);
