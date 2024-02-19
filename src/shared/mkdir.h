/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <fcntl.h>
#include <sys/types.h>

int mkdirat_parents(int dir_fd, char *path, mode_t mode);
static inline int mkdir_parents(char *path, mode_t mode) {
        return mkdirat_parents(AT_FDCWD, path, mode);
}

int mkdirat_label(int dirfd, const char *path, mode_t mode);
int mkdirat_parents_label(int dir_fd, char *path, mode_t mod);
