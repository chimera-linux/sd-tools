/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <fcntl.h>
#include <stdbool.h>
#include <sys/types.h>

typedef struct LabelOps {
        int (*pre)(int dir_fd, const char *path, mode_t mode);
        int (*post)(int dir_fd, const char *path);
} LabelOps;

int label_ops_set(const LabelOps *label_ops);

int label_ops_pre(int dir_fd, const char *path, mode_t mode);
int label_ops_post(int dir_fd, const char *path);

int label_fix(int atfd, const char *inode_path, const char *label_path);

int mac_init(void);
