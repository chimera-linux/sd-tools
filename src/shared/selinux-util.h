/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <fcntl.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "label-util.h"

bool mac_selinux_use(void);

int mac_selinux_init(void);

int mac_selinux_fix(int atfd, const char *inode_path, const char *label_path);

int mac_selinux_create_file_prepare_at(int dirfd, const char *path, mode_t mode);

static inline int mac_selinux_create_file_prepare(const char *path, mode_t mode) {
        return mac_selinux_create_file_prepare_at(AT_FDCWD, path, mode);
}

void mac_selinux_create_file_clear(void);
