/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/types.h>

#include "selinux-util.h"

bool mac_selinux_use(void) {
        return false;
}

int mac_selinux_init(void) {
        return 0;
}

int mac_selinux_fix(int atfd, const char *inode_path, const char *label_path) {
        return 0;
}

int mac_selinux_create_file_prepare_at(int dir_fd, const char *path, mode_t mode) {
        return 0;
}

void mac_selinux_create_file_clear(void) {
}
