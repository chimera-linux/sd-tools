/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>

int btrfs_subvol_make(int dir_fd, const char *path);
int btrfs_is_subvol_at(int dir_fd, const char *path);
int btrfs_subvol_remove_at(int dir_fd, const char *path);
int btrfs_subvol_auto_qgroup_fd(int fd, uint64_t subvol_id, bool new_qgroup);

static inline bool btrfs_might_be_subvol(const struct stat *st) {
        if (!st)
                return false;

        /* Returns true if this 'struct stat' looks like it could refer to a btrfs subvolume. To make a final
         * decision, needs to be combined with an fstatfs() check to see if this is actually btrfs. */

        return S_ISDIR(st->st_mode) && st->st_ino == 256;
}
