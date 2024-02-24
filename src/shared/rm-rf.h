/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <fcntl.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "errno-util.h"

typedef enum RemoveFlags {
        REMOVE_ROOT             = 1 << 1, /* Remove the specified directory itself too, not just the contents of it */
        REMOVE_SUBVOLUME        = 1 << 2, /* Drop btrfs subvolumes in the tree too */
        REMOVE_CHMOD            = 1 << 3, /* chmod() for write access if we cannot delete or access something */
        REMOVE_CHMOD_RESTORE    = 1 << 4, /* Restore the old mode before returning */
} RemoveFlags;

int unlinkat_harder(int dfd, const char *filename, int unlink_flags, RemoveFlags remove_flags);
int fstatat_harder(int dfd,
                const char *filename,
                struct stat *ret,
                int fstatat_flags,
                RemoveFlags remove_flags);

/* Note: directory file descriptors passed to the functions below must be
 * positioned at the beginning. If the fd was already used for reading, rewind it. */
int rm_rf_children(int fd, RemoveFlags flags, const struct stat *root_dev);
int rm_rf_child(int fd, char *name);
int rm_rf(const char *path, RemoveFlags flags);
