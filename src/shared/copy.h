/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

typedef enum CopyFlags {
        COPY_REFLINK       = 1 << 0,  /* Try to reflink */
        COPY_MERGE         = 1 << 1,  /* Merge existing trees with our new one to copy */
        COPY_MERGE_EMPTY   = 1 << 4,  /* Merge an existing, empty directory with our new tree to copy */
        COPY_MAC_CREATE    = 1 << 8,  /* Create files with the correct MAC label (currently SELinux only) */
        COPY_HARDLINKS     = 1 << 9,  /* Try to reproduce hard links */
} CopyFlags;

int copy_tree_at(int fdf, const char *from, int fdt, const char *to, uid_t override_uid, gid_t override_gid, CopyFlags copy_flags);
int copy_bytes(int fdf, int fdt, uint64_t max_bytes, CopyFlags copy_flags);
int copy_rights_with_fallback(int fdf, int fdt, const char *patht);
