/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <linux/magic.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "chase.h"
#include "dirent-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hash-funcs.h"
#include "macro.h"
#include "stat-util.h"
#include "string-util.h"

int is_fs_type_at(int dir_fd, const char *path, statfs_f_type_t magic_value) {
        _cleanup_close_ int fd = -EBADF;
        struct statfs s;
        int r;

        fd = xopenat(dir_fd, path, O_PATH|O_CLOEXEC|O_NOCTTY, /* xopen_flags = */ 0, /* mode = */ 0);
        if (fd < 0)
                return fd;

        r = RET_NERRNO(fstatfs(fd, &s));
        if (r < 0)
                return r;

        return s.f_type == magic_value;
}

int proc_mounted(void) {
        int r;

        /* A quick check of procfs is properly mounted */

        r = is_fs_type_at(AT_FDCWD, "/proc/", PROC_SUPER_MAGIC);
        if (r == -ENOENT) /* not mounted at all */
                return false;

        return r;
}

bool stat_inode_same(const struct stat *a, const struct stat *b) {

        /* Returns if the specified stat structure references the same (though possibly modified) inode. Does
         * a thorough check, comparing inode nr, backing device and if the inode is still of the same type. */

        return a && b &&
                (a->st_mode & S_IFMT) != 0 && /* We use the check for .st_mode if the structure was ever initialized */
                ((a->st_mode ^ b->st_mode) & S_IFMT) == 0 &&  /* same inode type */
                a->st_dev == b->st_dev &&
                a->st_ino == b->st_ino;
}
