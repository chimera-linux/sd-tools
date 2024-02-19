/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "label-util.h"
#include "macro.h"
#include "selinux-util.h"
#include "smack-util.h"

static const LabelOps *label_ops = NULL;

int label_ops_set(const LabelOps *ops) {
        if (label_ops)
                return -EBUSY;

        label_ops = ops;
        return 0;
}

int label_ops_pre(int dir_fd, const char *path, mode_t mode) {
        if (!label_ops || !label_ops->pre)
                return 0;

        return label_ops->pre(dir_fd, path, mode);
}

int label_ops_post(int dir_fd, const char *path) {
        if (!label_ops || !label_ops->post)
                return 0;

        return label_ops->post(dir_fd, path);
}

int label_fix(
                int atfd,
                const char *inode_path, /* path of inode to apply label to */
                const char *label_path  /* path to use as database lookup key in label database (typically same as inode_path, but not always) */
) {

        int r, q;

        if (atfd < 0 && atfd != AT_FDCWD)
                return -EBADF;

        if (!inode_path && atfd < 0) /* We need at least one of atfd and an inode path */
                return -EINVAL;

        /* If both atfd and inode_path are specified, we take the specified path relative to atfd which must be an fd to a dir.
         *
         * If only atfd is specified (and inode_path is NULL), we'll operated on the inode the atfd refers to.
         *
         * If atfd is AT_FDCWD then we'll operate on the inode the path refers to.
         */

        r = mac_selinux_fix(atfd, inode_path, label_path);
        q = mac_smack_fix(atfd, inode_path, label_path);
        if (r < 0)
                return r;
        if (q < 0)
                return q;

        return 0;
}

int mac_init(void) {
        int r;

        assert(!(mac_selinux_use() && mac_smack_use()));

        r = mac_selinux_init();
        if (r < 0)
                return r;

        return mac_smack_init();
}
