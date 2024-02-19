/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Intel Corporation

  Author: Auke Kok <auke-jan.h.kok@intel.com>
***/

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "smack-util.h"

bool mac_smack_use(void) {
        return false;
}

int mac_smack_fix(int atfd, const char *inode_path, const char *label_path) {
        return 0;
}

int rename_and_apply_smack_floor_label(const char *from, const char *to) {

        if (rename(from, to) < 0)
                return -errno;

        return 0;
}

static int mac_smack_label_pre(int dir_fd, const char *path, mode_t mode) {
        return 0;
}

static int mac_smack_label_post(int dir_fd, const char *path) {
        return mac_smack_fix(dir_fd, path, NULL);
}

int mac_smack_init(void) {
        static const LabelOps label_ops = {
                .pre = mac_smack_label_pre,
                .post = mac_smack_label_post,
        };

        if (!mac_smack_use())
                return 0;

        return label_ops_set(&label_ops);
}
