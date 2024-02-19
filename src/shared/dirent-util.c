/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>

#include "dirent-util.h"

static int dirent_ensure_type(int dir_fd, struct dirent *de) {
        struct stat st;

        assert(dir_fd >= 0);
        assert(de);

        if (de->d_type != DT_UNKNOWN)
                return 0;

        if (dot_or_dot_dot(de->d_name)) {
                de->d_type = DT_DIR;
                return 0;
        }

        if (fstatat(dir_fd, de->d_name, &st, AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT) < 0) {
                return -errno;
        }

        de->d_type = IFTODT(st.st_mode);
        de->d_ino = st.st_ino;

        return 0;
}

struct dirent *readdir_ensure_type(DIR *d) {
        int r;

        assert(d);

        /* Like readdir(), but fills in .d_type if it is DT_UNKNOWN */

        for (;;) {
                struct dirent *de;

                errno = 0;
                de = readdir(d);
                if (!de)
                        return NULL;

                r = dirent_ensure_type(dirfd(d), de);
                if (r >= 0)
                        return de;
                if (r != -ENOENT) {
                        errno = -r; /* We want to be compatible with readdir(), hence propagate error via errno here */
                        return NULL;
                }

                /* Vanished by now? Then skip immediately to next */
        }
}
