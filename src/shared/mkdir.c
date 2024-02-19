/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include "alloc-util.h"
#include "btrfs-util.h"
#include "chase.h"
#include "fd-util.h"
#include "fs-util.h"
#include "macro.h"
#include "mkdir.h"
#include "path-util.h"
#include "selinux-util.h"
#include "smack-util.h"
#include "stat-util.h"
#include "user-util.h"

/* The following are used to implement the mkdir_xyz_label() calls, don't use otherwise. */
typedef int (*mkdirat_func_t)(int dir_fd, const char *pathname, mode_t mode);

static int mkdirat_safe_internal(
                int dir_fd,
                const char *path,
                mode_t mode,
                uid_t uid,
                gid_t gid,
                mkdirat_func_t _mkdirat) {

        struct stat st;
        int r;

        r = _mkdirat(dir_fd, path, mode);
        if (r >= 0)
                return chmod_and_chown_at(dir_fd, path, mode, uid, gid);
        if (r != -EEXIST)
                return r;

        if (fstatat(dir_fd, path, &st, AT_SYMLINK_NOFOLLOW) < 0)
                return -errno;

        return 0;
}

static int mkdirat_errno_wrapper(int dirfd, const char *pathname, mode_t mode) {
        return RET_NERRNO(mkdirat(dirfd, pathname, mode));
}

static int mkdirat_parents_internal(int dir_fd, char *path, mode_t mode, uid_t uid, gid_t gid, mkdirat_func_t _mkdirat) {
        const char *e = NULL;
        int r;
        struct stat st;

        assert(path);
        assert(_mkdirat != mkdirat);

        if (isempty(path))
                return 0;

        if (!path_is_safe(path))
                return -ENOTDIR;

        /* return immediately if directory exists */
        r = path_find_last_component(path, /* accept_dot_dot= */ false, &e, NULL);
        if (r <= 0) /* r == 0 means path is equivalent to prefix. */
                return r;
        if (e == path)
                return 0;

        assert(e > path);
        assert(*e == '/');

        /* drop the last component */
        path[e - path] = '\0';
        if (fstatat(dir_fd, path, &st, 0) == 0) {
                path[e - path] = '/';
                return S_ISDIR(st.st_mode) ? 0 : -ENOTDIR;
        }

        /* create every parent directory in the path, except the last component */
        for (const char *p = path;;) {
                char *s;
                int n;

                n = path_find_first_component(&p, /* accept_dot_dot= */ false, (const char **) &s);
                if (n <= 0) {
                        path[e - path] = '/';
                        return n;
                }

                assert(p);
                assert(s >= path);
                assert(IN_SET(s[n], '/', '\0'));

                s[n] = '\0';

                r = mkdirat_safe_internal(dir_fd, path, mode, uid, gid, _mkdirat);
                if (r < 0 && r != -EEXIST) {
                        path[e - path] = '/';
                        return r;
                }

                s[n] = *p == '\0' ? '\0' : '/';
        }
  
        path[e - path] = '/';
}

int mkdirat_parents(int dir_fd, char *path, mode_t mode) {
        return mkdirat_parents_internal(dir_fd, path, mode, UID_INVALID, UID_INVALID, mkdirat_errno_wrapper);
}

int mkdirat_label(int dirfd, const char *path, mode_t mode) {
        int r;

        assert(path);

        r = mac_selinux_create_file_prepare_at(dirfd, path, S_IFDIR);
        if (r < 0)
                return r;

        r = RET_NERRNO(mkdirat(dirfd, path, mode));
        mac_selinux_create_file_clear();
        if (r < 0)
                return r;

        return mac_smack_fix(dirfd, path, NULL);
}

int mkdirat_parents_label(int dir_fd, char *path, mode_t mode) {
        return mkdirat_parents_internal(dir_fd, path, mode, UID_INVALID, UID_INVALID, mkdirat_label);
}
