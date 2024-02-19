/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/xattr.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "xattr-util.h"

int getxattr_at_malloc(
                int fd,
                const char *path,
                const char *name,
                int flags,
                char **ret) {

        _cleanup_close_ int opened_fd = -EBADF;
        unsigned n_attempts = 7;
        bool by_procfs = false;
        size_t l = 100;

        assert(fd >= 0 || fd == AT_FDCWD);
        assert(name);
        assert((flags & ~(AT_SYMLINK_FOLLOW|AT_EMPTY_PATH)) == 0);
        assert(ret);

        /* So, this is single function that does what getxattr()/lgetxattr()/fgetxattr() does, but in one go,
         * and with additional bells and whistles. Specifically:
         *
         * 1. This works on O_PATH fds (which fgetxattr() does not)
         * 2. Provides full openat()-style semantics, i.e. by-fd, by-path and combination thereof
         * 3. As extension to openat()-style semantics implies AT_EMPTY_PATH if path is NULL.
         * 4. Does a malloc() loop, automatically sizing the allocation
         * 5. NUL-terminates the returned buffer (for safety)
         */

        if (!path) /* If path is NULL, imply AT_EMPTY_PATH. – But if it's "", don't — for safety reasons. */
                flags |= AT_EMPTY_PATH;

        if (isempty(path)) {
                if (!FLAGS_SET(flags, AT_EMPTY_PATH))
                        return -EINVAL;

                if (fd == AT_FDCWD) /* Both unspecified? Then operate on current working directory */
                        path = ".";
                else
                        path = NULL;

        } else if (fd != AT_FDCWD) {

                /* If both have been specified, then we go via O_PATH */
                opened_fd = openat(fd, path, O_PATH|O_CLOEXEC|(FLAGS_SET(flags, AT_SYMLINK_FOLLOW) ? 0 : O_NOFOLLOW));
                if (opened_fd < 0)
                        return -errno;

                fd = opened_fd;
                path = NULL;
                by_procfs = true; /* fgetxattr() is not going to work, go via /proc/ link right-away */
        }

        for (;;) {
                _cleanup_free_ char *v = NULL;
                ssize_t n;

                if (n_attempts == 0) /* If someone is racing against us, give up eventually */
                        return -EBUSY;
                n_attempts--;

                v = calloc(l + 1, sizeof(char));
                if (!v)
                        return -ENOMEM;

                if (path)
                        n = FLAGS_SET(flags, AT_SYMLINK_FOLLOW) ? getxattr(path, name, v, l) : lgetxattr(path, name, v, l);
                else
                        n = by_procfs ? getxattr(FORMAT_PROC_FD_PATH(fd), name, v, l) : fgetxattr(fd, name, v, l);
                if (n < 0) {
                        if (errno == EBADF) {
                                if (by_procfs || path)
                                        return -EBADF;

                                by_procfs = true; /* Might be an O_PATH fd, try again via /proc/ link */
                                continue;
                        }

                        if (errno != ERANGE)
                                return -errno;
                } else {
                        v[n] = 0; /* NUL terminate */
                        *ret = TAKE_PTR(v);
                        return (int) n;
                }

                if (path)
                        n = FLAGS_SET(flags, AT_SYMLINK_FOLLOW) ? getxattr(path, name, NULL, 0) : lgetxattr(path, name, NULL, 0);
                else
                        n = by_procfs ? getxattr(FORMAT_PROC_FD_PATH(fd), name, NULL, 0) : fgetxattr(fd, name, NULL, 0);
                if (n < 0)
                        return -errno;
                if (n > INT_MAX) /* We couldn't return this as 'int' anymore */
                        return -E2BIG;

                l = (size_t) n;
        }
}

int listxattr_at_malloc(
                int fd,
                const char *path,
                int flags,
                char **ret) {

        _cleanup_close_ int opened_fd = -EBADF;
        bool by_procfs = false;
        unsigned n_attempts = 7;
        size_t l = 100;

        assert(fd >= 0 || fd == AT_FDCWD);
        assert((flags & ~(AT_SYMLINK_FOLLOW|AT_EMPTY_PATH)) == 0);
        assert(ret);

        /* This is to listxattr()/llistattr()/flistattr() what getxattr_at_malloc() is to getxattr()/… */

        if (!path) /* If path is NULL, imply AT_EMPTY_PATH. – But if it's "", don't. */
                flags |= AT_EMPTY_PATH;

        if (isempty(path)) {
                if (!FLAGS_SET(flags, AT_EMPTY_PATH))
                        return -EINVAL;

                if (fd == AT_FDCWD) /* Both unspecified? Then operate on current working directory */
                        path = ".";
                else
                        path = NULL;

        } else if (fd != AT_FDCWD) {
                /* If both have been specified, then we go via O_PATH */
                opened_fd = openat(fd, path, O_PATH|O_CLOEXEC|(FLAGS_SET(flags, AT_SYMLINK_FOLLOW) ? 0 : O_NOFOLLOW));
                if (opened_fd < 0)
                        return -errno;

                fd = opened_fd;
                path = NULL;
                by_procfs = true;
        }

        for (;;) {
                _cleanup_free_ char *v = NULL;
                ssize_t n;

                if (n_attempts == 0) /* If someone is racing against us, give up eventually */
                        return -EBUSY;
                n_attempts--;

                v = malloc(l+1);
                if (!v)
                        return -ENOMEM;

                if (path)
                        n = FLAGS_SET(flags, AT_SYMLINK_FOLLOW) ? listxattr(path, v, l) : llistxattr(path, v, l);
                else
                        n = by_procfs ? listxattr(FORMAT_PROC_FD_PATH(fd), v, l) : flistxattr(fd, v, l);
                if (n < 0) {
                        if (errno == EBADF) {
                                if (by_procfs || path)
                                        return -EBADF;

                                by_procfs = true; /* Might be an O_PATH fd, try again via /proc/ link */
                                continue;
                        }

                        if (errno != ERANGE)
                                return -errno;
                } else {
                        v[n] = 0; /* NUL terminate */
                        *ret = TAKE_PTR(v);
                        return (int) n;
                }

                if (path)
                        n = FLAGS_SET(flags, AT_SYMLINK_FOLLOW) ? listxattr(path, NULL, 0) : llistxattr(path, NULL, 0);
                else
                        n = by_procfs ? listxattr(FORMAT_PROC_FD_PATH(fd), NULL, 0) : flistxattr(fd, NULL, 0);
                if (n < 0)
                        return -errno;
                if (n > INT_MAX) /* We couldn't return this as 'int' anymore */
                        return -E2BIG;

                l = (size_t) n;
        }
}

int xsetxattr(int fd,
              const char *path,
              const char *name,
              const char *value,
              size_t size,
              int flags) {

        _cleanup_close_ int opened_fd = -EBADF;
        bool by_procfs = false;
        int r;

        assert(fd >= 0 || fd == AT_FDCWD);
        assert(name);
        assert(value);
        assert((flags & ~(AT_SYMLINK_FOLLOW|AT_EMPTY_PATH)) == 0);

        /* So, this is a single function that does what setxattr()/lsetxattr()/fsetxattr() do, but in one go,
         * and with additional bells and whistles. Specifically:
         *
         * 1. This works on O_PATH fds (which fsetxattr() does not)
         * 2. Provides full openat()-style semantics, i.e. by-fd, by-path and combination thereof
         * 3. As extension to openat()-style semantics implies AT_EMPTY_PATH if path is NULL.
         */

        if (!path) /* If path is NULL, imply AT_EMPTY_PATH. – But if it's "", don't — for safety reasons. */
                flags |= AT_EMPTY_PATH;

        if (size == SIZE_MAX)
                size = strlen(value);

        if (isempty(path)) {
                if (!FLAGS_SET(flags, AT_EMPTY_PATH))
                        return -EINVAL;

                if (fd == AT_FDCWD) /* Both unspecified? Then operate on current working directory */
                        path = ".";
                else {
                        r = fd_is_opath(fd);
                        if (r < 0)
                                return r;

                        by_procfs = r;
                        path = NULL;
                }

        } else if (fd != AT_FDCWD) {

                /* If both have been specified, then we go via O_PATH */
                opened_fd = openat(fd, path, O_PATH|O_CLOEXEC|(FLAGS_SET(flags, AT_SYMLINK_FOLLOW) ? 0 : O_NOFOLLOW));
                if (opened_fd < 0)
                        return -errno;

                fd = opened_fd;
                path = NULL;
                by_procfs = true; /* fsetxattr() is not going to work, go via /proc/ link right-away */
        }

        if (path)
                r = FLAGS_SET(flags, AT_SYMLINK_FOLLOW) ? setxattr(path, name, value, size, 0)
                                                        : lsetxattr(path, name, value, size, 0);
        else
                r = by_procfs ? setxattr(FORMAT_PROC_FD_PATH(fd), name, value, size, 0)
                              : fsetxattr(fd, name, value, size, 0);
        if (r < 0)
                return -errno;

        return 0;
}
