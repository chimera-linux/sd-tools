/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "macro.h"
#include "mountpoint-util.h"
#include "path-util.h"

int close_nointr(int fd) {
        assert(fd >= 0);

        if (close(fd) >= 0)
                return 0;

        /*
         * Just ignore EINTR; a retry loop is the wrong thing to do on
         * Linux.
         *
         * http://lkml.indiana.edu/hypermail/linux/kernel/0509.1/0877.html
         * https://bugzilla.gnome.org/show_bug.cgi?id=682819
         * http://utcc.utoronto.ca/~cks/space/blog/unix/CloseEINTR
         * https://sites.google.com/site/michaelsafyan/software-engineering/checkforeintrwheninvokingclosethinkagain
         */
        if (errno == EINTR)
                return 0;

        return -errno;
}

int safe_close(int fd) {
        /*
         * Like close_nointr() but cannot fail. Guarantees errno is unchanged. Is a noop for negative fds,
         * and returns -EBADF, so that it can be used in this syntax:
         *
         * fd = safe_close(fd);
         */

        if (fd >= 0) {
                PROTECT_ERRNO;

                /* The kernel might return pretty much any error code
                 * via close(), but the fd will be closed anyway. The
                 * only condition we want to check for here is whether
                 * the fd was invalid at all... */

                assert_se(close_nointr(fd) != -EBADF);
        }

        return -EBADF;
}

static int fclose_nointr(FILE *f) {
        assert(f);

        /* Same as close_nointr(), but for fclose() */

        errno = 0; /* Extra safety: if the FILE* object is not encapsulating an fd, it might not set errno
                    * correctly. Let's hence initialize it to zero first, so that we aren't confused by any
                    * prior errno here */
        if (fclose(f) == 0)
                return 0;

        if (errno == EINTR)
                return 0;

        return errno_or_else(EIO);
}

FILE* safe_fclose(FILE *f) {
        /* Same as safe_close(), but for fclose() */
        if (f) {
                PROTECT_ERRNO;
                assert_se(fclose_nointr(f) != -EBADF);
        }
        return NULL;
}

int fd_get_path(int fd, char **ret) {
        int r;

        assert(fd >= 0 || fd == AT_FDCWD);

        if (fd == AT_FDCWD)
                return safe_getcwd(ret);

        r = readlinkat_malloc(AT_FDCWD, FORMAT_PROC_FD_PATH(fd), ret);
        if (r == -ENOENT) {
                /* ENOENT can mean two things: that the fd does not exist or that /proc is not mounted. Let's make
                 * things debuggable and distinguish the two. */

                if (proc_mounted() == 0)
                        return -ENOSYS;  /* /proc is not available or not set up properly, we're most likely in some chroot
                                          * environment. */
                return -EBADF; /* The directory exists, hence it's the fd that doesn't. */
        }

        return r;
}

int fd_reopen(int fd, int flags) {
        int r;

        assert(fd >= 0 || fd == AT_FDCWD);
        assert(!FLAGS_SET(flags, O_CREAT));

        /* Reopens the specified fd with new flags. This is useful for convert an O_PATH fd into a regular one, or to
         * turn O_RDWR fds into O_RDONLY fds.
         *
         * This doesn't work on sockets (since they cannot be open()ed, ever).
         *
         * This implicitly resets the file read index to 0.
         *
         * If AT_FDCWD is specified as file descriptor gets an fd to the current cwd.
         *
         * If the specified file descriptor refers to a symlink via O_PATH, then this function cannot be used
         * to follow that symlink. Because we cannot have non-O_PATH fds to symlinks reopening it without
         * O_PATH will always result in -ELOOP. Or in other words: if you have an O_PATH fd to a symlink you
         * can reopen it only if you pass O_PATH again. */

        if (FLAGS_SET(flags, O_NOFOLLOW))
                /* O_NOFOLLOW is not allowed in fd_reopen(), because after all this is primarily implemented
                 * via a symlink-based interface in /proc/self/fd. Let's refuse this here early. Note that
                 * the kernel would generate ELOOP here too, hence this manual check is mostly redundant –
                 * the only reason we add it here is so that the O_DIRECTORY special case (see below) behaves
                 * the same way as the non-O_DIRECTORY case. */
                return -ELOOP;

        if (FLAGS_SET(flags, O_DIRECTORY) || fd == AT_FDCWD)
                /* If we shall reopen the fd as directory we can just go via "." and thus bypass the whole
                 * magic /proc/ directory, and make ourselves independent of that being mounted. */
                return RET_NERRNO(openat(fd, ".", flags | O_DIRECTORY));

        int new_fd = open(FORMAT_PROC_FD_PATH(fd), flags);
        if (new_fd < 0) {
                if (errno != ENOENT)
                        return -errno;

                r = proc_mounted();
                if (r == 0)
                        return -ENOSYS; /* if we have no /proc/, the concept is not implementable */

                return r > 0 ? -EBADF : -ENOENT; /* If /proc/ is definitely around then this means the fd is
                                                  * not valid, otherwise let's propagate the original
                                                  * error */
        }

        return new_fd;
}

int fd_reopen_condition(
                int fd,
                int flags,
                int mask,
                int *ret_new_fd) {

        int r, new_fd;

        assert(fd >= 0);
        assert(!FLAGS_SET(flags, O_CREAT));

        /* Invokes fd_reopen(fd, flags), but only if the existing F_GETFL flags don't match the specified
         * flags (masked by the specified mask). This is useful for converting O_PATH fds into real fds if
         * needed, but only then. */

        r = fcntl(fd, F_GETFL);
        if (r < 0)
                return -errno;

        if ((r & mask) == (flags & mask)) {
                *ret_new_fd = -EBADF;
                return fd;
        }

        new_fd = fd_reopen(fd, flags);
        if (new_fd < 0)
                return new_fd;

        *ret_new_fd = new_fd;
        return new_fd;
}

int fd_is_opath(int fd) {
        int r;

        assert(fd >= 0);

        r = fcntl(fd, F_GETFL);
        if (r < 0)
                return -errno;

        return FLAGS_SET(r, O_PATH);
}

int path_is_root_at(int dir_fd, const char *path) {
        struct stat st, pst;
        _cleanup_close_ int fd = -EBADF;
        int r, mntid, pmntid;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);

        if (!isempty(path)) {
                fd = openat(dir_fd, path, O_PATH|O_DIRECTORY|O_CLOEXEC);
                if (fd < 0)
                        return errno == ENOTDIR ? false : -errno;

                dir_fd = fd;
        }

        if (fstatat(dir_fd, ".", &st, AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT) < 0) {
                if (errno == ENOTDIR) return false;
                return -errno;
        }

        if (fstatat(dir_fd, "..", &pst, AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT) < 0) {
                if (errno == ENOTDIR) return false;
                return -errno;
        }

        /* First, compare inode. If these are different, the fd does not point to the root directory "/". */
        if (!stat_inode_same(&st, &pst))
                return false;

        /* Even if the parent directory has the same inode, the fd may not point to the root directory "/",
         * and we also need to check that the mount ids are the same. Otherwise, a construct like the
         * following could be used to trick us:
         *
         * $ mkdir /tmp/x /tmp/x/y
         * $ mount --bind /tmp/x /tmp/x/y
         */

        r = path_get_mnt_id_at_fallback(dir_fd, "", &mntid);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return true; /* skip the mount ID check */
        if (r < 0)
                return r;
        assert(mntid >= 0);

        r = path_get_mnt_id_at_fallback(dir_fd, "..", &pmntid);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return true; /* skip the mount ID check */
        if (r < 0)
                return r;
        assert(mntid >= 0);

        return mntid == pmntid;
}
