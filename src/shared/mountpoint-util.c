/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <linux/fs.h>

#include "alloc-util.h"
#include "chase.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "mkdir.h"
#include "mountpoint-util.h"
#include "path-util.h"
#include "stat-util.h"
#include "strv.h"
#include "user-util.h"

/* This is the original MAX_HANDLE_SZ definition from the kernel, when the API was introduced. We use that in place of
 * any more currently defined value to future-proof things: if the size is increased in the API headers, and our code
 * is recompiled then it would cease working on old kernels, as those refuse any sizes larger than this value with
 * EINVAL right-away. Hence, let's disconnect ourselves from any such API changes, and stick to the original definition
 * from when it was introduced. We use it as a start value only anyway (see below), and hence should be able to deal
 * with large file handles anyway. */
#define ORIGINAL_MAX_HANDLE_SZ 128

static int name_to_handle_at_loop(
                int fd,
                const char *path,
                struct file_handle **ret_handle,
                int *ret_mnt_id,
                int flags) {

        size_t n = ORIGINAL_MAX_HANDLE_SZ;

        assert((flags & ~(AT_SYMLINK_FOLLOW|AT_EMPTY_PATH)) == 0);

        /* We need to invoke name_to_handle_at() in a loop, given that it might return EOVERFLOW when the specified
         * buffer is too small. Note that in contrast to what the docs might suggest, MAX_HANDLE_SZ is only good as a
         * start value, it is not an upper bound on the buffer size required.
         *
         * This improves on raw name_to_handle_at() also in one other regard: ret_handle and ret_mnt_id can be passed
         * as NULL if there's no interest in either. */

        for (;;) {
                _cleanup_free_ struct file_handle *h = NULL;
                int mnt_id = -1;

                h = calloc(1, offsetof(struct file_handle, f_handle) + n);
                if (!h)
                        return -ENOMEM;

                h->handle_bytes = n;

                if (name_to_handle_at(fd, strempty(path), h, &mnt_id, flags) >= 0) {

                        if (ret_handle)
                                *ret_handle = TAKE_PTR(h);

                        if (ret_mnt_id)
                                *ret_mnt_id = mnt_id;

                        return 0;
                }
                if (errno != EOVERFLOW)
                        return -errno;

                if (!ret_handle && ret_mnt_id && mnt_id >= 0) {

                        /* As it appears, name_to_handle_at() fills in mnt_id even when it returns EOVERFLOW when the
                         * buffer is too small, but that's undocumented. Hence, let's make use of this if it appears to
                         * be filled in, and the caller was interested in only the mount ID an nothing else. */

                        *ret_mnt_id = mnt_id;
                        return 0;
                }

                /* If name_to_handle_at() didn't increase the byte size, then this EOVERFLOW is caused by something
                 * else (apparently EOVERFLOW is returned for untriggered nfs4 mounts sometimes), not by the too small
                 * buffer. In that case propagate EOVERFLOW */
                if (h->handle_bytes <= n)
                        return -EOVERFLOW;

                /* The buffer was too small. Size the new buffer by what name_to_handle_at() returned. */
                n = h->handle_bytes;

                /* paranoia: check for overflow (note that .handle_bytes is unsigned only) */
                if (n > UINT_MAX - offsetof(struct file_handle, f_handle))
                        return -EOVERFLOW;
        }
}

/* The maximum size of virtual files (i.e. procfs, sysfs, and other virtual "API" files) we'll read in one go
 * in read_virtual_file(). Note that this limit is different (and much lower) than the READ_FULL_BYTES_MAX
 * limit. This reflects the fact that we use different strategies for reading virtual and regular files:
 * virtual files we generally have to read in a single read() syscall since the kernel doesn't support
 * continuation read()s for them. Thankfully they are somewhat size constrained. Thus we can allocate the
 * full potential buffer in advance. Regular files OTOH can be much larger, and there we grow the allocations
 * exponentially in a loop. We use a size limit of 4M-2 because 4M-1 is the maximum buffer that /proc/sys/
 * allows us to read() (larger reads will fail with ENOMEM), and we want to read one extra byte so that we
 * can detect EOFs. */
#define READ_VIRTUAL_BYTES_MAX (4U*1024U*1024U - 2U)

static int read_virtual_file(
                const char *filename,
                size_t max_size,
                char **ret_contents,
                size_t *ret_size) {

        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *buf = NULL;
        size_t n, size;
        int n_retries;
        bool truncated = false;

        fd = openat(AT_FDCWD, filename, O_RDONLY | O_NOCTTY | O_CLOEXEC);
        if (fd < 0)
                return -errno;

        /* Virtual filesystems such as sysfs or procfs use kernfs, and kernfs can work with two sorts of
         * virtual files. One sort uses "seq_file", and the results of the first read are buffered for the
         * second read. The other sort uses "raw" reads which always go direct to the device. In the latter
         * case, the content of the virtual file must be retrieved with a single read otherwise a second read
         * might get the new value instead of finding EOF immediately. That's the reason why the usage of
         * fread(3) is prohibited in this case as it always performs a second call to read(2) looking for
         * EOF. See issue #13585.
         *
         * max_size specifies a limit on the bytes read. If max_size is SIZE_MAX, the full file is read. If
         * the full file is too large to read, an error is returned. For other values of max_size, *partial
         * contents* may be returned. (Though the read is still done using one syscall.) Returns 0 on
         * partial success, 1 if untruncated contents were read. */

        assert(fd >= 0);
        assert(max_size <= READ_VIRTUAL_BYTES_MAX || max_size == SIZE_MAX);

        /* Limit the number of attempts to read the number of bytes returned by fstat(). */
        n_retries = 3;

        for (;;) {
                struct stat st;

                if (fstat(fd, &st) < 0)
                        return -errno;

                if (!S_ISREG(st.st_mode))
                        return -EBADF;

                /* Be prepared for files from /proc which generally report a file size of 0. */
                assert_cc(READ_VIRTUAL_BYTES_MAX < SSIZE_MAX);
                if (st.st_size > 0 && n_retries > 1) {
                        /* Let's use the file size if we have more than 1 attempt left. On the last attempt
                         * we'll ignore the file size */

                        if (st.st_size > SSIZE_MAX) { /* Avoid overflow with 32-bit size_t and 64-bit off_t. */

                                if (max_size == SIZE_MAX)
                                        return -EFBIG;

                                size = max_size;
                        } else {
                                size = MIN((size_t) st.st_size, max_size);

                                if (size > READ_VIRTUAL_BYTES_MAX)
                                        return -EFBIG;
                        }

                        n_retries--;
                } else if (n_retries > 1) {
                        /* Files in /proc are generally smaller than the page size so let's start with
                         * a page size buffer from malloc and only use the max buffer on the final try. */
                        size = MIN3((size_t)sysconf(_SC_PAGESIZE) - 1, READ_VIRTUAL_BYTES_MAX, max_size);
                        n_retries = 1;
                } else {
                        size = MIN(READ_VIRTUAL_BYTES_MAX, max_size);
                        n_retries = 0;
                }

                buf = malloc(size + 1);
                if (!buf)
                        return -ENOMEM;

                for (;;) {
                        ssize_t k;

                        /* Read one more byte so we can detect whether the content of the
                         * file has already changed or the guessed size for files from /proc
                         * wasn't large enough . */
                        k = read(fd, buf, size + 1);
                        if (k >= 0) {
                                n = k;
                                break;
                        }

                        if (errno != EINTR)
                                return -errno;
                }

                /* Consider a short read as EOF */
                if (n <= size)
                        break;

                /* If a maximum size is specified and we already read more we know the file is larger, and
                 * can handle this as truncation case. Note that if the size of what we read equals the
                 * maximum size then this doesn't mean truncation, the file might or might not end on that
                 * byte. We need to rerun the loop in that case, with a larger buffer size, so that we read
                 * at least one more byte to be able to distinguish EOF from truncation. */
                if (max_size != SIZE_MAX && n > max_size) {
                        n = size; /* Make sure we never use more than what we sized the buffer for (so that
                                   * we have one free byte in it for the trailing NUL we add below). */
                        truncated = true;
                        break;
                }

                /* We have no further attempts left? Then the file is apparently larger than our limits. Give up. */
                if (n_retries <= 0)
                        return -EFBIG;

                /* Hmm... either we read too few bytes from /proc or less likely the content of the file
                 * might have been changed (and is now bigger) while we were processing, let's try again
                 * either with the new file size. */

                if (lseek(fd, 0, SEEK_SET) < 0)
                        return -errno;

                buf = mfree(buf);
        }

        if (ret_contents) {

                /* Safety check: if the caller doesn't want to know the size of what we just read it will
                 * rely on the trailing NUL byte. But if there's an embedded NUL byte, then we should refuse
                 * operation as otherwise there'd be ambiguity about what we just read. */
                if (!ret_size && memchr(buf, 0, n))
                        return -EBADMSG;

                if (n < size) {
                        char *p;

                        /* Return rest of the buffer to libc */
                        p = realloc(buf, n + 1);
                        if (!p)
                                return -ENOMEM;
                        buf = p;
                }

                buf[n] = 0;
                *ret_contents = TAKE_PTR(buf);
        }

        if (ret_size)
                *ret_size = n;

        return !truncated;
}

static int fd_fdinfo_mnt_id(int fd, const char *filename, int flags, int *ret_mnt_id) {
        char path[STRLEN("/proc/self/fdinfo/") + DECIMAL_STR_MAX(int)];
        _cleanup_free_ char *fdinfo = NULL;
        _cleanup_close_ int subfd = -EBADF;
        unsigned long mid;
        char *p, *end = NULL;
        int r;

        assert(ret_mnt_id);
        assert((flags & ~(AT_SYMLINK_FOLLOW|AT_EMPTY_PATH)) == 0);

        if ((flags & AT_EMPTY_PATH) && isempty(filename))
                snprintf(path, sizeof(path), "/proc/self/fdinfo/%i", fd);
        else {
                subfd = openat(fd, filename, O_CLOEXEC|O_PATH|(flags & AT_SYMLINK_FOLLOW ? 0 : O_NOFOLLOW));
                if (subfd < 0)
                        return -errno;

                snprintf(path, sizeof(path), "/proc/self/fdinfo/%i", subfd);
        }

        r = read_virtual_file(path, SIZE_MAX, &fdinfo, NULL);
        if (r == -ENOENT) /* The fdinfo directory is a relatively new addition */
                return proc_mounted() > 0 ? -EOPNOTSUPP : -ENOSYS;
        if (r < 0)
                return r;

        p = find_line_startswith(fdinfo, "mnt_id:");
        if (!p) /* The mnt_id field is a relatively new addition */
                return -EOPNOTSUPP;

        p += strspn(p, WHITESPACE);
        p[strcspn(p, WHITESPACE)] = 0;

        mid = strtoul(p, &end, 10);
        if (!end || *end || mid > INT_MAX)
                return -EINVAL;

        *ret_mnt_id = (int)mid;
        return 0;
}

static bool filename_possibly_with_slash_suffix(char *s) {
        char *slash;
        bool valid;

        /* Checks whether the specified string is either file name, or a filename with a suffix of
         * slashes. But nothing else.
         *
         * this is OK: foo, bar, foo/, bar/, foo//, bar///
         * this is not OK: "", "/", "/foo", "foo/bar", ".", ".." … */

        slash = strchr(s, '/');
        if (!slash)
                return filename_is_valid(s);

        if (slash[strspn(slash, "/")] != 0) /* Check that the suffix consist only of one or more slashes */
                return false;

        *slash = '\0';
        valid = filename_is_valid(s);
        *slash = '\0';
        return valid;
}

static bool is_name_to_handle_at_fatal_error(int err) {
        /* name_to_handle_at() can return "acceptable" errors that are due to the context. For
         * example the kernel does not support name_to_handle_at() at all (ENOSYS), or the syscall
         * was blocked (EACCES/EPERM; maybe through seccomp, because we are running inside of a
         * container), or the mount point is not triggered yet (EOVERFLOW, think nfs4), or some
         * general name_to_handle_at() flakiness (EINVAL). However other errors are not supposed to
         * happen and therefore are considered fatal ones. */

        assert(err < 0);

        return !IN_SET(err, -EOPNOTSUPP, -ENOSYS, -EACCES, -EPERM, -EOVERFLOW, -EINVAL);
}

int fd_is_mount_point(int fd, char *filename, int flags) {
        _cleanup_free_ struct file_handle *h = NULL, *h_parent = NULL;
        int mount_id = -1, mount_id_parent = -1;
        bool nosupp = false, check_st_dev = true;
        struct stat a, b;
        int r;
        char empty[] = "";

        assert(fd >= 0);
        assert((flags & ~AT_SYMLINK_FOLLOW) == 0);

        if (!filename) {
                /* If the file name is specified as NULL we'll see if the specified 'fd' is a mount
                 * point. That's only supported if the kernel supports statx(), or if the inode specified via
                 * 'fd' refers to a directory. Otherwise, we'll have to fail (ENOTDIR), because we have no
                 * kernel API to query the information we need. */
                flags |= AT_EMPTY_PATH;
                filename = empty;
        } else if (!filename_possibly_with_slash_suffix(filename))
                /* Insist that the specified filename is actually a filename, and not a path, i.e. some inode further
                 * up or down the tree then immediately below the specified directory fd. */
                return -EINVAL;

        r = name_to_handle_at_loop(fd, filename, &h, &mount_id, flags);
        if (r < 0) {
                if (is_name_to_handle_at_fatal_error(r))
                        return r;
                if (r != -EOPNOTSUPP)
                        goto fallback_fdinfo;

                /* This kernel or file system does not support name_to_handle_at(), hence let's see
                 * if the upper fs supports it (in which case it is a mount point), otherwise fall
                 * back to the traditional stat() logic */
                nosupp = true;
        }

        if (isempty(filename))
                r = name_to_handle_at_loop(fd, "..", &h_parent, &mount_id_parent, 0); /* can't work for non-directories 😢 */
        else
                r = name_to_handle_at_loop(fd, "", &h_parent, &mount_id_parent, AT_EMPTY_PATH);
        if (r < 0) {
                if (is_name_to_handle_at_fatal_error(r))
                        return r;
                if (r != -EOPNOTSUPP)
                        goto fallback_fdinfo;
                if (nosupp)
                        /* Both the parent and the directory can't do name_to_handle_at() */
                        goto fallback_fdinfo;

                /* The parent can't do name_to_handle_at() but the directory we are
                 * interested in can?  If so, it must be a mount point. */
                return 1;
        }

        /* The parent can do name_to_handle_at() but the directory we are interested in can't? If
         * so, it must be a mount point. */
        if (nosupp)
                return 1;

        /* If the file handle for the directory we are interested in and its parent are identical,
         * we assume this is the root directory, which is a mount point. */

        if (h->handle_type == h_parent->handle_type && h->handle_bytes == h_parent->handle_bytes &&
            memcmp(h->f_handle, h_parent->f_handle, h->handle_bytes) == 0)
                return 1;

        return mount_id != mount_id_parent;

fallback_fdinfo:
        r = fd_fdinfo_mnt_id(fd, filename, flags, &mount_id);
        if (IN_SET(r, -EOPNOTSUPP, -EACCES, -EPERM, -ENOSYS))
                goto fallback_fstat;
        if (r < 0)
                return r;

        if (isempty(filename))
                r = fd_fdinfo_mnt_id(fd, "..", 0, &mount_id_parent); /* can't work for non-directories 😢 */
        else
                r = fd_fdinfo_mnt_id(fd, "", AT_EMPTY_PATH, &mount_id_parent);
        if (r < 0)
                return r;

        if (mount_id != mount_id_parent)
                return 1;

        /* Hmm, so, the mount ids are the same. This leaves one special case though for the root file
         * system. For that, let's see if the parent directory has the same inode as we are interested
         * in. Hence, let's also do fstat() checks now, too, but avoid the st_dev comparisons, since they
         * aren't that useful on unionfs mounts. */
        check_st_dev = false;

fallback_fstat:
        /* yay for fstatat() taking a different set of flags than the other _at() above */
        if (flags & AT_SYMLINK_FOLLOW)
                flags &= ~AT_SYMLINK_FOLLOW;
        else
                flags |= AT_SYMLINK_NOFOLLOW;
        if (fstatat(fd, filename, &a, flags) < 0)
                return -errno;
        if (S_ISLNK(a.st_mode)) /* Symlinks are never mount points */
                return false;

        if (isempty(filename))
                r = fstatat(fd, "..", &b, 0);
        else
                r = fstatat(fd, "", &b, AT_EMPTY_PATH);
        if (r < 0)
                return -errno;

        /* A directory with same device and inode as its parent? Must be the root directory */
        if (stat_inode_same(&a, &b))
                return 1;

        return check_st_dev && (a.st_dev != b.st_dev);
}

int path_get_mnt_id_at_fallback(int dir_fd, const char *path, int *ret) {
        int r;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);
        assert(ret);

        r = name_to_handle_at_loop(dir_fd, path, NULL, ret, isempty(path) ? AT_EMPTY_PATH : 0);
        if (r == 0 || is_name_to_handle_at_fatal_error(r))
                return r;

        return fd_fdinfo_mnt_id(dir_fd, path, isempty(path) ? AT_EMPTY_PATH : 0, ret);
}
