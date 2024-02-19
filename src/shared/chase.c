/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/magic.h>
#include <pwd.h>

#include "alloc-util.h"
#include "chase.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "path-util.h"
#include "string-util.h"
#include "user-util.h"

/* How many iterations to execute before returning -ELOOP */
#define CHASE_MAX 32

bool unsafe_transition(const struct stat *a, const struct stat *b) {
        /* Returns true if the transition from a to b is safe, i.e. that we never transition from unprivileged to
         * privileged files or directories. Why bother? So that unprivileged code can't symlink to privileged files
         * making us believe we read something safe even though it isn't safe in the specific context we open it in. */

        if (a->st_uid == 0) /* Transitioning from privileged to unprivileged is always fine */
                return false;

        return a->st_uid != b->st_uid; /* Otherwise we need to stay within the same UID */
}

static int log_unsafe_transition(int a, int b, const char *path, ChaseFlags flags) {
        _cleanup_free_ char *n1 = NULL, *n2 = NULL;
        struct stat st;
        long long uid_a = -1, uid_b = -1;

        if (!FLAGS_SET(flags, CHASE_WARN))
                return -ENOLINK;

        (void) fd_get_path(a, &n1);
        (void) fd_get_path(b, &n2);

        if (fstat(a, &st) == 0)
                uid_a = st.st_uid;
        if (fstat(b, &st) == 0)
                uid_b = st.st_uid;

        return log_warning_errno(SYNTHETIC_ERRNO(ENOLINK),
                                 "Detected unsafe path transition %s (owned by %lld) => %s (owned by %lld) during canonicalization of %s.",
                                 strna(n1), uid_a, strna(n2), uid_b, path);
}

static int log_autofs_mount_point(int fd, const char *path, ChaseFlags flags) {
        _cleanup_free_ char *n1 = NULL;

        if (!FLAGS_SET(flags, CHASE_WARN))
                return -EREMOTE;

        (void) fd_get_path(fd, &n1);

        return log_warning_errno(SYNTHETIC_ERRNO(EREMOTE),
                                 "Detected autofs mount point %s during canonicalization of %s.",
                                 strna(n1), path);
}

static int chaseat_needs_absolute(int dir_fd, const char *path) {
        if (dir_fd < 0)
                return path_is_absolute(path);

        return path_is_root_at(dir_fd, NULL);
}

int chaseat(int dir_fd, const char *path, ChaseFlags flags, char **ret_path, int *ret_fd) {
        _cleanup_free_ char *buffer = NULL, *done = NULL;
        _cleanup_close_ int fd = -EBADF, root_fd = -EBADF;
        unsigned max_follow = CHASE_MAX; /* how many symlinks to follow before giving up and returning ELOOP */
        bool exists = true;
        struct stat st; /* stat obtained from fd */
        const char *todo;
        int r;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);

        /* Either the file may be missing, or we return an fd to the final object, but both make no sense */
        if (FLAGS_SET(flags, CHASE_NONEXISTENT))
                assert(!ret_fd);

        if (isempty(path))
                path = ".";

        /* This function resolves symlinks of the path relative to the given directory file descriptor. If
         * CHASE_AT_RESOLVE_IN_ROOT is specified and a directory file descriptor is provided, symlinks
         * are resolved relative to the given directory file descriptor. Otherwise, they are resolved
         * relative to the root directory of the host.
         *
         * Note that when a positive directory file descriptor is provided and CHASE_AT_RESOLVE_IN_ROOT is
         * specified and we find an absolute symlink, it is resolved relative to given directory file
         * descriptor and not the root of the host. Also, when following relative symlinks, this functions
         * ensures they cannot be used to "escape" the given directory file descriptor. If a positive
         * directory file descriptor is provided, the "path" parameter is always interpreted relative to the
         * given directory file descriptor, even if it is absolute. If the given directory file descriptor is
         * AT_FDCWD and "path" is absolute, it is interpreted relative to the root directory of the host.
         *
         * When "dir_fd" points to a non-root directory and CHASE_AT_RESOLVE_IN_ROOT is set, this function
         * always returns a relative path in "ret_path", even if "path" is an absolute path, because openat()
         * like functions generally ignore the directory fd if they are provided with an absolute path. When
         * CHASE_AT_RESOLVE_IN_ROOT is not set, then this returns relative path to the specified file
         * descriptor if all resolved symlinks are relative, otherwise absolute path will be returned. When
         * "dir_fd" is AT_FDCWD and "path" is an absolute path, we return an absolute path in "ret_path"
         * because otherwise, if the caller passes the returned relative path to another openat() like
         * function, it would be resolved relative to the current working directory instead of to "/".
         *
         * Summary about the result path:
         * - "dir_fd" points to the root directory
         *    → result will be absolute
         * - "dir_fd" points to a non-root directory, and CHASE_AT_RESOLVE_IN_ROOT is set
         *    → relative
         * - "dir_fd" points to a non-root directory, and CHASE_AT_RESOLVE_IN_ROOT is not set
         *    → relative when all resolved symlinks are relative, otherwise absolute
         * - "dir_fd" is AT_FDCWD, and "path" is absolute
         *    → absolute
         * - "dir_fd" is AT_FDCWD, and "path" is relative
         *    → relative when all resolved symlinks are relative, otherwise absolute
         *
         * Algorithmically this operates on two path buffers: "done" are the components of the path we
         * already processed and resolved symlinks, "." and ".." of. "todo" are the components of the path we
         * still need to process. On each iteration, we move one component from "todo" to "done", processing
         * its special meaning each time. We always keep an O_PATH fd to the component we are currently
         * processing, thus keeping lookup races to a minimum.
         *
         * Suggested usage: whenever you want to canonicalize a path, use this function. Pass the absolute
         * path you got as-is: fully qualified and relative to your host's root. Optionally, specify the
         * "dir_fd" parameter to tell this function what to do when encountering a symlink with an absolute
         * path as directory: resolve it relative to the given directory file descriptor.
         *
         * There are five ways to invoke this function:
         *
         * 1. Without CHASE_STEP or ret_fd: in this case the path is resolved and the normalized path is
         *    returned in `ret_path`. The return value is < 0 on error. If CHASE_NONEXISTENT is also set, 0
         *    is returned if the file doesn't exist, > 0 otherwise. If CHASE_NONEXISTENT is not set, >= 0 is
         *    returned if the destination was found, -ENOENT if it wasn't.
         *
         * 2. With ret_fd: in this case the destination is opened after chasing it as O_PATH and this file
         *    descriptor is returned as return value. This is useful to open files relative to some root
         *    directory. Note that the returned O_PATH file descriptors must be converted into a regular one
         *    (using fd_reopen() or such) before it can be used for reading/writing. ret_fd may not be
         *    combined with CHASE_NONEXISTENT.
         *
         * 3. With CHASE_STEP: in this case only a single step of the normalization is executed, i.e. only
         *    the first symlink or ".." component of the path is resolved, and the resulting path is
         *    returned. This is useful if a caller wants to trace the path through the file system verbosely.
         *    Returns < 0 on error, > 0 if the path is fully normalized, and == 0 for each normalization
         *    step. This may be combined with CHASE_NONEXISTENT, in which case 1 is returned when a component
         *    is not found.
         *
         * 4. With CHASE_SAFE: in this case the path must not contain unsafe transitions, i.e. transitions
         *    from unprivileged to privileged files or directories. In such cases the return value is
         *    -ENOLINK. If CHASE_WARN is also set, a warning describing the unsafe transition is emitted.
         *    CHASE_WARN cannot be used in PID 1.
         *
         * 5. With CHASE_NO_AUTOFS: in this case if an autofs mount point is encountered, path normalization
         *    is aborted and -EREMOTE is returned. If CHASE_WARN is also set, a warning showing the path of
         *    the mount point is emitted. CHASE_WARN cannot be used in PID 1.
         */

        if (FLAGS_SET(flags, CHASE_AT_RESOLVE_IN_ROOT)) {
                /* If we get AT_FDCWD or dir_fd points to "/", then we always resolve symlinks relative to
                 * the host's root. Hence, CHASE_AT_RESOLVE_IN_ROOT is meaningless. */

                r = path_is_root_at(dir_fd, NULL);
                if (r < 0)
                        return r;
                if (r > 0)
                        flags &= ~CHASE_AT_RESOLVE_IN_ROOT;
        }

        if (!(flags &
              (CHASE_AT_RESOLVE_IN_ROOT|CHASE_NONEXISTENT|CHASE_NO_AUTOFS|CHASE_SAFE)) &&
            !ret_path && ret_fd) {

                /* Shortcut the ret_fd case if the caller isn't interested in the actual path and has no root
                 * set and doesn't care about any of the other special features we provide either. */
                r = openat(dir_fd, path, O_PATH|O_CLOEXEC|(FLAGS_SET(flags, CHASE_NOFOLLOW) ? O_NOFOLLOW : 0));
                if (r < 0)
                        return -errno;

                *ret_fd = r;
                return 0;
        }

        buffer = strdup(path);
        if (!buffer)
                return -ENOMEM;

        /* If we receive an absolute path together with AT_FDCWD, we need to return an absolute path, because
         * a relative path would be interpreted relative to the current working directory. Also, let's make
         * the result absolute when the file descriptor of the root directory is specified. */
        r = chaseat_needs_absolute(dir_fd, path);
        if (r < 0)
                return r;

        bool need_absolute = r;
        if (need_absolute) {
                done = strdup("/");
                if (!done)
                        return -ENOMEM;
        }

        /* If a positive directory file descriptor is provided, always resolve the given path relative to it,
         * regardless of whether it is absolute or not. If we get AT_FDCWD, follow regular openat()
         * semantics, if the path is relative, resolve against the current working directory. Otherwise,
         * resolve against root. */
        fd = openat(dir_fd, done ?: ".", O_CLOEXEC|O_DIRECTORY|O_PATH);
        if (fd < 0)
                return -errno;

        if (fstat(fd, &st) < 0)
                return -errno;

        /* If we get AT_FDCWD, we always resolve symlinks relative to the host's root. Only if a positive
         * directory file descriptor is provided we will look at CHASE_AT_RESOLVE_IN_ROOT to determine
         * whether to resolve symlinks in it or not. */
        if (dir_fd >= 0 && FLAGS_SET(flags, CHASE_AT_RESOLVE_IN_ROOT))
                root_fd = openat(dir_fd, ".", O_CLOEXEC|O_DIRECTORY|O_PATH);
        else
                root_fd = open("/", O_CLOEXEC|O_DIRECTORY|O_PATH);
        if (root_fd < 0)
                return -errno;

        for (todo = buffer;;) {
                _cleanup_free_ char *first = NULL;
                _cleanup_close_ int child = -EBADF;
                struct stat st_child;
                const char *e;

                r = path_find_first_component(&todo, /* accept_dot_dot= */ true, &e);
                if (r < 0)
                        return r;
                if (r == 0) { /* We reached the end. */
                        break;
                }

                first = strndup(e, r);
                if (!first)
                        return -ENOMEM;

                /* Two dots? Then chop off the last bit of what we already found out. */
                if (path_equal(first, "..")) {
                        _cleanup_free_ char *parent = NULL;
                        _cleanup_close_ int fd_parent = -EBADF;
                        struct stat st_parent;

                        /* If we already are at the top, then going up will not change anything. This is
                         * in-line with how the kernel handles this. */
                        if (empty_or_root(done) && FLAGS_SET(flags, CHASE_AT_RESOLVE_IN_ROOT)) {
                                continue;
                        }

                        fd_parent = openat(fd, "..", O_CLOEXEC|O_NOFOLLOW|O_PATH|O_DIRECTORY);
                        if (fd_parent < 0)
                                return -errno;

                        if (fstat(fd_parent, &st_parent) < 0)
                                return -errno;

                        /* If we opened the same directory, that _may_ indicate that we're at the host root
                         * directory. Let's confirm that in more detail with path_is_root_at(). And if so,
                         * going up won't change anything. */
                        if (stat_inode_same(&st_parent, &st)) {
                                r = path_is_root_at(fd, NULL);
                                if (r < 0)
                                        return r;
                                if (r > 0) {
                                        continue;
                                }
                        }

                        r = path_extract_directory(done, &parent);
                        if (r >= 0) {
                                assert(!need_absolute || path_is_absolute(parent));
                                free_and_replace(done, parent);
                        } else if (r == -EDESTADDRREQ) {
                                /* 'done' contains filename only (i.e. no slash). */
                                assert(!need_absolute);
                                done = mfree(done);
                        } else if (r == -EADDRNOTAVAIL) {
                                /* 'done' is "/". This branch should be already handled in the above. */
                                assert(!FLAGS_SET(flags, CHASE_AT_RESOLVE_IN_ROOT));
                                assert_not_reached();
                        } else if (r == -EINVAL) {
                                /* 'done' is an empty string, ends with '..', or an invalid path. */
                                assert(!need_absolute);
                                assert(!FLAGS_SET(flags, CHASE_AT_RESOLVE_IN_ROOT));

                                if (!path_is_valid(done))
                                        return -EINVAL;

                                /* If we're at the top of "dir_fd", start appending ".." to "done". */
                                if (!path_extend(&done, ".."))
                                        return -ENOMEM;
                        } else
                                return r;

                        if (FLAGS_SET(flags, CHASE_SAFE) &&
                            unsafe_transition(&st, &st_parent))
                                return log_unsafe_transition(fd, fd_parent, path, flags);

                        /* If the path ends on a "..", and CHASE_PARENT is specified then our current 'fd' is
                         * the child of the returned normalized path, not the parent as requested. To correct
                         * this we have to go *two* levels up. */
                        if (FLAGS_SET(flags, CHASE_PARENT) && isempty(todo)) {
                                _cleanup_close_ int fd_grandparent = -EBADF;
                                struct stat st_grandparent;

                                fd_grandparent = openat(fd_parent, "..", O_CLOEXEC|O_NOFOLLOW|O_PATH|O_DIRECTORY);
                                if (fd_grandparent < 0)
                                        return -errno;

                                if (fstat(fd_grandparent, &st_grandparent) < 0)
                                        return -errno;

                                if (FLAGS_SET(flags, CHASE_SAFE) &&
                                    unsafe_transition(&st_parent, &st_grandparent))
                                        return log_unsafe_transition(fd_parent, fd_grandparent, path, flags);

                                st = st_grandparent;
                                close_and_replace(fd, fd_grandparent);
                                break;
                        }

                        /* update fd and stat */
                        st = st_parent;
                        close_and_replace(fd, fd_parent);
                        continue;
                }

                /* Otherwise let's see what this is. */
                child = r = RET_NERRNO(openat(fd, first, O_CLOEXEC|O_NOFOLLOW|O_PATH));
                if (r < 0) {
                        if (r != -ENOENT)
                                return r;

                        if (!isempty(todo) && !path_is_safe(todo))
                                return r;

                        if (FLAGS_SET(flags, CHASE_PARENT) && isempty(todo)) {
                                if (!path_extend(&done, first))
                                        return -ENOMEM;

                                break;
                        } else if (FLAGS_SET(flags, CHASE_NONEXISTENT)) {
                                if (!path_extend(&done, first, todo))
                                        return -ENOMEM;

                                exists = false;
                                break;
                        } else
                                return r;
                }

                if (fstat(child, &st_child) < 0)
                        return -errno;

                if (FLAGS_SET(flags, CHASE_SAFE) &&
                    unsafe_transition(&st, &st_child))
                        return log_unsafe_transition(fd, child, path, flags);

                if (FLAGS_SET(flags, CHASE_NO_AUTOFS) &&
                    is_fs_type_at(child, NULL, AUTOFS_SUPER_MAGIC) > 0)
                        return log_autofs_mount_point(child, path, flags);

                if (S_ISLNK(st_child.st_mode) && !(FLAGS_SET(flags, CHASE_NOFOLLOW) && isempty(todo))) {
                        _cleanup_free_ char *destination = NULL;

                        /* This is a symlink, in this case read the destination. But let's make sure we
                         * don't follow symlinks without bounds. */
                        if (--max_follow <= 0)
                                return -ELOOP;

                        r = readlinkat_malloc(fd, first, &destination);
                        if (r < 0)
                                return r;
                        if (isempty(destination))
                                return -EINVAL;

                        if (path_is_absolute(destination)) {

                                /* An absolute destination. Start the loop from the beginning, but use the
                                 * root file descriptor as base. */

                                safe_close(fd);
                                fd = fd_reopen(root_fd, O_CLOEXEC|O_PATH|O_DIRECTORY);
                                if (fd < 0)
                                        return fd;

                                if (fstat(fd, &st) < 0)
                                        return -errno;

                                if (FLAGS_SET(flags, CHASE_SAFE) &&
                                    unsafe_transition(&st_child, &st))
                                        return log_unsafe_transition(child, fd, path, flags);

                                /* When CHASE_AT_RESOLVE_IN_ROOT is not set, now the chased path may be
                                 * outside of the specified dir_fd. Let's make the result absolute. */
                                if (!FLAGS_SET(flags, CHASE_AT_RESOLVE_IN_ROOT))
                                        need_absolute = true;

                                r = free_and_strdup(&done, need_absolute ? "/" : NULL);
                                if (r < 0)
                                        return r;
                        }

                        /* Prefix what's left to do with what we just read, and start the loop again, but
                         * remain in the current directory. */
                        if (!path_extend(&destination, todo))
                                return -ENOMEM;

                        free_and_replace(buffer, destination);
                        todo = buffer;

                        continue;
                }

                /* If this is not a symlink, then let's just add the name we read to what we already verified. */
                if (!path_extend(&done, first))
                        return -ENOMEM;

                if (FLAGS_SET(flags, CHASE_PARENT) && isempty(todo))
                        break;

                /* And iterate again, but go one directory further down. */
                st = st_child;
                close_and_replace(fd, child);
        }

        if (FLAGS_SET(flags, CHASE_PARENT)) {
                if (S_ISLNK(st.st_mode))
                        return -ELOOP;
                if (!S_ISDIR(st.st_mode))
                        return -ENOTDIR;
        }

        if (ret_path) {
                if (FLAGS_SET(flags, CHASE_EXTRACT_FILENAME) && done) {
                        _cleanup_free_ char *f = NULL;

                        r = path_extract_filename(done, &f);
                        if (r < 0 && r != -EADDRNOTAVAIL)
                                return r;

                        /* If we get EADDRNOTAVAIL we clear done and it will get reinitialized by the next block. */
                        free_and_replace(done, f);
                }

                if (!done) {
                        assert(!need_absolute || FLAGS_SET(flags, CHASE_EXTRACT_FILENAME));
                        done = strdup(".");
                        if (!done)
                                return -ENOMEM;
                }

                *ret_path = TAKE_PTR(done);
        }

        if (ret_fd) {
                /* Return the O_PATH fd we currently are looking to the caller. It can translate it to a
                 * proper fd by opening /proc/self/fd/xyz. */

                assert(fd >= 0);
                *ret_fd = TAKE_FD(fd);
        }

        return exists;
}

static int empty_or_root_to_null(const char **path) {
        int r;

        assert(path);

        /* This nullifies the input path when the path is empty or points to "/". */

        if (empty_or_root(*path)) {
                *path = NULL;
                return 0;
        }

        r = path_is_root_at(AT_FDCWD, *path);
        if (r < 0)
                return r;
        if (r > 0)
                *path = NULL;

        return 0;
}

int chase(const char *path, const char *root, ChaseFlags flags, char **ret_path, int *ret_fd) {
        _cleanup_free_ char *root_abs = NULL, *absolute = NULL, *p = NULL;
        _cleanup_close_ int fd = -EBADF, pfd = -EBADF;
        int r;

        assert(path);

        if (isempty(path))
                return -EINVAL;

        r = empty_or_root_to_null(&root);
        if (r < 0)
                return r;

        /* A root directory of "/" or "" is identical to "/". */
        if (empty_or_root(root)) {
                root = "/";

                /* When the root directory is "/", we will drop CHASE_AT_RESOLVE_IN_ROOT in chaseat(),
                 * hence below is not necessary, but let's shortcut. */
                flags &= ~CHASE_AT_RESOLVE_IN_ROOT;

        } else {
                r = path_make_absolute_cwd(root, &root_abs);
                if (r < 0)
                        return r;

                /* Simplify the root directory, so that it has no duplicate slashes and nothing at the
                 * end. While we won't resolve the root path we still simplify it. */
                root = path_simplify(root_abs);

                assert(path_is_absolute(root));
                assert(!empty_or_root(root));

                if (FLAGS_SET(flags, CHASE_PREFIX_ROOT)) {
                        absolute = path_join(root, path);
                        if (!absolute)
                                return -ENOMEM;
                }

                flags |= CHASE_AT_RESOLVE_IN_ROOT;
        }

        if (!absolute) {
                r = path_make_absolute_cwd(path, &absolute);
                if (r < 0)
                        return r;
        }

        path = path_startswith(absolute, root);
        if (!path)
                return log_full_errno(FLAGS_SET(flags, CHASE_WARN) ? LOG_WARNING : LOG_DEBUG,
                                      SYNTHETIC_ERRNO(ECHRNG),
                                      "Specified path '%s' is outside of specified root directory '%s', refusing to resolve.",
                                      absolute, root);

        fd = open(root, O_CLOEXEC|O_DIRECTORY|O_PATH);
        if (fd < 0)
                return -errno;

        r = chaseat(fd, path, flags & ~CHASE_PREFIX_ROOT, ret_path ? &p : NULL, ret_fd ? &pfd : NULL);
        if (r < 0)
                return r;

        if (ret_path) {
                if (!FLAGS_SET(flags, CHASE_EXTRACT_FILENAME)) {

                        /* When "root" points to the root directory, the result of chaseat() is always
                         * absolute, hence it is not necessary to prefix with the root. When "root" points to
                         * a non-root directory, the result path is always normalized and relative, hence
                         * we can simply call path_join() and not necessary to call path_simplify().
                         * Note that the result of chaseat() may start with "." (more specifically, it may be
                         * "." or "./"), and we need to drop "." in that case. */

                        if (empty_or_root(root))
                                assert(path_is_absolute(p));
                        else {
                                char *q;

                                assert(!path_is_absolute(p));

                                q = path_join(root, p + (*p == '.'));
                                if (!q)
                                        return -ENOMEM;

                                free_and_replace(p, q);
                        }
                }

                *ret_path = TAKE_PTR(p);
        }

        if (ret_fd)
                *ret_fd = TAKE_FD(pfd);

        return r;
}


int chase_extract_filename(const char *path, const char *root, char **ret) {
        int r;

        /* This is similar to path_extract_filename(), but takes root directory.
         * The result should be consistent with chase() with CHASE_EXTRACT_FILENAME. */

        assert(path);
        assert(ret);

        if (isempty(path))
                return -EINVAL;

        if (!path_is_absolute(path))
                return -EINVAL;

        r = empty_or_root_to_null(&root);
        if (r < 0 && r != -ENOENT)
                return r;

        if (!empty_or_root(root)) {
                _cleanup_free_ char *root_abs = NULL;

                r = path_make_absolute_cwd(root, &root_abs);
                if (r < 0)
                        return r;

                path = path_startswith(path, root_abs);
                if (!path)
                        return -EINVAL;
        }

        if (!isempty(path)) {
                r = path_extract_filename(path, ret);
                if (r != -EADDRNOTAVAIL)
                        return r;
        }

        char *fname = strdup(".");
        if (!fname)
                return -ENOMEM;

        *ret = fname;
        return 0;
}
