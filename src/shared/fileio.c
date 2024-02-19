/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "chase.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "macro.h"
#include "mkdir.h"
#include "path-util.h"
#include "string-util.h"
#include "tmpfile-util.h"

int fdopen_unlocked(int fd, const char *options, FILE **ret) {
        assert(ret);

        FILE *f = fdopen(fd, options);
        if (!f)
                return -errno;

        (void) __fsetlocking(f, FSETLOCKING_BYCALLER);

        *ret = f;
        return 0;
}

int take_fdopen_unlocked(int *fd, const char *options, FILE **ret) {
        int r;

        assert(fd);

        r = fdopen_unlocked(*fd, options, ret);
        if (r < 0)
                return r;

        *fd = -EBADF;

        return 0;
}

FILE* take_fdopen(int *fd, const char *options) {
        assert(fd);

        FILE *f = fdopen(*fd, options);
        if (!f)
                return NULL;

        *fd = -EBADF;

        return f;
}

DIR* take_fdopendir(int *dfd) {
        assert(dfd);

        DIR *d = fdopendir(*dfd);
        if (!d)
                return NULL;

        *dfd = -EBADF;

        return d;
}

DIR *xopendirat(int fd, const char *name, int flags) {
        _cleanup_close_ int nfd = -EBADF;

        assert(!(flags & O_CREAT));

        if (fd == AT_FDCWD && flags == 0)
                return opendir(name);

        nfd = openat(fd, name, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|flags, 0);
        if (nfd < 0)
                return NULL;

        return take_fdopendir(&nfd);
}

static int search_and_open_internal(
                const char *path,
                int mode,            /* if ret_fd is NULL this is an [FRWX]_OK mode for access(), otherwise an open mode for open() */
                const char *root,
                char **search,
                int *ret_fd,
                char **ret_path) {

        int r;

        assert(!ret_fd || !FLAGS_SET(mode, O_CREAT)); /* We don't support O_CREAT for this */
        assert(path);

        if (path_is_absolute(path)) {
                _cleanup_close_ int fd = -EBADF;

                if (ret_fd)
                        /* We only specify 0777 here to appease static analyzers, it's never used since we
                         * don't support O_CREAT here */
                        r = fd = RET_NERRNO(open(path, mode, 0777));
                else
                        r = RET_NERRNO(access(path, mode));
                if (r < 0)
                        return r;

                if (ret_path) {
                        r = path_simplify_alloc(path, ret_path);
                        if (r < 0)
                                return r;
                }

                if (ret_fd)
                        *ret_fd = TAKE_FD(fd);

                return 0;
        }

        if (!path_strv_resolve_uniq(search, root))
                return -ENOMEM;

        STRV_FOREACH(i, search) {
                _cleanup_close_ int fd = -EBADF;
                _cleanup_free_ char *p = NULL;

                p = path_join(root, *i, path);
                if (!p)
                        return -ENOMEM;

                if (ret_fd)
                        /* as above, 0777 is static analyzer appeasement */
                        r = fd = RET_NERRNO(open(p, mode, 0777));
                else
                        r = RET_NERRNO(access(p, F_OK));
                if (r >= 0) {
                        if (ret_path)
                                *ret_path = path_simplify(TAKE_PTR(p));

                        if (ret_fd)
                                *ret_fd = TAKE_FD(fd);

                        return 0;
                }
                if (r != -ENOENT)
                        return r;
        }

        return -ENOENT;
}

static int search_and_open(
                const char *path,
                int mode,
                const char *root,
                char **search,
                int *ret_fd,
                char **ret_path) {

        _cleanup_strv_free_ char **copy = NULL;

        assert(path);

        copy = strv_copy((char**) search);
        if (!copy)
                return -ENOMEM;

        return search_and_open_internal(path, mode, root, copy, ret_fd, ret_path);
}

static int search_and_fopen_internal(
                const char *path,
                const char *root,
                char **search,
                FILE **ret_file,
                char **ret_path) {

        _cleanup_free_ char *found_path = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(path);

        r = search_and_open(
                        path,
                        O_RDONLY|O_CLOEXEC,
                        root,
                        search,
                        ret_file ? &fd : NULL,
                        ret_path ? &found_path : NULL);
        if (r < 0)
                return r;

        if (ret_file) {
                FILE *f = take_fdopen(&fd, "re");
                if (!f)
                        return -errno;

                *ret_file = f;
        }

        if (ret_path)
                *ret_path = TAKE_PTR(found_path);

        return 0;
}

int search_and_fopen_re(
                const char *path,
                const char *root,
                const char **search,
                FILE **ret_file,
                char **ret_path) {

        _cleanup_strv_free_ char **copy = NULL;

        assert(path);

        copy = strv_copy((char**) search);
        if (!copy)
                return -ENOMEM;

        return search_and_fopen_internal(path, root, copy, ret_file, ret_path);
}

/* A bitmask of the EOL markers we know */
typedef enum EndOfLineMarker {
        EOL_NONE     = 0,
        EOL_ZERO     = 1 << 0,  /* \0 (aka NUL) */
        EOL_TEN      = 1 << 1,  /* \n (aka NL, aka LF)  */
        EOL_THIRTEEN = 1 << 2,  /* \r (aka CR)  */
} EndOfLineMarker;

static EndOfLineMarker categorize_eol(char c) {
        if (c == '\n')
                return EOL_TEN;
        if (c == '\r')
                return EOL_THIRTEEN;
        if (c == '\0')
                return EOL_ZERO;

        return EOL_NONE;
}

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(FILE*, funlockfile, NULL);

static int safe_fgetc(FILE *f, char *ret) {
        int k;

        assert(f);

        /* A safer version of plain fgetc(): let's propagate the error that happened while reading as such, and
         * separate the EOF condition from the byte read, to avoid those confusion signed/unsigned issues fgetc()
         * has. */

        errno = 0;
        k = fgetc(f);
        if (k == EOF) {
                if (ferror(f))
                        return errno_or_else(EIO);

                if (ret)
                        *ret = 0;

                return 0;
        }

        if (ret)
                *ret = k;

        return 1;
}

int read_line(FILE *f, size_t limit, char **ret) {
        _cleanup_free_ char *buffer = NULL;
        size_t n = 0, count = 0;
        void *np;
        int r;

        assert(f);

        /* Something like a bounded version of getline().
         *
         * Considers EOF, \n, \r and \0 end of line delimiters (or combinations of these), and does not include these
         * delimiters in the string returned. Specifically, recognizes the following combinations of markers as line
         * endings:
         *
         *     • \n        (UNIX)
         *     • \r        (old MacOS)
         *     • \0        (C strings)
         *     • \n\0
         *     • \r\0
         *     • \r\n      (Windows)
         *     • \n\r
         *     • \r\n\0
         *     • \n\r\0
         *
         * Returns the number of bytes read from the files (i.e. including delimiters — this hence usually differs from
         * the number of characters in the returned string). When EOF is hit, 0 is returned.
         *
         * The input parameter limit is the maximum numbers of characters in the returned string, i.e. excluding
         * delimiters. If the limit is hit we fail and return -ENOBUFS.
         *
         * If a line shall be skipped ret may be initialized as NULL. */

        if (ret) {
                buffer = realloc(buffer, 1);
                if (!buffer)
                        return -ENOMEM;
        }

        {
                _unused_ _cleanup_(funlockfilep) FILE *flocked = f;
                EndOfLineMarker previous_eol = EOL_NONE;
                flockfile(f);

                for (;;) {
                        EndOfLineMarker eol;
                        char c;

                        if (n >= limit)
                                return -ENOBUFS;

                        if (count >= INT_MAX) /* We couldn't return the counter anymore as "int", hence refuse this */
                                return -ENOBUFS;

                        r = safe_fgetc(f, &c);
                        if (r < 0)
                                return r;
                        if (r == 0) /* EOF is definitely EOL */
                                break;

                        eol = categorize_eol(c);

                        if (FLAGS_SET(previous_eol, EOL_ZERO) ||
                            (eol == EOL_NONE && previous_eol != EOL_NONE) ||
                            (eol != EOL_NONE && (previous_eol & eol) != 0)) {
                                /* Previous char was a NUL? This is not an EOL, but the previous char was? This type of
                                 * EOL marker has been seen right before?  In either of these three cases we are
                                 * done. But first, let's put this character back in the queue. (Note that we have to
                                 * cast this to (unsigned char) here as ungetc() expects a positive 'int', and if we
                                 * are on an architecture where 'char' equals 'signed char' we need to ensure we don't
                                 * pass a negative value here. That said, to complicate things further ungetc() is
                                 * actually happy with most negative characters and implicitly casts them back to
                                 * positive ones as needed, except for \xff (aka -1, aka EOF), which it refuses. What a
                                 * godawful API!) */
                                assert_se(ungetc((unsigned char) c, f) != EOF);
                                break;
                        }

                        count++;

                        if (eol != EOL_NONE) {
                                previous_eol |= eol;
                                continue;
                        }

                        if (ret) {
                                np = realloc(buffer, n + 2);
                                if (!np)
                                        return -ENOMEM;
                                buffer = np;

                                buffer[n] = c;
                        }

                        n++;
                }
        }

        if (ret) {
                buffer[n] = 0;

                *ret = TAKE_PTR(buffer);
        }

        return (int) count;
}

int read_stripped_line(FILE *f, size_t limit, char **ret) {
        _cleanup_free_ char *s = NULL;
        int r;

        assert(f);

        r = read_line(f, limit, ret ? &s : NULL);
        if (r < 0)
                return r;

        if (ret) {
                const char *p;

                p = strstrip(s);
                if (p == s)
                        *ret = TAKE_PTR(s);
                else {
                        char *copy;

                        copy = strdup(p);
                        if (!copy)
                                return -ENOMEM;

                        *ret = copy;
                }
        }

        return r;
}
