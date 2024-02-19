/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <threads.h>
#include <sys/utsname.h>
#include <stdio_ext.h>

#include "alloc-util.h"
#include "chase.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "macro.h"
#include "path-util.h"
#include "specifier.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"

/*
 * Generic infrastructure for replacing %x style specifiers in
 * strings. Will call a callback for each replacement.
 */

/* Any ASCII character or digit: our pool of potential specifiers,
 * and "%" used for escaping. */
#define POSSIBLE_SPECIFIERS ALPHANUMERICAL "%"

int specifier_printf(const char *text, size_t max_length, const Specifier table[], const char *root, const void *userdata, char **ret) {
        _cleanup_free_ char *result = NULL;
        bool percent = false;
        size_t l;
        char *t;
        int r;
        void *np;

        assert(ret);
        assert(text);
        assert(table);

        l = strlen(text);
        np = realloc(result, l + 1);
        if (!np)
                return -ENOMEM;
        result = np;
        t = result;

        for (const char *f = text; *f != '\0'; f++, l--) {
                if (percent) {
                        percent = false;

                        if (*f == '%')
                                *(t++) = '%';
                        else {
                                const Specifier *i;

                                for (i = table; i->specifier; i++)
                                        if (i->specifier == *f)
                                                break;

                                if (i->lookup) {
                                        _cleanup_free_ char *w = NULL;
                                        size_t k, j;

                                        r = i->lookup(i->specifier, i->data, root, userdata, &w);
                                        if (r < 0)
                                                return r;
                                        if (isempty(w))
                                                continue;

                                        j = t - result;
                                        k = strlen(w);

                                        np = realloc(result, j + k + l + 1);
                                        if (!np)
                                                return -ENOMEM;
                                        result = np;
                                        memcpy(result + j, w, k);
                                        t = result + j + k;
                                } else if (strchr(POSSIBLE_SPECIFIERS, *f))
                                        /* Oops, an unknown specifier. */
                                        return -EBADSLT;
                                else {
                                        *(t++) = '%';
                                        *(t++) = *f;
                                }
                        }
                } else if (*f == '%')
                        percent = true;
                else
                        *(t++) = *f;

                if ((size_t) (t - result) > max_length)
                        return -ENAMETOOLONG;
        }

        /* If string ended with a stray %, also end with % */
        if (percent) {
                *(t++) = '%';
                if ((size_t) (t - result) > max_length)
                        return -ENAMETOOLONG;
        }
        *(t++) = 0;

        *ret = TAKE_PTR(result);
        return 0;
}

static int fopen_mode_to_flags(const char *mode) {
        const char *p;
        int flags;

        assert(mode);

        if ((p = startswith(mode, "r+")))
                flags = O_RDWR;
        else if ((p = startswith(mode, "r")))
                flags = O_RDONLY;
        else if ((p = startswith(mode, "w+")))
                flags = O_RDWR|O_CREAT|O_TRUNC;
        else if ((p = startswith(mode, "w")))
                flags = O_WRONLY|O_CREAT|O_TRUNC;
        else if ((p = startswith(mode, "a+")))
                flags = O_RDWR|O_CREAT|O_APPEND;
        else if ((p = startswith(mode, "a")))
                flags = O_WRONLY|O_CREAT|O_APPEND;
        else
                return -EINVAL;

        for (; *p != 0; p++) {

                switch (*p) {

                case 'e':
                        flags |= O_CLOEXEC;
                        break;

                case 'x':
                        flags |= O_EXCL;
                        break;

                case 'm':
                        /* ignore this here, fdopen() might care later though */
                        break;

                case 'c': /* not sure what to do about this one */
                default:
                        return -EINVAL;
                }
        }

        return flags;
}

static int xfopenat(int dir_fd, const char *path, const char *mode, int open_flags, FILE **ret) {
        FILE *f;

        /* A combination of fopen() with openat() */

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);
        assert(path);
        assert(mode);
        assert(ret);

        if (dir_fd == AT_FDCWD && open_flags == 0)
                f = fopen(path, mode);
        else {
                _cleanup_close_ int fd = -EBADF;
                int mode_flags;

                mode_flags = fopen_mode_to_flags(mode);
                if (mode_flags < 0)
                        return mode_flags;

                fd = openat(dir_fd, path, mode_flags | open_flags);
                if (fd < 0)
                        return -errno;

                f = take_fdopen(&fd, mode);
        }
        if (!f)
                return -errno;

        *ret = f;
        return 0;
}

/* The maximum size of the file we'll read in one go in read_full_file() (64M). */
#define READ_FULL_BYTES_MAX (64U*1024U*1024U - 1U)

static int read_full_stream(
                FILE *f,
                char **ret_contents,
                size_t *ret_size) {

        _cleanup_free_ char *buf = NULL;
        size_t n, n_next = 0, l;
        int fd, r;

        assert(f);
        assert(ret_contents);

        fd = fileno(f);
        if (fd >= 0) { /* If the FILE* object is backed by an fd (as opposed to memory or such, see
                        * fmemopen()), let's optimize our buffering */
                struct stat st;

                if (fstat(fd, &st) < 0)
                        return -errno;

                if (S_ISREG(st.st_mode)) {

                        /* Try to start with the right file size if we shall read the file in full. Note
                         * that we increase the size to read here by one, so that the first read attempt
                         * already makes us notice the EOF. If the reported size of the file is zero, we
                         * avoid this logic however, since quite likely it might be a virtual file in procfs
                         * that all report a zero file size. */

                        if (st.st_size > 0) {

                                uint64_t rsize =
                                        LESS_BY((uint64_t) st.st_size, 0);

                                if (rsize < SIZE_MAX) /* overflow check */
                                        n_next = rsize + 1;
                        }
                }
        }

        if (n_next == 0)
                n_next = LINE_MAX;

        /* Never read more than we need to determine that our own limit is hit */
        if (n_next > READ_FULL_BYTES_MAX)
                n_next = READ_FULL_BYTES_MAX + 1;

        n = l = 0;
        for (;;) {
                char *t;
                size_t k;

                t = realloc(buf, n_next + 1);
                if (!t)
                        return -ENOMEM;

                buf = t;
                n = n_next;

                errno = 0;
                k = fread(buf + l, 1, n - l, f);

                assert(k <= n - l);
                l += k;

                if (ferror(f)) {
                        r = errno_or_else(EIO);
                        goto finalize;
                }
                if (feof(f))
                        break;

                assert(k > 0); /* we can't have read zero bytes because that would have been EOF */

                if (n >= READ_FULL_BYTES_MAX) {
                        r = -E2BIG;
                        goto finalize;
                }

                n_next = MIN(n * 2, READ_FULL_BYTES_MAX);
        }

        if (!ret_size) {
                /* Safety check: if the caller doesn't want to know the size of what we just read it will rely on the
                 * trailing NUL byte. But if there's an embedded NUL byte, then we should refuse operation as otherwise
                 * there'd be ambiguity about what we just read. */

                if (memchr(buf, 0, l)) {
                        r = -EBADMSG;
                        goto finalize;
                }
        }

        buf[l] = 0;
        *ret_contents = TAKE_PTR(buf);

        if (ret_size)
                *ret_size = l;

        return 0;

finalize:
        return r;
}

static int read_full_file_(
                const char *filename,
                char **ret_contents,
                size_t *ret_size) {

        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(filename);
        assert(ret_contents);

        r = xfopenat(AT_FDCWD, filename, "re", 0, &f);
        if (r < 0)
                return r;

        (void) __fsetlocking(f, FSETLOCKING_BYCALLER);

        return read_full_stream(f, ret_contents, ret_size);
}

int specifier_machine_id(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        if (empty_or_root(root))
                /* Shortcut this call if none of the special features of this call are requested */
                r = RET_NERRNO(xfopenat(AT_FDCWD, "/etc/machine-id", "re",
                                        O_RDONLY|O_CLOEXEC|O_NOCTTY, &f));
        else {
                _cleanup_close_ int path_fd = -EBADF;
                _cleanup_free_ char *p = NULL, *fname = NULL;

                r = chase("/etc/machine-id", root, CHASE_PARENT|CHASE_PREFIX_ROOT, &p, &path_fd);
                if (r < 0) {
                        if (r == -ENOENT) return -EUNATCH;
                        return r;
                }
                assert(path_fd >= 0);

                r = chase_extract_filename(p, root, &fname);
                if (r < 0)
                        return r;

                r = xfopenat(path_fd, strempty(fname), "re", O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW, &f);
        }
        if (r < 0) {
                if (r == -ENOENT) return -EUNATCH;
                return r;
        }

        return read_full_stream(f, ret, NULL);
}

int specifier_boot_id(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        char *src, *dest;
        int r = read_full_file_("/proc/sys/kernel/random/boot_id", ret, NULL);
        if (r < 0) {
                if (r == -ENOENT) return -EUNATCH;
                return r;
        }

        /* turn into 128-bit id */
        src = dest = *ret;
        for (; *src; ++src) {
                if (*src == '-') continue;
                *dest++ = *src;
        }
        *dest = '\0';

        return 0;
}

static char *gethostname_str(bool shrt) {
        struct utsname u;
        const char *s;

        if (uname(&u) < 0) return NULL;

        s = u.nodename;
        if (isempty(s) || streq(s, "(none)") || (shrt && s[0] == '.')) {
                s = "localhost";
        }

        if (shrt) return strdupcspn(s, ".");
        return strdup(s);
}

int specifier_hostname(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        char *n;

        assert(ret);

        n = gethostname_str(false);
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

int specifier_short_hostname(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        char *n;

        assert(ret);

        n = gethostname_str(true);
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

int specifier_kernel_release(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        struct utsname uts;
        char *n;

        assert(ret);

        if (uname(&uts) < 0)
                return -errno;

        n = strdup(uts.release);
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

int specifier_architecture(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        char *t;
        struct utsname buf;

        assert(ret);

        if (uname(&buf) < 0)
                return -errno;

        t = strdup(buf.machine);
        if (!t)
                return -ENOMEM;

        *ret = t;
        return 0;
}

static int fdopen_independent(int fd, const char *mode, FILE **ret) {
        _cleanup_close_ int copy_fd = -EBADF;
        _cleanup_fclose_ FILE *f = NULL;
        int mode_flags;

        assert(fd >= 0);
        assert(mode);
        assert(ret);

        /* A combination of fdopen() + fd_reopen(). i.e. reopens the inode the specified fd points to and
         * returns a FILE* for it */

        mode_flags = fopen_mode_to_flags(mode);
        if (mode_flags < 0)
                return mode_flags;

        /* Flags returned by fopen_mode_to_flags might contain O_CREAT, but it doesn't make sense for fd_reopen
         * since we're working on an existing fd anyway. Let's drop it here to avoid triggering assertion. */
        copy_fd = fd_reopen(fd, mode_flags & ~O_CREAT);
        if (copy_fd < 0)
                return copy_fd;

        f = take_fdopen(&copy_fd, mode);
        if (!f)
                return -errno;

        *ret = TAKE_PTR(f);
        return 0;
}

static int parse_env_file_fd(
                int fd,
                const char *fname, /* only used for logging */
                const char *okey,
                char **ovalue) {
        _cleanup_fclose_ FILE *f = NULL;
        size_t n_key = 0, n_value = 0, last_value_whitespace = SIZE_MAX, last_key_whitespace = SIZE_MAX;
        _cleanup_free_ char *contents = NULL, *key = NULL, *value = NULL;
        void *np;
        int r;

        assert(fd >= 0);

        r = fdopen_independent(fd, "re", &f);
        if (r < 0)
                return r;

        enum {
                PRE_KEY,
                KEY,
                PRE_VALUE,
                VALUE,
                VALUE_ESCAPE,
                SINGLE_QUOTE_VALUE,
                DOUBLE_QUOTE_VALUE,
                DOUBLE_QUOTE_VALUE_ESCAPE,
                COMMENT,
                COMMENT_ESCAPE
        } state = PRE_KEY;

        assert(f || fname);

        if (f)
                r = read_full_stream(f, &contents, NULL);
        else
                r = read_full_file_(fname, &contents, NULL);
        if (r < 0)
                return r;

        for (char *p = contents; *p; p++) {
                char c = *p;

                switch (state) {

                case PRE_KEY:
                        if (strchr(COMMENTS, c))
                                state = COMMENT;
                        else if (!strchr(WHITESPACE, c)) {
                                state = KEY;
                                last_key_whitespace = SIZE_MAX;

                                np = realloc(key, n_key + 2);
                                if (!np)
                                        return -ENOMEM;
                                key = np;

                                key[n_key++] = c;
                        }
                        break;

                case KEY:
                        if (strchr(NEWLINE, c)) {
                                state = PRE_KEY;
                                n_key = 0;
                        } else if (c == '=') {
                                state = PRE_VALUE;
                                last_value_whitespace = SIZE_MAX;
                        } else {
                                if (!strchr(WHITESPACE, c))
                                        last_key_whitespace = SIZE_MAX;
                                else if (last_key_whitespace == SIZE_MAX)
                                         last_key_whitespace = n_key;

                                np = realloc(key, n_key + 2);
                                if (!np)
                                        return -ENOMEM;
                                key = np;

                                key[n_key++] = c;
                        }

                        break;

                case PRE_VALUE:
                        if (strchr(NEWLINE, c)) {
                                state = PRE_KEY;
                                key[n_key] = 0;

                                if (value)
                                        value[n_value] = 0;

                                /* strip trailing whitespace from key */
                                if (last_key_whitespace != SIZE_MAX)
                                        key[last_key_whitespace] = 0;

                                if (streq(key, okey)) {
                                        free_and_replace(*ovalue, value);
                                }
                                free(value);

                                n_key = 0;
                                value = NULL;
                                n_value = 0;

                        } else if (c == '\'')
                                state = SINGLE_QUOTE_VALUE;
                        else if (c == '"')
                                state = DOUBLE_QUOTE_VALUE;
                        else if (c == '\\')
                                state = VALUE_ESCAPE;
                        else if (!strchr(WHITESPACE, c)) {
                                state = VALUE;

                                np = realloc(value, n_value + 2);
                                if (!np)
                                        return -ENOMEM;
                                value = np;

                                value[n_value++] = c;
                        }

                        break;

                case VALUE:
                        if (strchr(NEWLINE, c)) {
                                state = PRE_KEY;

                                key[n_key] = 0;

                                if (value)
                                        value[n_value] = 0;

                                /* Chomp off trailing whitespace from value */
                                if (last_value_whitespace != SIZE_MAX)
                                        value[last_value_whitespace] = 0;

                                /* strip trailing whitespace from key */
                                if (last_key_whitespace != SIZE_MAX)
                                        key[last_key_whitespace] = 0;

                                if (streq(key, okey)) {
                                        free_and_replace(*ovalue, value);
                                }
                                free(value);

                                n_key = 0;
                                value = NULL;
                                n_value = 0;

                        } else if (c == '\\') {
                                state = VALUE_ESCAPE;
                                last_value_whitespace = SIZE_MAX;
                        } else {
                                if (!strchr(WHITESPACE, c))
                                        last_value_whitespace = SIZE_MAX;
                                else if (last_value_whitespace == SIZE_MAX)
                                        last_value_whitespace = n_value;

                                np = realloc(value, n_value + 2);
                                if (!np)
                                        return -ENOMEM;
                                value = np;

                                value[n_value++] = c;
                        }

                        break;

                case VALUE_ESCAPE:
                        state = VALUE;

                        if (!strchr(NEWLINE, c)) {
                                /* Escaped newlines we eat up entirely */
                                np = realloc(value, n_value + 2);
                                if (!np)
                                        return -ENOMEM;
                                value = np;

                                value[n_value++] = c;
                        }
                        break;

                case SINGLE_QUOTE_VALUE:
                        if (c == '\'')
                                state = PRE_VALUE;
                        else {
                                np = realloc(value, n_value + 2);
                                if (!np)
                                        return -ENOMEM;
                                value = np;

                                value[n_value++] = c;
                        }

                        break;

                case DOUBLE_QUOTE_VALUE:
                        if (c == '"')
                                state = PRE_VALUE;
                        else if (c == '\\')
                                state = DOUBLE_QUOTE_VALUE_ESCAPE;
                        else {
                                np = realloc(value, n_value + 2);
                                if (!np)
                                        return -ENOMEM;
                                value = np;

                                value[n_value++] = c;
                        }

                        break;

                case DOUBLE_QUOTE_VALUE_ESCAPE:
                        state = DOUBLE_QUOTE_VALUE;

                        if (strchr("\"\\`$", c)) {
                                /* If this is a char that needs escaping, just unescape it. */
                                np = realloc(value, n_value + 2);
                                if (!np)
                                        return -ENOMEM;
                                value = np;
                                value[n_value++] = c;
                        } else if (c != '\n') {
                                /* If other char than what needs escaping, keep the "\" in place, like the
                                 * real shell does. */
                                np = realloc(value, n_value + 3);
                                if (!np)
                                        return -ENOMEM;
                                value = np;
                                value[n_value++] = '\\';
                                value[n_value++] = c;
                        }

                        /* Escaped newlines (aka "continuation lines") are eaten up entirely */
                        break;

                case COMMENT:
                        if (c == '\\')
                                state = COMMENT_ESCAPE;
                        else if (strchr(NEWLINE, c)) {
                                state = PRE_KEY;
                        }
                        break;

                case COMMENT_ESCAPE:
                        log_debug("The line which doesn't begin with \";\" or \"#\", but follows a comment" \
                                  " line trailing with escape is now treated as a non comment line since v254.");
                        if (strchr(NEWLINE, c)) {
                                state = PRE_KEY;
                        } else
                                state = COMMENT;
                        break;
                }
        }

        if (IN_SET(state,
                   PRE_VALUE,
                   VALUE,
                   VALUE_ESCAPE,
                   SINGLE_QUOTE_VALUE,
                   DOUBLE_QUOTE_VALUE,
                   DOUBLE_QUOTE_VALUE_ESCAPE)) {

                key[n_key] = 0;

                if (value)
                        value[n_value] = 0;

                if (state == VALUE)
                        if (last_value_whitespace != SIZE_MAX)
                                value[last_value_whitespace] = 0;

                /* strip trailing whitespace from key */
                if (last_key_whitespace != SIZE_MAX)
                        key[last_key_whitespace] = 0;

                if (streq(key, okey)) {
                        free_and_replace(*ovalue, value);
                }
                free(value);

                value = NULL;
        }

        return 0;
}

/* Note: fields in /etc/os-release might quite possibly be missing, even if everything is entirely valid
 * otherwise. We'll return an empty value or NULL in that case from the functions below. But if the
 * os-release file is missing, we'll return -EUNATCH. This means that something is seriously wrong with the
 * installation. */

static int parse_os_release_specifier(const char *root, const char *id, char **ret) {
        _cleanup_close_ int rfd = -EBADF, fd = -EBADF;
        _cleanup_free_ char *p = NULL;
        _cleanup_free_ char *v = NULL;
        int r;

        assert(ret);

        rfd = open(empty_to_root(root), O_CLOEXEC | O_DIRECTORY | O_PATH);
        if (rfd < 0)
                return -errno;

        FOREACH_STRING(path, "/etc/os-release", "/usr/lib/os-release") {
                r = chaseat(rfd, path, CHASE_AT_RESOLVE_IN_ROOT, &p, &fd);
                if (r < 0 && r != -ENOENT)
                        return r;
        }
        if (r < 0)
                return r;

        r =  parse_env_file_fd(fd, p, id, &v);
        if (r >= 0)
                /* parse_os_release() calls parse_env_file() which only sets the return value for
                 * entries found. Let's make sure we set the return value in all cases. */
                *ret = TAKE_PTR(v);

        /* Translate error for missing os-release file to EUNATCH. */
        return r == -ENOENT ? -EUNATCH : r;
}

int specifier_os_id(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        return parse_os_release_specifier(root, "ID", ret);
}

int specifier_os_version_id(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        return parse_os_release_specifier(root, "VERSION_ID", ret);
}

int specifier_os_build_id(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        return parse_os_release_specifier(root, "BUILD_ID", ret);
}

int specifier_os_variant_id(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        return parse_os_release_specifier(root, "VARIANT_ID", ret);
}

int specifier_os_image_id(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        return parse_os_release_specifier(root, "IMAGE_ID", ret);
}

int specifier_os_image_version(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        return parse_os_release_specifier(root, "IMAGE_VERSION", ret);
}

int specifier_tmp_dir(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        const char *p;
        char *copy;
        int r;

        assert(ret);

        if (root) /* If root dir is set, don't honour $TMP or similar */
                p = "/tmp";
        else {
                r = tmp_dir(&p);
                if (r < 0)
                        return r;
        }
        copy = strdup(p);
        if (!copy)
                return -ENOMEM;

        *ret = copy;
        return 0;
}

int specifier_var_tmp_dir(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        const char *p;
        char *copy;
        int r;

        assert(ret);

        if (root)
                p = "/var/tmp";
        else {
                r = var_tmp_dir(&p);
                if (r < 0)
                        return r;
        }
        copy = strdup(p);
        if (!copy)
                return -ENOMEM;

        *ret = copy;
        return 0;
}
