/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "chase.h"
#include "conf-files.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hashmap.h"
#include "log.h"
#include "macro.h"
#include "path-util.h"
#include "set.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"

static int files_add(
                DIR *dir,
                const char *dirpath,
                Hashmap **files,
                Set **masked,
                const char *suffix) {

        int r;

        assert(dir);
        assert(dirpath);
        assert(files);
        assert(masked);

        FOREACH_DIRENT(de, dir, return -errno) {
                _cleanup_free_ char *n = NULL, *p = NULL;

                /* Does this match the suffix? */
                if (suffix && !endswith(de->d_name, suffix))
                        continue;

                /* Has this file already been found in an earlier directory? */
                if (hashmap_contains(*files, de->d_name)) {
                        log_debug("Skipping overridden file '%s/%s'.", dirpath, de->d_name);
                        continue;
                }

                n = strdup(de->d_name);
                if (!n)
                        return -ENOMEM;

                p = path_join(dirpath, de->d_name);
                if (!p)
                        return -ENOMEM;

                r = hashmap_ensure_put(files, &string_hash_ops_free_free, n, p);
                if (r < 0)
                        return r;
                assert(r > 0);

                TAKE_PTR(n);
                TAKE_PTR(p);
        }

        return 0;
}

static int base_cmp(const void *a, const void *b) {
        return path_compare_filename(*((const char **)a), *((const char **)b));
}

static int copy_and_sort_files_from_hashmap(Hashmap *fh, char ***ret) {
        _cleanup_free_ char **sv = NULL;
        char **files;
        size_t len;

        assert(ret);

        sv = hashmap_get_strv(fh);
        if (!sv)
                return -ENOMEM;

        /* The entries in the array given by hashmap_get_strv() are still owned by the hashmap. */
        files = strv_copy(sv);
        if (!files)
                return -ENOMEM;

        len = strv_length(files);

        if (len > 0)
                qsort(files, len, sizeof(char *), base_cmp);

        *ret = files;
        return 0;
}

static int conf_files_list_strv(
                char ***ret,
                const char *suffix,
                const char *root,
                const char * const *dirs) {

        _cleanup_hashmap_free_ Hashmap *fh = NULL;
        _cleanup_set_free_ Set *masked = NULL;
        int r;

        assert(ret);

        STRV_FOREACH(p, dirs) {
                _cleanup_close_ int path_fd = -EBADF;
                _cleanup_closedir_ DIR *dir = NULL;
                _cleanup_free_ char *path = NULL;

                r = chase(*p, root, CHASE_PREFIX_ROOT, &path, &path_fd);
                if (r >= 0) {
                        dir = xopendirat(path_fd, ".", O_NOFOLLOW);
                        if (!dir)
                                r = -errno;
                }
                if (r < 0) {
                        if (r != -ENOENT)
                                log_debug_errno(r, "Failed to chase and open directory '%s', ignoring: %m", *p);
                        continue;
                }

                r = files_add(dir, path, &fh, &masked, suffix);
                if (r == -ENOMEM)
                        return r;
                if (r < 0)
                        log_debug_errno(r, "Failed to search for files in '%s', ignoring: %m", path);
        }

        return copy_and_sort_files_from_hashmap(fh, ret);
}

static int conf_files_insert(char ***strv, const char *root, char **dirs, const char *path) {
        /* Insert a path into strv, at the place honouring the usual sorting rules:
         * - we first compare by the basename
         * - and then we compare by dirname, allowing just one file with the given
         *   basename.
         * This means that we will
         * - add a new entry if basename(path) was not on the list,
         * - do nothing if an entry with higher priority was already present,
         * - do nothing if our new entry matches the existing entry,
         * - replace the existing entry if our new entry has higher priority.
         */
        size_t i, n;
        char *t;
        int r;

        n = strv_length(*strv);
        for (i = 0; i < n; i++) {
                int c;

                c = base_cmp((char* const*) *strv + i, (char* const*) &path);
                if (c == 0)
                        /* Oh, there already is an entry with a matching name (the last component). */
                        STRV_FOREACH(dir, dirs) {
                                _cleanup_free_ char *rdir = NULL;
                                char *p1, *p2;

                                rdir = path_join(root, *dir);
                                if (!rdir)
                                        return -ENOMEM;

                                p1 = path_startswith((*strv)[i], rdir);
                                if (p1)
                                        /* Existing entry with higher priority
                                         * or same priority, no need to do anything. */
                                        return 0;

                                p2 = path_startswith(path, *dir);
                                if (p2) {
                                        /* Our new entry has higher priority */

                                        t = path_join(root, path);
                                        if (!t)
                                                return log_oom();

                                        return free_and_replace((*strv)[i], t);
                                }
                        }

                else if (c > 0)
                        /* Following files have lower priority, let's go insert our
                         * new entry. */
                        break;

                /* … we are not there yet, let's continue */
        }

        /* The new file has lower priority than all the existing entries */
        t = path_join(root, path);
        if (!t)
                return -ENOMEM;

        r = strv_insert(strv, i, t);
        if (r < 0)
                free(t);

        return r;
}

int conf_files_list_with_replacement(
                const char *root,
                char **config_dirs,
                const char *replacement,
                char ***ret_files,
                char **ret_replace_file) {

        _cleanup_strv_free_ char **f = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(config_dirs);
        assert(ret_files);
        assert(ret_replace_file || !replacement);

        r = conf_files_list_strv(&f, ".conf", root, (const char* const*) config_dirs);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate config files: %m");

        if (replacement) {
                r = conf_files_insert(&f, root, config_dirs, replacement);
                if (r < 0)
                        return log_error_errno(r, "Failed to extend config file list: %m");

                p = path_join(root, replacement);
                if (!p)
                        return log_oom();
        }

        *ret_files = TAKE_PTR(f);
        if (ret_replace_file)
                *ret_replace_file = TAKE_PTR(p);

        return 0;
}

typedef enum {
        LINE_SECTION,
        LINE_COMMENT,
        LINE_NORMAL,
} LineType;

static LineType classify_line_type(const char *line, CatFlags flags) {
        const char *t = skip_leading_chars(line, WHITESPACE);

        if ((flags & CAT_FORMAT_HAS_SECTIONS) && *t == '[')
                return LINE_SECTION;
        if (IN_SET(*t, '#', ';', '\0'))
                return LINE_COMMENT;
        return LINE_NORMAL;
}

static int cat_file(const char *filename, bool newline, CatFlags flags) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *section = NULL, *old_section = NULL;
        int r;

        f = fopen(filename, "re");
        if (!f)
                return -errno;

        printf("%s# %s\n",
               newline ? "\n" : "",
               filename);
        fflush(stdout);

        for (;;) {
                _cleanup_free_ char *line = NULL;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read \"%s\": %m", filename);
                if (r == 0)
                        break;

                LineType line_type = classify_line_type(line, flags);
                if (flags & CAT_TLDR) {
                        if (line_type == LINE_SECTION) {
                                /* The start of a section, let's not print it yet. */
                                free_and_replace(section, line);
                                continue;
                        }

                        if (line_type == LINE_COMMENT)
                                continue;

                        /* Before we print the actual line, print the last section header */
                        if (section) {
                                /* Do not print redundant section headers */
                                if (!streq_ptr(section, old_section))
                                        printf("%s%s%s\n",
                                               "",
                                               section,
                                               "");

                                free_and_replace(old_section, section);
                        }
                }

                printf("%s%s%s\n",
                       line_type == LINE_SECTION ? "" :
                       line_type == LINE_COMMENT ? "" :
                       "",
                       line,
                       line_type != LINE_NORMAL ? "" : "");
        }

        return 0;
}

int cat_files(const char *file, char **dropins, CatFlags flags) {
        int r;

        if (file) {
                r = cat_file(file, /* newline= */ false, flags);
                if (r < 0)
                        return log_warning_errno(r, "Failed to cat %s: %m", file);
        }

        STRV_FOREACH(path, dropins) {
                r = cat_file(*path, /* newline= */ file || path != dropins, flags);
                if (r < 0)
                        return log_warning_errno(r, "Failed to cat %s: %m", *path);
        }

        return 0;
}

int conf_file_read(
                const char *root,
                const char **config_dirs,
                const char *fn,
                parse_line_t parse_line,
                void *userdata,
                bool ignore_enoent,
                bool *invalid_config) {

        _cleanup_fclose_ FILE *_f = NULL;
        _cleanup_free_ char *_fn = NULL;
        unsigned v = 0;
        FILE *f;
        int r = 0;

        assert(fn);

        if (streq(fn, "-")) {
                f = stdin;
                fn = "<stdin>";

                log_debug("Reading config from stdin...");

        } else if (is_path(fn)) {
                r = path_make_absolute_cwd(fn, &_fn);
                if (r < 0)
                        return log_error_errno(r, "Failed to make path absolute: %m");
                fn = _fn;

                f = _f = fopen(fn, "re");
                if (!_f)
                        r = -errno;
                else
                        log_debug("Reading config file \"%s\"...", fn);

        } else {
                r = search_and_fopen_re(fn, root, config_dirs, &_f, &_fn);
                if (r >= 0) {
                        f = _f;
                        fn = _fn;
                        log_debug("Reading config file \"%s\"...", fn);
                }
        }

        if (r == -ENOENT && ignore_enoent) {
                log_debug_errno(r, "Failed to open \"%s\", ignoring: %m", fn);
                return 0; /* No error, but nothing happened. */
        }
        if (r < 0)
                return log_error_errno(r, "Failed to read '%s': %m", fn);

        r = 1;  /* We entered the part where we may modify state. */

        for (;;) {
                _cleanup_free_ char *line = NULL;
                bool invalid_line = false;
                int k;

                k = read_stripped_line(f, LONG_LINE_MAX, &line);
                if (k < 0)
                        return log_error_errno(k, "Failed to read '%s': %m", fn);
                if (k == 0)
                        break;

                v++;

                if (IN_SET(line[0], 0, '#'))
                        continue;

                k = parse_line(fn, v, line, invalid_config ? &invalid_line : NULL, userdata);
                if (k < 0 && invalid_line)
                        /* Allow reporting with a special code if the caller requested this. */
                        *invalid_config = true;
                else {
                        /* The first error, if any, becomes our return value. */
                        if (r >= 0 && k < 0)
                                r = k;
                }
        }

        if (ferror(f)) {
                int k = log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to read from file %s.", fn);
                if (r >= 0)
                        r = k;
        }

        return r;
}
