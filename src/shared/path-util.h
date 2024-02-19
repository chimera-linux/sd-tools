/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <alloca.h>
#include <stdbool.h>
#include <stddef.h>

#include "macro.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"

static inline bool is_path(const char *p) {
        if (!p) /* A NULL pointer is definitely not a path */
                return false;

        return strchr(p, '/');
}

static inline bool path_is_absolute(const char *p) {
        if (!p) /* A NULL pointer is definitely not an absolute path */
                return false;

        return p[0] == '/';
}

int safe_getcwd(char **ret);
int path_make_absolute_cwd(const char *p, char **ret);
int path_make_relative(const char *from, const char *to, char **ret);
int path_make_relative_parent(const char *from_child, const char *to, char **ret);
char* path_startswith_full(const char *path, const char *prefix, bool accept_dot_dot) _pure_;
static inline char* path_startswith(const char *path, const char *prefix) {
        return path_startswith_full(path, prefix, true);
}

int path_compare(const char *a, const char *b) _pure_;
static inline bool path_equal(const char *a, const char *b) {
        return path_compare(a, b) == 0;
}

int path_compare_filename(const char *a, const char *b);

char* path_extend_internal(char **x, ...);
#define path_extend(x, ...) path_extend_internal(x, __VA_ARGS__, (void *) UINTPTR_MAX)
#define path_join(...) path_extend_internal(NULL, __VA_ARGS__, (void *) UINTPTR_MAX)

char* path_simplify(char *path);

static inline int path_simplify_alloc(const char *path, char **ret) {
        assert(ret);

        if (!path) {
                *ret = NULL;
                return 0;
        }

        char *t = strdup(path);
        if (!t)
                return -ENOMEM;

        *ret = path_simplify(t);
        return 0;
}

static inline bool path_equal_ptr(const char *a, const char *b) {
        return !!a == !!b && (!a || path_equal(a, b));
}

/* Note: the search terminates on the first NULL item. */
#define PATH_IN_SET(p, ...) path_strv_contains(STRV_MAKE(__VA_ARGS__), p)

int path_strv_make_absolute_cwd(char **l);
char** path_strv_resolve(char **l, const char *root);
char** path_strv_resolve_uniq(char **l, const char *root);

/* Iterates through the path prefixes of the specified path, going up
 * the tree, to root. Also returns "" (and not "/"!) for the root
 * directory. Excludes the specified directory itself */
#define PATH_FOREACH_PREFIX(prefix, path)                               \
        for (char *_slash = ({                                          \
                                path_simplify(strcpy(prefix, path));    \
                                streq(prefix, "/") ? NULL : strrchr(prefix, '/'); \
                        });                                             \
             _slash && ((*_slash = 0), true);                           \
             _slash = strrchr((prefix), '/'))

int path_find_first_component(const char **p, bool accept_dot_dot, const char **ret);
int path_find_last_component(const char *path, bool accept_dot_dot, const char **next, const char **ret);
int path_extract_filename(const char *path, char **ret);
int path_extract_directory(const char *path, char **ret);

bool filename_is_valid(const char *p) _pure_;
bool path_is_valid_full(const char *p, bool accept_dot_dot) _pure_;
static inline bool path_is_valid(const char *p) {
        return path_is_valid_full(p, /* accept_dot_dot= */ true);
}
static inline bool path_is_safe(const char *p) {
        return path_is_valid_full(p, /* accept_dot_dot= */ false);
}
bool path_is_normalized(const char *p) _pure_;

bool hidden_or_backup_file(const char *filename) _pure_;

bool dot_or_dot_dot(const char *path);

bool empty_or_root(const char *path);
static inline const char* empty_to_root(const char *path) {
        return isempty(path) ? "/" : path;
}

bool path_strv_contains(char **l, const char *path);

int parse_path_argument(const char *path, char **arg);
