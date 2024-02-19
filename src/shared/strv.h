/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <fnmatch.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "alloc-util.h"
#include "extract-word.h"
#include "hashmap.h"
#include "macro.h"
#include "string-util.h"

char* strv_find(char * const *l, const char *name) _pure_;

#define strv_contains(l, s) (!!strv_find((l), (s)))

char** strv_free(char **l);
DEFINE_TRIVIAL_CLEANUP_FUNC(char**, strv_free);
#define _cleanup_strv_free_ _cleanup_(strv_freep)

char** strv_copy_n(char * const *l, size_t n);
static inline char** strv_copy(char * const *l) {
        return strv_copy_n(l, SIZE_MAX);
}
size_t strv_length(char * const *l) _pure_;

int strv_extend_strv(char ***a, char * const *b, bool filter_duplicates);
int strv_extend_strv_concat(char ***a, char * const *b, const char *suffix);

/* _with_size() are lower-level functions where the size can be provided externally,
 * which allows us to skip iterating over the strv to find the end, which saves
 * a bit of time and reduces the complexity of appending from O(n²) to O(n). */

int strv_extend_with_size(char ***l, size_t *n, const char *value);
static inline int strv_extend(char ***l, const char *value) {
        return strv_extend_with_size(l, NULL, value);
}

int strv_push_with_size(char ***l, size_t *n, char *value);
static inline int strv_push(char ***l, char *value) {
        return strv_push_with_size(l, NULL, value);
}
int strv_push_pair(char ***l, char *a, char *b);

int strv_insert(char ***l, size_t position, char *value);

int strv_consume_with_size(char ***l, size_t *n, char *value);
static inline int strv_consume(char ***l, char *value) {
        return strv_consume_with_size(l, NULL, value);
}

char** strv_remove(char **l, const char *s);
char** strv_uniq(char **l);

char** strv_new_internal(const char *x, ...) _sentinel_;
#define strv_new(...) strv_new_internal(__VA_ARGS__, NULL)

static inline bool strv_isempty(char * const *l) {
        return !l || !*l;
}

int strv_split_full(char ***t, const char *s, const char *separators, ExtractFlags flags);
static inline char** strv_split(const char *s, const char *separators) {
        char **ret;

        if (strv_split_full(&ret, s, separators, EXTRACT_RETAIN_ESCAPE) < 0)
                return NULL;

        return ret;
}

char* strv_join_full(char * const *l, const char *separator, const char *prefix, bool escape_separator);
static inline char *strv_join(char * const *l, const char *separator) {
        return strv_join_full(l, separator, NULL, false);
}

#define _STRV_FOREACH_PAIR(x, y, l, i)                          \
        for (typeof(*l) *x, *y, *i = (l);                       \
             i && *(x = i) && *(y = i + 1);                     \
             i += 2)

#define STRV_FOREACH_PAIR(x, y, l)                      \
        _STRV_FOREACH_PAIR(x, y, l, UNIQ_T(i, UNIQ))

char** strv_sort(char **l);

#define STR_IN_SET(x, ...) strv_contains(STRV_MAKE(__VA_ARGS__), x)

#define _FOREACH_STRING(uniq, x, y, ...)                                \
        for (const char *x, * const*UNIQ_T(l, uniq) = STRV_MAKE_CONST(({ x = y; }), ##__VA_ARGS__); \
             x;                                                         \
             x = *(++UNIQ_T(l, uniq)))

#define FOREACH_STRING(x, y, ...)                       \
        _FOREACH_STRING(UNIQ, x, y, ##__VA_ARGS__)

extern const struct hash_ops string_strv_hash_ops;
int _string_strv_hashmap_put(Hashmap **h, const char *key, const char *value);
int _string_strv_ordered_hashmap_put(OrderedHashmap **h, const char *key, const char *value);
#define string_strv_hashmap_put(h, k, v) _string_strv_hashmap_put(h, k, v)
#define string_strv_ordered_hashmap_put(h, k, v) _string_strv_ordered_hashmap_put(h, k, v)
