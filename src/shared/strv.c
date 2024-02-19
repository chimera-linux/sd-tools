/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fnmatch.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "escape.h"
#include "extract-word.h"
#include "fileio.h"
#include "string-util.h"
#include "strv.h"

char* strv_find(char * const *l, const char *name) {
        assert(name);

        STRV_FOREACH(i, l)
                if (streq(*i, name))
                        return *i;

        return NULL;
}

char** strv_free(char **l) {
        STRV_FOREACH(k, l)
                free(*k);

        return mfree(l);
}

char** strv_copy_n(char * const *l, size_t m) {
        _cleanup_strv_free_ char **result = NULL;
        char **k;

        result = malloc((MIN(strv_length(l), m) + 1) * sizeof(char *));
        if (!result)
                return NULL;

        k = result;
        STRV_FOREACH(i, l) {
                if (m == 0)
                        break;

                *k = strdup(*i);
                if (!*k)
                        return NULL;
                k++;

                if (m != SIZE_MAX)
                        m--;
        }

        *k = NULL;
        return TAKE_PTR(result);
}

size_t strv_length(char * const *l) {
        size_t n = 0;

        STRV_FOREACH(i, l)
                n++;

        return n;
}

#define STRV_IGNORE ((const char *) (void *) UINTPTR_MAX)

static char** strv_new_ap(const char *x, va_list ap) {
        _cleanup_strv_free_ char **a = NULL;
        size_t n = 0, i = 0;
        va_list aq;

        /* As a special trick we ignore all listed strings that equal
         * STRV_IGNORE. This is supposed to be used with the
         * STRV_IFNOTNULL() macro to include possibly NULL strings in
         * the string list. */

        va_copy(aq, ap);
        for (const char *s = x; s; s = va_arg(aq, const char*)) {
                if (s == STRV_IGNORE)
                        continue;

                n++;
        }
        va_end(aq);

        a = malloc((n+1) * sizeof(char *));
        if (!a)
                return NULL;

        for (const char *s = x; s; s = va_arg(ap, const char*)) {
                if (s == STRV_IGNORE)
                        continue;

                a[i] = strdup(s);
                if (!a[i])
                        return NULL;

                i++;
        }

        a[i] = NULL;

        return TAKE_PTR(a);
}

char** strv_new_internal(const char *x, ...) {
        char **r;
        va_list ap;

        va_start(ap, x);
        r = strv_new_ap(x, ap);
        va_end(ap);

        return r;
}

int strv_extend_strv(char ***a, char * const *b, bool filter_duplicates) {
        size_t p, q, i = 0;
        char **t;

        assert(a);

        if (strv_isempty(b))
                return 0;

        p = strv_length(*a);
        q = strv_length(b);

        if (p >= SIZE_MAX - q)
                return -ENOMEM;

        t = reallocarray(*a, GREEDY_ALLOC_ROUND_UP(p + q + 1), sizeof(char *));
        if (!t)
                return -ENOMEM;

        t[p] = NULL;
        *a = t;

        STRV_FOREACH(s, b) {
                if (filter_duplicates && strv_contains(t, *s))
                        continue;

                t[p+i] = strdup(*s);
                if (!t[p+i])
                        goto rollback;

                i++;
                t[p+i] = NULL;
        }

        assert(i <= q);

        return (int) i;

rollback:
        for (size_t j = 0; j < i; ++i)
                t[p + j] = mfree(t[p + j]);
        t[p] = NULL;
        return -ENOMEM;
}

int strv_extend_strv_concat(char ***a, char * const *b, const char *suffix) {
        int r;

        STRV_FOREACH(s, b) {
                char *v;

                v = strjoin(*s, suffix);
                if (!v)
                        return -ENOMEM;

                r = strv_push(a, v);
                if (r < 0) {
                        free(v);
                        return r;
                }
        }

        return 0;
}

int strv_split_full(char ***t, const char *s, const char *separators, ExtractFlags flags) {
        _cleanup_strv_free_ char **l = NULL;
        void *np;
        size_t n = 0;
        int r;

        assert(t);
        assert(s);

        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&s, &word, separators, flags);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                np = reallocarray(l, n + 2, sizeof(char *));
                if (!np)
                        return -ENOMEM;
                l = np;

                l[n++] = TAKE_PTR(word);
                l[n] = NULL;
        }

        if (!l) {
                l = calloc(1, sizeof(char*));
                if (!l)
                        return -ENOMEM;
        }

        *t = TAKE_PTR(l);

        return (int) n;
}

char* strv_join_full(char * const *l, const char *separator, const char *prefix, bool escape_separator) {
        char *r, *e;
        size_t n, k, m;

        if (!separator)
                separator = " ";

        k = strlen(separator);
        m = strlen_ptr(prefix);

        if (escape_separator) /* If the separator was multi-char, we wouldn't know how to escape it. */
                assert(k == 1);

        n = 0;
        STRV_FOREACH(s, l) {
                if (s != l)
                        n += k;

                bool needs_escaping = escape_separator && strchr(*s, *separator);

                n += m + strlen(*s) * (1 + needs_escaping);
        }

        r = malloc(n+1);
        if (!r)
                return NULL;

        e = r;
        STRV_FOREACH(s, l) {
                if (s != l)
                        e = stpcpy(e, separator);

                if (prefix)
                        e = stpcpy(e, prefix);

                bool needs_escaping = escape_separator && strchr(*s, *separator);

                if (needs_escaping)
                        for (size_t i = 0; (*s)[i]; i++) {
                                if ((*s)[i] == *separator)
                                        *(e++) = '\\';
                                *(e++) = (*s)[i];
                        }
                else
                        e = stpcpy(e, *s);
        }

        *e = 0;

        return r;
}

int strv_push_with_size(char ***l, size_t *n, char *value) {
        /* n is a pointer to a variable to store the size of l.
         * If not given (i.e. n is NULL or *n is SIZE_MAX), size will be calculated using strv_length().
         * If n is not NULL, the size after the push will be returned.
         * If value is empty, no action is taken and *n is not set. */

        if (!value)
                return 0;

        size_t size = n ? *n : SIZE_MAX;
        if (size == SIZE_MAX)
                size = strv_length(*l);

        /* Check for overflow */
        if (size > SIZE_MAX-2)
                return -ENOMEM;

        char **c = reallocarray(*l, GREEDY_ALLOC_ROUND_UP(size + 2), sizeof(char*));
        if (!c)
                return -ENOMEM;

        c[size] = value;
        c[size+1] = NULL;

        *l = c;
        if (n)
                *n = size + 1;
        return 0;
}

int strv_push_pair(char ***l, char *a, char *b) {
        char **c;
        size_t n;

        if (!a && !b)
                return 0;

        n = strv_length(*l);

        /* Check for overflow */
        if (n > SIZE_MAX-3)
                return -ENOMEM;

        /* increase and check for overflow */
        c = reallocarray(*l, GREEDY_ALLOC_ROUND_UP(n + !!a + !!b + 1), sizeof(char*));
        if (!c)
                return -ENOMEM;

        if (a)
                c[n++] = a;
        if (b)
                c[n++] = b;
        c[n] = NULL;

        *l = c;
        return 0;
}

int strv_insert(char ***l, size_t position, char *value) {
        char **c;
        size_t n, m;

        if (!value)
                return 0;

        n = strv_length(*l);
        position = MIN(position, n);

        /* increase and check for overflow */
        m = n + 2;
        if (m < n)
                return -ENOMEM;

        c = malloc(m * sizeof(char *));
        if (!c)
                return -ENOMEM;

        for (size_t i = 0; i < position; i++)
                c[i] = (*l)[i];
        c[position] = value;
        for (size_t i = position; i < n; i++)
                c[i+1] = (*l)[i];
        c[n+1] = NULL;

        return free_and_replace(*l, c);
}

int strv_consume_with_size(char ***l, size_t *n, char *value) {
        int r;

        r = strv_push_with_size(l, n, value);
        if (r < 0)
                free(value);

        return r;
}

int strv_extend_with_size(char ***l, size_t *n, const char *value) {
        char *v;

        if (!value)
                return 0;

        v = strdup(value);
        if (!v)
                return -ENOMEM;

        return strv_consume_with_size(l, n, v);
}

char** strv_uniq(char **l) {
        /* Drops duplicate entries. The first identical string will be
         * kept, the others dropped */

        STRV_FOREACH(i, l)
                strv_remove(i+1, *i);

        return l;
}

char** strv_remove(char **l, const char *s) {
        char **f, **t;

        if (!l)
                return NULL;

        assert(s);

        /* Drops every occurrence of s in the string list, edits
         * in-place. */

        for (f = t = l; *f; f++)
                if (streq(*f, s))
                        free(*f);
                else
                        *(t++) = *f;

        *t = NULL;
        return l;
}

static int str_compare(const void *a, const void *b) {
        return strcmp(*((const char **)a), *((const char **)b));
}

char** strv_sort(char **l) {
        size_t len = strv_length(l);
        if (len > 0)
                qsort(l, len, sizeof(char *), str_compare);
        return l;
}

static int string_strv_hashmap_put_internal(Hashmap *h, const char *key, const char *value) {
        char **l;
        int r;

        l = hashmap_get(h, key);
        if (l) {
                /* A list for this key already exists, let's append to it if it is not listed yet */
                if (strv_contains(l, value))
                        return 0;

                r = strv_extend(&l, value);
                if (r < 0)
                        return r;

                assert_se(hashmap_update(h, key, l) >= 0);
        } else {
                /* No list for this key exists yet, create one */
                _cleanup_strv_free_ char **l2 = NULL;
                _cleanup_free_ char *t = NULL;

                t = strdup(key);
                if (!t)
                        return -ENOMEM;

                r = strv_extend(&l2, value);
                if (r < 0)
                        return r;

                r = hashmap_put(h, t, l2);
                if (r < 0)
                        return r;
                TAKE_PTR(t);
                TAKE_PTR(l2);
        }

        return 1;
}

int _string_strv_ordered_hashmap_put(OrderedHashmap **h, const char *key, const char *value) {
        int r;

        r = _ordered_hashmap_ensure_allocated(h, &string_strv_hash_ops);
        if (r < 0)
                return r;

        return string_strv_hashmap_put_internal(PLAIN_HASHMAP(*h), key, value);
}

DEFINE_HASH_OPS_FULL(string_strv_hash_ops, char, string_hash_func, string_compare_func, free, char*, strv_free);
