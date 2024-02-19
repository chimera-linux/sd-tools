/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "extract-word.h"
#include "hashmap.h"
#include "macro.h"

#define set_free_and_replace(a, b)              \
        free_and_replace_full(a, b, set_free)

Set* _set_new(const struct hash_ops *hash_ops);
#define set_new(ops) _set_new(ops)

static inline Set* set_free(Set *s) {
        return (Set*) _hashmap_free(HASHMAP_BASE(s), NULL, NULL);
}

static inline Set* set_free_free(Set *s) {
        return (Set*) _hashmap_free(HASHMAP_BASE(s), free, NULL);
}

int _set_ensure_allocated(Set **s, const struct hash_ops *hash_ops);
#define set_ensure_allocated(h, ops) _set_ensure_allocated(h, ops)

int set_put(Set *s, const void *key);

static inline void *set_get(const Set *s, const void *key) {
        return _hashmap_get(HASHMAP_BASE((Set *) s), key);
}

static inline bool set_contains(const Set *s, const void *key) {
        return _hashmap_contains(HASHMAP_BASE((Set *) s), key);
}

static inline void *set_remove(Set *s, const void *key) {
        return _hashmap_remove(HASHMAP_BASE(s), key);
}

static inline unsigned set_size(const Set *s) {
        return _hashmap_size(HASHMAP_BASE((Set *) s));
}

static inline bool set_isempty(const Set *s) {
        return set_size(s) == 0;
}

static inline bool set_iterate(const Set *s, Iterator *i, void **value) {
        return _hashmap_iterate(HASHMAP_BASE((Set*) s), i, value, NULL);
}

#define set_clear_with_destructor(s, f)                 \
        ({                                              \
                Set *_s = (s);                          \
                void *_item;                            \
                while ((_item = set_steal_first(_s)))   \
                        f(_item);                       \
                _s;                                     \
        })
#define set_free_with_destructor(s, f)                  \
        set_free(set_clear_with_destructor(s, f))

static inline char **set_get_strv(Set *s) {
        return _hashmap_get_strv(HASHMAP_BASE(s));
}

int _set_ensure_put(Set **s, const struct hash_ops *hash_ops, const void *key);
#define set_ensure_put(s, hash_ops, key) _set_ensure_put(s, hash_ops, key)

int set_consume(Set *s, void *value);

int _set_put_strndup_full(Set **s, const struct hash_ops *hash_ops, const char *p, size_t n);
#define set_put_strndup_full(s, hash_ops, p, n) _set_put_strndup_full(s, hash_ops, p, n)
#define set_put_strdup_full(s, hash_ops, p) set_put_strndup_full(s, hash_ops, p, SIZE_MAX)

#define _SET_FOREACH(e, s, i) \
        for (Iterator i = ITERATOR_FIRST; set_iterate((s), &i, (void**)&(e)); )
#define SET_FOREACH(e, s) \
        _SET_FOREACH(e, s, UNIQ_T(i, UNIQ))

DEFINE_TRIVIAL_CLEANUP_FUNC(Set*, set_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(Set*, set_free_free);

#define _cleanup_set_free_ _cleanup_(set_freep)
#define _cleanup_set_free_free_ _cleanup_(set_free_freep)
