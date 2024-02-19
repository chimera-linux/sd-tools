/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>

#include "hash-funcs.h"
#include "macro.h"

/*
 * A hash table implementation. As a minor optimization a NULL hashmap object
 * will be treated as empty hashmap for all read operations. That way it is not
 * necessary to instantiate an object for each Hashmap use.
 */

#define HASH_KEY_SIZE 16

typedef void* (*hashmap_destroy_t)(void *p);

/* The base type for all hashmap and set types. Many functions in the implementation take (HashmapBase*)
 * parameters and are run-time polymorphic, though the API is not meant to be polymorphic (do not call
 * underscore-prefixed functions directly). */
typedef struct HashmapBase HashmapBase;

/* Specific hashmap/set types */
typedef struct Hashmap Hashmap;               /* Maps keys to values */
typedef struct OrderedHashmap OrderedHashmap; /* Like Hashmap, but also remembers entry insertion order */
typedef struct Set Set;                       /* Stores just keys */

/* Ideally the Iterator would be an opaque struct, but it is instantiated
 * by hashmap users, so the definition has to be here. Do not use its fields
 * directly. */
typedef struct {
        unsigned idx;         /* index of an entry to be iterated next */
        const void *next_key; /* expected value of that entry's key pointer */
} Iterator;

#define _IDX_ITERATOR_FIRST (UINT_MAX - 1)
#define ITERATOR_FIRST ((Iterator) { .idx = _IDX_ITERATOR_FIRST, .next_key = NULL })
#define ITERATOR_IS_FIRST(i) ((i).idx == _IDX_ITERATOR_FIRST)

/* Macros for type checking */
#define PTR_COMPATIBLE_WITH_HASHMAP_BASE(h) \
        (__builtin_types_compatible_p(typeof(h), HashmapBase*) || \
         __builtin_types_compatible_p(typeof(h), Hashmap*) || \
         __builtin_types_compatible_p(typeof(h), OrderedHashmap*) || \
         __builtin_types_compatible_p(typeof(h), Set*))

#define PTR_COMPATIBLE_WITH_PLAIN_HASHMAP(h) \
        (__builtin_types_compatible_p(typeof(h), Hashmap*) || \
         __builtin_types_compatible_p(typeof(h), OrderedHashmap*)) \

#define HASHMAP_BASE(h) \
        __builtin_choose_expr(PTR_COMPATIBLE_WITH_HASHMAP_BASE(h), \
                (HashmapBase*)(h), \
                (void)0)

#define PLAIN_HASHMAP(h) \
        __builtin_choose_expr(PTR_COMPATIBLE_WITH_PLAIN_HASHMAP(h), \
                (Hashmap*)(h), \
                (void)0)

Hashmap* _hashmap_new(const struct hash_ops *hash_ops);
OrderedHashmap* _ordered_hashmap_new(const struct hash_ops *hash_ops);
#define hashmap_new(ops) _hashmap_new(ops)
#define ordered_hashmap_new(ops) _ordered_hashmap_new(ops)

#define hashmap_free_and_replace(a, b)          \
        free_and_replace_full(a, b, hashmap_free)

HashmapBase* _hashmap_free(HashmapBase *h, free_func_t default_free_key, free_func_t default_free_value);
static inline Hashmap* hashmap_free(Hashmap *h) {
        return (void*) _hashmap_free(HASHMAP_BASE(h), NULL, NULL);
}
static inline OrderedHashmap* ordered_hashmap_free(OrderedHashmap *h) {
        return (void*) _hashmap_free(HASHMAP_BASE(h), NULL, NULL);
}

static inline Hashmap* hashmap_free_free(Hashmap *h) {
        return (void*) _hashmap_free(HASHMAP_BASE(h), NULL, free);
}
static inline OrderedHashmap* ordered_hashmap_free_free(OrderedHashmap *h) {
        return (void*) _hashmap_free(HASHMAP_BASE(h), NULL, free);
}

static inline Hashmap* hashmap_free_free_key(Hashmap *h) {
        return (void*) _hashmap_free(HASHMAP_BASE(h), free, NULL);
}
static inline OrderedHashmap* ordered_hashmap_free_free_key(OrderedHashmap *h) {
        return (void*) _hashmap_free(HASHMAP_BASE(h), free, NULL);
}

static inline Hashmap* hashmap_free_free_free(Hashmap *h) {
        return (void*) _hashmap_free(HASHMAP_BASE(h), free, free);
}
static inline OrderedHashmap* ordered_hashmap_free_free_free(OrderedHashmap *h) {
        return (void*) _hashmap_free(HASHMAP_BASE(h), free, free);
}

int _hashmap_ensure_allocated(Hashmap **h, const struct hash_ops *hash_ops);
int _hashmap_ensure_put(Hashmap **h, const struct hash_ops *hash_ops, const void *key, void *value);
int _ordered_hashmap_ensure_allocated(OrderedHashmap **h, const struct hash_ops *hash_ops);

#define hashmap_ensure_allocated(h, ops) _hashmap_ensure_allocated(h, ops)
#define hashmap_ensure_put(s, ops, key, value) _hashmap_ensure_put(s, ops, key, value)
#define ordered_hashmap_ensure_allocated(h, ops) _ordered_hashmap_ensure_allocated(h, ops)

int _ordered_hashmap_ensure_put(OrderedHashmap **h, const struct hash_ops *hash_ops, const void *key, void *value);
#define ordered_hashmap_ensure_put(s, ops, key, value) _ordered_hashmap_ensure_put(s, ops, key, value)

int hashmap_put(Hashmap *h, const void *key, void *value);
static inline int ordered_hashmap_put(OrderedHashmap *h, const void *key, void *value) {
        return hashmap_put(PLAIN_HASHMAP(h), key, value);
}

int hashmap_update(Hashmap *h, const void *key, void *value);
static inline int ordered_hashmap_update(OrderedHashmap *h, const void *key, void *value) {
        return hashmap_update(PLAIN_HASHMAP(h), key, value);
}

void* _hashmap_get(HashmapBase *h, const void *key);
static inline void *hashmap_get(Hashmap *h, const void *key) {
        return _hashmap_get(HASHMAP_BASE(h), key);
}
static inline void *ordered_hashmap_get(OrderedHashmap *h, const void *key) {
        return _hashmap_get(HASHMAP_BASE(h), key);
}

bool _hashmap_contains(HashmapBase *h, const void *key);
static inline bool hashmap_contains(Hashmap *h, const void *key) {
        return _hashmap_contains(HASHMAP_BASE(h), key);
}
static inline bool ordered_hashmap_contains(OrderedHashmap *h, const void *key) {
        return _hashmap_contains(HASHMAP_BASE(h), key);
}

void* _hashmap_remove(HashmapBase *h, const void *key);
static inline void *hashmap_remove(Hashmap *h, const void *key) {
        return _hashmap_remove(HASHMAP_BASE(h), key);
}
static inline void *ordered_hashmap_remove(OrderedHashmap *h, const void *key) {
        return _hashmap_remove(HASHMAP_BASE(h), key);
}

unsigned _hashmap_size(HashmapBase *h) _pure_;
static inline unsigned hashmap_size(Hashmap *h) {
        return _hashmap_size(HASHMAP_BASE(h));
}
static inline unsigned ordered_hashmap_size(OrderedHashmap *h) {
        return _hashmap_size(HASHMAP_BASE(h));
}

static inline bool hashmap_isempty(Hashmap *h) {
        return hashmap_size(h) == 0;
}
static inline bool ordered_hashmap_isempty(OrderedHashmap *h) {
        return ordered_hashmap_size(h) == 0;
}

bool _hashmap_iterate(HashmapBase *h, Iterator *i, void **value, const void **key);
static inline bool hashmap_iterate(Hashmap *h, Iterator *i, void **value, const void **key) {
        return _hashmap_iterate(HASHMAP_BASE(h), i, value, key);
}
static inline bool ordered_hashmap_iterate(OrderedHashmap *h, Iterator *i, void **value, const void **key) {
        return _hashmap_iterate(HASHMAP_BASE(h), i, value, key);
}

void _hashmap_clear(HashmapBase *h, free_func_t default_free_key, free_func_t default_free_value);

/*
 * Note about all *_first*() functions
 *
 * For plain Hashmaps and Sets the order of entries is undefined.
 * The functions find whatever entry is first in the implementation
 * internal order.
 *
 * Only for OrderedHashmaps the order is well defined and finding
 * the first entry is O(1).
 */

void *_hashmap_first_key_and_value(HashmapBase *h, bool remove, void **ret_key);

char** _hashmap_get_strv(HashmapBase *h);
static inline char** hashmap_get_strv(Hashmap *h) {
        return _hashmap_get_strv(HASHMAP_BASE(h));
}
static inline char** ordered_hashmap_get_strv(OrderedHashmap *h) {
        return _hashmap_get_strv(HASHMAP_BASE(h));
}

/*
 * Hashmaps are iterated in unpredictable order.
 * OrderedHashmaps are an exception to this. They are iterated in the order
 * the entries were inserted.
 * It is safe to remove the current entry.
 */
#define _HASHMAP_BASE_FOREACH(e, h, i) \
        for (Iterator i = ITERATOR_FIRST; _hashmap_iterate((h), &i, (void**)&(e), NULL); )
#define HASHMAP_BASE_FOREACH(e, h) \
        _HASHMAP_BASE_FOREACH(e, h, UNIQ_T(i, UNIQ))

#define _HASHMAP_FOREACH(e, h, i) \
        for (Iterator i = ITERATOR_FIRST; hashmap_iterate((h), &i, (void**)&(e), NULL); )
#define HASHMAP_FOREACH(e, h) \
        _HASHMAP_FOREACH(e, h, UNIQ_T(i, UNIQ))

#define _ORDERED_HASHMAP_FOREACH(e, h, i) \
        for (Iterator i = ITERATOR_FIRST; ordered_hashmap_iterate((h), &i, (void**)&(e), NULL); )
#define ORDERED_HASHMAP_FOREACH(e, h) \
        _ORDERED_HASHMAP_FOREACH(e, h, UNIQ_T(i, UNIQ))

#define _HASHMAP_BASE_FOREACH_KEY(e, k, h, i) \
        for (Iterator i = ITERATOR_FIRST; _hashmap_iterate((h), &i, (void**)&(e), (const void**) &(k)); )
#define HASHMAP_BASE_FOREACH_KEY(e, k, h) \
        _HASHMAP_BASE_FOREACH_KEY(e, k, h, UNIQ_T(i, UNIQ))

#define _HASHMAP_FOREACH_KEY(e, k, h, i) \
        for (Iterator i = ITERATOR_FIRST; hashmap_iterate((h), &i, (void**)&(e), (const void**) &(k)); )
#define HASHMAP_FOREACH_KEY(e, k, h) \
        _HASHMAP_FOREACH_KEY(e, k, h, UNIQ_T(i, UNIQ))

#define _ORDERED_HASHMAP_FOREACH_KEY(e, k, h, i) \
        for (Iterator i = ITERATOR_FIRST; ordered_hashmap_iterate((h), &i, (void**)&(e), (const void**) &(k)); )
#define ORDERED_HASHMAP_FOREACH_KEY(e, k, h) \
        _ORDERED_HASHMAP_FOREACH_KEY(e, k, h, UNIQ_T(i, UNIQ))

DEFINE_TRIVIAL_CLEANUP_FUNC(Hashmap*, hashmap_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(Hashmap*, hashmap_free_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(Hashmap*, hashmap_free_free_key);
DEFINE_TRIVIAL_CLEANUP_FUNC(Hashmap*, hashmap_free_free_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(OrderedHashmap*, ordered_hashmap_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(OrderedHashmap*, ordered_hashmap_free_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(OrderedHashmap*, ordered_hashmap_free_free_key);
DEFINE_TRIVIAL_CLEANUP_FUNC(OrderedHashmap*, ordered_hashmap_free_free_free);

#define _cleanup_hashmap_free_ _cleanup_(hashmap_freep)
#define _cleanup_hashmap_free_free_ _cleanup_(hashmap_free_freep)
#define _cleanup_hashmap_free_free_free_ _cleanup_(hashmap_free_free_freep)
#define _cleanup_ordered_hashmap_free_ _cleanup_(ordered_hashmap_freep)
#define _cleanup_ordered_hashmap_free_free_ _cleanup_(ordered_hashmap_free_freep)
#define _cleanup_ordered_hashmap_free_free_free_ _cleanup_(ordered_hashmap_free_free_freep)
