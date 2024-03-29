/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fnmatch.h>
#include <stdint.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "fileio.h"
#include "hashmap.h"
#include "macro.h"
#include "random-util.h"
#include "set.h"
#include "siphash24.h"
#include "string-util.h"
#include "strv.h"

#define CONST_LOG2ULL(x) ((x) > 1 ? (unsigned) __builtin_clzll(x) ^ 63U : 0)
#define NONCONST_LOG2ULL(x) ({                                     \
                unsigned long long _x = (x);                       \
                _x > 1 ? (unsigned) __builtin_clzll(_x) ^ 63U : 0; \
        })
#define LOG2ULL(x) __builtin_choose_expr(__builtin_constant_p(x), CONST_LOG2ULL(x), NONCONST_LOG2ULL(x))

#define popcount(n)                                             \
        _Generic((n),                                           \
                 unsigned char: __builtin_popcount(n),          \
                 unsigned short: __builtin_popcount(n),         \
                 unsigned: __builtin_popcount(n),               \
                 unsigned long: __builtin_popcountl(n),         \
                 unsigned long long: __builtin_popcountll(n))

#define CONST_LOG2U(x) ((x) > 1 ? __SIZEOF_INT__ * 8 - __builtin_clz(x) - 1 : 0)
#define NONCONST_LOG2U(x) ({                                             \
                unsigned _x = (x);                                       \
                _x > 1 ? __SIZEOF_INT__ * 8 - __builtin_clz(_x) - 1 : 0; \
        })
#define LOG2U(x) __builtin_choose_expr(__builtin_constant_p(x), CONST_LOG2U(x), NONCONST_LOG2U(x))

static inline unsigned log2u(unsigned x) {
        return LOG2U(x);
}

static inline unsigned log2u_round_up(unsigned x) {
        if (x <= 1)
                return 0;

        return log2u(x - 1) + 1;
}

/*
 * Implementation of hashmaps.
 * Addressing: open
 *   - uses less RAM compared to closed addressing (chaining), because
 *     our entries are small (especially in Sets, which tend to contain
 *     the majority of entries in systemd).
 * Collision resolution: Robin Hood
 *   - tends to equalize displacement of entries from their optimal buckets.
 * Probe sequence: linear
 *   - though theoretically worse than random probing/uniform hashing/double
 *     hashing, it is good for cache locality.
 *
 * References:
 * Celis, P. 1986. Robin Hood Hashing.
 * Ph.D. Dissertation. University of Waterloo, Waterloo, Ont., Canada, Canada.
 * https://cs.uwaterloo.ca/research/tr/1986/CS-86-14.pdf
 * - The results are derived for random probing. Suggests deletion with
 *   tombstones and two mean-centered search methods. None of that works
 *   well for linear probing.
 *
 * Janson, S. 2005. Individual displacements for linear probing hashing with different insertion policies.
 * ACM Trans. Algorithms 1, 2 (October 2005), 177-213.
 * DOI=10.1145/1103963.1103964 http://doi.acm.org/10.1145/1103963.1103964
 * http://www.math.uu.se/~svante/papers/sj157.pdf
 * - Applies to Robin Hood with linear probing. Contains remarks on
 *   the unsuitability of mean-centered search with linear probing.
 *
 * Viola, A. 2005. Exact distribution of individual displacements in linear probing hashing.
 * ACM Trans. Algorithms 1, 2 (October 2005), 214-242.
 * DOI=10.1145/1103963.1103965 http://doi.acm.org/10.1145/1103963.1103965
 * - Similar to Janson. Note that Viola writes about C_{m,n} (number of probes
 *   in a successful search), and Janson writes about displacement. C = d + 1.
 *
 * Goossaert, E. 2013. Robin Hood hashing: backward shift deletion.
 * http://codecapsule.com/2013/11/17/robin-hood-hashing-backward-shift-deletion/
 * - Explanation of backward shift deletion with pictures.
 *
 * Khuong, P. 2013. The Other Robin Hood Hashing.
 * http://www.pvk.ca/Blog/2013/11/26/the-other-robin-hood-hashing/
 * - Short summary of random vs. linear probing, and tombstones vs. backward shift.
 */

/*
 * XXX Ideas for improvement:
 * For unordered hashmaps, randomize iteration order, similarly to Perl:
 * http://blog.booking.com/hardening-perls-hash-function.html
 */

/* INV_KEEP_FREE = 1 / (1 - max_load_factor)
 * e.g. 1 / (1 - 0.8) = 5 ... keep one fifth of the buckets free. */
#define INV_KEEP_FREE            5U

/* Fields common to entries of all hashmap/set types */
struct hashmap_base_entry {
        const void *key;
};

/* Entry types for specific hashmap/set types
 * hashmap_base_entry must be at the beginning of each entry struct. */

struct plain_hashmap_entry {
        struct hashmap_base_entry b;
        void *value;
};

struct ordered_hashmap_entry {
        struct plain_hashmap_entry p;
        unsigned iterate_next, iterate_previous;
};

struct set_entry {
        struct hashmap_base_entry b;
};

/* In several functions it is advantageous to have the hash table extended
 * virtually by a couple of additional buckets. We reserve special index values
 * for these "swap" buckets. */
#define _IDX_SWAP_BEGIN     (UINT_MAX - 3)
#define IDX_PUT             (_IDX_SWAP_BEGIN + 0)
#define IDX_TMP             (_IDX_SWAP_BEGIN + 1)
#define _IDX_SWAP_END       (_IDX_SWAP_BEGIN + 2)

#define IDX_FIRST           (UINT_MAX - 1) /* special index for freshly initialized iterators */
#define IDX_NIL             UINT_MAX       /* special index value meaning "none" or "end" */

assert_cc(IDX_FIRST == _IDX_SWAP_END);
assert_cc(IDX_FIRST == _IDX_ITERATOR_FIRST);

/* Storage space for the "swap" buckets.
 * All entry types can fit into an ordered_hashmap_entry. */
struct swap_entries {
        struct ordered_hashmap_entry e[_IDX_SWAP_END - _IDX_SWAP_BEGIN];
};

/* Distance from Initial Bucket */
typedef uint8_t dib_raw_t;
#define DIB_RAW_OVERFLOW ((dib_raw_t)0xfdU)   /* indicates DIB value is greater than representable */
#define DIB_RAW_REHASH   ((dib_raw_t)0xfeU)   /* entry yet to be rehashed during in-place resize */
#define DIB_RAW_FREE     ((dib_raw_t)0xffU)   /* a free bucket */
#define DIB_RAW_INIT     ((char)DIB_RAW_FREE) /* a byte to memset a DIB store with when initializing */

#define DIB_FREE UINT_MAX

enum HashmapType {
        HASHMAP_TYPE_PLAIN,
        HASHMAP_TYPE_ORDERED,
        HASHMAP_TYPE_SET,
        _HASHMAP_TYPE_MAX
};

struct _packed_ indirect_storage {
        void *storage;                     /* where buckets and DIBs are stored */
        uint8_t  hash_key[HASH_KEY_SIZE];  /* hash key; changes during resize */

        unsigned n_entries;                /* number of stored entries */
        unsigned n_buckets;                /* number of buckets */

        unsigned idx_lowest_entry;         /* Index below which all buckets are free.
                                              Makes "while (hashmap_steal_first())" loops
                                              O(n) instead of O(n^2) for unordered hashmaps. */
        uint8_t  _pad[3];                  /* padding for the whole HashmapBase */
        /* The bitfields in HashmapBase complete the alignment of the whole thing. */
};

struct direct_storage {
        /* This gives us 39 bytes on 64-bit, or 35 bytes on 32-bit.
         * That's room for 4 set_entries + 4 DIB bytes + 3 unused bytes on 64-bit,
         *              or 7 set_entries + 7 DIB bytes + 0 unused bytes on 32-bit. */
        uint8_t storage[sizeof(struct indirect_storage)];
};

#define DIRECT_BUCKETS(entry_t) \
        (sizeof(struct direct_storage) / (sizeof(entry_t) + sizeof(dib_raw_t)))

/* We should be able to store at least one entry directly. */
assert_cc(DIRECT_BUCKETS(struct ordered_hashmap_entry) >= 1);

/* We have 3 bits for n_direct_entries. */
assert_cc(DIRECT_BUCKETS(struct set_entry) < (1 << 3));

/* Hashmaps with directly stored entries all use this shared hash key.
 * It's no big deal if the key is guessed, because there can be only
 * a handful of directly stored entries in a hashmap. When a hashmap
 * outgrows direct storage, it gets its own key for indirect storage. */
static uint8_t shared_hash_key[HASH_KEY_SIZE];

/* Fields that all hashmap/set types must have */
struct HashmapBase {
        const struct hash_ops *hash_ops;  /* hash and compare ops to use */

        union _packed_ {
                struct indirect_storage indirect; /* if  has_indirect */
                struct direct_storage direct;     /* if !has_indirect */
        };

        enum HashmapType type:2;     /* HASHMAP_TYPE_* */
        bool has_indirect:1;         /* whether indirect storage is used */
        unsigned n_direct_entries:3; /* Number of entries in direct storage.
                                      * Only valid if !has_indirect. */
        bool dirty:1;                /* whether dirtied since last iterated_cache_get() */
        bool cached:1;               /* whether this hashmap is being cached */
};

/* Specific hash types
 * HashmapBase must be at the beginning of each hashmap struct. */

struct Hashmap {
        struct HashmapBase b;
};

struct OrderedHashmap {
        struct HashmapBase b;
        unsigned iterate_list_head, iterate_list_tail;
};

struct Set {
        struct HashmapBase b;
};

typedef struct CacheMem {
        const void **ptr;
        size_t n_populated;
        bool active:1;
} CacheMem;

struct IteratedCache {
        HashmapBase *hashmap;
        CacheMem keys, values;
};

struct hashmap_type_info {
        size_t head_size;
        size_t entry_size;
        unsigned n_direct_buckets;
};

static _used_ const struct hashmap_type_info hashmap_type_info[_HASHMAP_TYPE_MAX] = {
        [HASHMAP_TYPE_PLAIN] = {
                .head_size        = sizeof(Hashmap),
                .entry_size       = sizeof(struct plain_hashmap_entry),
                .n_direct_buckets = DIRECT_BUCKETS(struct plain_hashmap_entry),
        },
        [HASHMAP_TYPE_ORDERED] = {
                .head_size        = sizeof(OrderedHashmap),
                .entry_size       = sizeof(struct ordered_hashmap_entry),
                .n_direct_buckets = DIRECT_BUCKETS(struct ordered_hashmap_entry),
        },
        [HASHMAP_TYPE_SET] = {
                .head_size        = sizeof(Set),
                .entry_size       = sizeof(struct set_entry),
                .n_direct_buckets = DIRECT_BUCKETS(struct set_entry),
        },
};

static unsigned n_buckets(HashmapBase *h) {
        return h->has_indirect ? h->indirect.n_buckets
                               : hashmap_type_info[h->type].n_direct_buckets;
}

static unsigned n_entries(HashmapBase *h) {
        return h->has_indirect ? h->indirect.n_entries
                               : h->n_direct_entries;
}

static void n_entries_inc(HashmapBase *h) {
        if (h->has_indirect)
                h->indirect.n_entries++;
        else
                h->n_direct_entries++;
}

static void n_entries_dec(HashmapBase *h) {
        if (h->has_indirect)
                h->indirect.n_entries--;
        else
                h->n_direct_entries--;
}

static void* storage_ptr(HashmapBase *h) {
        return h->has_indirect ? h->indirect.storage
                               : h->direct.storage;
}

static uint8_t* hash_key(HashmapBase *h) {
        return h->has_indirect ? h->indirect.hash_key
                               : shared_hash_key;
}

static unsigned base_bucket_hash(HashmapBase *h, const void *p) {
        struct siphash state;
        uint64_t hash;

        siphash24_init(&state, hash_key(h));

        h->hash_ops->hash(p, &state);

        hash = siphash24_finalize(&state);

        return (unsigned) (hash % n_buckets(h));
}
#define bucket_hash(h, p) base_bucket_hash(HASHMAP_BASE(h), p)

static void base_set_dirty(HashmapBase *h) {
        h->dirty = true;
}
#define hashmap_set_dirty(h) base_set_dirty(HASHMAP_BASE(h))

static void get_hash_key(uint8_t hash_key[HASH_KEY_SIZE], bool reuse_is_ok) {
        static uint8_t current[HASH_KEY_SIZE];
        static bool current_initialized = false;

        /* Returns a hash function key to use. In order to keep things
         * fast we will not generate a new key each time we allocate a
         * new hash table. Instead, we'll just reuse the most recently
         * generated one, except if we never generated one or when we
         * are rehashing an entire hash table because we reached a
         * fill level */

        if (!current_initialized || !reuse_is_ok) {
                random_bytes(current, sizeof(current));
                current_initialized = true;
        }

        memcpy(hash_key, current, sizeof(current));
}

static struct hashmap_base_entry* bucket_at(HashmapBase *h, unsigned idx) {
        return CAST_ALIGN_PTR(
                        struct hashmap_base_entry,
                        (uint8_t *) storage_ptr(h) + idx * hashmap_type_info[h->type].entry_size);
}

static struct plain_hashmap_entry* plain_bucket_at(Hashmap *h, unsigned idx) {
        return (struct plain_hashmap_entry*) bucket_at(HASHMAP_BASE(h), idx);
}

static struct ordered_hashmap_entry* ordered_bucket_at(OrderedHashmap *h, unsigned idx) {
        return (struct ordered_hashmap_entry*) bucket_at(HASHMAP_BASE(h), idx);
}

static struct ordered_hashmap_entry* bucket_at_swap(struct swap_entries *swap, unsigned idx) {
        return &swap->e[idx - _IDX_SWAP_BEGIN];
}

/* Returns a pointer to the bucket at index idx.
 * Understands real indexes and swap indexes, hence "_virtual". */
static struct hashmap_base_entry* bucket_at_virtual(HashmapBase *h, struct swap_entries *swap,
                                                    unsigned idx) {
        if (idx < _IDX_SWAP_BEGIN)
                return bucket_at(h, idx);

        if (idx < _IDX_SWAP_END)
                return &bucket_at_swap(swap, idx)->p.b;

        assert_not_reached();
}

static dib_raw_t* dib_raw_ptr(HashmapBase *h) {
        return (dib_raw_t*)
                ((uint8_t*) storage_ptr(h) + hashmap_type_info[h->type].entry_size * n_buckets(h));
}

static unsigned bucket_distance(HashmapBase *h, unsigned idx, unsigned from) {
        return idx >= from ? idx - from
                           : n_buckets(h) + idx - from;
}

static unsigned bucket_calculate_dib(HashmapBase *h, unsigned idx, dib_raw_t raw_dib) {
        unsigned initial_bucket;

        if (raw_dib == DIB_RAW_FREE)
                return DIB_FREE;

        if (_likely_(raw_dib < DIB_RAW_OVERFLOW))
                return raw_dib;

        /*
         * Having an overflow DIB value is very unlikely. The hash function
         * would have to be bad. For example, in a table of size 2^24 filled
         * to load factor 0.9 the maximum observed DIB is only about 60.
         * In theory (assuming I used Maxima correctly), for an infinite size
         * hash table with load factor 0.8 the probability of a given entry
         * having DIB > 40 is 1.9e-8.
         * This returns the correct DIB value by recomputing the hash value in
         * the unlikely case. XXX Hitting this case could be a hint to rehash.
         */
        initial_bucket = bucket_hash(h, bucket_at(h, idx)->key);
        return bucket_distance(h, idx, initial_bucket);
}

static void bucket_set_dib(HashmapBase *h, unsigned idx, unsigned dib) {
        dib_raw_ptr(h)[idx] = dib != DIB_FREE ? MIN(dib, DIB_RAW_OVERFLOW) : DIB_RAW_FREE;
}

static unsigned skip_free_buckets(HashmapBase *h, unsigned idx) {
        dib_raw_t *dibs;

        dibs = dib_raw_ptr(h);

        for ( ; idx < n_buckets(h); idx++)
                if (dibs[idx] != DIB_RAW_FREE)
                        return idx;

        return IDX_NIL;
}

static void bucket_mark_free(HashmapBase *h, unsigned idx) {
        memset(bucket_at(h, idx), 0, hashmap_type_info[h->type].entry_size);
        bucket_set_dib(h, idx, DIB_FREE);
}

static void bucket_move_entry(HashmapBase *h, struct swap_entries *swap,
                              unsigned from, unsigned to) {
        struct hashmap_base_entry *e_from, *e_to;

        assert(from != to);

        e_from = bucket_at_virtual(h, swap, from);
        e_to   = bucket_at_virtual(h, swap, to);

        memcpy(e_to, e_from, hashmap_type_info[h->type].entry_size);

        if (h->type == HASHMAP_TYPE_ORDERED) {
                OrderedHashmap *lh = (OrderedHashmap*) h;
                struct ordered_hashmap_entry *le, *le_to;

                le_to = (struct ordered_hashmap_entry*) e_to;

                if (le_to->iterate_next != IDX_NIL) {
                        le = (struct ordered_hashmap_entry*)
                             bucket_at_virtual(h, swap, le_to->iterate_next);
                        le->iterate_previous = to;
                }

                if (le_to->iterate_previous != IDX_NIL) {
                        le = (struct ordered_hashmap_entry*)
                             bucket_at_virtual(h, swap, le_to->iterate_previous);
                        le->iterate_next = to;
                }

                if (lh->iterate_list_head == from)
                        lh->iterate_list_head = to;
                if (lh->iterate_list_tail == from)
                        lh->iterate_list_tail = to;
        }
}

static unsigned next_idx(HashmapBase *h, unsigned idx) {
        return (idx + 1U) % n_buckets(h);
}

static unsigned prev_idx(HashmapBase *h, unsigned idx) {
        return (n_buckets(h) + idx - 1U) % n_buckets(h);
}

static void* entry_value(HashmapBase *h, struct hashmap_base_entry *e) {
        switch (h->type) {

        case HASHMAP_TYPE_PLAIN:
        case HASHMAP_TYPE_ORDERED:
                return ((struct plain_hashmap_entry*)e)->value;

        case HASHMAP_TYPE_SET:
                return (void*) e->key;

        default:
                assert_not_reached();
        }
}

static void base_remove_entry(HashmapBase *h, unsigned idx) {
        unsigned left, right, prev, dib;
        dib_raw_t raw_dib, *dibs;

        dibs = dib_raw_ptr(h);
        assert(dibs[idx] != DIB_RAW_FREE);

        left = idx;
        /* Find the stop bucket ("right"). It is either free or has DIB == 0. */
        for (right = next_idx(h, left); ; right = next_idx(h, right)) {
                raw_dib = dibs[right];
                if (IN_SET(raw_dib, 0, DIB_RAW_FREE))
                        break;

                /* The buckets are not supposed to be all occupied and with DIB > 0.
                 * That would mean we could make everyone better off by shifting them
                 * backward. This scenario is impossible. */
                assert(left != right);
        }

        if (h->type == HASHMAP_TYPE_ORDERED) {
                OrderedHashmap *lh = (OrderedHashmap*) h;
                struct ordered_hashmap_entry *le = ordered_bucket_at(lh, idx);

                if (le->iterate_next != IDX_NIL)
                        ordered_bucket_at(lh, le->iterate_next)->iterate_previous = le->iterate_previous;
                else
                        lh->iterate_list_tail = le->iterate_previous;

                if (le->iterate_previous != IDX_NIL)
                        ordered_bucket_at(lh, le->iterate_previous)->iterate_next = le->iterate_next;
                else
                        lh->iterate_list_head = le->iterate_next;
        }

        /* Now shift all buckets in the interval (left, right) one step backwards */
        for (prev = left, left = next_idx(h, left); left != right;
             prev = left, left = next_idx(h, left)) {
                dib = bucket_calculate_dib(h, left, dibs[left]);
                assert(dib != 0);
                bucket_move_entry(h, NULL, left, prev);
                bucket_set_dib(h, prev, dib - 1);
        }

        bucket_mark_free(h, prev);
        n_entries_dec(h);
        base_set_dirty(h);
}
#define remove_entry(h, idx) base_remove_entry(HASHMAP_BASE(h), idx)

static unsigned hashmap_iterate_in_insertion_order(OrderedHashmap *h, Iterator *i) {
        struct ordered_hashmap_entry *e;
        unsigned idx;

        assert(h);
        assert(i);

        if (i->idx == IDX_NIL)
                goto at_end;

        if (i->idx == IDX_FIRST && h->iterate_list_head == IDX_NIL)
                goto at_end;

        if (i->idx == IDX_FIRST) {
                idx = h->iterate_list_head;
                e = ordered_bucket_at(h, idx);
        } else {
                idx = i->idx;
                e = ordered_bucket_at(h, idx);
                /*
                 * We allow removing the current entry while iterating, but removal may cause
                 * a backward shift. The next entry may thus move one bucket to the left.
                 * To detect when it happens, we remember the key pointer of the entry we were
                 * going to iterate next. If it does not match, there was a backward shift.
                 */
                if (e->p.b.key != i->next_key) {
                        idx = prev_idx(HASHMAP_BASE(h), idx);
                        e = ordered_bucket_at(h, idx);
                }
                assert(e->p.b.key == i->next_key);
        }

        if (e->iterate_next != IDX_NIL) {
                struct ordered_hashmap_entry *n;
                i->idx = e->iterate_next;
                n = ordered_bucket_at(h, i->idx);
                i->next_key = n->p.b.key;
        } else
                i->idx = IDX_NIL;

        return idx;

at_end:
        i->idx = IDX_NIL;
        return IDX_NIL;
}

static unsigned hashmap_iterate_in_internal_order(HashmapBase *h, Iterator *i) {
        unsigned idx;

        assert(h);
        assert(i);

        if (i->idx == IDX_NIL)
                goto at_end;

        if (i->idx == IDX_FIRST) {
                /* fast forward to the first occupied bucket */
                if (h->has_indirect) {
                        i->idx = skip_free_buckets(h, h->indirect.idx_lowest_entry);
                        h->indirect.idx_lowest_entry = i->idx;
                } else
                        i->idx = skip_free_buckets(h, 0);

                if (i->idx == IDX_NIL)
                        goto at_end;
        } else {
                struct hashmap_base_entry *e;

                assert(i->idx > 0);

                e = bucket_at(h, i->idx);
                /*
                 * We allow removing the current entry while iterating, but removal may cause
                 * a backward shift. The next entry may thus move one bucket to the left.
                 * To detect when it happens, we remember the key pointer of the entry we were
                 * going to iterate next. If it does not match, there was a backward shift.
                 */
                if (e->key != i->next_key)
                        e = bucket_at(h, --i->idx);

                assert(e->key == i->next_key);
        }

        idx = i->idx;

        i->idx = skip_free_buckets(h, i->idx + 1);
        if (i->idx != IDX_NIL)
                i->next_key = bucket_at(h, i->idx)->key;
        else
                i->idx = IDX_NIL;

        return idx;

at_end:
        i->idx = IDX_NIL;
        return IDX_NIL;
}

static unsigned hashmap_iterate_entry(HashmapBase *h, Iterator *i) {
        if (!h) {
                i->idx = IDX_NIL;
                return IDX_NIL;
        }

        return h->type == HASHMAP_TYPE_ORDERED ? hashmap_iterate_in_insertion_order((OrderedHashmap*) h, i)
                                               : hashmap_iterate_in_internal_order(h, i);
}

bool _hashmap_iterate(HashmapBase *h, Iterator *i, void **value, const void **key) {
        struct hashmap_base_entry *e;
        void *data;
        unsigned idx;

        idx = hashmap_iterate_entry(h, i);
        if (idx == IDX_NIL) {
                if (value)
                        *value = NULL;
                if (key)
                        *key = NULL;

                return false;
        }

        e = bucket_at(h, idx);
        data = entry_value(h, e);
        if (value)
                *value = data;
        if (key)
                *key = e->key;

        return true;
}

#define HASHMAP_FOREACH_IDX(idx, h, i) \
        for ((i) = ITERATOR_FIRST, (idx) = hashmap_iterate_entry((h), &(i)); \
             (idx != IDX_NIL); \
             (idx) = hashmap_iterate_entry((h), &(i)))

static void reset_direct_storage(HashmapBase *h) {
        const struct hashmap_type_info *hi = &hashmap_type_info[h->type];
        void *p;
        size_t nset;

        assert(!h->has_indirect);

        nset = hi->entry_size * hi->n_direct_buckets;
        memset(h->direct.storage, 0, nset);
        p = ((uint8_t*)h->direct.storage) + nset;
        memset(p, DIB_RAW_INIT, sizeof(dib_raw_t) * hi->n_direct_buckets);
}

static struct HashmapBase* hashmap_base_new(const struct hash_ops *hash_ops, enum HashmapType type) {
        HashmapBase *h;
        const struct hashmap_type_info *hi = &hashmap_type_info[type];

        h = calloc(1, hi->head_size);
        if (!h)
                return NULL;

        h->type = type;
        h->hash_ops = hash_ops ?: &trivial_hash_ops;

        if (type == HASHMAP_TYPE_ORDERED) {
                OrderedHashmap *lh = (OrderedHashmap*)h;
                lh->iterate_list_head = lh->iterate_list_tail = IDX_NIL;
        }

        reset_direct_storage(h);

        static bool once = true;
        if (once) {
                random_bytes(shared_hash_key, sizeof(shared_hash_key));
                once = false;
        }

        return h;
}

Hashmap *_hashmap_new(const struct hash_ops *hash_ops) {
        return (Hashmap*)        hashmap_base_new(hash_ops, HASHMAP_TYPE_PLAIN);
}

OrderedHashmap *_ordered_hashmap_new(const struct hash_ops *hash_ops) {
        return (OrderedHashmap*) hashmap_base_new(hash_ops, HASHMAP_TYPE_ORDERED);
}

Set *_set_new(const struct hash_ops *hash_ops) {
        return (Set*)            hashmap_base_new(hash_ops, HASHMAP_TYPE_SET);
}

static int hashmap_base_ensure_allocated(HashmapBase **h, const struct hash_ops *hash_ops,
                                         enum HashmapType type) {
        HashmapBase *q;

        assert(h);

        if (*h)
                return 0;

        q = hashmap_base_new(hash_ops, type);
        if (!q)
                return -ENOMEM;

        *h = q;
        return 1;
}

int _hashmap_ensure_allocated(Hashmap **h, const struct hash_ops *hash_ops) {
        return hashmap_base_ensure_allocated((HashmapBase**)h, hash_ops, HASHMAP_TYPE_PLAIN);
}

int _ordered_hashmap_ensure_allocated(OrderedHashmap **h, const struct hash_ops *hash_ops) {
        return hashmap_base_ensure_allocated((HashmapBase**)h, hash_ops, HASHMAP_TYPE_ORDERED);
}

int _set_ensure_allocated(Set **s, const struct hash_ops *hash_ops) {
        return hashmap_base_ensure_allocated((HashmapBase**)s, hash_ops, HASHMAP_TYPE_SET);
}

int _hashmap_ensure_put(Hashmap **h, const struct hash_ops *hash_ops, const void *key, void *value) {
        int r;

        r = _hashmap_ensure_allocated(h, hash_ops);
        if (r < 0)
                return r;

        return hashmap_put(*h, key, value);
}

int _ordered_hashmap_ensure_put(OrderedHashmap **h, const struct hash_ops *hash_ops, const void *key, void *value) {
        int r;

        r = _ordered_hashmap_ensure_allocated(h, hash_ops);
        if (r < 0)
                return r;

        return ordered_hashmap_put(*h, key, value);
}

static void hashmap_free_no_clear(HashmapBase *h) {
        assert(!h->has_indirect);
        assert(h->n_direct_entries == 0);

        free(h);
}

HashmapBase* _hashmap_free(HashmapBase *h, free_func_t default_free_key, free_func_t default_free_value) {
        if (h) {
                _hashmap_clear(h, default_free_key, default_free_value);
                hashmap_free_no_clear(h);
        }

        return NULL;
}

void _hashmap_clear(HashmapBase *h, free_func_t default_free_key, free_func_t default_free_value) {
        free_func_t free_key, free_value;
        if (!h)
                return;

        free_key = h->hash_ops->free_key ?: default_free_key;
        free_value = h->hash_ops->free_value ?: default_free_value;

        if (free_key || free_value) {

                /* If destructor calls are defined, let's destroy things defensively: let's take the item out of the
                 * hash table, and only then call the destructor functions. If these destructors then try to unregister
                 * themselves from our hash table a second time, the entry is already gone. */

                while (_hashmap_size(h) > 0) {
                        void *k = NULL;
                        void *v;

                        v = _hashmap_first_key_and_value(h, true, &k);

                        if (free_key)
                                free_key(k);

                        if (free_value)
                                free_value(v);
                }
        }

        if (h->has_indirect) {
                free(h->indirect.storage);
                h->has_indirect = false;
        }

        h->n_direct_entries = 0;
        reset_direct_storage(h);

        if (h->type == HASHMAP_TYPE_ORDERED) {
                OrderedHashmap *lh = (OrderedHashmap*) h;
                lh->iterate_list_head = lh->iterate_list_tail = IDX_NIL;
        }

        base_set_dirty(h);
}

static int resize_buckets(HashmapBase *h, unsigned entries_add);

/*
 * Finds an empty bucket to put an entry into, starting the scan at 'idx'.
 * Performs Robin Hood swaps as it goes. The entry to put must be placed
 * by the caller into swap slot IDX_PUT.
 * If used for in-place resizing, may leave a displaced entry in swap slot
 * IDX_PUT. Caller must rehash it next.
 * Returns: true if it left a displaced entry to rehash next in IDX_PUT,
 *          false otherwise.
 */
static bool hashmap_put_robin_hood(HashmapBase *h, unsigned idx,
                                   struct swap_entries *swap) {
        dib_raw_t raw_dib, *dibs;
        unsigned dib, distance;

        dibs = dib_raw_ptr(h);

        for (distance = 0; ; distance++) {
                raw_dib = dibs[idx];
                if (IN_SET(raw_dib, DIB_RAW_FREE, DIB_RAW_REHASH)) {
                        if (raw_dib == DIB_RAW_REHASH)
                                bucket_move_entry(h, swap, idx, IDX_TMP);

                        if (h->has_indirect && h->indirect.idx_lowest_entry > idx)
                                h->indirect.idx_lowest_entry = idx;

                        bucket_set_dib(h, idx, distance);
                        bucket_move_entry(h, swap, IDX_PUT, idx);
                        if (raw_dib == DIB_RAW_REHASH) {
                                bucket_move_entry(h, swap, IDX_TMP, IDX_PUT);
                                return true;
                        }

                        return false;
                }

                dib = bucket_calculate_dib(h, idx, raw_dib);

                if (dib < distance) {
                        /* Found a wealthier entry. Go Robin Hood! */
                        bucket_set_dib(h, idx, distance);

                        /* swap the entries */
                        bucket_move_entry(h, swap, idx, IDX_TMP);
                        bucket_move_entry(h, swap, IDX_PUT, idx);
                        bucket_move_entry(h, swap, IDX_TMP, IDX_PUT);

                        distance = dib;
                }

                idx = next_idx(h, idx);
        }
}

/*
 * Puts an entry into a hashmap, boldly - no check whether key already exists.
 * The caller must place the entry (only its key and value, not link indexes)
 * in swap slot IDX_PUT.
 * Caller must ensure: the key does not exist yet in the hashmap.
 *                     that resize is not needed if !may_resize.
 * Returns: 1 if entry was put successfully.
 *          -ENOMEM if may_resize==true and resize failed with -ENOMEM.
 *          Cannot return -ENOMEM if !may_resize.
 */
static int hashmap_base_put_boldly(HashmapBase *h, unsigned idx,
                                   struct swap_entries *swap, bool may_resize) {
        struct ordered_hashmap_entry *new_entry;
        int r;

        assert(idx < n_buckets(h));

        new_entry = bucket_at_swap(swap, IDX_PUT);

        if (may_resize) {
                r = resize_buckets(h, 1);
                if (r < 0)
                        return r;
                if (r > 0)
                        idx = bucket_hash(h, new_entry->p.b.key);
        }
        assert(n_entries(h) < n_buckets(h));

        if (h->type == HASHMAP_TYPE_ORDERED) {
                OrderedHashmap *lh = (OrderedHashmap*) h;

                new_entry->iterate_next = IDX_NIL;
                new_entry->iterate_previous = lh->iterate_list_tail;

                if (lh->iterate_list_tail != IDX_NIL) {
                        struct ordered_hashmap_entry *old_tail;

                        old_tail = ordered_bucket_at(lh, lh->iterate_list_tail);
                        assert(old_tail->iterate_next == IDX_NIL);
                        old_tail->iterate_next = IDX_PUT;
                }

                lh->iterate_list_tail = IDX_PUT;
                if (lh->iterate_list_head == IDX_NIL)
                        lh->iterate_list_head = IDX_PUT;
        }

        assert_se(hashmap_put_robin_hood(h, idx, swap) == false);

        n_entries_inc(h);
        base_set_dirty(h);

        return 1;
}
#define hashmap_put_boldly(h, idx, swap, may_resize) \
        hashmap_base_put_boldly(HASHMAP_BASE(h), idx, swap, may_resize)

/*
 * Returns 0 if resize is not needed.
 *         1 if successfully resized.
 *         -ENOMEM on allocation failure.
 */
static int resize_buckets(HashmapBase *h, unsigned entries_add) {
        struct swap_entries swap;
        void *new_storage;
        dib_raw_t *old_dibs, *new_dibs;
        const struct hashmap_type_info *hi;
        unsigned idx, optimal_idx;
        unsigned old_n_buckets, new_n_buckets, n_rehashed, new_n_entries;
        uint8_t new_shift;
        bool rehash_next;

        assert(h);

        hi = &hashmap_type_info[h->type];
        new_n_entries = n_entries(h) + entries_add;

        /* overflow? */
        if (_unlikely_(new_n_entries < entries_add))
                return -ENOMEM;

        /* For direct storage we allow 100% load, because it's tiny. */
        if (!h->has_indirect && new_n_entries <= hi->n_direct_buckets)
                return 0;

        /*
         * Load factor = n/m = 1 - (1/INV_KEEP_FREE).
         * From it follows: m = n + n/(INV_KEEP_FREE - 1)
         */
        new_n_buckets = new_n_entries + new_n_entries / (INV_KEEP_FREE - 1);
        /* overflow? */
        if (_unlikely_(new_n_buckets < new_n_entries))
                return -ENOMEM;

        if (_unlikely_(new_n_buckets > UINT_MAX / (hi->entry_size + sizeof(dib_raw_t))))
                return -ENOMEM;

        old_n_buckets = n_buckets(h);

        if (_likely_(new_n_buckets <= old_n_buckets))
                return 0;

        new_shift = log2u_round_up(MAX(
                        new_n_buckets * (hi->entry_size + sizeof(dib_raw_t)),
                        2 * sizeof(struct direct_storage)));

        /* Realloc storage (buckets and DIB array). */
        new_storage = realloc(h->has_indirect ? h->indirect.storage : NULL,
                              1U << new_shift);
        if (!new_storage)
                return -ENOMEM;

        /* Must upgrade direct to indirect storage. */
        if (!h->has_indirect) {
                memcpy(new_storage, h->direct.storage,
                       old_n_buckets * (hi->entry_size + sizeof(dib_raw_t)));
                h->indirect.n_entries = h->n_direct_entries;
                h->indirect.idx_lowest_entry = 0;
                h->n_direct_entries = 0;
        }

        /* Get a new hash key. If we've just upgraded to indirect storage,
         * allow reusing a previously generated key. It's still a different key
         * from the shared one that we used for direct storage. */
        get_hash_key(h->indirect.hash_key, !h->has_indirect);

        h->has_indirect = true;
        h->indirect.storage = new_storage;
        h->indirect.n_buckets = (1U << new_shift) /
                                (hi->entry_size + sizeof(dib_raw_t));

        old_dibs = (dib_raw_t*)((uint8_t*) new_storage + hi->entry_size * old_n_buckets);
        new_dibs = dib_raw_ptr(h);

        /*
         * Move the DIB array to the new place, replacing valid DIB values with
         * DIB_RAW_REHASH to indicate all of the used buckets need rehashing.
         * Note: Overlap is not possible, because we have at least doubled the
         * number of buckets and dib_raw_t is smaller than any entry type.
         */
        for (idx = 0; idx < old_n_buckets; idx++) {
                assert(old_dibs[idx] != DIB_RAW_REHASH);
                new_dibs[idx] = old_dibs[idx] == DIB_RAW_FREE ? DIB_RAW_FREE
                                                              : DIB_RAW_REHASH;
        }

        /* Zero the area of newly added entries (including the old DIB area) */
        memset(bucket_at(h, old_n_buckets), 0,
               (n_buckets(h) - old_n_buckets) * hi->entry_size);

        /* The upper half of the new DIB array needs initialization */
        memset(&new_dibs[old_n_buckets], DIB_RAW_INIT,
               (n_buckets(h) - old_n_buckets) * sizeof(dib_raw_t));

        /* Rehash entries that need it */
        n_rehashed = 0;
        for (idx = 0; idx < old_n_buckets; idx++) {
                if (new_dibs[idx] != DIB_RAW_REHASH)
                        continue;

                optimal_idx = bucket_hash(h, bucket_at(h, idx)->key);

                /*
                 * Not much to do if by luck the entry hashes to its current
                 * location. Just set its DIB.
                 */
                if (optimal_idx == idx) {
                        new_dibs[idx] = 0;
                        n_rehashed++;
                        continue;
                }

                new_dibs[idx] = DIB_RAW_FREE;
                bucket_move_entry(h, &swap, idx, IDX_PUT);
                /* bucket_move_entry does not clear the source */
                memset(bucket_at(h, idx), 0, hi->entry_size);

                do {
                        /*
                         * Find the new bucket for the current entry. This may make
                         * another entry homeless and load it into IDX_PUT.
                         */
                        rehash_next = hashmap_put_robin_hood(h, optimal_idx, &swap);
                        n_rehashed++;

                        /* Did the current entry displace another one? */
                        if (rehash_next)
                                optimal_idx = bucket_hash(h, bucket_at_swap(&swap, IDX_PUT)->p.b.key);
                } while (rehash_next);
        }

        assert_se(n_rehashed == n_entries(h));

        return 1;
}

/*
 * Finds an entry with a matching key
 * Returns: index of the found entry, or IDX_NIL if not found.
 */
static unsigned base_bucket_scan(HashmapBase *h, unsigned idx, const void *key) {
        struct hashmap_base_entry *e;
        unsigned dib, distance;
        dib_raw_t *dibs = dib_raw_ptr(h);

        assert(idx < n_buckets(h));

        for (distance = 0; ; distance++) {
                if (dibs[idx] == DIB_RAW_FREE)
                        return IDX_NIL;

                dib = bucket_calculate_dib(h, idx, dibs[idx]);

                if (dib < distance)
                        return IDX_NIL;
                if (dib == distance) {
                        e = bucket_at(h, idx);
                        if (h->hash_ops->compare(e->key, key) == 0)
                                return idx;
                }

                idx = next_idx(h, idx);
        }
}
#define bucket_scan(h, idx, key) base_bucket_scan(HASHMAP_BASE(h), idx, key)

int hashmap_put(Hashmap *h, const void *key, void *value) {
        struct swap_entries swap;
        struct plain_hashmap_entry *e;
        unsigned hash, idx;

        assert(h);

        hash = bucket_hash(h, key);
        idx = bucket_scan(h, hash, key);
        if (idx != IDX_NIL) {
                e = plain_bucket_at(h, idx);
                if (e->value == value)
                        return 0;
                return -EEXIST;
        }

        e = &bucket_at_swap(&swap, IDX_PUT)->p;
        e->b.key = key;
        e->value = value;
        return hashmap_put_boldly(h, hash, &swap, true);
}

int set_put(Set *s, const void *key) {
        struct swap_entries swap;
        struct hashmap_base_entry *e;
        unsigned hash, idx;

        assert(s);

        hash = bucket_hash(s, key);
        idx = bucket_scan(s, hash, key);
        if (idx != IDX_NIL)
                return 0;

        e = &bucket_at_swap(&swap, IDX_PUT)->p.b;
        e->key = key;
        return hashmap_put_boldly(s, hash, &swap, true);
}

int _set_ensure_put(Set **s, const struct hash_ops *hash_ops, const void *key) {
        int r;

        r = _set_ensure_allocated(s, hash_ops);
        if (r < 0)
                return r;

        return set_put(*s, key);
}

int hashmap_update(Hashmap *h, const void *key, void *value) {
        struct plain_hashmap_entry *e;
        unsigned hash, idx;

        assert(h);

        hash = bucket_hash(h, key);
        idx = bucket_scan(h, hash, key);
        if (idx == IDX_NIL)
                return -ENOENT;

        e = plain_bucket_at(h, idx);
        e->value = value;
        hashmap_set_dirty(h);

        return 0;
}

void* _hashmap_get(HashmapBase *h, const void *key) {
        struct hashmap_base_entry *e;
        unsigned hash, idx;

        if (!h)
                return NULL;

        hash = bucket_hash(h, key);
        idx = bucket_scan(h, hash, key);
        if (idx == IDX_NIL)
                return NULL;

        e = bucket_at(h, idx);
        return entry_value(h, e);
}

bool _hashmap_contains(HashmapBase *h, const void *key) {
        unsigned hash;

        if (!h)
                return false;

        hash = bucket_hash(h, key);
        return bucket_scan(h, hash, key) != IDX_NIL;
}

void* _hashmap_remove(HashmapBase *h, const void *key) {
        struct hashmap_base_entry *e;
        unsigned hash, idx;
        void *data;

        if (!h)
                return NULL;

        hash = bucket_hash(h, key);
        idx = bucket_scan(h, hash, key);
        if (idx == IDX_NIL)
                return NULL;

        e = bucket_at(h, idx);
        data = entry_value(h, e);
        remove_entry(h, idx);

        return data;
}

static unsigned find_first_entry(HashmapBase *h) {
        Iterator i = ITERATOR_FIRST;

        if (!h || !n_entries(h))
                return IDX_NIL;

        return hashmap_iterate_entry(h, &i);
}

void* _hashmap_first_key_and_value(HashmapBase *h, bool remove, void **ret_key) {
        struct hashmap_base_entry *e;
        void *key, *data;
        unsigned idx;

        idx = find_first_entry(h);
        if (idx == IDX_NIL) {
                if (ret_key)
                        *ret_key = NULL;
                return NULL;
        }

        e = bucket_at(h, idx);
        key = (void*) e->key;
        data = entry_value(h, e);

        if (remove)
                remove_entry(h, idx);

        if (ret_key)
                *ret_key = key;

        return data;
}

unsigned _hashmap_size(HashmapBase *h) {
        if (!h)
                return 0;

        return n_entries(h);
}

char** _hashmap_get_strv(HashmapBase *h) {
        char **sv;
        Iterator i;
        unsigned idx, n;

        if (!h)
                return calloc(1, sizeof(char*));

        sv = malloc((n_entries(h)+1) * sizeof(char*));
        if (!sv)
                return NULL;

        n = 0;
        HASHMAP_FOREACH_IDX(idx, h, i)
                sv[n++] = entry_value(h, bucket_at(h, idx));
        sv[n] = NULL;

        return sv;
}

int set_consume(Set *s, void *value) {
        int r;

        assert(s);
        assert(value);

        r = set_put(s, value);
        if (r <= 0)
                free(value);

        return r;
}

int _set_put_strndup_full(Set **s, const struct hash_ops *hash_ops, const char *p, size_t n) {
        char *c;
        int r;

        assert(s);
        assert(p);

        r = _set_ensure_allocated(s, hash_ops);
        if (r < 0)
                return r;

        if (n == SIZE_MAX) {
                if (set_contains(*s, (char*) p))
                        return 0;

                c = strdup(p);
        } else
                c = strndup(p, n);
        if (!c)
                return -ENOMEM;

        return set_consume(*s, c);
}
