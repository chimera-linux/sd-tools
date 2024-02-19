/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

/* Temporarily disable some warnings */
#define DISABLE_WARNING_DEPRECATED_DECLARATIONS                         \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")

#define DISABLE_WARNING_FORMAT_NONLITERAL                               \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wformat-nonliteral\"")

#define DISABLE_WARNING_MISSING_PROTOTYPES                              \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wmissing-prototypes\"")

#define DISABLE_WARNING_NONNULL                                         \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wnonnull\"")

#define DISABLE_WARNING_SHADOW                                          \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wshadow\"")

#define DISABLE_WARNING_INCOMPATIBLE_POINTER_TYPES                      \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wincompatible-pointer-types\"")

#define DISABLE_WARNING_TYPE_LIMITS                                     \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Wtype-limits\"")

#define DISABLE_WARNING_ADDRESS                                         \
        _Pragma("GCC diagnostic push");                                 \
        _Pragma("GCC diagnostic ignored \"-Waddress\"")

#define REENABLE_WARNING                                                \
        _Pragma("GCC diagnostic pop")

#define _align_(x) __attribute__((__aligned__(x)))
#define _alignas_(x) __attribute__((__aligned__(alignof(x))))
#define _alignptr_ __attribute__((__aligned__(sizeof(void *))))
#define _cleanup_(x) __attribute__((__cleanup__(x)))
#define _const_ __attribute__((__const__))
#define _deprecated_ __attribute__((__deprecated__))
#define _destructor_ __attribute__((__destructor__))
#define _hidden_ __attribute__((__visibility__("hidden")))
#define _likely_(x) (__builtin_expect(!!(x), 1))
#define _malloc_ __attribute__((__malloc__))
#define _noinline_ __attribute__((noinline))
#define _noreturn_ _Noreturn
#define _packed_ __attribute__((__packed__))
#define _printf_(a, b) __attribute__((__format__(printf, a, b)))
#define _public_ __attribute__((__visibility__("default")))
#define _pure_ __attribute__((__pure__))
#define _retain_ __attribute__((__retain__))
#define _returns_nonnull_ __attribute__((__returns_nonnull__))
#define _section_(x) __attribute__((__section__(x)))
#define _sentinel_ __attribute__((__sentinel__))
#define _unlikely_(x) (__builtin_expect(!!(x), 0))
#define _unused_ __attribute__((__unused__))
#define _used_ __attribute__((__used__))
#define _warn_unused_result_ __attribute__((__warn_unused_result__))
#define _weak_ __attribute__((__weak__))
#define _weakref_(x) __attribute__((__weakref__(#x)))

#ifdef __clang__
#  define _alloc_(...)
#else
#  define _alloc_(...) __attribute__((__alloc_size__(__VA_ARGS__)))
#endif

#if __GNUC__ >= 7 || (defined(__clang__) && __clang_major__ >= 10)
#  define _fallthrough_ __attribute__((__fallthrough__))
#else
#  define _fallthrough_
#endif

#define XSTRINGIFY(x) #x
#define STRINGIFY(x) XSTRINGIFY(x)

#define VOID_0 ((void)0)

#define ELEMENTSOF(x)                                                   \
        (__builtin_choose_expr(                                         \
                !__builtin_types_compatible_p(typeof(x), typeof(&*(x))), \
                sizeof(x)/sizeof((x)[0]),                               \
                VOID_0))

#define XCONCATENATE(x, y) x ## y
#define CONCATENATE(x, y) XCONCATENATE(x, y)

/* This passes the argument through after (if asserts are enabled) checking that it is not null. */
#define ASSERT_PTR(expr) _ASSERT_PTR(expr, UNIQ_T(_expr_, UNIQ), assert)
#define ASSERT_SE_PTR(expr) _ASSERT_PTR(expr, UNIQ_T(_expr_, UNIQ), assert_se)
#define _ASSERT_PTR(expr, var, check)      \
        ({                                 \
                typeof(expr) var = (expr); \
                check(var);                \
                var;                       \
        })

#define assert_cc(expr) static_assert(expr, #expr)

#define UNIQ_T(x, uniq) CONCATENATE(__unique_prefix_, CONCATENATE(x, uniq))
#define UNIQ __COUNTER__

#define IS_UNSIGNED_INTEGER_TYPE(type) \
        (__builtin_types_compatible_p(typeof(type), unsigned char) ||   \
         __builtin_types_compatible_p(typeof(type), unsigned short) ||  \
         __builtin_types_compatible_p(typeof(type), unsigned) ||        \
         __builtin_types_compatible_p(typeof(type), unsigned long) ||   \
         __builtin_types_compatible_p(typeof(type), unsigned long long))

#define IS_SIGNED_INTEGER_TYPE(type) \
        (__builtin_types_compatible_p(typeof(type), signed char) ||   \
         __builtin_types_compatible_p(typeof(type), signed short) ||  \
         __builtin_types_compatible_p(typeof(type), signed) ||        \
         __builtin_types_compatible_p(typeof(type), signed long) ||   \
         __builtin_types_compatible_p(typeof(type), signed long long))

/* Evaluates to (void) if _A or _B are not constant or of different types (being integers of different sizes
 * is also OK as long as the signedness matches) */
#define CONST_MAX(_A, _B) \
        (__builtin_choose_expr(                                         \
                __builtin_constant_p(_A) &&                             \
                __builtin_constant_p(_B) &&                             \
                (__builtin_types_compatible_p(typeof(_A), typeof(_B)) || \
                 (IS_UNSIGNED_INTEGER_TYPE(_A) && IS_UNSIGNED_INTEGER_TYPE(_B)) || \
                 (IS_SIGNED_INTEGER_TYPE(_A) && IS_SIGNED_INTEGER_TYPE(_B))), \
                ((_A) > (_B)) ? (_A) : (_B),                            \
                VOID_0))

#define MIN3(x, y, z)                                   \
        ({                                              \
                const typeof(x) _c = MIN(x, y);         \
                MIN(_c, z);                             \
        })

#define LESS_BY(a, b) __LESS_BY(UNIQ, (a), UNIQ, (b))
#define __LESS_BY(aq, a, bq, b)                         \
        ({                                              \
                const typeof(a) UNIQ_T(A, aq) = (a);    \
                const typeof(b) UNIQ_T(B, bq) = (b);    \
                UNIQ_T(A, aq) > UNIQ_T(B, bq) ? UNIQ_T(A, aq) - UNIQ_T(B, bq) : 0; \
        })

#define CMP(a, b) __CMP(UNIQ, (a), UNIQ, (b))
#define __CMP(aq, a, bq, b)                             \
        ({                                              \
                const typeof(a) UNIQ_T(A, aq) = (a);    \
                const typeof(b) UNIQ_T(B, bq) = (b);    \
                UNIQ_T(A, aq) < UNIQ_T(B, bq) ? -1 :    \
                UNIQ_T(A, aq) > UNIQ_T(B, bq) ? 1 : 0;  \
        })

#define  CASE_F_1(X)      case X:
#define  CASE_F_2(X, ...) case X:  CASE_F_1( __VA_ARGS__)
#define  CASE_F_3(X, ...) case X:  CASE_F_2( __VA_ARGS__)
#define  CASE_F_4(X, ...) case X:  CASE_F_3( __VA_ARGS__)
#define  CASE_F_5(X, ...) case X:  CASE_F_4( __VA_ARGS__)
#define  CASE_F_6(X, ...) case X:  CASE_F_5( __VA_ARGS__)
#define  CASE_F_7(X, ...) case X:  CASE_F_6( __VA_ARGS__)
#define  CASE_F_8(X, ...) case X:  CASE_F_7( __VA_ARGS__)
#define  CASE_F_9(X, ...) case X:  CASE_F_8( __VA_ARGS__)
#define CASE_F_10(X, ...) case X:  CASE_F_9( __VA_ARGS__)
#define CASE_F_11(X, ...) case X: CASE_F_10( __VA_ARGS__)
#define CASE_F_12(X, ...) case X: CASE_F_11( __VA_ARGS__)
#define CASE_F_13(X, ...) case X: CASE_F_12( __VA_ARGS__)
#define CASE_F_14(X, ...) case X: CASE_F_13( __VA_ARGS__)
#define CASE_F_15(X, ...) case X: CASE_F_14( __VA_ARGS__)
#define CASE_F_16(X, ...) case X: CASE_F_15( __VA_ARGS__)
#define CASE_F_17(X, ...) case X: CASE_F_16( __VA_ARGS__)
#define CASE_F_18(X, ...) case X: CASE_F_17( __VA_ARGS__)
#define CASE_F_19(X, ...) case X: CASE_F_18( __VA_ARGS__)
#define CASE_F_20(X, ...) case X: CASE_F_19( __VA_ARGS__)

#define GET_CASE_F(_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12,_13,_14,_15,_16,_17,_18,_19,_20,NAME,...) NAME
#define FOR_EACH_MAKE_CASE(...) \
        GET_CASE_F(__VA_ARGS__,CASE_F_20,CASE_F_19,CASE_F_18,CASE_F_17,CASE_F_16,CASE_F_15,CASE_F_14,CASE_F_13,CASE_F_12,CASE_F_11, \
                               CASE_F_10,CASE_F_9,CASE_F_8,CASE_F_7,CASE_F_6,CASE_F_5,CASE_F_4,CASE_F_3,CASE_F_2,CASE_F_1) \
                   (__VA_ARGS__)

#define IN_SET(x, first, ...)                                           \
        ({                                                              \
                bool _found = false;                                    \
                /* If the build breaks in the line below, you need to extend the case macros. We use typeof(+x) \
                 * here to widen the type of x if it is a bit-field as this would otherwise be illegal. */      \
                static const typeof(+x) __assert_in_set[] _unused_ = { first, __VA_ARGS__ }; \
                assert_cc(ELEMENTSOF(__assert_in_set) <= 20);           \
                switch (x) {                                            \
                FOR_EACH_MAKE_CASE(first, __VA_ARGS__)                  \
                        _found = true;                                  \
                        break;                                          \
                default:                                                \
                        break;                                          \
                }                                                       \
                _found;                                                 \
        })

/* Takes inspiration from Rust's Option::take() method: reads and returns a pointer, but at the same time
 * resets it to NULL. See: https://doc.rust-lang.org/std/option/enum.Option.html#method.take */
#define TAKE_GENERIC(var, type, nullvalue)                       \
        ({                                                       \
                type *_pvar_ = &(var);                           \
                type _var_ = *_pvar_;                            \
                type _nullvalue_ = nullvalue;                    \
                *_pvar_ = _nullvalue_;                           \
                _var_;                                           \
        })
#define TAKE_PTR_TYPE(ptr, type) TAKE_GENERIC(ptr, type, NULL)
#define TAKE_PTR(ptr) TAKE_PTR_TYPE(ptr, typeof(ptr))
#define TAKE_STRUCT_TYPE(s, type) TAKE_GENERIC(s, type, {})
#define TAKE_STRUCT(s) TAKE_STRUCT_TYPE(s, typeof(s))

/*
 * STRLEN - return the length of a string literal, minus the trailing NUL byte.
 *          Contrary to strlen(), this is a constant expression.
 * @x: a string literal.
 */
#define STRLEN(x) (sizeof(""x"") - sizeof(typeof(x[0])))

#define mfree(memory)                           \
        ({                                      \
                free(memory);                   \
                (typeof(memory)) NULL;          \
        })

/* Similar to ((t *) (void *) (p)) to cast a pointer. The macro asserts that the pointer has a suitable
 * alignment for type "t". This exists for places where otherwise "-Wcast-align=strict" would issue a
 * warning or if you want to assert that the cast gives a pointer of suitable alignment. */
#define CAST_ALIGN_PTR(t, p)                                    \
        ({                                                      \
                const void *_p = (p);                           \
                assert(((uintptr_t) _p) % alignof(t) == 0); \
                (t *) _p;                                       \
        })

#define UPDATE_FLAG(orig, flag, b)                      \
        ((b) ? ((orig) | (flag)) : ((orig) & ~(flag)))
#define SET_FLAG(v, flag, b) \
        (v) = UPDATE_FLAG(v, flag, b)
#define FLAGS_SET(v, flags) \
        ((~(v) & (flags)) == 0)

/* When func() returns the void value (NULL, -1, …) of the appropriate type */
#define DEFINE_TRIVIAL_CLEANUP_FUNC(type, func)                 \
        static inline void func##p(type *p) {                   \
                if (*p)                                         \
                        *p = func(*p);                          \
        }

/* When func() doesn't return the appropriate type, set variable to empty afterwards.
 * The func() may be provided by a dynamically loaded shared library, hence add an assertion. */
#define DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(type, func, empty)     \
        static inline void func##p(type *p) {                   \
                if (*p != (empty)) {                            \
                        DISABLE_WARNING_ADDRESS;                \
                        assert(func);                           \
                        REENABLE_WARNING;                       \
                        func(*p);                               \
                        *p = (empty);                           \
                }                                               \
        }

/* builtins */
#if __SIZEOF_INT__ == 4
#define BUILTIN_FFS_U32(x) __builtin_ffs(x);
#elif __SIZEOF_LONG__ == 4
#define BUILTIN_FFS_U32(x) __builtin_ffsl(x);
#else
#error "neither int nor long are four bytes long?!?"
#endif

/* align to next higher power-of-2 (except for: 0 => 0, overflow => 0) */
static inline unsigned long ALIGN_POWER2(unsigned long u) {

        /* Avoid subtraction overflow */
        if (u == 0)
                return 0;

        /* clz(0) is undefined */
        if (u == 1)
                return 1;

        /* left-shift overflow is undefined */
        if (__builtin_clzl(u - 1UL) < 1)
                return 0;

        return 1UL << (sizeof(u) * 8 - __builtin_clzl(u - 1UL));
}

static inline size_t GREEDY_ALLOC_ROUND_UP(size_t l) {
        size_t m;

        /* Round up allocation sizes a bit to some reasonable, likely larger value. This is supposed to be
         * used for cases which are likely called in an allocation loop of some form, i.e. that repetitively
         * grow stuff, for example strv_extend() and suchlike.
         *
         * Note the benefits of direct ALIGN_POWER2() usage: type-safety for size_t, sane handling for very
         * small (i.e. <= 2) and safe handling for very large (i.e. > SSIZE_MAX) values. */

        if (l <= 2)
                return 2; /* Never allocate less than 2 of something.  */

        m = ALIGN_POWER2(l);
        if (m == 0) /* overflow? */
                return l;

        return m;
}

#define assert_message_se(expr, message)                                \
        do {                                                            \
                if (_unlikely_(!(expr)))                                \
                        log_assert_failed(message, __FILE__, __LINE__, __func__); \
        } while (false)

#define assert_log(expr, message) ((_likely_(expr))                     \
        ? (true)                                                        \
        : (log_assert_failed_return(message, __FILE__, __LINE__, __func__), false))

#define assert_se(expr) assert_message_se(expr, #expr)

/* We override the glibc assert() here. */
#undef assert
#ifdef NDEBUG
#define assert(expr) ({ if (!(expr)) __builtin_unreachable(); })
#else
#define assert(expr) assert_message_se(expr, #expr)
#endif

#define assert_not_reached()                                            \
        log_assert_failed_unreachable(__FILE__, __LINE__, __func__)

#define assert_return(expr, r)                                          \
        do {                                                            \
                if (!assert_log(expr, #expr))                           \
                        return (r);                                     \
        } while (false)

#define PTR_TO_UINT(p) ((unsigned) ((uintptr_t) (p)))
#define UINT_TO_PTR(u) ((void *) ((uintptr_t) (u)))

/* Returns the number of chars needed to format variables of the specified type as a decimal string. Adds in
 * extra space for a negative '-' prefix for signed types. Includes space for the trailing NUL. */
#define DECIMAL_STR_MAX(type)                                           \
        ((size_t) IS_SIGNED_INTEGER_TYPE(type) + 1U +                   \
            (sizeof(type) <= 1 ? 3U :                                   \
             sizeof(type) <= 2 ? 5U :                                   \
             sizeof(type) <= 4 ? 10U :                                  \
             sizeof(type) <= 8 ? (IS_SIGNED_INTEGER_TYPE(type) ? 19U : 20U) : sizeof(int[-2*(sizeof(type) > 8)])))


#define STRV_MAKE(...) ((char**) ((const char*[]) { __VA_ARGS__, NULL }))
#define STRV_MAKE_EMPTY ((char*[1]) { NULL })
#define STRV_MAKE_CONST(...) ((const char* const*) ((const char*[]) { __VA_ARGS__, NULL }))

typedef struct {
        int _empty[0];
} dummy_t;

assert_cc(sizeof(dummy_t) == 0);

/* A little helper for subtracting 1 off a pointer in a safe UB-free way. This is intended to be used for
 * loops that count down from a high pointer until some base. A naive loop would implement this like this:
 *
 * for (p = end-1; p >= base; p--) …
 *
 * But this is not safe because p before the base is UB in C. With this macro the loop becomes this instead:
 *
 * for (p = PTR_SUB1(end, base); p; p = PTR_SUB1(p, base)) …
 *
 * And is free from UB! */
#define PTR_SUB1(p, base)                                \
        ({                                               \
                typeof(p) _q = (p);                      \
                _q && _q > (base) ? &_q[-1] : NULL;      \
        })

#include "log.h"
