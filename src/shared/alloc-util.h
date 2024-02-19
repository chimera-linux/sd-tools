/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <alloca.h>
#include <malloc.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "macro.h"

typedef void (*free_func_t)(void *p);
typedef void* (*mfree_func_t)(void *p);

#define free_and_replace_full(a, b, free_func)  \
        ({                                      \
                typeof(a)* _a = &(a);           \
                typeof(b)* _b = &(b);           \
                free_func(*_a);                 \
                *_a = *_b;                      \
                *_b = NULL;                     \
                0;                              \
        })

#define free_and_replace(a, b)                  \
        free_and_replace_full(a, b, free)

static inline void freep(void *p) {
        *(void**)p = mfree(*(void**) p);
}

#define _cleanup_free_ _cleanup_(freep)
