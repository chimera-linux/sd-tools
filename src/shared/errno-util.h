/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "macro.h"

static inline void _reset_errno_(int *saved_errno) {
        if (*saved_errno < 0) /* Invalidated by UNPROTECT_ERRNO? */
                return;

        errno = *saved_errno;
}

#define PROTECT_ERRNO                           \
        _cleanup_(_reset_errno_) _unused_ int _saved_errno_ = errno

#define UNPROTECT_ERRNO                         \
        do {                                    \
                errno = _saved_errno_;          \
                _saved_errno_ = -1;             \
        } while (false)

#define LOCAL_ERRNO(value)                      \
        PROTECT_ERRNO;                          \
        errno = abs(value)

static inline int negative_errno(void) {
        /* This helper should be used to shut up gcc if you know 'errno' is
         * negative. Instead of "return -errno;", use "return negative_errno();"
         * It will suppress bogus gcc warnings in case it assumes 'errno' might
         * be 0 and thus the caller's error-handling might not be triggered. */
        assert_return(errno > 0, -EINVAL);
        return -errno;
}

static inline int RET_NERRNO(int ret) {

        /* Helper to wrap system calls in to make them return negative errno errors. This brings system call
         * error handling in sync with how we usually handle errors in our own code, i.e. with immediate
         * returning of negative errno. Usage is like this:
         *
         *     …
         *     r = RET_NERRNO(unlink(t));
         *     …
         *
         * or
         *
         *     …
         *     fd = RET_NERRNO(open("/etc/fstab", O_RDONLY|O_CLOEXEC));
         *     …
         */

        if (ret < 0)
                return negative_errno();

        return ret;
}

static inline int errno_or_else(int fallback) {
        /* To be used when invoking library calls where errno handling is not defined clearly: we return
         * errno if it is set, and the specified error otherwise. The idea is that the caller initializes
         * errno to zero before doing an API call, and then uses this helper to retrieve a somewhat useful
         * error code */
        if (errno > 0)
                return -errno;

        return -abs(fallback);
}

/* abs(3) says: Trying to take the absolute value of the most negative integer is not defined. */
#define _DEFINE_ABS_WRAPPER(name)                         \
        static inline bool ERRNO_IS_##name(intmax_t r) {  \
                if (r == INTMAX_MIN)                      \
                        return false;                     \
                return ERRNO_IS_NEG_##name(-imaxabs(r));  \
        }

assert_cc(INT_MAX <= INTMAX_MAX);

/* Resource exhaustion, could be our fault or general system trouble */
static inline bool ERRNO_IS_NEG_RESOURCE(intmax_t r) {
        return IN_SET(r,
                      -EMFILE,
                      -ENFILE,
                      -ENOMEM);
}
_DEFINE_ABS_WRAPPER(RESOURCE);

/* Seven different errors for "operation/system call/ioctl/socket feature not supported" */
static inline bool ERRNO_IS_NEG_NOT_SUPPORTED(intmax_t r) {
        return IN_SET(r,
                      -EOPNOTSUPP,
                      -ENOTTY,
                      -ENOSYS,
                      -EAFNOSUPPORT,
                      -EPFNOSUPPORT,
                      -EPROTONOSUPPORT,
                      -ESOCKTNOSUPPORT);
}
_DEFINE_ABS_WRAPPER(NOT_SUPPORTED);

/* Two different errors for access problems */
static inline bool ERRNO_IS_NEG_PRIVILEGE(intmax_t r) {
        return IN_SET(r,
                      -EACCES,
                      -EPERM);
}
_DEFINE_ABS_WRAPPER(PRIVILEGE);
