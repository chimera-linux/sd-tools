/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utmp.h>

#include "alloc-util.h"
#include "chase.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "lock-util.h"
#include "macro.h"
#include "mkdir.h"
#include "path-util.h"
#include "random-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"
#include "utf8.h"

bool uid_is_valid(uid_t uid) {

        /* Also see POSIX IEEE Std 1003.1-2008, 2016 Edition, 3.436. */

        /* Some libc APIs use UID_INVALID as special placeholder */
        if (uid == (uid_t) UINT32_C(0xFFFFFFFF))
                return false;

        /* A long time ago UIDs where 16 bit, hence explicitly avoid the 16-bit -1 too */
        if (uid == (uid_t) UINT32_C(0xFFFF))
                return false;

        return true;
}

int parse_uid(const char *s, uid_t *ret) {
        uint32_t uid = 0;
        int r = 0;

        assert(s);

        assert_cc(sizeof(uid_t) == sizeof(uint32_t));

        if (*s < '1' || *s > '9') {
                if (*s == '0' && !s[1])
                        uid = 0;
                else
                        r = -EINVAL;
        } else {
                char *end = NULL;
                unsigned long v = strtoul(s, &end, 10);
                if (!end || *end)
                        r = -EINVAL;
                else if (v > UINT_MAX)
                        r = -ERANGE;
                else
                        uid = v;
        }
        if (r < 0)
                return r;

        if (!uid_is_valid(uid))
                return -ENXIO; /* we return ENXIO instead of EINVAL
                                * here, to make it easy to distinguish
                                * invalid numeric uids from invalid
                                * strings. */

        if (ret)
                *ret = uid;

        return 0;
}
