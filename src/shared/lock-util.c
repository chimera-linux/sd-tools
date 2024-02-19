/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "lock-util.h"
#include "macro.h"
#include "path-util.h"

static int fcntl_lock(int fd, int operation, bool ofd) {
        int cmd, type, r;

        assert(fd >= 0);

        if (ofd)
                cmd = (operation & LOCK_NB) ? F_OFD_SETLK : F_OFD_SETLKW;
        else
                cmd = (operation & LOCK_NB) ? F_SETLK : F_SETLKW;

        switch (operation & ~LOCK_NB) {
                case LOCK_EX:
                        type = F_WRLCK;
                        break;
                case LOCK_SH:
                        type = F_RDLCK;
                        break;
                case LOCK_UN:
                        type = F_UNLCK;
                        break;
                default:
                        assert_not_reached();
        }

        r = RET_NERRNO(fcntl(fd, cmd, &(struct flock) {
                .l_type = type,
                .l_whence = SEEK_SET,
                .l_start = 0,
                .l_len = 0,
        }));

        if (r == -EACCES) /* Treat EACCESS/EAGAIN the same as per man page. */
                r = -EAGAIN;

        return r;
}

int lock_generic(int fd, LockType type, int operation) {
        assert(fd >= 0);

        switch (type) {
        case LOCK_NONE:
                return 0;
        case LOCK_BSD:
                return RET_NERRNO(flock(fd, operation));
        case LOCK_POSIX:
                return fcntl_lock(fd, operation, /*ofd=*/ false);
        case LOCK_UNPOSIX:
                return fcntl_lock(fd, operation, /*ofd=*/ true);
        default:
                assert_not_reached();
        }
}
