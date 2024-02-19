/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef enum LockType {
        LOCK_NONE, /* Don't lock the file descriptor. Useful if you need to conditionally lock a file. */
        LOCK_BSD,
        LOCK_POSIX,
        LOCK_UNPOSIX,
} LockType;

int lock_generic(int fd, LockType type, int operation);
