/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <sys/types.h>

bool uid_is_valid(uid_t uid);

static inline bool gid_is_valid(gid_t gid) {
        return uid_is_valid((uid_t) gid);
}

int parse_uid(const char *s, uid_t* ret_uid);

static inline int parse_gid(const char *s, gid_t *ret_gid) {
        return parse_uid(s, (uid_t*) ret_gid);
}

#define UID_INVALID ((uid_t) -1)
#define GID_INVALID ((gid_t) -1)

#define PTR_TO_UID(p) ((uid_t) (((uintptr_t) (p))-1))
#define UID_TO_PTR(u) ((void*) (((uintptr_t) (u))+1))

#define PTR_TO_GID(p) ((gid_t) (((uintptr_t) (p))-1))
#define GID_TO_PTR(u) ((void*) (((uintptr_t) (u))+1))


