/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#define CONF_PATHS_USR(n)                       \
        "/etc/" n,                              \
        "/run/" n,                              \
        "/usr/local/lib/" n,                    \
        "/usr/lib/" n

#define CONF_PATHS_STRV(n)                      \
        STRV_MAKE(CONF_PATHS_USR(n))

