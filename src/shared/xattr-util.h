/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>

int getxattr_at_malloc(int fd, const char *path, const char *name, int flags, char **ret);
int listxattr_at_malloc(int fd, const char *path, int flags, char **ret);
int xsetxattr(int fd, const char *path, const char *name, const char *value, size_t size, int flags);
