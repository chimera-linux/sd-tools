/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>

int fopen_temporary_at(int dir_fd, const char *path, FILE **ret_file, char **ret_path);

int tempfn_random(const char *p, const char *extra, char **ret);
int tempfn_random_child(const char *p, const char *extra, char **ret);

