/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

#define LONG_LINE_MAX (1U*1024U*1024U)

int fdopen_unlocked(int fd, const char *options, FILE **ret);
int take_fdopen_unlocked(int *fd, const char *options, FILE **ret);
FILE* take_fdopen(int *fd, const char *options);
DIR* take_fdopendir(int *dfd);
DIR *xopendirat(int dirfd, const char *name, int flags);

int search_and_fopen_re(const char *path, const char *root, const char **search, FILE **ret_file, char **ret_path);

int read_line(FILE *f, size_t limit, char **ret);
int read_stripped_line(FILE *f, size_t limit, char **ret);
