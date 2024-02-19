/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <uchar.h>

int cunescape_one(const char *p, size_t length, char32_t *ret, bool *eight_bit);
ssize_t cunescape(const char *s, char **ret);
