/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <uchar.h>

bool unichar_is_valid(char32_t c);
size_t utf8_encode_unichar(char *out_utf8, char32_t g);
int utf8_encoded_to_unichar(const char *str, char32_t *ret_unichar);

