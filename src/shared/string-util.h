/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "alloc-util.h"
#include "macro.h"

#define streq(a,b) (strcmp((a),(b)) == 0)
#define strneq(a, b, n) (strncmp((a), (b), (n)) == 0)

static inline int strcmp_ptr(const char *a, const char *b) {
        if (a && b)
                return strcmp(a, b);

        return CMP(a, b);
}

static inline bool streq_ptr(const char *a, const char *b) {
        return strcmp_ptr(a, b) == 0;
}

static inline size_t strlen_ptr(const char *s) {
        if (!s)
                return 0;

        return strlen(s);
}

char *startswith(const char *s, const char *prefix) _pure_;
char *endswith(const char *s, const char *postfix) _pure_;

static inline bool isempty(const char *a) {
        return !a || a[0] == '\0';
}

static inline const char *strempty(const char *s) {
        return s ?: "";
}

#define _STRV_FOREACH(s, l, i)                                          \
        for (typeof(*(l)) *s, *i = (l); (s = i) && *i; i++)

#define STRV_FOREACH(s, l)                      \
        _STRV_FOREACH(s, l, UNIQ_T(i, UNIQ))

static inline bool ascii_isdigit(char a) {
        /* A pure ASCII, locale independent version of isdigit() */
        return a >= '0' && a <= '9';
}

static inline bool ascii_isalpha(char a) {
        /* A pure ASCII, locale independent version of isalpha() */
        return (a >= 'a' && a <= 'z') || (a >= 'A' && a <= 'Z');
}

/* What is interpreted as whitespace? */
#define WHITESPACE          " \t\n\r"
#define NEWLINE             "\n\r"
#define QUOTES              "\"\'"
#define COMMENTS            "#;"
#define GLOB_CHARS          "*?["
#define DIGITS              "0123456789"
#define LOWERCASE_LETTERS   "abcdefghijklmnopqrstuvwxyz"
#define UPPERCASE_LETTERS   "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define LETTERS             LOWERCASE_LETTERS UPPERCASE_LETTERS
#define ALPHANUMERICAL      LETTERS DIGITS

static inline const char* strnull(const char *s) {
        return s ?: "(null)";
}

static inline const char *strna(const char *s) {
        return s ?: "n/a";
}

static inline bool empty_or_dash(const char *str) {
        return !str ||
                str[0] == 0 ||
                (str[0] == '-' && str[1] == 0);
}

char *strjoin_real(const char *x, ...) _sentinel_;
#define strjoin(a, ...) strjoin_real((a), __VA_ARGS__, NULL)

char *strstrip(char *s);
char *delete_trailing_chars(char *s, const char *bad);

static inline char *skip_leading_chars(const char *s, const char *bad) {
        if (!s)
                return NULL;

        if (!bad)
                bad = WHITESPACE;

        return (char*) s + strspn(s, bad);
}

char ascii_toupper(char x);

bool string_has_cc(const char *p, const char *ok) _pure_;

char *strextend_with_separator_internal(char **x, const char *separator, ...) _sentinel_;
#define strextend_with_separator(x, separator, ...) strextend_with_separator_internal(x, separator, __VA_ARGS__, NULL)
#define strextend(x, ...) strextend_with_separator_internal(x, NULL, __VA_ARGS__, NULL)

int split_pair(const char *s, const char *sep, char **l, char **r);

int free_and_strdup(char **p, const char *s);

char *string_replace_char(char *str, char old_char, char new_char);

char *strdupcspn(const char *a, const char *reject);

char *find_line_startswith(const char *haystack, const char *needle);
