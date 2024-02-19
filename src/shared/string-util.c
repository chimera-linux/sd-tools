/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "alloc-util.h"
#include "escape.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "macro.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"

char *startswith(const char *s, const char *prefix) {
        size_t l;

        assert(s);
        assert(prefix);

        l = strlen(prefix);
        if (!strneq(s, prefix, l))
                return NULL;

        return (char*) s + l;
}

char* endswith(const char *s, const char *postfix) {
        size_t sl, pl;

        assert(s);
        assert(postfix);

        sl = strlen(s);
        pl = strlen(postfix);

        if (pl == 0)
                return (char*) s + sl;

        if (sl < pl)
                return NULL;

        if (strcmp(s + sl - pl, postfix) != 0)
                return NULL;

        return (char*) s + sl - pl;
}

char *strjoin_real(const char *x, ...) {
        va_list ap;
        size_t l = 1;
        char *r, *p;

        va_start(ap, x);
        for (const char *t = x; t; t = va_arg(ap, const char *)) {
                size_t n;

                n = strlen(t);
                if (n > SIZE_MAX - l) {
                        va_end(ap);
                        return NULL;
                }
                l += n;
        }
        va_end(ap);

        p = r = malloc(l);
        if (!r)
                return NULL;

        va_start(ap, x);
        for (const char *t = x; t; t = va_arg(ap, const char *))
                p = stpcpy(p, t);
        va_end(ap);

        *p = 0;

        return r;
}

char *strstrip(char *s) {
        if (!s)
                return NULL;

        /* Drops trailing whitespace. Modifies the string in place. Returns pointer to first non-space character */

        return delete_trailing_chars(skip_leading_chars(s, WHITESPACE), WHITESPACE);
}

char *delete_trailing_chars(char *s, const char *bad) {
        char *c = s;

        /* Drops all specified bad characters, at the end of the string */

        if (!s)
                return NULL;

        if (!bad)
                bad = WHITESPACE;

        for (char *p = s; *p; p++)
                if (!strchr(bad, *p))
                        c = p + 1;

        *c = 0;

        return s;
}

char ascii_toupper(char x) {

        if (x >= 'a' && x <= 'z')
                return x - 'a' + 'A';

        return x;
}

static inline bool char_is_cc(char p) {
        /* char is unsigned on some architectures, e.g. aarch64. So, compiler may warn the condition
         * p >= 0 is always true. See #19543. Hence, let's cast to unsigned before the comparison. Note
         * that the cast in the right hand side is redundant, as according to the C standard, compilers
         * automatically cast a signed value to unsigned when comparing with an unsigned variable. Just
         * for safety and readability. */
        return (uint8_t) p < (uint8_t) ' ' || p == 127;
}

bool string_has_cc(const char *p, const char *ok) {
        assert(p);

        /*
         * Check if a string contains control characters. If 'ok' is
         * non-NULL it may be a string containing additional CCs to be
         * considered OK.
         */

        for (const char *t = p; *t; t++) {
                if (ok && strchr(ok, *t))
                        continue;

                if (char_is_cc(*t))
                        return true;
        }

        return false;
}


char *strextend_with_separator_internal(char **x, const char *separator, ...) {
        size_t f, l, l_separator;
        bool need_separator;
        char *nr, *p;
        va_list ap;

        assert(x);

        l = f = strlen_ptr(*x);

        need_separator = !isempty(*x);
        l_separator = strlen_ptr(separator);

        va_start(ap, separator);
        for (;;) {
                const char *t;
                size_t n;

                t = va_arg(ap, const char *);
                if (!t)
                        break;

                n = strlen(t);

                if (need_separator)
                        n += l_separator;

                if (n >= SIZE_MAX - l) {
                        va_end(ap);
                        return NULL;
                }

                l += n;
                need_separator = true;
        }
        va_end(ap);

        need_separator = !isempty(*x);

        nr = realloc(*x, GREEDY_ALLOC_ROUND_UP(l+1));
        if (!nr)
                return NULL;

        *x = nr;
        p = nr + f;

        va_start(ap, separator);
        for (;;) {
                const char *t;

                t = va_arg(ap, const char *);
                if (!t)
                        break;

                if (need_separator && separator)
                        p = stpcpy(p, separator);

                p = stpcpy(p, t);

                need_separator = true;
        }
        va_end(ap);

        assert(p == nr + l);

        *p = 0;

        return p;
}

int split_pair(const char *s, const char *sep, char **l, char **r) {
        char *x, *a, *b;

        assert(s);
        assert(sep);
        assert(l);
        assert(r);

        if (isempty(sep))
                return -EINVAL;

        x = strstr(s, sep);
        if (!x)
                return -EINVAL;

        a = strndup(s, x - s);
        if (!a)
                return -ENOMEM;

        b = strdup(x + strlen(sep));
        if (!b) {
                free(a);
                return -ENOMEM;
        }

        *l = a;
        *r = b;

        return 0;
}

int free_and_strdup(char **p, const char *s) {
        char *t;

        assert(p);

        /* Replaces a string pointer with a strdup()ed new string,
         * possibly freeing the old one. */

        if (streq_ptr(*p, s))
                return 0;

        if (s) {
                t = strdup(s);
                if (!t)
                        return -ENOMEM;
        } else
                t = NULL;

        free_and_replace(*p, t);

        return 1;
}

char *string_replace_char(char *str, char old_char, char new_char) {
        assert(str);
        assert(old_char != '\0');
        assert(new_char != '\0');
        assert(old_char != new_char);

        for (char *p = strchr(str, old_char); p; p = strchr(p + 1, old_char))
                *p = new_char;

        return str;
}

char *strdupcspn(const char *a, const char *reject) {
        if (isempty(a))
                return strdup("");
        if (isempty(reject))
                return strdup(a);

        return strndup(a, strcspn(a, reject));
}

char *find_line_startswith(const char *haystack, const char *needle) {
        char *p;

        assert(haystack);
        assert(needle);

        /* Finds the first line in 'haystack' that starts with the specified string. Returns a pointer to the
         * first character after it */

        p = strstr(haystack, needle);
        if (!p)
                return NULL;

        if (p > haystack)
                while (p[-1] != '\n') {
                        p = strstr(p + 1, needle);
                        if (!p)
                                return NULL;
                }

        return p + strlen(needle);
}

