/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <syslog.h>

#include "alloc-util.h"
#include "escape.h"
#include "extract-word.h"
#include "macro.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"

int extract_first_word(const char **p, char **ret, const char *separators, ExtractFlags flags) {
        _cleanup_free_ char *s = NULL;
        size_t sz = 0;
        char quote = 0;                 /* 0 or ' or " */
        bool backslash = false;         /* whether we've just seen a backslash */
        char c;
        int r;
        void *np;

        assert(p);
        assert(ret);
        assert(!FLAGS_SET(flags, EXTRACT_KEEP_QUOTE | EXTRACT_UNQUOTE));

        /* Bail early if called after last value or with no input */
        if (!*p)
                goto finish;
        c = **p;

        if (!separators)
                separators = WHITESPACE;

        /* Parses the first word of a string, and returns it in
         * *ret. Removes all quotes in the process. When parsing fails
         * (because of an uneven number of quotes or similar), leaves
         * the pointer *p at the first invalid character. */

        if (flags & EXTRACT_DONT_COALESCE_SEPARATORS) {
                np = realloc(s, sz + 1);
                if (!np)
                        return -ENOMEM;
                s = np;
        }

        for (;; (*p)++, c = **p) {
                if (c == 0)
                        goto finish_force_terminate;
                else if (strchr(separators, c)) {
                        if (flags & EXTRACT_DONT_COALESCE_SEPARATORS) {
                                if (!(flags & EXTRACT_RETAIN_SEPARATORS))
                                        (*p)++;
                                goto finish_force_next;
                        }
                } else {
                        /* We found a non-blank character, so we will always
                         * want to return a string (even if it is empty),
                         * allocate it here. */
                        np = realloc(s, sz + 1);
                        if (!np)
                                return -ENOMEM;
                        s = np;
                        break;
                }
        }

        for (;; (*p)++, c = **p) {
                if (backslash) {
                        np = realloc(s, sz + 7);
                        if (!np)
                                return -ENOMEM;
                        s = np;

                        if (c == 0) {
                                if ((flags & EXTRACT_UNESCAPE_RELAX) &&
                                    (quote == 0 || flags & EXTRACT_RELAX)) {
                                        /* If we find an unquoted trailing backslash and we're in
                                         * EXTRACT_UNESCAPE_RELAX mode, keep it verbatim in the
                                         * output.
                                         *
                                         * Unbalanced quotes will only be allowed in EXTRACT_RELAX
                                         * mode, EXTRACT_UNESCAPE_RELAX mode does not allow them.
                                         */
                                        s[sz++] = '\\';
                                        goto finish_force_terminate;
                                }
                                if (flags & EXTRACT_RELAX)
                                        goto finish_force_terminate;
                                return -EINVAL;
                        }

                        if (flags & (EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_SEPARATORS)) {
                                bool eight_bit = false;
                                char32_t u;

                                if ((flags & EXTRACT_CUNESCAPE) &&
                                    (r = cunescape_one(*p, SIZE_MAX, &u, &eight_bit)) >= 0) {
                                        /* A valid escaped sequence */
                                        assert(r >= 1);

                                        (*p) += r - 1;

                                        if (eight_bit)
                                                s[sz++] = u;
                                        else
                                                sz += utf8_encode_unichar(s + sz, u);
                                } else if ((flags & EXTRACT_UNESCAPE_SEPARATORS) &&
                                           (strchr(separators, **p) || **p == '\\'))
                                        /* An escaped separator char or the escape char itself */
                                        s[sz++] = c;
                                else if (flags & EXTRACT_UNESCAPE_RELAX) {
                                        s[sz++] = '\\';
                                        s[sz++] = c;
                                } else
                                        return -EINVAL;
                        } else
                                s[sz++] = c;

                        backslash = false;

                } else if (quote != 0) {     /* inside either single or double quotes */
                        for (;; (*p)++, c = **p) {
                                if (c == 0) {
                                        if (flags & EXTRACT_RELAX)
                                                goto finish_force_terminate;
                                        return -EINVAL;
                                } else if (c == quote) {        /* found the end quote */
                                        quote = 0;
                                        if (flags & EXTRACT_UNQUOTE)
                                                break;
                                } else if (c == '\\' && !(flags & EXTRACT_RETAIN_ESCAPE)) {
                                        backslash = true;
                                        break;
                                }

                                np = realloc(s, sz + 2);
                                if (!np)
                                        return -ENOMEM;
                                s = np;

                                s[sz++] = c;

                                if (quote == 0)
                                        break;
                        }

                } else {
                        for (;; (*p)++, c = **p) {
                                if (c == 0)
                                        goto finish_force_terminate;
                                else if (IN_SET(c, '\'', '"') && (flags & (EXTRACT_KEEP_QUOTE | EXTRACT_UNQUOTE))) {
                                        quote = c;
                                        if (flags & EXTRACT_UNQUOTE)
                                                break;
                                } else if (c == '\\' && !(flags & EXTRACT_RETAIN_ESCAPE)) {
                                        backslash = true;
                                        break;
                                } else if (strchr(separators, c)) {
                                        if (flags & EXTRACT_DONT_COALESCE_SEPARATORS) {
                                                if (!(flags & EXTRACT_RETAIN_SEPARATORS))
                                                        (*p)++;
                                                goto finish_force_next;
                                        }
                                        if (!(flags & EXTRACT_RETAIN_SEPARATORS))
                                                /* Skip additional coalesced separators. */
                                                for (;; (*p)++, c = **p) {
                                                        if (c == 0)
                                                                goto finish_force_terminate;
                                                        if (!strchr(separators, c))
                                                                break;
                                                }
                                        goto finish;

                                }

                                np = realloc(s, sz + 2);
                                if (!np)
                                        return -ENOMEM;
                                s = np;

                                s[sz++] = c;

                                if (quote != 0)
                                        break;
                        }
                }
        }

finish_force_terminate:
        *p = NULL;
finish:
        if (!s) {
                *p = NULL;
                *ret = NULL;
                return 0;
        }

finish_force_next:
        s[sz] = 0;
        *ret = TAKE_PTR(s);

        return 1;
}
