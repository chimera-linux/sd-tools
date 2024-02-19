/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <threads.h>
#include <unistd.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "macro.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"

static int log_dispatch_internal(int error, char *buffer) {
        struct iovec iovec[2];

        do {
                char *e;

                buffer += strspn(buffer, NEWLINE);

                if (buffer[0] == 0)
                        break;

                if ((e = strpbrk(buffer, NEWLINE)))
                        *(e++) = 0;

                iovec[0].iov_base = (void *)buffer;
                iovec[0].iov_len = strlen(buffer);
                iovec[1].iov_base = (void *)"\n";
                iovec[1].iov_len = 1;

                if (writev(STDERR_FILENO, iovec, 2) < 0) {
                        return -errno;
                }
        
                buffer = e;
        } while (buffer);

        return -ERRNO_VALUE(error);
}

int log_internalv(
                int level,
                int error,
                const char *format,
                va_list ap) {

        if (_likely_(LOG_PRI(level) > log_get_max_level()))
                return -ERRNO_VALUE(error);

        /* Make sure that %m maps to the specified error (or "Success"). */
        char buffer[LINE_MAX];
        LOCAL_ERRNO(ERRNO_VALUE(error));

        (void) vsnprintf(buffer, sizeof buffer, format, ap);

        return log_dispatch_internal(error, buffer);
}

int log_internal(
                int level,
                int error,
                const char *format, ...) {

        va_list ap;
        int r;

        va_start(ap, format);
        r = log_internalv(level, error, format, ap);
        va_end(ap);

        return r;
}

static void log_assert(
                int level,
                const char *text,
                const char *file,
                int line,
                const char *func,
                const char *format) {

        static char buffer[LINE_MAX];

        if (_likely_(LOG_PRI(level) > log_get_max_level()))
                return;

        DISABLE_WARNING_FORMAT_NONLITERAL;
        (void) snprintf(buffer, sizeof buffer, format, text, file, line, func);
        REENABLE_WARNING;

        log_dispatch_internal(0, buffer);
}

_noreturn_ void log_assert_failed(
                const char *text,
                const char *file,
                int line,
                const char *func) {
        log_assert(LOG_CRIT, text, file, line, func,
                   "Assertion '%s' failed at %s:%u, function %s(). Aborting.");
        abort();
}

_noreturn_ void log_assert_failed_unreachable(
                const char *file,
                int line,
                const char *func) {
        log_assert(LOG_CRIT, "Code should not be reached", file, line, func,
                   "%s at %s:%u, function %s(). Aborting. 💥");
        abort();
}

void log_assert_failed_return(
                const char *text,
                const char *file,
                int line,
                const char *func) {
        PROTECT_ERRNO;
        log_assert(LOG_DEBUG, text, file, line, func,
                   "Assertion '%s' failed at %s:%u, function %s(). Ignoring.");
}

int log_oom_internal(int level) {
        return log_internal(level, ENOMEM, "Out of memory.");
}

int log_get_max_level(void) {
        return LOG_INFO;
}

