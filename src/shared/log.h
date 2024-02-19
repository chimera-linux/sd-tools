/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "macro.h"

/* Note to readers: << and >> have lower precedence (are evaluated earlier) than & and | */
#define SYNTHETIC_ERRNO(num)                (1 << 30 | (num))
#define ERRNO_VALUE(val)                    (abs(val) & ~(1 << 30))

int log_get_max_level(void) _pure_;

/* Functions below that open and close logs or configure logging based on the
 * environment should not be called from library code — this is always a job
 * for the application itself. */

int log_internal(
                int level,
                int error,
                const char *format, ...) _printf_(3,4);

int log_internalv(
                int level,
                int error,
                const char *format,
                va_list ap) _printf_(3,0);

int log_oom_internal(
                int level);

/* Logging for various assertions */
_noreturn_ void log_assert_failed(
                const char *text,
                const char *file,
                int line,
                const char *func);

_noreturn_ void log_assert_failed_unreachable(
                const char *file,
                int line,
                const char *func);

void log_assert_failed_return(
                const char *text,
                const char *file,
                int line,
                const char *func);

/* Logging with level */
#define log_full_errno_zerook(level, error, ...)                        \
        ({                                                              \
                int _level = (level), _e = (error);                     \
                _e = (log_get_max_level() >= LOG_PRI(_level))           \
                        ? log_internal(_level, _e, __VA_ARGS__) \
                        : -ERRNO_VALUE(_e);                             \
                _e < 0 ? _e : -ESTRPIPE;                                \
        })

#define log_full_errno(level, error, ...)                               \
        ({                                                              \
                int _error = (error);                                   \
                log_full_errno_zerook(level, _error, __VA_ARGS__);      \
        })

#define log_full(level, fmt, ...)                                      \
        ({                                                             \
                (void) log_full_errno_zerook(level, 0, fmt, ##__VA_ARGS__); \
        })

/* Normal logging */
#define log_debug(...)     log_full(LOG_DEBUG,   __VA_ARGS__)
#define log_info(...)      log_full(LOG_INFO,    __VA_ARGS__)
#define log_notice(...)    log_full(LOG_NOTICE,  __VA_ARGS__)
#define log_warning(...)   log_full(LOG_WARNING, __VA_ARGS__)
#define log_error(...)     log_full(LOG_ERR,     __VA_ARGS__)

/* Logging triggered by an errno-like error */
#define log_debug_errno(error, ...)     log_full_errno(LOG_DEBUG,   error, __VA_ARGS__)
#define log_info_errno(error, ...)      log_full_errno(LOG_INFO,    error, __VA_ARGS__)
#define log_notice_errno(error, ...)    log_full_errno(LOG_NOTICE,  error, __VA_ARGS__)
#define log_warning_errno(error, ...)   log_full_errno(LOG_WARNING, error, __VA_ARGS__)
#define log_error_errno(error, ...)     log_full_errno(LOG_ERR,     error, __VA_ARGS__)

#define log_oom() log_oom_internal(LOG_ERR)
#define log_oom_debug() log_oom_internal(LOG_DEBUG)
#define log_oom_warning() log_oom_internal(LOG_WARNING)

#define DEBUG_LOGGING _unlikely_(log_get_max_level() >= LOG_DEBUG)

