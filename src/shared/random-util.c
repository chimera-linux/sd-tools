/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/random.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/time.h>
#include <threads.h>
#include <unistd.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "random-util.h"

static ssize_t loop_read(int fd, void *buf, size_t nbytes) {
        uint8_t *p = ASSERT_PTR(buf);
        ssize_t n = 0;

        assert(fd >= 0);

        /* If called with nbytes == 0, let's call read() at least once, to validate the operation */

        if (nbytes > (size_t) SSIZE_MAX)
                return -EINVAL;

        do {
                ssize_t k;

                k = read(fd, p, nbytes);
                if (k < 0) {
                        if (errno == EINTR)
                                continue;

                        return n > 0 ? n : -errno;
                }

                if (k == 0)
                        return n;

                assert((size_t) k <= nbytes);

                p += k;
                nbytes -= k;
                n += k;
        } while (nbytes > 0);

        return n;
}

void random_bytes(void *p, size_t n) {
        static bool have_getrandom = true, have_grndinsecure = true;
        _cleanup_close_ int fd = -EBADF;

        if (n == 0)
                return;

        for (;;) {
                ssize_t l;

                if (!have_getrandom)
                        break;

                l = getrandom(p, n, have_grndinsecure ? GRND_INSECURE : GRND_NONBLOCK);
                if (l > 0) {
                        if ((size_t) l == n)
                                return; /* Done reading, success. */
                        p = (uint8_t *) p + l;
                        n -= l;
                        continue; /* Interrupted by a signal; keep going. */
                } else if (l == 0)
                        break; /* Weird, so fallback to /dev/urandom. */
                else if (ERRNO_IS_NOT_SUPPORTED(errno)) {
                        have_getrandom = false;
                        break; /* No syscall, so fallback to /dev/urandom. */
                } else if (errno == EINVAL && have_grndinsecure) {
                        have_grndinsecure = false;
                        continue; /* No GRND_INSECURE; fallback to GRND_NONBLOCK. */
                } else if (errno == EAGAIN && !have_grndinsecure)
                        break; /* Will block, but no GRND_INSECURE, so fallback to /dev/urandom. */

                break; /* Unexpected, so just give up and fallback to /dev/urandom. */
        }

        fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd >= 0 && loop_read(fd, p, n) == (ssize_t)n)
                return;

        /* fall back to crappy randomness */
        struct timespec ts;
        uint64_t seed;

        clock_gettime(CLOCK_REALTIME, &ts);
        seed = ts.tv_sec + ts.tv_nsec + gettid() * 65537UL - 1;

        for (char *buf = p, *ebuf = buf + n; buf < ebuf; buf += sizeof(seed)) {
                size_t left = ebuf - buf;
                seed = 6364136223846793005ULL * seed + 1;
                memcpy(buf, &seed, (left > sizeof(seed)) ? sizeof(seed) : left);
        }
}
