/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "config.h"

#include <ctype.h>
#include <getopt.h>
#include <grp.h>
#if HAVE_GSHADOW
#include <gshadow.h>
#endif
#include <pwd.h>
#include <shadow.h>
#include <time.h>
#include <utmp.h>
#include <sys/file.h>

#include "alloc-util.h"
#include "chase.h"
#include "conf-files.h"
#include "constants.h"
#include "copy.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hashmap.h"
#include "mkdir.h"
#include "path-util.h"
#include "selinux-util.h"
#include "set.h"
#include "smack-util.h"
#include "specifier.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "user-util.h"
#include "utf8.h"

/* TODO: read login.defs at runtime? */
#define SYSTEM_ALLOC_GID_MIN 1
#define SYSTEM_ALLOC_UID_MIN 1
#define SYSTEM_GID_MAX 999
#define SYSTEM_UID_MAX 999

assert_cc(sizeof(uid_t) == sizeof(uint32_t));
#define UID_FMT "%" PRIu32

assert_cc(sizeof(gid_t) == sizeof(uint32_t));
#define GID_FMT "%" PRIu32

static int putpwent_sane(const struct passwd *pw, FILE *stream) {
        assert(pw);
        assert(stream);

        errno = 0;
        if (putpwent(pw, stream) != 0)
                return errno_or_else(EIO);

        return 0;
}

static int putspent_sane(const struct spwd *sp, FILE *stream) {
        assert(sp);
        assert(stream);

        errno = 0;
        if (putspent(sp, stream) != 0)
                return errno_or_else(EIO);

        return 0;
}

static int putgrent_sane(const struct group *gr, FILE *stream) {
        assert(gr);
        assert(stream);

        errno = 0;
        if (putgrent(gr, stream) != 0)
                return errno_or_else(EIO);

        return 0;
}

#if HAVE_GSHADOW
static int putsgent_sane(const struct sgrp *sg, FILE *stream) {
        assert(sg);
        assert(stream);

        errno = 0;
        if (putsgent(sg, stream) != 0)
                return errno_or_else(EIO);

        return 0;
}
#endif

static int fgetpwent_sane(FILE *stream, struct passwd **pw) {
        assert(stream);
        assert(pw);

        errno = 0;
        struct passwd *p = fgetpwent(stream);
        if (!p && errno && errno != ENOENT)
                return errno_or_else(EIO);

        *pw = p;
        return !!p;
}

static int fgetspent_sane(FILE *stream, struct spwd **sp) {
        assert(stream);
        assert(sp);

        errno = 0;
        struct spwd *s = fgetspent(stream);
        if (!s && errno && errno != ENOENT)
                return errno_or_else(EIO);

        *sp = s;
        return !!s;
}

static int fgetgrent_sane(FILE *stream, struct group **gr) {
        assert(stream);
        assert(gr);

        errno = 0;
        struct group *g = fgetgrent(stream);
        if (!g && errno && errno != ENOENT)
                return errno_or_else(EIO);

        *gr = g;
        return !!g;
}

#if HAVE_GSHADOW
static int fgetsgent_sane(FILE *stream, struct sgrp **sg) {
        assert(stream);
        assert(sg);

        errno = 0;
        struct sgrp *s = fgetsgent(stream);
        if (!s && errno && errno != ENOENT)
                return errno_or_else(EIO);

        *sg = s;
        return !!s;
}
#endif

typedef struct UidRangeEntry {
        uid_t start, nr;
} UidRangeEntry;

typedef struct UidRange {
        UidRangeEntry *entries;
        size_t n_entries;
} UidRange;

static UidRange *uid_range_free(UidRange *range) {
        if (!range)
                return NULL;

        free(range->entries);
        return mfree(range);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(UidRange*, uid_range_free);

static bool uid_range_entry_intersect(const UidRangeEntry *a, const UidRangeEntry *b) {
        assert(a);
        assert(b);

        return a->start <= b->start + b->nr && a->start + a->nr >= b->start;
}

static int uid_range_entry_compare(const void *ap, const void *bp) {
        const UidRangeEntry *a = ap;
        const UidRangeEntry *b = bp;

        int r;

        assert(a);
        assert(b);

        r = CMP(a->start, b->start);
        if (r != 0)
                return r;

        return CMP(a->nr, b->nr);
}

static void uid_range_coalesce(UidRange *range) {
        assert(range);

        if (range->n_entries <= 0)
                return;

        qsort(range->entries, range->n_entries, sizeof(const UidRangeEntry), uid_range_entry_compare);

        for (size_t i = 0; i < range->n_entries; i++) {
                UidRangeEntry *x = range->entries + i;

                for (size_t j = i + 1; j < range->n_entries; j++) {
                        UidRangeEntry *y = range->entries + j;
                        uid_t begin, end;

                        if (!uid_range_entry_intersect(x, y))
                                break;

                        begin = MIN(x->start, y->start);
                        end = MAX(x->start + x->nr, y->start + y->nr);

                        x->start = begin;
                        x->nr = end - begin;

                        if (range->n_entries > j + 1)
                                memmove(y, y + 1, sizeof(UidRangeEntry) * (range->n_entries - j - 1));

                        range->n_entries--;
                        j--;
                }
        }
}

static int uid_range_add_internal(UidRange **range, uid_t start, uid_t nr, bool coalesce) {
        _cleanup_(uid_range_freep) UidRange *range_new = NULL;
        UidRange *p;
        void *np;

        assert(range);

        if (nr <= 0)
                return 0;

        if (start > UINT32_MAX - nr) /* overflow check */
                return -ERANGE;

        if (*range)
                p = *range;
        else {
                range_new = calloc(1, sizeof(UidRange));
                if (!range_new)
                        return -ENOMEM;

                p = range_new;
        }

        np = reallocarray(p->entries, p->n_entries + 1, sizeof(*p->entries));
        if (!np)
                return -ENOMEM;
        p->entries = np;

        p->entries[p->n_entries++] = (UidRangeEntry) {
                .start = start,
                .nr = nr,
        };

        if (coalesce)
                uid_range_coalesce(p);

        TAKE_PTR(range_new);
        *range = p;

        return 0;
}

static int parse_uid_range(const char *s, uid_t *ret_lower, uid_t *ret_upper) {
        _cleanup_free_ char *word = NULL;
        uid_t l, u;
        int r;

        assert(s);
        assert(ret_lower);
        assert(ret_upper);

        r = extract_first_word(&s, &word, "-", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL;

        r = parse_uid(word, &l);
        if (r < 0)
                return r;

        /* Check for the upper bound and extract it if needed */
        if (!s)
                /* Single number with no dash. */
                u = l;
        else if (!*s)
                /* Trailing dash is an error. */
                return -EINVAL;
        else {
                r = parse_uid(s, &u);
                if (r < 0)
                        return r;

                if (l > u)
                        return -EINVAL;
        }

        *ret_lower = l;
        *ret_upper = u;
        return 0;
}

static inline int uid_range_add(UidRange **range, uid_t start, uid_t nr) {
        return uid_range_add_internal(range, start, nr, true);
}

static int uid_range_add_str(UidRange **range, const char *s) {
        uid_t start, end;
        int r;

        assert(range);
        assert(s);

        r = parse_uid_range(s, &start, &end);
        if (r < 0)
                return r;

        return uid_range_add_internal(range, start, end - start + 1, /* coalesce = */ true);
}

static int uid_range_next_lower(const UidRange *range, uid_t *uid) {
        uid_t closest = UID_INVALID, candidate;

        assert(range);
        assert(uid);

        if (*uid == 0)
                return -EBUSY;

        candidate = *uid - 1;

        for (size_t i = 0; i < range->n_entries; i++) {
                uid_t begin, end;

                begin = range->entries[i].start;
                end = range->entries[i].start + range->entries[i].nr - 1;

                if (candidate >= begin && candidate <= end) {
                        *uid = candidate;
                        return 1;
                }

                if (end < candidate)
                        closest = end;
        }

        if (closest == UID_INVALID)
                return -EBUSY;

        *uid = closest;
        return 1;
}

static bool uid_range_contains(const UidRange *range, uid_t uid) {
        if (uid > UINT32_MAX - 1) /* range overflows? definitely not covered... */
                return false;

        if (!range)
                return false;

        for (size_t i = 0; i < range->n_entries; i++)
                if (uid >= range->entries[i].start &&
                    uid + 1 <= range->entries[i].start + range->entries[i].nr)
                        return true;

        return false;
}

typedef enum ItemType {
        ADD_USER =   'u',
        ADD_GROUP =  'g',
        ADD_MEMBER = 'm',
        ADD_RANGE =  'r',
} ItemType;

static const char* item_type_to_string(ItemType t) {
        switch (t) {
        case ADD_USER:
                return "user";
        case ADD_GROUP:
                return "group";
        case ADD_MEMBER:
                return "member";
        case ADD_RANGE:
                return "range";
        default:
                assert_not_reached();
        }
}

typedef struct Item {
        ItemType type;

        char *name;
        char *group_name;
        char *uid_path;
        char *gid_path;
        char *description;
        char *home;
        char *shell;

        gid_t gid;
        uid_t uid;

        char *filename;
        unsigned line;

        bool gid_set;

        /* When set the group with the specified GID must exist
         * and the check if a UID clashes with the GID is skipped.
         */
        bool id_set_strict;

        bool uid_set;

        bool todo_user;
        bool todo_group;
} Item;

static char *arg_root = NULL;
static CatFlags arg_cat_flags = CAT_CONFIG_OFF;
static const char *arg_replace = NULL;
static bool arg_dry_run = false;
static bool arg_inline = false;

static void exit_dtor(void) {
        free(arg_root);
}

typedef struct Context {
        OrderedHashmap *users, *groups;
        OrderedHashmap *todo_uids, *todo_gids;
        OrderedHashmap *members;

        Hashmap *database_by_uid, *database_by_username;
        Hashmap *database_by_gid, *database_by_groupname;

        /* A helper set to hold names that are used by database_by_{uid,gid,username,groupname} above. */
        Set *names;

        uid_t search_uid;
        UidRange *uid_range;
} Context;

static void context_done(Context *c) {
        assert(c);

        ordered_hashmap_free(c->groups);
        ordered_hashmap_free(c->users);
        ordered_hashmap_free(c->members);
        ordered_hashmap_free(c->todo_uids);
        ordered_hashmap_free(c->todo_gids);

        hashmap_free(c->database_by_uid);
        hashmap_free(c->database_by_username);
        hashmap_free(c->database_by_gid);
        hashmap_free(c->database_by_groupname);

        set_free_free(c->names);
        uid_range_free(c->uid_range);
}

static int errno_is_not_exists(int code) {
        /* See getpwnam(3) and getgrnam(3): those codes and others can be returned if the user or group are
         * not found. */
        return IN_SET(code, 0, ENOENT, ESRCH, EBADF, EPERM);
}

static int load_user_database(Context *c) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *passwd_path;
        struct passwd *pw;
        int r;

        assert(c);

        passwd_path = path_join(arg_root, "/etc/passwd");
        f = fopen(passwd_path, "re");
        if (!f)
                return errno == ENOENT ? 0 : -errno;

        r = hashmap_ensure_allocated(&c->database_by_username, &string_hash_ops);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&c->database_by_uid, NULL);
        if (r < 0)
                return r;

        /* Note that we use NULL, i.e. trivial_hash_ops here, so identical strings can exist in the set. */
        r = set_ensure_allocated(&c->names, NULL);
        if (r < 0)
                return r;

        while ((r = fgetpwent_sane(f, &pw)) > 0) {

                char *n = strdup(pw->pw_name);
                if (!n)
                        return -ENOMEM;

                r = set_consume(c->names, n);
                if (r < 0)
                        return r;
                assert(r > 0);  /* The set uses pointer comparisons, so n must not be in the set. */

                r = hashmap_put(c->database_by_username, n, UID_TO_PTR(pw->pw_uid));
                if (r == -EEXIST)
                        log_debug_errno(r, "%s: user '%s' is listed twice, ignoring duplicate uid.",
                                        passwd_path, n);
                else if (r < 0)
                        return r;

                r = hashmap_put(c->database_by_uid, UID_TO_PTR(pw->pw_uid), n);
                if (r == -EEXIST)
                        log_debug_errno(r, "%s: uid "UID_FMT" is listed twice, ignoring duplicate name.",
                                        passwd_path, pw->pw_uid);
                else if (r < 0)
                        return r;
        }
        return r;
}

static int load_group_database(Context *c) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *group_path;
        struct group *gr;
        int r;

        assert(c);

        group_path = path_join(arg_root, "/etc/group");
        f = fopen(group_path, "re");
        if (!f)
                return errno == ENOENT ? 0 : -errno;

        r = hashmap_ensure_allocated(&c->database_by_groupname, &string_hash_ops);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&c->database_by_gid, NULL);
        if (r < 0)
                return r;

        /* Note that we use NULL, i.e. trivial_hash_ops here, so identical strings can exist in the set. */
        r = set_ensure_allocated(&c->names, NULL);
        if (r < 0)
                return r;

        while ((r = fgetgrent_sane(f, &gr)) > 0) {

                char *n = strdup(gr->gr_name);
                if (!n)
                        return -ENOMEM;

                r = set_consume(c->names, n);
                if (r < 0)
                        return r;
                assert(r > 0);  /* The set uses pointer comparisons, so n must not be in the set. */

                r = hashmap_put(c->database_by_groupname, n, GID_TO_PTR(gr->gr_gid));
                if (r == -EEXIST)
                        log_debug_errno(r, "%s: group '%s' is listed twice, ignoring duplicate gid.",
                                        group_path, n);
                else if (r < 0)
                        return r;

                r = hashmap_put(c->database_by_gid, GID_TO_PTR(gr->gr_gid), n);
                if (r == -EEXIST)
                        log_debug_errno(r, "%s: gid "GID_FMT" is listed twice, ignoring duplicate name.",
                                        group_path, gr->gr_gid);
                else if (r < 0)
                        return r;
        }
        return r;
}

static int fopen_temporary_label(
                const char *target,
                const char *path,
                FILE **f,
                char **temp_path) {

        int r;

        assert(path);

        r = mac_selinux_create_file_prepare_at(AT_FDCWD, target, S_IFREG);
        if (r < 0)
                return r;

        r = fopen_temporary_at(AT_FDCWD, path, f, temp_path);

        mac_selinux_create_file_clear();

        return r;
}

static int fsync_directory_of_file(int fd) {
        _cleanup_close_ int dfd = -EBADF;
        struct stat st;
        int r;

        assert(fd >= 0);

        /* We only reasonably can do this for regular files and directories, or for O_PATH fds, hence check
         * for the inode type first */
        if (fstat(fd, &st) < 0)
                return -errno;

        if (S_ISDIR(st.st_mode)) {
                dfd = openat(fd, "..", O_RDONLY|O_DIRECTORY|O_CLOEXEC, 0);
                if (dfd < 0)
                        return -errno;

        } else if (!S_ISREG(st.st_mode)) { /* Regular files are OK regardless if O_PATH or not, for all other
                                            * types check O_PATH flag */
                r = fd_is_opath(fd);
                if (r < 0)
                        return r;
                if (!r) /* If O_PATH this refers to the inode in the fs, in which case we can sensibly do
                         * what is requested. Otherwise this refers to a socket, fifo or device node, where
                         * the concept of a containing directory doesn't make too much sense. */
                        return -ENOTTY;
        }

        if (dfd < 0) {
                _cleanup_free_ char *path = NULL;

                r = fd_get_path(fd, &path);
                if (r < 0) {
                        log_debug_errno(r, "Failed to query /proc/self/fd/%d%s: %m",
                                        fd,
                                        r == -ENOSYS ? ", ignoring" : "");

                        if (r == -ENOSYS)
                                /* If /proc is not available, we're most likely running in some
                                 * chroot environment, and syncing the directory is not very
                                 * important in that case. Let's just silently do nothing. */
                                return 0;

                        return r;
                }

                if (!path_is_absolute(path))
                        return -EINVAL;

                dfd = open_parent_at(AT_FDCWD, path, O_CLOEXEC|O_NOFOLLOW, 0);
                if (dfd < 0)
                        return dfd;
        }

        return RET_NERRNO(fsync(dfd));
}

static int fsync_full(int fd) {
        int r, q;

        /* Sync both the file and the directory */

        r = RET_NERRNO(fsync(fd));

        q = fsync_directory_of_file(fd);
        if (r < 0) /* Return earlier error */
                return r;
        if (q == -ENOTTY) /* Ignore if the 'fd' refers to a block device or so which doesn't really have a
                           * parent dir */
                return 0;
        return q;
}

static int make_backup(const char *target, char *x) {
        _cleanup_(unlink_and_freep) char *dst_tmp = NULL;
        _cleanup_fclose_ FILE *dst = NULL;
        _cleanup_close_ int src = -EBADF;
        size_t xsz;
        struct stat st;
        int r;

        assert(target);
        assert(x);

        src = open(x, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (src < 0) {
                if (errno == ENOENT) /* No backup necessary... */
                        return 0;

                return -errno;
        }

        if (fstat(src, &st) < 0)
                return -errno;

        r = fopen_temporary_label(
                        target,   /* The path for which to the look up the label */
                        x,        /* Where we want the file actually to end up */
                        &dst,     /* The temporary file we write to */
                        &dst_tmp);
        if (r < 0)
                return r;

        r = copy_bytes(src, fileno(dst), UINT64_MAX, COPY_REFLINK);
        if (r < 0)
                return r;

        /* we know we have the extra byte */
        xsz = strlen(x);
        x[xsz] = '-';

        /* Copy over the access mask. Don't fail on chmod() or chown(). If it stays owned by us and/or
         * unreadable by others, then it isn't too bad... */
        r = fchmod_and_chown_with_fallback(fileno(dst), dst_tmp, st.st_mode & 07777, st.st_uid, st.st_gid);
        if (r < 0)
                log_warning_errno(r, "Failed to change access mode or ownership of %s: %m", x);

        if (futimens(fileno(dst), (const struct timespec[2]) { st.st_atim, st.st_mtim }) < 0)
                log_warning_errno(errno, "Failed to fix access and modification time of %s: %m", x);

        r = fsync_full(fileno(dst));
        if (r < 0) {
                x[xsz] = '\0';
                return r;
        }

        if (rename(dst_tmp, x) < 0) {
                x[xsz] = '\0';
                return errno;
        }

        x[xsz] = '\0';
        dst_tmp = mfree(dst_tmp); /* disable the unlink_and_freep() hook now that the file has been renamed */
        return 0;
}

static int putgrent_with_members(
                Context *c,
                const struct group *gr,
                FILE *group) {

        char **a;
        int r;

        assert(c);
        assert(gr);
        assert(group);

        a = ordered_hashmap_get(c->members, gr->gr_name);
        if (a) {
                _cleanup_strv_free_ char **l = NULL;
                bool added = false;

                l = strv_copy(gr->gr_mem);
                if (!l)
                        return -ENOMEM;

                STRV_FOREACH(i, a) {
                        if (strv_contains(l, *i))
                                continue;

                        r = strv_extend(&l, *i);
                        if (r < 0)
                                return r;

                        added = true;
                }

                if (added) {
                        struct group t;

                        strv_uniq(l);
                        strv_sort(l);

                        t = *gr;
                        t.gr_mem = l;

                        r = putgrent_sane(&t, group);
                        return r < 0 ? r : 1;
                }
        }

        return putgrent_sane(gr, group);
}

#if HAVE_GSHADOW
static int putsgent_with_members(
                Context *c,
                const struct sgrp *sg,
                FILE *gshadow) {

        char **a;
        int r;

        assert(sg);
        assert(gshadow);

        a = ordered_hashmap_get(c->members, sg->sg_namp);
        if (a) {
                _cleanup_strv_free_ char **l = NULL;
                bool added = false;

                l = strv_copy(sg->sg_mem);
                if (!l)
                        return -ENOMEM;

                STRV_FOREACH(i, a) {
                        if (strv_contains(l, *i))
                                continue;

                        r = strv_extend(&l, *i);
                        if (r < 0)
                                return r;

                        added = true;
                }

                if (added) {
                        struct sgrp t;

                        strv_uniq(l);
                        strv_sort(l);

                        t = *sg;
                        t.sg_mem = l;

                        r = putsgent_sane(&t, gshadow);
                        return r < 0 ? r : 1;
                }
        }

        return putsgent_sane(sg, gshadow);
}
#endif

static const char* default_root_shell(const char *root) {
        return "/bin/sh";
}

static const char* pick_shell(const Item *i) {
        if (i->type != ADD_USER)
                return NULL;
        if (i->shell)
                return i->shell;
        if (i->uid_set && i->uid == 0)
                return default_root_shell(arg_root);
        return "/usr/bin/nologin";
}

static int fflush_and_check(FILE *f) {
        assert(f);

        errno = 0;
        fflush(f);

        if (ferror(f))
                return errno_or_else(EIO);

        return 0;
}

static int fflush_sync_and_check(FILE *f) {
        int r, fd;

        assert(f);

        r = fflush_and_check(f);
        if (r < 0)
                return r;

        /* Not all file streams have an fd associated (think: fmemopen()), let's handle this gracefully and
         * assume that in that case we need no explicit syncing */
        fd = fileno(f);
        if (fd < 0)
                return 0;

        r = fsync_full(fd);
        if (r < 0)
                return r;

        return 0;
}

static int write_temporary_passwd(
                Context *c,
                const char *passwd_path,
                FILE **ret_tmpfile,
                char **ret_tmpfile_path) {

        _cleanup_fclose_ FILE *original = NULL, *passwd = NULL;
        _cleanup_(unlink_and_freep) char *passwd_tmp = NULL;
        struct passwd *pw = NULL;
        Item *i;
        int r;

        assert(c);

        if (ordered_hashmap_isempty(c->todo_uids))
                return 0;

        if (arg_dry_run) {
                log_info("Would write /etc/passwd...");
                return 0;
        }

        r = fopen_temporary_label("/etc/passwd", passwd_path, &passwd, &passwd_tmp);
        if (r < 0)
                return log_debug_errno(r, "Failed to open temporary copy of %s: %m", passwd_path);

        original = fopen(passwd_path, "re");
        if (original) {

                /* Allow fallback path for when /proc is not mounted. On any normal system /proc will be
                 * mounted, but e.g. when 'dnf --installroot' is used, it might not be. There is no security
                 * relevance here, since the environment is ultimately trusted, and not requiring /proc makes
                 * it easier to depend on sysusers in packaging scripts and suchlike. */
                r = copy_rights_with_fallback(fileno(original), fileno(passwd), passwd_tmp);
                if (r < 0)
                        return log_debug_errno(r, "Failed to copy permissions from %s to %s: %m",
                                               passwd_path, passwd_tmp);

                while ((r = fgetpwent_sane(original, &pw)) > 0) {
                        i = ordered_hashmap_get(c->users, pw->pw_name);
                        if (i && i->todo_user)
                                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                                       "%s: User \"%s\" already exists.",
                                                       passwd_path, pw->pw_name);

                        if (ordered_hashmap_contains(c->todo_uids, UID_TO_PTR(pw->pw_uid)))
                                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                                       "%s: Detected collision for UID " UID_FMT ".",
                                                       passwd_path, pw->pw_uid);

                        /* Make sure we keep the NIS entries (if any) at the end. */
                        if (IN_SET(pw->pw_name[0], '+', '-'))
                                break;

                        r = putpwent_sane(pw, passwd);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to add existing user \"%s\" to temporary passwd file: %m",
                                                       pw->pw_name);
                }
                if (r < 0)
                        return log_debug_errno(r, "Failed to read %s: %m", passwd_path);

        } else {
                if (errno != ENOENT)
                        return log_debug_errno(errno, "Failed to open %s: %m", passwd_path);
                if (fchmod(fileno(passwd), 0644) < 0)
                        return log_debug_errno(errno, "Failed to fchmod %s: %m", passwd_tmp);
        }

        ORDERED_HASHMAP_FOREACH(i, c->todo_uids) {
                struct passwd n = {
                        .pw_name = i->name,
                        .pw_uid = i->uid,
                        .pw_gid = i->gid,
                        .pw_gecos = (char*) strempty(i->description),

                        /* "x" means the password is stored in the shadow file */
                        .pw_passwd = (char*) "x",

                        /* We default to the root directory as home */
                        .pw_dir = i->home ?: (char*) "/",

                        /* Initialize the shell to nologin, with one exception:
                         * for root we patch in something special */
                        .pw_shell = (char*) pick_shell(i),
                };

                r = putpwent_sane(&n, passwd);
                if (r < 0)
                        return log_debug_errno(r, "Failed to add new user \"%s\" to temporary passwd file: %m",
                                               i->name);
        }

        /* Append the remaining NIS entries if any */
        while (pw) {
                r = putpwent_sane(pw, passwd);
                if (r < 0)
                        return log_debug_errno(r, "Failed to add existing user \"%s\" to temporary passwd file: %m",
                                               pw->pw_name);

                r = fgetpwent_sane(original, &pw);
                if (r < 0)
                        return log_debug_errno(r, "Failed to read %s: %m", passwd_path);
                if (r == 0)
                        break;
        }

        r = fflush_sync_and_check(passwd);
        if (r < 0)
                return log_debug_errno(r, "Failed to flush %s: %m", passwd_tmp);

        *ret_tmpfile = TAKE_PTR(passwd);
        *ret_tmpfile_path = TAKE_PTR(passwd_tmp);

        return 0;
}

static int write_temporary_shadow(
                Context *c,
                const char *shadow_path,
                FILE **ret_tmpfile,
                char **ret_tmpfile_path) {

        _cleanup_fclose_ FILE *original = NULL, *shadow = NULL;
        _cleanup_(unlink_and_freep) char *shadow_tmp = NULL;
        struct spwd *sp = NULL;
        struct timespec ts;
        long lstchg;
        Item *i;
        int r;

        assert(c);

        if (ordered_hashmap_isempty(c->todo_uids))
                return 0;

        if (arg_dry_run) {
                log_info("Would write /etc/shadow...");
                return 0;
        }

        r = fopen_temporary_label("/etc/shadow", shadow_path, &shadow, &shadow_tmp);
        if (r < 0)
                return log_debug_errno(r, "Failed to open temporary copy of %s: %m", shadow_path);

        assert_se(clock_gettime(CLOCK_REALTIME, &ts) == 0);
        lstchg = (long) (ts.tv_sec / (24ULL*60ULL*60ULL));

        original = fopen(shadow_path, "re");
        if (original) {

                r = copy_rights_with_fallback(fileno(original), fileno(shadow), shadow_tmp);
                if (r < 0)
                        return log_debug_errno(r, "Failed to copy permissions from %s to %s: %m",
                                               shadow_path, shadow_tmp);

                while ((r = fgetspent_sane(original, &sp)) > 0) {
                        i = ordered_hashmap_get(c->users, sp->sp_namp);
                        if (i && i->todo_user) {
                                /* we will update the existing entry */
                                sp->sp_lstchg = lstchg;

                                /* only the /etc/shadow stage is left, so we can
                                 * safely remove the item from the todo set */
                                i->todo_user = false;
                                ordered_hashmap_remove(c->todo_uids, UID_TO_PTR(i->uid));
                        }

                        /* Make sure we keep the NIS entries (if any) at the end. */
                        if (IN_SET(sp->sp_namp[0], '+', '-'))
                                break;

                        r = putspent_sane(sp, shadow);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to add existing user \"%s\" to temporary shadow file: %m",
                                                       sp->sp_namp);

                }
                if (r < 0)
                        return log_debug_errno(r, "Failed to read %s: %m", shadow_path);

        } else {
                if (errno != ENOENT)
                        return log_debug_errno(errno, "Failed to open %s: %m", shadow_path);
                if (fchmod(fileno(shadow), 0000) < 0)
                        return log_debug_errno(errno, "Failed to fchmod %s: %m", shadow_tmp);
        }

        ORDERED_HASHMAP_FOREACH(i, c->todo_uids) {
                struct spwd n = {
                        .sp_namp = i->name,
                        .sp_lstchg = lstchg,
                        .sp_min = -1,
                        .sp_max = -1,
                        .sp_warn = -1,
                        .sp_inact = -1,
                        .sp_expire = -1,
                        .sp_flag = ULONG_MAX, /* this appears to be what everybody does ... */
                };

                if (streq(i->name, "root"))
                        /* Let firstboot set the password later */
                        n.sp_pwdp = (char*) "!unprovisioned";
                else
                        n.sp_pwdp = (char*) "!*";

                r = putspent_sane(&n, shadow);
                if (r < 0)
                        return log_debug_errno(r, "Failed to add new user \"%s\" to temporary shadow file: %m",
                                               i->name);
        }

        /* Append the remaining NIS entries if any */
        while (sp) {
                r = putspent_sane(sp, shadow);
                if (r < 0)
                        return log_debug_errno(r, "Failed to add existing user \"%s\" to temporary shadow file: %m",
                                               sp->sp_namp);

                r = fgetspent_sane(original, &sp);
                if (r < 0)
                        return log_debug_errno(r, "Failed to read %s: %m", shadow_path);
                if (r == 0)
                        break;
        }
        if (!IN_SET(errno, 0, ENOENT))
                return -errno;

        r = fflush_sync_and_check(shadow);
        if (r < 0)
                return log_debug_errno(r, "Failed to flush %s: %m", shadow_tmp);

        *ret_tmpfile = TAKE_PTR(shadow);
        *ret_tmpfile_path = TAKE_PTR(shadow_tmp);

        return 0;
}

static int write_temporary_group(
                Context *c,
                const char *group_path,
                FILE **ret_tmpfile,
                char **ret_tmpfile_path) {

        _cleanup_fclose_ FILE *original = NULL, *group = NULL;
        _cleanup_(unlink_and_freep) char *group_tmp = NULL;
        bool group_changed = false;
        struct group *gr = NULL;
        Item *i;
        int r;

        assert(c);

        if (ordered_hashmap_isempty(c->todo_gids) && ordered_hashmap_isempty(c->members))
                return 0;

        if (arg_dry_run) {
                log_info("Would write /etc/group...");
                return 0;
        }

        r = fopen_temporary_label("/etc/group", group_path, &group, &group_tmp);
        if (r < 0)
                return log_error_errno(r, "Failed to open temporary copy of %s: %m", group_path);

        original = fopen(group_path, "re");
        if (original) {

                r = copy_rights_with_fallback(fileno(original), fileno(group), group_tmp);
                if (r < 0)
                        return log_error_errno(r, "Failed to copy permissions from %s to %s: %m",
                                               group_path, group_tmp);

                while ((r = fgetgrent_sane(original, &gr)) > 0) {
                        /* Safety checks against name and GID collisions. Normally,
                         * this should be unnecessary, but given that we look at the
                         * entries anyway here, let's make an extra verification
                         * step that we don't generate duplicate entries. */

                        i = ordered_hashmap_get(c->groups, gr->gr_name);
                        if (i && i->todo_group)
                                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                                       "%s: Group \"%s\" already exists.",
                                                       group_path, gr->gr_name);

                        if (ordered_hashmap_contains(c->todo_gids, GID_TO_PTR(gr->gr_gid)))
                                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                                       "%s: Detected collision for GID " GID_FMT ".",
                                                       group_path, gr->gr_gid);

                        /* Make sure we keep the NIS entries (if any) at the end. */
                        if (IN_SET(gr->gr_name[0], '+', '-'))
                                break;

                        r = putgrent_with_members(c, gr, group);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add existing group \"%s\" to temporary group file: %m",
                                                       gr->gr_name);
                        if (r > 0)
                                group_changed = true;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to read %s: %m", group_path);

        } else {
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to open %s: %m", group_path);
                if (fchmod(fileno(group), 0644) < 0)
                        return log_error_errno(errno, "Failed to fchmod %s: %m", group_tmp);
        }

        ORDERED_HASHMAP_FOREACH(i, c->todo_gids) {
                struct group n = {
                        .gr_name = i->name,
                        .gr_gid = i->gid,
                        .gr_passwd = (char*) "x",
                };

                r = putgrent_with_members(c, &n, group);
                if (r < 0)
                        return log_error_errno(r, "Failed to add new group \"%s\" to temporary group file: %m",
                                               gr->gr_name);

                group_changed = true;
        }

        /* Append the remaining NIS entries if any */
        while (gr) {
                r = putgrent_sane(gr, group);
                if (r < 0)
                        return log_error_errno(r, "Failed to add existing group \"%s\" to temporary group file: %m",
                                               gr->gr_name);

                r = fgetgrent_sane(original, &gr);
                if (r < 0)
                        return log_error_errno(r, "Failed to read %s: %m", group_path);
                if (r == 0)
                        break;
        }

        r = fflush_sync_and_check(group);
        if (r < 0)
                return log_error_errno(r, "Failed to flush %s: %m", group_tmp);

        if (group_changed) {
                *ret_tmpfile = TAKE_PTR(group);
                *ret_tmpfile_path = TAKE_PTR(group_tmp);
        }
        return 0;
}

static int write_temporary_gshadow(
                Context *c,
                const char * gshadow_path,
                FILE **ret_tmpfile,
                char **ret_tmpfile_path) {

#if HAVE_GSHADOW
        _cleanup_fclose_ FILE *original = NULL, *gshadow = NULL;
        _cleanup_(unlink_and_freep) char *gshadow_tmp = NULL;
        bool group_changed = false;
        Item *i;
        int r;

        assert(c);

        if (ordered_hashmap_isempty(c->todo_gids) && ordered_hashmap_isempty(c->members))
                return 0;

        if (arg_dry_run) {
                log_info("Would write /etc/gshadow...");
                return 0;
        }

        r = fopen_temporary_label("/etc/gshadow", gshadow_path, &gshadow, &gshadow_tmp);
        if (r < 0)
                return log_error_errno(r, "Failed to open temporary copy of %s: %m", gshadow_path);

        original = fopen(gshadow_path, "re");
        if (original) {
                struct sgrp *sg;

                r = copy_rights_with_fallback(fileno(original), fileno(gshadow), gshadow_tmp);
                if (r < 0)
                        return log_error_errno(r, "Failed to copy permissions from %s to %s: %m",
                                               gshadow_path, gshadow_tmp);

                while ((r = fgetsgent_sane(original, &sg)) > 0) {

                        i = ordered_hashmap_get(c->groups, sg->sg_namp);
                        if (i && i->todo_group)
                                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                                       "%s: Group \"%s\" already exists.",
                                                       gshadow_path, sg->sg_namp);

                        r = putsgent_with_members(c, sg, gshadow);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add existing group \"%s\" to temporary gshadow file: %m",
                                                       sg->sg_namp);
                        if (r > 0)
                                group_changed = true;
                }
                if (r < 0)
                        return r;

        } else {
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to open %s: %m", gshadow_path);
                if (fchmod(fileno(gshadow), 0000) < 0)
                        return log_error_errno(errno, "Failed to fchmod %s: %m", gshadow_tmp);
        }

        ORDERED_HASHMAP_FOREACH(i, c->todo_gids) {
                struct sgrp n = {
                        .sg_namp = i->name,
                        .sg_passwd = (char*) "!*",
                };

                r = putsgent_with_members(c, &n, gshadow);
                if (r < 0)
                        return log_error_errno(r, "Failed to add new group \"%s\" to temporary gshadow file: %m",
                                               n.sg_namp);

                group_changed = true;
        }

        r = fflush_sync_and_check(gshadow);
        if (r < 0)
                return log_error_errno(r, "Failed to flush %s: %m", gshadow_tmp);

        if (group_changed) {
                *ret_tmpfile = TAKE_PTR(gshadow);
                *ret_tmpfile_path = TAKE_PTR(gshadow_tmp);
        }
#endif
        return 0;
}

static int write_files(Context *c) {
        _cleanup_fclose_ FILE *passwd = NULL, *group = NULL, *shadow = NULL, *gshadow = NULL;
        _cleanup_(unlink_and_freep) char *passwd_tmp = NULL, *group_tmp = NULL, *shadow_tmp = NULL, *gshadow_tmp = NULL;
        int r;

        _cleanup_free_ char
                *passwd_path = path_join(arg_root, "/etc/passwd-"),
                *shadow_path = path_join(arg_root, "/etc/shadow-"),
                *group_path = path_join(arg_root, "/etc/group-"),
                *gshadow_path = path_join(arg_root, "/etc/gshadow-");

        /* re-terminate at original names first */
        *strrchr(passwd_path, '-') = '\0';
        *strrchr(shadow_path, '-') = '\0';
        *strrchr(group_path, '-') = '\0';
        *strrchr(gshadow_path, '-') = '\0';

        assert(c);

        r = write_temporary_group(c, group_path, &group, &group_tmp);
        if (r < 0)
                return r;

        r = write_temporary_gshadow(c, gshadow_path, &gshadow, &gshadow_tmp);
        if (r < 0)
                return r;

        r = write_temporary_passwd(c, passwd_path, &passwd, &passwd_tmp);
        if (r < 0)
                return r;

        r = write_temporary_shadow(c, shadow_path, &shadow, &shadow_tmp);
        if (r < 0)
                return r;

        /* Make a backup of the old files */
        if (group) {
                r = make_backup("/etc/group", group_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to backup %s: %m", group_path);
        }
        if (gshadow) {
                r = make_backup("/etc/gshadow", gshadow_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to backup %s: %m", gshadow_path);
        }

        if (passwd) {
                r = make_backup("/etc/passwd", passwd_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to backup %s: %m", passwd_path);
        }
        if (shadow) {
                r = make_backup("/etc/shadow", shadow_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to backup %s: %m", shadow_path);
        }

        /* And make the new files count */
        if (group) {
                r = rename_and_apply_smack_floor_label(group_tmp, group_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to rename %s to %s: %m",
                                               group_tmp, group_path);
                group_tmp = mfree(group_tmp);
        }
        if (gshadow) {
                r = rename_and_apply_smack_floor_label(gshadow_tmp, gshadow_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to rename %s to %s: %m",
                                               gshadow_tmp, gshadow_path);

                gshadow_tmp = mfree(gshadow_tmp);
        }

        if (passwd) {
                r = rename_and_apply_smack_floor_label(passwd_tmp, passwd_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to rename %s to %s: %m",
                                               passwd_tmp, passwd_path);

                passwd_tmp = mfree(passwd_tmp);
        }
        if (shadow) {
                r = rename_and_apply_smack_floor_label(shadow_tmp, shadow_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to rename %s to %s: %m",
                                               shadow_tmp, shadow_path);

                shadow_tmp = mfree(shadow_tmp);
        }

        return 0;
}

static int uid_is_ok(
                Context *c,
                uid_t uid,
                const char *name,
                bool check_with_gid) {

        assert(c);

        /* Let's see if we already have assigned the UID a second time */
        if (ordered_hashmap_get(c->todo_uids, UID_TO_PTR(uid)))
                return 0;

        /* Try to avoid using uids that are already used by a group
         * that doesn't have the same name as our new user. */
        if (check_with_gid) {
                Item *i;

                i = ordered_hashmap_get(c->todo_gids, GID_TO_PTR(uid));
                if (i && !streq(i->name, name))
                        return 0;
        }

        /* Let's check the files directly */
        if (hashmap_contains(c->database_by_uid, UID_TO_PTR(uid)))
                return 0;

        if (check_with_gid) {
                const char *n;

                n = hashmap_get(c->database_by_gid, GID_TO_PTR(uid));
                if (n && !streq(n, name))
                        return 0;
        }

        /* Let's also check via NSS, to avoid UID clashes over LDAP and such, just in case */
        if (!arg_root) {
                struct passwd *p;
                struct group *g;

                errno = 0;
                p = getpwuid(uid);
                if (p)
                        return 0;
                if (!IN_SET(errno, 0, ENOENT))
                        return -errno;

                if (check_with_gid) {
                        errno = 0;
                        g = getgrgid((gid_t) uid);
                        if (g) {
                                if (!streq(g->gr_name, name))
                                        return 0;
                        } else if (!IN_SET(errno, 0, ENOENT))
                                return -errno;
                }
        }

        return 1;
}

static int root_stat(const char *p, struct stat *st) {
        _cleanup_free_ char *fix;

        fix = path_join(arg_root, p);
        return RET_NERRNO(stat(fix, st));
}

static int read_id_from_file(Item *i, uid_t *ret_uid, gid_t *ret_gid) {
        struct stat st;
        bool found_uid = false, found_gid = false;
        uid_t uid = 0;
        gid_t gid = 0;

        assert(i);

        /* First, try to get the GID directly */
        if (ret_gid && i->gid_path && root_stat(i->gid_path, &st) >= 0) {
                gid = st.st_gid;
                found_gid = true;
        }

        /* Then, try to get the UID directly */
        if ((ret_uid || (ret_gid && !found_gid))
            && i->uid_path
            && root_stat(i->uid_path, &st) >= 0) {

                uid = st.st_uid;
                found_uid = true;

                /* If we need the gid, but had no success yet, also derive it from the UID path */
                if (ret_gid && !found_gid) {
                        gid = st.st_gid;
                        found_gid = true;
                }
        }

        /* If that didn't work yet, then let's reuse the GID as UID */
        if (ret_uid && !found_uid && i->gid_path) {

                if (found_gid) {
                        uid = (uid_t) gid;
                        found_uid = true;
                } else if (root_stat(i->gid_path, &st) >= 0) {
                        uid = (uid_t) st.st_gid;
                        found_uid = true;
                }
        }

        if (ret_uid) {
                if (!found_uid)
                        return 0;

                *ret_uid = uid;
        }

        if (ret_gid) {
                if (!found_gid)
                        return 0;

                *ret_gid = gid;
        }

        return 1;
}

static int add_user(Context *c, Item *i) {
        void *z;
        int r;

        assert(c);
        assert(i);

        /* Check the database directly */
        z = hashmap_get(c->database_by_username, i->name);
        if (z) {
                log_debug("User %s already exists.", i->name);
                i->uid = PTR_TO_UID(z);
                i->uid_set = true;
                return 0;
        }

        if (!arg_root) {
                struct passwd *p;

                /* Also check NSS */
                errno = 0;
                p = getpwnam(i->name);
                if (p) {
                        log_debug("User %s already exists.", i->name);
                        i->uid = p->pw_uid;
                        i->uid_set = true;

                        r = free_and_strdup(&i->description, p->pw_gecos);
                        if (r < 0)
                                return log_oom();

                        return 0;
                }
                if (!errno_is_not_exists(errno))
                        return log_error_errno(errno, "Failed to check if user %s already exists: %m", i->name);
        }

        /* Try to use the suggested numeric UID */
        if (i->uid_set) {
                r = uid_is_ok(c, i->uid, i->name, !i->id_set_strict);
                if (r < 0)
                        return log_error_errno(r, "Failed to verify UID " UID_FMT ": %m", i->uid);
                if (r == 0) {
                        log_info("Suggested user ID " UID_FMT " for %s already used.", i->uid, i->name);
                        i->uid_set = false;
                }
        }

        /* If that didn't work, try to read it from the specified path */
        if (!i->uid_set) {
                uid_t candidate;

                if (read_id_from_file(i, &candidate, NULL) > 0) {

                        if (candidate <= 0 || !uid_range_contains(c->uid_range, candidate))
                                log_debug("User ID " UID_FMT " of file not suitable for %s.", candidate, i->name);
                        else {
                                r = uid_is_ok(c, candidate, i->name, true);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to verify UID " UID_FMT ": %m", i->uid);
                                else if (r > 0) {
                                        i->uid = candidate;
                                        i->uid_set = true;
                                } else
                                        log_debug("User ID " UID_FMT " of file for %s is already used.", candidate, i->name);
                        }
                }
        }

        /* Otherwise, try to reuse the group ID */
        if (!i->uid_set && i->gid_set) {
                r = uid_is_ok(c, (uid_t) i->gid, i->name, true);
                if (r < 0)
                        return log_error_errno(r, "Failed to verify UID " UID_FMT ": %m", i->uid);
                if (r > 0) {
                        i->uid = (uid_t) i->gid;
                        i->uid_set = true;
                }
        }

        /* And if that didn't work either, let's try to find a free one */
        if (!i->uid_set) {
                for (;;) {
                        r = uid_range_next_lower(c->uid_range, &c->search_uid);
                        if (r < 0)
                                return log_error_errno(r, "No free user ID available for %s.", i->name);

                        r = uid_is_ok(c, c->search_uid, i->name, true);
                        if (r < 0)
                                return log_error_errno(r, "Failed to verify UID " UID_FMT ": %m", i->uid);
                        else if (r > 0)
                                break;
                }

                i->uid_set = true;
                i->uid = c->search_uid;
        }

        r = ordered_hashmap_ensure_put(&c->todo_uids, NULL, UID_TO_PTR(i->uid), i);
        if (r == -EEXIST)
                return log_error_errno(r, "Requested user %s with UID " UID_FMT " and gid" GID_FMT " to be created is duplicated "
                                       "or conflicts with another user.", i->name, i->uid, i->gid);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_error_errno(r, "Failed to store user %s with UID " UID_FMT " and GID " GID_FMT " to be created: %m",
                                       i->name, i->uid, i->gid);

        i->todo_user = true;
        log_info("Creating user '%s' (%s) with UID " UID_FMT " and GID " GID_FMT ".",
                 i->name, strna(i->description), i->uid, i->gid);

        return 0;
}

static int gid_is_ok(
                Context *c,
                gid_t gid,
                const char *groupname,
                bool check_with_uid) {

        struct group *g;
        struct passwd *p;
        Item *user;
        char *username;

        assert(c);
        assert(groupname);

        if (ordered_hashmap_get(c->todo_gids, GID_TO_PTR(gid)))
                return 0;

        /* Avoid reusing gids that are already used by a different user */
        if (check_with_uid) {
                user = ordered_hashmap_get(c->todo_uids, UID_TO_PTR(gid));
                if (user && !streq(user->name, groupname))
                        return 0;
        }

        if (hashmap_contains(c->database_by_gid, GID_TO_PTR(gid)))
                return 0;

        if (check_with_uid) {
                username = hashmap_get(c->database_by_uid, UID_TO_PTR(gid));
                if (username && !streq(username, groupname))
                        return 0;
        }

        if (!arg_root) {
                errno = 0;
                g = getgrgid(gid);
                if (g)
                        return 0;
                if (!IN_SET(errno, 0, ENOENT))
                        return -errno;

                if (check_with_uid) {
                        errno = 0;
                        p = getpwuid((uid_t) gid);
                        if (p)
                                return 0;
                        if (!IN_SET(errno, 0, ENOENT))
                                return -errno;
                }
        }

        return 1;
}

static int get_gid_by_name(
                Context *c,
                const char *name,
                gid_t *ret_gid) {

        void *z;

        assert(c);
        assert(ret_gid);

        /* Check the database directly */
        z = hashmap_get(c->database_by_groupname, name);
        if (z) {
                *ret_gid = PTR_TO_GID(z);
                return 0;
        }

        /* Also check NSS */
        if (!arg_root) {
                struct group *g;

                errno = 0;
                g = getgrnam(name);
                if (g) {
                        *ret_gid = g->gr_gid;
                        return 0;
                }
                if (!errno_is_not_exists(errno))
                        return log_error_errno(errno, "Failed to check if group %s already exists: %m", name);
        }

        return -ENOENT;
}

static int add_group(Context *c, Item *i) {
        int r;

        assert(c);
        assert(i);

        r = get_gid_by_name(c, i->name, &i->gid);
        if (r != -ENOENT) {
                if (r < 0)
                        return r;
                log_debug("Group %s already exists.", i->name);
                i->gid_set = true;
                return 0;
        }

        /* Try to use the suggested numeric GID */
        if (i->gid_set) {
                r = gid_is_ok(c, i->gid, i->name, false);
                if (r < 0)
                        return log_error_errno(r, "Failed to verify GID " GID_FMT ": %m", i->gid);
                if (i->id_set_strict) {
                        /* If we require the GID to already exist we can return here:
                         * r > 0: means the GID does not exist -> fail
                         * r == 0: means the GID exists -> nothing more to do.
                         */
                        if (r > 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to create %s: please create GID " GID_FMT,
                                                       i->name, i->gid);
                        if (r == 0)
                                return 0;
                }
                if (r == 0) {
                        log_info("Suggested group ID " GID_FMT " for %s already used.", i->gid, i->name);
                        i->gid_set = false;
                }
        }

        /* Try to reuse the numeric uid, if there's one */
        if (!i->gid_set && i->uid_set) {
                r = gid_is_ok(c, (gid_t) i->uid, i->name, true);
                if (r < 0)
                        return log_error_errno(r, "Failed to verify GID " GID_FMT ": %m", i->gid);
                if (r > 0) {
                        i->gid = (gid_t) i->uid;
                        i->gid_set = true;
                }
        }

        /* If that didn't work, try to read it from the specified path */
        if (!i->gid_set) {
                gid_t candidate;

                if (read_id_from_file(i, NULL, &candidate) > 0) {

                        if (candidate <= 0 || !uid_range_contains(c->uid_range, candidate))
                                log_debug("Group ID " GID_FMT " of file not suitable for %s.", candidate, i->name);
                        else {
                                r = gid_is_ok(c, candidate, i->name, true);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to verify GID " GID_FMT ": %m", i->gid);
                                else if (r > 0) {
                                        i->gid = candidate;
                                        i->gid_set = true;
                                } else
                                        log_debug("Group ID " GID_FMT " of file for %s already used.", candidate, i->name);
                        }
                }
        }

        /* And if that didn't work either, let's try to find a free one */
        if (!i->gid_set) {
                for (;;) {
                        /* We look for new GIDs in the UID pool! */
                        r = uid_range_next_lower(c->uid_range, &c->search_uid);
                        if (r < 0)
                                return log_error_errno(r, "No free group ID available for %s.", i->name);

                        r = gid_is_ok(c, c->search_uid, i->name, true);
                        if (r < 0)
                                return log_error_errno(r, "Failed to verify GID " GID_FMT ": %m", i->gid);
                        else if (r > 0)
                                break;
                }

                i->gid_set = true;
                i->gid = c->search_uid;
        }

        r = ordered_hashmap_ensure_put(&c->todo_gids, NULL, GID_TO_PTR(i->gid), i);
        if (r == -EEXIST)
                return log_error_errno(r, "Requested group %s with GID "GID_FMT " to be created is duplicated or conflicts with another user.", i->name, i->gid);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0)
                return log_error_errno(r, "Failed to store group %s with GID " GID_FMT " to be created: %m", i->name, i->gid);

        i->todo_group = true;
        log_info("Creating group '%s' with GID " GID_FMT ".", i->name, i->gid);

        return 0;
}

static int process_item(Context *c, Item *i) {
        int r;

        assert(c);
        assert(i);

        switch (i->type) {

        case ADD_USER: {
                Item *j = NULL;

                if (!i->gid_set)
                        j = ordered_hashmap_get(c->groups, i->group_name ?: i->name);

                if (j && j->todo_group) {
                        /* When a group with the target name is already in queue,
                         * use the information about the group and do not create
                         * duplicated group entry. */
                        i->gid_set = j->gid_set;
                        i->gid = j->gid;
                        i->id_set_strict = true;
                } else if (i->group_name) {
                        /* When a group name was given instead of a GID and it's
                         * not in queue, then it must already exist. */
                        r = get_gid_by_name(c, i->group_name, &i->gid);
                        if (r < 0)
                                return log_error_errno(r, "Group %s not found.", i->group_name);
                        i->gid_set = true;
                        i->id_set_strict = true;
                } else {
                        r = add_group(c, i);
                        if (r < 0)
                                return r;
                }

                return add_user(c, i);
        }

        case ADD_GROUP:
                return add_group(c, i);

        default:
                assert_not_reached();
        }
}

static Item* item_free(Item *i) {
        if (!i)
                return NULL;

        free(i->name);
        free(i->group_name);
        free(i->uid_path);
        free(i->gid_path);
        free(i->description);
        free(i->home);
        free(i->shell);
        free(i->filename);
        return mfree(i);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Item*, item_free);
DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(item_hash_ops, char, string_hash_func, string_compare_func, Item, item_free);

static Item* item_new(ItemType type, const char *name, const char *filename, unsigned line) {
        assert(name);
        assert(!!filename == (line > 0));

        _cleanup_(item_freep) Item *new = malloc(sizeof(Item));
        if (!new)
                return NULL;

        *new = (Item) {
                .type = type,
                .line = line,
        };

        if (free_and_strdup(&new->name, name) < 0 ||
            free_and_strdup(&new->filename, filename) < 0)
                return NULL;

        return TAKE_PTR(new);
}

static int add_implicit(Context *c) {
        char *g, **l;
        int r;

        assert(c);

        /* Implicitly create additional users and groups, if they were listed in "m" lines */
        ORDERED_HASHMAP_FOREACH_KEY(l, g, c->members) {
                STRV_FOREACH(m, l)
                        if (!ordered_hashmap_get(c->users, *m)) {
                                _cleanup_(item_freep) Item *j =
                                        item_new(ADD_USER, *m, /* filename= */ NULL, /* line= */ 0);
                                if (!j)
                                        return log_oom();

                                r = ordered_hashmap_ensure_put(&c->users, &item_hash_ops, j->name, j);
                                if (r == -ENOMEM)
                                        return log_oom();
                                if (r < 0)
                                        return log_error_errno(r, "Failed to add implicit user '%s': %m", j->name);

                                log_debug("Adding implicit user '%s' due to m line", j->name);
                                TAKE_PTR(j);
                        }

                if (!(ordered_hashmap_get(c->users, g) ||
                      ordered_hashmap_get(c->groups, g))) {
                        _cleanup_(item_freep) Item *j =
                                item_new(ADD_GROUP, g, /* filename= */ NULL, /* line= */ 0);
                        if (!j)
                                return log_oom();

                        r = ordered_hashmap_ensure_put(&c->groups, &item_hash_ops, j->name, j);
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0)
                                return log_error_errno(r, "Failed to add implicit group '%s': %m", j->name);

                        log_debug("Adding implicit group '%s' due to m line", j->name);
                        TAKE_PTR(j);
                }
        }

        return 0;
}

static bool is_nologin_shell(const char *shell) {
        return PATH_IN_SET(shell,
                           /* 'nologin' is the friendliest way to disable logins for a user account. It prints a nice
                            * message and exits. Different distributions place the binary at different places though,
                            * hence let's list them all. */
                           "/bin/nologin",
                           "/sbin/nologin",
                           "/usr/bin/nologin",
                           "/usr/sbin/nologin",
                           /* 'true' and 'false' work too for the same purpose, but are less friendly as they don't do
                            * any message printing. Different distributions place the binary at various places but at
                            * least not in the 'sbin' directory. */
                           "/bin/false",
                           "/usr/bin/false",
                           "/bin/true",
                           "/usr/bin/true");
}

static int item_equivalent(Item *a, Item *b) {
        int r;

        assert(a);
        assert(b);

        if (a->type != b->type) {
                log_debug("%s:%u: Item not equivalent because types differ", a->filename, a->line);
                return false;
        }

        if (!streq_ptr(a->name, b->name)) {
                log_debug("%s:%u: Item not equivalent because names differ ('%s' vs. '%s')", a->filename, a->line,
                           a->name, b->name);
                return false;
        }

        /* Paths were simplified previously, so we can use streq. */
        if (!streq_ptr(a->uid_path, b->uid_path)) {
                log_debug("%s:%u: Item not equivalent because UID paths differ (%s vs. %s)", a->filename, a->line,
                           a->uid_path ?: "(unset)", b->uid_path ?: "(unset)");
                return false;
        }

        if (!streq_ptr(a->gid_path, b->gid_path)) {
                log_debug("%s:%u: Item not equivalent because GID paths differ (%s vs. %s)", a->filename, a->line,
                           a->gid_path ?: "(unset)", b->gid_path ?: "(unset)");
                return false;
        }

        if (!streq_ptr(a->description, b->description))  {
                log_debug("%s:%u: Item not equivalent because descriptions differ ('%s' vs. '%s')", a->filename, a->line,
                           strempty(a->description), strempty(b->description));
                return false;
        }

        if ((a->uid_set != b->uid_set) ||
            (a->uid_set && a->uid != b->uid)) {
                log_debug("%s:%u: Item not equivalent because UIDs differ (%lld vs. %lld)", a->filename, a->line,
                           a->uid_set ? (long long)a->uid : (long long)-1, b->uid_set ? (long long)b->uid : (long long)-1);
                return false;
        }

        if ((a->gid_set != b->gid_set) ||
            (a->gid_set && a->gid != b->gid)) {
                log_debug("%s:%u: Item not equivalent because GIDs differ (%lld vs. %lld)", a->filename, a->line,
                           a->gid_set ? (long long)a->gid : (long long)-1, b->gid_set ? (long long)b->gid : (long long)-1);
                return false;
        }

        if (!streq_ptr(a->home, b->home)) {
                log_debug("%s:%u: Item not equivalent because home directories differ ('%s' vs. '%s')", a->filename, a->line,
                           strempty(a->description), strempty(b->description));
                return false;
        }

        /* Check if the two paths refer to the same file.
         * If the paths are equal (after normalization), it's obviously the same file.
         * If both paths specify a nologin shell, treat them as the same (e.g. /bin/true and /bin/false).
         * Otherwise, try to resolve the paths, and see if we get the same result, (e.g. /sbin/nologin and
         * /usr/sbin/nologin).
         * If we can't resolve something, treat different paths as different. */

        const char *a_shell = pick_shell(a),
                   *b_shell = pick_shell(b);
        if (!path_equal_ptr(a_shell, b_shell) &&
            !(is_nologin_shell(a_shell) && is_nologin_shell(b_shell))) {
                _cleanup_free_ char *pa = NULL, *pb = NULL;

                r = chase(a_shell, arg_root, CHASE_PREFIX_ROOT | CHASE_NONEXISTENT, &pa, NULL);
                if (r < 0) {
                        log_full_errno(ERRNO_IS_RESOURCE(r) ? LOG_ERR : LOG_DEBUG,
                                       r, "Failed to look up path '%s%s%s': %m",
                                       strempty(arg_root), arg_root ? "/" : "", a_shell);
                        return ERRNO_IS_RESOURCE(r) ? r : false;
                }

                r = chase(b_shell, arg_root, CHASE_PREFIX_ROOT | CHASE_NONEXISTENT, &pb, NULL);
                if (r < 0) {
                        log_full_errno(ERRNO_IS_RESOURCE(r) ? LOG_ERR : LOG_DEBUG,
                                       r, "Failed to look up path '%s%s%s': %m",
                                       strempty(arg_root), arg_root ? "/" : "", b_shell);
                        return ERRNO_IS_RESOURCE(r) ? r : false;
                }

                if (!path_equal(pa, pb)) {
                        log_debug("%s:%u: Item not equivalent because shells differ ('%s' vs. '%s')", a->filename, a->line,
                                   pa, pb);
                        return false;
                }
        }

        return true;
}

static bool valid_home(const char *p) {
        if (isempty(p))
                return false;

        for (const char *s = p; *s; ++s)
                if (!isascii(*s))
                        return false;

        if (string_has_cc(p, NULL))
                return false;

        if (!path_is_absolute(p))
                return false;

        if (!path_is_normalized(p))
                return false;

        /* Colons are used as field separators, and hence not OK */
        if (strchr(p, ':'))
                return false;

        return true;
}

static inline bool valid_shell(const char *p) {
        return valid_home(p);
}

static bool valid_gecos(const char *d) {
        if (!d)
                return false;

        if (string_has_cc(d, NULL))
                return false;

        /* Colons are used as field separators, and hence not OK */
        if (strchr(d, ':'))
                return false;

        return true;
}

static bool valid_user_group_name(const char *u) {
        const char *i;

        /* Checks if the specified name is a valid user/group name. There are two flavours of this call:
         * strict mode is the default which is POSIX plus some extra rules; and relaxed mode where we accept
         * pretty much everything except the really worst offending names.
         *
         * Whenever we synthesize users ourselves we should use the strict mode. But when we process users
         * created by other stuff, let's be more liberal. */

        if (isempty(u)) /* An empty user name is never valid */
                return false;

        if (parse_uid(u, NULL) >= 0) /* Something that parses as numeric UID string is valid exactly when the
                                      * flag for it is set */
                return false;

        long sz;
        size_t l;

        /* Also see POSIX IEEE Std 1003.1-2008, 2016 Edition, 3.437. We are a bit stricter here
         * however. Specifically we deviate from POSIX rules:
         *
         * - We don't allow empty user names (see above)
         * - We require that names fit into the appropriate utmp field
         * - We don't allow any dots (this conflicts with chown syntax which permits dots as user/group name separator)
         * - We don't allow dashes or digit as the first character
         *
         * Note that other systems are even more restrictive, and don't permit underscores or uppercase characters.
         */

        if (!ascii_isalpha(u[0]) &&
            u[0] != '_')
                return false;

        for (i = u+1; *i; i++)
                if (!ascii_isalpha(*i) &&
                    !ascii_isdigit(*i) &&
                    !IN_SET(*i, '_', '-'))
                        return false;

        l = i - u;

        sz = sysconf(_SC_LOGIN_NAME_MAX);
        assert_se(sz > 0);

        if (l > (size_t) sz)
                return false;
        if (l > NAME_MAX) /* must fit in a filename */
                return false;
        if (l > UT_NAMESIZE - 1)
                return false;

        return true;
}

static int parse_line(
                const char *fname,
                unsigned line,
                const char *buffer,
                bool *invalid_config,
                void *context) {

        Context *c = ASSERT_PTR(context);
        _cleanup_free_ char *action = NULL,
                *name = NULL, *resolved_name = NULL,
                *id = NULL, *resolved_id = NULL,
                *description = NULL, *resolved_description = NULL,
                *home = NULL, *resolved_home = NULL,
                *shell = NULL, *resolved_shell = NULL;
        _cleanup_(item_freep) Item *i = NULL;
        Item *existing;
        OrderedHashmap *h;
        int r;
        const char *p;

        assert(fname);
        assert(line >= 1);
        assert(buffer);
        assert(!invalid_config); /* We don't support invalid_config yet. */

        const Specifier specifier_table[] = {
                { 'a', specifier_architecture,     NULL },
                { 'A', specifier_os_image_version, NULL },
                { 'b', specifier_boot_id,          NULL },
                { 'B', specifier_os_build_id,      NULL },
                { 'H', specifier_hostname,         NULL },
                { 'l', specifier_short_hostname,   NULL },
                { 'm', specifier_machine_id,       NULL },
                { 'M', specifier_os_image_id,      NULL },
                { 'o', specifier_os_id,            NULL },
                { 'v', specifier_kernel_release,   NULL },
                { 'w', specifier_os_version_id,    NULL },
                { 'W', specifier_os_variant_id,    NULL },
                { 'T', specifier_tmp_dir,          NULL },
                { 'V', specifier_var_tmp_dir,      NULL },
                {}
        };

        /* Parse columns, at least 2 words */
        p = buffer;
        r = extract_first_word(&p, &action, NULL, EXTRACT_UNQUOTE);
        if (r <= 0) goto ext_done;
        r = extract_first_word(&p, &name, NULL, EXTRACT_UNQUOTE);
        if (r <= 0) goto ext_done;
        r = extract_first_word(&p, &id, NULL, EXTRACT_UNQUOTE);
        if (r > 0) r = extract_first_word(&p, &description, NULL, EXTRACT_UNQUOTE);
        if (r > 0) r = extract_first_word(&p, &home, NULL, EXTRACT_UNQUOTE);
        if (r > 0) r = extract_first_word(&p, &shell, NULL, EXTRACT_UNQUOTE);
        /* not an error if not all fields are read */
        if (r >= 0) r = 1;
ext_done:
        if (r < 0)
                return log_error_errno(r, "%s:%u: Syntax error.", fname, line);
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "%s:%u: Missing action and name columns.", fname, line);
        if (!isempty(p))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "%s:%u: Trailing garbage.", fname, line);

        /* Verify action */
        if (strlen(action) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "%s:%u: Unknown modifier '%s'.", fname, line, action);

        if (!IN_SET(action[0], ADD_USER, ADD_GROUP, ADD_MEMBER, ADD_RANGE))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "%s:%u: Unknown command type '%c'.", fname, line, action[0]);

        /* Verify name */
        if (empty_or_dash(name))
                name = mfree(name);

        if (name) {
                r = specifier_printf(name, NAME_MAX, specifier_table, arg_root, NULL, &resolved_name);
                if (r < 0)
                        return log_error_errno(r, "%s:%u: Failed to replace specifiers in '%s': %m", fname, line, name);

                if (!valid_user_group_name(resolved_name))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                          "%s:%u: '%s' is not a valid user or group name.", fname, line, resolved_name);
        }

        /* Verify id */
        if (empty_or_dash(id))
                id = mfree(id);

        if (id) {
                r = specifier_printf(id, PATH_MAX-1, specifier_table, arg_root, NULL, &resolved_id);
                if (r < 0)
                        return log_error_errno(r, "%s:%u: Failed to replace specifiers in '%s': %m", fname, line, name);
        }

        /* Verify description */
        if (empty_or_dash(description))
                description = mfree(description);

        if (description) {
                r = specifier_printf(description, LONG_LINE_MAX, specifier_table, arg_root, NULL, &resolved_description);
                if (r < 0)
                        return log_error_errno(r, "%s:%u: Failed to replace specifiers in '%s': %m", fname, line, description);

                if (!valid_gecos(resolved_description))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "%s:%u: '%s' is not a valid GECOS field.", fname, line, resolved_description);
        }

        /* Verify home */
        if (empty_or_dash(home))
                home = mfree(home);

        if (home) {
                r = specifier_printf(home, PATH_MAX-1, specifier_table, arg_root, NULL, &resolved_home);
                if (r < 0)
                        return log_error_errno(r, "%s:%u: Failed to replace specifiers in '%s': %m", fname, line, home);

                path_simplify(resolved_home);

                if (!valid_home(resolved_home))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "%s:%u: '%s' is not a valid home directory field.", fname, line, resolved_home);
        }

        /* Verify shell */
        if (empty_or_dash(shell))
                shell = mfree(shell);

        if (shell) {
                r = specifier_printf(shell, PATH_MAX-1, specifier_table, arg_root, NULL, &resolved_shell);
                if (r < 0)
                        return log_error_errno(r, "%s:%u: Failed to replace specifiers in '%s': %m", fname, line, shell);

                path_simplify(resolved_shell);

                if (!valid_shell(resolved_shell))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "%s:%u: '%s' is not a valid login shell field.", fname, line, resolved_shell);
        }

        switch (action[0]) {

        case ADD_RANGE:
                if (resolved_name)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "%s:%u: Lines of type 'r' don't take a name field.", fname, line);

                if (!resolved_id)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "%s:%u: Lines of type 'r' require an ID range in the third field.", fname, line);

                if (description || home || shell)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "%s:%u: Lines of type '%c' don't take a %s field.", fname, line,
                                          action[0],
                                          description ? "GECOS" : home ? "home directory" : "login shell");

                r = uid_range_add_str(&c->uid_range, resolved_id);
                if (r < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "%s:%u: Invalid UID range %s.", fname, line, resolved_id);

                return 0;

        case ADD_MEMBER: {
                /* Try to extend an existing member or group item */
                if (!name)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "%s:%u: Lines of type 'm' require a user name in the second field.", fname, line);

                if (!resolved_id)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "%s:%u: Lines of type 'm' require a group name in the third field.", fname, line);

                if (!valid_user_group_name(resolved_id))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "%s:%u: '%s' is not a valid user or group name.", fname, line, resolved_id);

                if (description || home || shell)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "%s:%u: Lines of type '%c' don't take a %s field.", fname, line,
                                          action[0],
                                          description ? "GECOS" : home ? "home directory" : "login shell");

                r = string_strv_ordered_hashmap_put(&c->members, resolved_id, resolved_name);
                if (r < 0)
                        return log_error_errno(r, "Failed to store mapping for %s: %m", resolved_id);

                return 0;
        }

        case ADD_USER:
                if (!name)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "%s:%u: Lines of type 'u' require a user name in the second field.", fname, line);

                r = ordered_hashmap_ensure_allocated(&c->users, &item_hash_ops);
                if (r < 0)
                        return log_oom();

                i = item_new(ADD_USER, resolved_name, fname, line);
                if (!i)
                        return log_oom();

                if (resolved_id) {
                        if (path_is_absolute(resolved_id))
                                i->uid_path = path_simplify(TAKE_PTR(resolved_id));
                        else {
                                _cleanup_free_ char *uid = NULL, *gid = NULL;
                                if (split_pair(resolved_id, ":", &uid, &gid) == 0) {
                                        r = parse_gid(gid, &i->gid);
                                        if (r < 0) {
                                                if (valid_user_group_name(gid))
                                                        i->group_name = TAKE_PTR(gid);
                                                else
                                                        return log_error_errno(r, "%s:%u: Failed to parse GID: '%s': %m", fname, line, id);
                                        } else {
                                                i->gid_set = true;
                                                i->id_set_strict = true;
                                        }
                                        free_and_replace(resolved_id, uid);
                                }
                                if (!streq(resolved_id, "-")) {
                                        r = parse_uid(resolved_id, &i->uid);
                                        if (r < 0)
                                                return log_error_errno(r, "%s:%u: Failed to parse UID: '%s': %m", fname, line, id);
                                        i->uid_set = true;
                                }
                        }
                }

                i->description = TAKE_PTR(resolved_description);
                i->home = TAKE_PTR(resolved_home);
                i->shell = TAKE_PTR(resolved_shell);

                h = c->users;
                break;

        case ADD_GROUP:
                if (!name)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "%s:%u: Lines of type 'g' require a user name in the second field.", fname, line);

                if (description || home || shell)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "%s:%u: Lines of type '%c' don't take a %s field.", fname, line,
                                          action[0],
                                          description ? "GECOS" : home ? "home directory" : "login shell");

                r = ordered_hashmap_ensure_allocated(&c->groups, &item_hash_ops);
                if (r < 0)
                        return log_oom();

                i = item_new(ADD_GROUP, resolved_name, fname, line);
                if (!i)
                        return log_oom();

                if (resolved_id) {
                        if (path_is_absolute(resolved_id))
                                i->gid_path = path_simplify(TAKE_PTR(resolved_id));
                        else {
                                r = parse_gid(resolved_id, &i->gid);
                                if (r < 0)
                                        return log_error_errno(r, "%s:%u: Failed to parse GID: '%s': %m", fname, line, id);

                                i->gid_set = true;
                        }
                }

                h = c->groups;
                break;

        default:
                assert_not_reached();
        }

        existing = ordered_hashmap_get(h, i->name);
        if (existing) {
                /* Two functionally-equivalent items are fine */
                r = item_equivalent(i, existing);
                if (r < 0)
                        return r;
                if (r == 0) {
                        if (existing->filename)
                                log_warning("%s:%u: Conflict with earlier configuration for %s '%s' in %s:%u, ignoring line.", fname, line,
                                           item_type_to_string(i->type),
                                           i->name,
                                           existing->filename, existing->line);
                        else
                                log_warning("%s:%u: Conflict with earlier configuration for %s '%s', ignoring line.", fname, line,
                                           item_type_to_string(i->type),
                                           i->name);
                }

                return 0;
        }

        r = ordered_hashmap_put(h, i->name, i);
        if (r < 0)
                return log_oom();

        i = NULL;
        return 0;
}

static int read_config_file(Context *c, const char *fn, bool ignore_enoent) {
        return conf_file_read(
                        arg_root,
                        (const char**) CONF_PATHS_STRV("sysusers.d"),
                        ASSERT_PTR(fn),
                        parse_line,
                        ASSERT_PTR(c),
                        ignore_enoent,
                        /* invalid_config= */ NULL);
}

static int cat_config(void) {
        _cleanup_strv_free_ char **files = NULL;
        int r;

        r = conf_files_list_with_replacement(arg_root, CONF_PATHS_STRV("sysusers.d"), arg_replace, &files, NULL);
        if (r < 0)
                return r;

        return cat_files(NULL, files, arg_cat_flags);
}

static int help(void) {
        printf("%s [OPTIONS...] [CONFIGURATION FILE...]\n\n"
               "Creates system user accounts.\n\n"
               "  -h --help                 Show this help\n"
               "     --version              Show package version\n"
               "     --cat-config           Show configuration files\n"
               "     --tldr                 Show non-comment parts of configuration\n"
               "     --root=PATH            Operate on an alternate filesystem root\n"
               "     --replace=PATH         Treat arguments as replacement for PATH\n"
               "     --dry-run              Just print what would be done\n"
               "     --inline               Treat arguments as configuration lines\n",
               program_invocation_short_name);

        return 0;
}

static int version(void) {
        printf("%s %s\n", PROJECT_NAME, PROJECT_VERSION);
        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_CAT_CONFIG,
                ARG_TLDR,
                ARG_ROOT,
                ARG_REPLACE,
                ARG_DRY_RUN,
                ARG_INLINE,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'              },
                { "version",      no_argument,       NULL, ARG_VERSION      },
                { "cat-config",   no_argument,       NULL, ARG_CAT_CONFIG   },
                { "tldr",         no_argument,       NULL, ARG_TLDR         },
                { "root",         required_argument, NULL, ARG_ROOT         },
                { "replace",      required_argument, NULL, ARG_REPLACE      },
                { "dry-run",      no_argument,       NULL, ARG_DRY_RUN      },
                { "inline",       no_argument,       NULL, ARG_INLINE       },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_CAT_CONFIG:
                        arg_cat_flags = CAT_CONFIG_ON;
                        break;

                case ARG_TLDR:
                        arg_cat_flags = CAT_TLDR;
                        break;

                case ARG_ROOT:
                        r = parse_path_argument(optarg, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                case ARG_REPLACE:
                        if (!path_is_absolute(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "The argument to --replace= must be an absolute path.");
                        if (!endswith(optarg, ".conf"))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "The argument to --replace= must have the extension '.conf'.");

                        arg_replace = optarg;
                        break;

                case ARG_DRY_RUN:
                        arg_dry_run = true;
                        break;

                case ARG_INLINE:
                        arg_inline = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (arg_replace && arg_cat_flags != CAT_CONFIG_OFF)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --replace= is not supported with --cat-config/--tldr.");

        if (arg_replace && optind >= argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "When --replace= is given, some configuration items must be specified.");

        return 1;
}

static int parse_arguments(Context *c, char **args) {
        unsigned pos = 1;
        int r;

        assert(c);

        STRV_FOREACH(arg, args) {
                if (arg_inline)
                        /* Use (argument):n, where n==1 for the first positional arg */
                        r = parse_line("(argument)", pos, *arg, /* invalid_config= */ NULL, c);
                else
                        r = read_config_file(c, *arg, /* ignore_enoent= */ false);
                if (r < 0)
                        return r;

                pos++;
        }

        return 0;
}

static int read_config_files(Context *c, char **args) {
        _cleanup_strv_free_ char **files = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(c);

        r = conf_files_list_with_replacement(arg_root, CONF_PATHS_STRV("sysusers.d"), arg_replace, &files, &p);
        if (r < 0)
                return r;

        STRV_FOREACH(f, files)
                if (p && path_equal(*f, p)) {
                        log_debug("Parsing arguments at position \"%s\"...", *f);

                        r = parse_arguments(c, args);
                        if (r < 0)
                                return r;
                } else {
                        log_debug("Reading config file \"%s\"...", *f);

                        /* Just warn, ignore result otherwise */
                        (void) read_config_file(c, *f, /* ignore_enoent= */ true);
                }

        return 0;
}

static int run(int argc, char **argv) {
        _cleanup_close_ int lock = -EBADF;
        _cleanup_(context_done) Context c = {
                .search_uid = UID_INVALID,
        };

        Item *i;
        int r;

        if (atexit(exit_dtor))
                return -66;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_cat_flags != CAT_CONFIG_OFF)
                return cat_config();

        umask(0022);

        r = mac_init();
        if (r < 0)
                return r;

        /* If command line arguments are specified along with --replace, read all configuration files and
         * insert the positional arguments at the specified place. Otherwise, if command line arguments are
         * specified, execute just them, and finally, without --replace= or any positional arguments, just
         * read configuration and execute it. */
        if (arg_replace || optind >= argc)
                r = read_config_files(&c, argv + optind);
        else
                r = parse_arguments(&c, argv + optind);
        if (r < 0)
                return r;

        if (!c.uid_range) {
                /* We pick a range that very conservative: we look at compiled-in maximum and the value in
                 * /etc/login.defs. That way the UIDs/GIDs which we allocate will be interpreted correctly,
                 * even if /etc/login.defs is removed later. (The bottom bound doesn't matter much, since
                 * it's only used during allocation, so we use the configured value directly). */
                uid_t begin = (uid_t)SYSTEM_ALLOC_UID_MIN,
                      end = MIN((uid_t)SYSTEM_UID_MAX, (uid_t)SYSTEM_UID_MAX);
                if (begin < end) {
                        r = uid_range_add(&c.uid_range, begin, end - begin + 1);
                        if (r < 0)
                                return log_oom();
                }
        }

        r = add_implicit(&c);
        if (r < 0)
                return r;

        if (!arg_dry_run) {
                _cleanup_free_ char *path = path_join(arg_root, "/etc/.pwd.lock");
                if (!path)
                        return log_error_errno(log_oom_debug(), "Failed to take /etc/passwd lock: %m");

                (void)mkdir_parents(path, 0755);

                lock = open(path, O_WRONLY|O_CREAT|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW, 0600);
                if (lock < 0)
                        return log_error_errno(errno, "Cannot open %s: %m", path);

                r = lock_generic(lock, LOCK_UNPOSIX, LOCK_EX);
                if (r < 0)
                        return log_error_errno(r, "Locking %s failed: %m", path);
        }

        r = load_user_database(&c);
        if (r < 0)
                return log_error_errno(r, "Failed to load user database: %m");

        r = load_group_database(&c);
        if (r < 0)
                return log_error_errno(r, "Failed to read group database: %m");

        ORDERED_HASHMAP_FOREACH(i, c.groups)
                (void) process_item(&c, i);

        ORDERED_HASHMAP_FOREACH(i, c.users)
                (void) process_item(&c, i);

        return write_files(&c);
}

int main(int argc, char **argv) {
        int r;

        if (argc <= 0 || !*argv[0])
                return 1;

        r = run(argc, argv);
        if (r < 0)
                return 1;

        return 0;
}
