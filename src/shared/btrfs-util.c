/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/btrfs_tree.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <linux/magic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "alloc-util.h"
#include "btrfs-util.h"
#include "chase.h"
#include "copy.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "macro.h"
#include "path-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "string-util.h"

static int btrfs_validate_subvolume_name(const char *name) {

        if (!filename_is_valid(name))
                return -EINVAL;

        if (strlen(name) > BTRFS_SUBVOL_NAME_MAX)
                return -E2BIG;

        return 0;
}

static int extract_subvolume_name(const char *path, char **ret) {
        _cleanup_free_ char *fn = NULL;
        int r;

        assert(path);
        assert(ret);

        r = path_extract_filename(path, &fn);
        if (r < 0)
                return r;

        r = btrfs_validate_subvolume_name(fn);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(fn);
        return 0;
}

int btrfs_subvol_make(int dir_fd, const char *path) {
        struct btrfs_ioctl_vol_args args = {};
        _cleanup_free_ char *subvolume = NULL, *parent = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);
        assert(!isempty(path));

        r = extract_subvolume_name(path, &subvolume);
        if (r < 0)
                return r;

        r = path_extract_directory(path, &parent);
        if (r < 0) {
                if (r != -EDESTADDRREQ) /* Propagate error, unless only a filename was specified, which is OK */
                        return r;

                dir_fd = fd_reopen_condition(dir_fd, O_CLOEXEC, O_PATH, &fd); /* drop O_PATH if it is set */
                if (dir_fd < 0)
                        return dir_fd;
        } else {
                fd = openat(dir_fd, parent, O_DIRECTORY|O_RDONLY|O_CLOEXEC, 0);
                if (fd < 0)
                        return -errno;

                dir_fd = fd;
        }

        strncpy(args.name, subvolume, sizeof(args.name)-1);

        return RET_NERRNO(ioctl(dir_fd, BTRFS_IOC_SUBVOL_CREATE, &args));
}

/* WARNING: Be careful with file system ioctls! When we get an fd, we
 * need to make sure it either refers to only a regular file or
 * directory, or that it is located on btrfs, before invoking any
 * btrfs ioctls. The ioctl numbers are reused by some device drivers
 * (such as DRM), and hence might have bad effects when invoked on
 * device nodes (that reference drivers) rather than fds to normal
 * files or directories. */

int btrfs_is_subvol_at(int dir_fd, const char *path) {
        struct stat st;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);

        /* On btrfs subvolumes always have the inode 256 */

        if (fstatat(dir_fd, strempty(path), &st, isempty(path) ? AT_EMPTY_PATH : 0) < 0)
                return -errno;

        if (!btrfs_might_be_subvol(&st))
                return 0;

        return is_fs_type_at(dir_fd, path, BTRFS_SUPER_MAGIC);
}

static int btrfs_subvol_set_read_only_at(int dir_fd, const char *path, bool b) {
        _cleanup_close_ int fd = -EBADF;
        uint64_t flags, nflags;
        struct stat st;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);

        fd = xopenat(dir_fd, path, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY, /* xopen_flags = */ 0, /* mode = */ 0);
        if (fd < 0)
                return fd;

        if (fstat(fd, &st) < 0)
                return -errno;

        if (!btrfs_might_be_subvol(&st))
                return -EINVAL;

        if (ioctl(fd, BTRFS_IOC_SUBVOL_GETFLAGS, &flags) < 0)
                return -errno;

        nflags = UPDATE_FLAG(flags, BTRFS_SUBVOL_RDONLY, b);
        if (flags == nflags)
                return 0;

        return RET_NERRNO(ioctl(fd, BTRFS_IOC_SUBVOL_SETFLAGS, &nflags));
}

static int btrfs_subvol_get_id_fd(int fd, uint64_t *ret) {
        struct btrfs_ioctl_ino_lookup_args args = {
                .objectid = BTRFS_FIRST_FREE_OBJECTID
        };
        int r;

        assert(fd >= 0);
        assert(ret);

        r = is_fs_type_at(fd, NULL, BTRFS_SUPER_MAGIC);
        if (r < 0)
                return r;
        if (r == 0)
                return -ENOTTY;

        if (ioctl(fd, BTRFS_IOC_INO_LOOKUP, &args) < 0)
                return -errno;

        *ret = args.treeid;
        return 0;
}

static bool btrfs_ioctl_search_args_inc(struct btrfs_ioctl_search_args *args) {
        assert(args);

        /* the objectid, type, offset together make up the btrfs key,
         * which is considered a single 136byte integer when
         * comparing. This call increases the counter by one, dealing
         * with the overflow between the overflows */

        if (args->key.min_offset < UINT64_MAX) {
                args->key.min_offset++;
                return true;
        }

        if (args->key.min_type < UINT8_MAX) {
                args->key.min_type++;
                args->key.min_offset = 0;
                return true;
        }

        if (args->key.min_objectid < UINT64_MAX) {
                args->key.min_objectid++;
                args->key.min_offset = 0;
                args->key.min_type = 0;
                return true;
        }

        return 0;
}

static void btrfs_ioctl_search_args_set(struct btrfs_ioctl_search_args *args, const struct btrfs_ioctl_search_header *h) {
        assert(args);
        assert(h);

        args->key.min_objectid = h->objectid;
        args->key.min_type = h->type;
        args->key.min_offset = h->offset;
}

static int btrfs_ioctl_search_args_compare(const struct btrfs_ioctl_search_args *args) {
        int r;

        assert(args);

        /* Compare min and max */

        r = CMP(args->key.min_objectid, args->key.max_objectid);
        if (r != 0)
                return r;

        r = CMP(args->key.min_type, args->key.max_type);
        if (r != 0)
                return r;

        return CMP(args->key.min_offset, args->key.max_offset);
}

#define FOREACH_BTRFS_IOCTL_SEARCH_HEADER(i, sh, args)                  \
        for ((i) = 0,                                                   \
             (sh) = (const struct btrfs_ioctl_search_header*) (args).buf; \
             (i) < (args).key.nr_items;                                 \
             (i)++,                                                     \
             (sh) = (const struct btrfs_ioctl_search_header*) ((uint8_t*) (sh) + sizeof(struct btrfs_ioctl_search_header) + (sh)->len))

#define BTRFS_IOCTL_SEARCH_HEADER_BODY(sh)                              \
        ((void*) ((uint8_t*) sh + sizeof(struct btrfs_ioctl_search_header)))


static int btrfs_qgroupid_make(uint64_t level, uint64_t id, uint64_t *ret) {
        assert(ret);

        if (level >= (UINT64_C(1) << (64 - BTRFS_QGROUP_LEVEL_SHIFT)))
                return -EINVAL;

        if (id >= (UINT64_C(1) << BTRFS_QGROUP_LEVEL_SHIFT))
                return -EINVAL;

        *ret = (level << BTRFS_QGROUP_LEVEL_SHIFT) | id;
        return 0;
}

static int btrfs_qgroupid_split(uint64_t qgroupid, uint64_t *level, uint64_t *id) {
        assert(level || id);

        if (level)
                *level = qgroupid >> BTRFS_QGROUP_LEVEL_SHIFT;

        if (id)
                *id = qgroupid & ((UINT64_C(1) << BTRFS_QGROUP_LEVEL_SHIFT) - 1);

        return 0;
}

static int btrfs_quota_scan_start(int fd) {
        struct btrfs_ioctl_quota_rescan_args args = {};

        assert(fd >= 0);

        return RET_NERRNO(ioctl(fd, BTRFS_IOC_QUOTA_RESCAN, &args));
}

static int btrfs_quota_scan_wait(int fd) {
        assert(fd >= 0);

        return RET_NERRNO(ioctl(fd, BTRFS_IOC_QUOTA_RESCAN_WAIT));
}

static int qgroup_create_or_destroy(int fd, bool b, uint64_t qgroupid) {
        struct btrfs_ioctl_qgroup_create_args args = {
                .create = b,
                .qgroupid = qgroupid,
        };
        int r;

        r = is_fs_type_at(fd, NULL, BTRFS_SUPER_MAGIC);
        if (r < 0)
                return r;
        if (r == 0)
                return -ENOTTY;

        for (unsigned c = 0;; c++) {
                if (ioctl(fd, BTRFS_IOC_QGROUP_CREATE, &args) < 0) {

                        /* On old kernels if quota is not enabled, we get EINVAL. On newer kernels we get
                         * ENOTCONN. Let's always convert this to ENOTCONN to make this recognizable
                         * everywhere the same way. */

                        if (IN_SET(errno, EINVAL, ENOTCONN))
                                return -ENOTCONN;

                        if (errno == EBUSY && c < 10) {
                                (void) btrfs_quota_scan_wait(fd);
                                continue;
                        }

                        return -errno;
                }

                break;
        }

        return 0;
}

static int qgroup_find_parents(int fd, uint64_t qgroupid, uint64_t **ret) {

        struct btrfs_ioctl_search_args args = {
                /* Tree of quota items */
                .key.tree_id = BTRFS_QUOTA_TREE_OBJECTID,

                /* Look precisely for the quota relation items */
                .key.min_type = BTRFS_QGROUP_RELATION_KEY,
                .key.max_type = BTRFS_QGROUP_RELATION_KEY,

                /* No restrictions on the other components */
                .key.min_offset = 0,
                .key.max_offset = UINT64_MAX,

                .key.min_transid = 0,
                .key.max_transid = UINT64_MAX,
        };

        _cleanup_free_ uint64_t *items = NULL;
        size_t n_items = 0;
        int r;

        assert(fd >= 0);
        assert(ret);

        if (qgroupid == 0) {
                r = btrfs_subvol_get_id_fd(fd, &qgroupid);
                if (r < 0)
                        return r;
        } else {
                r = is_fs_type_at(fd, NULL, BTRFS_SUPER_MAGIC);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ENOTTY;
        }

        args.key.min_objectid = args.key.max_objectid = qgroupid;

        while (btrfs_ioctl_search_args_compare(&args) <= 0) {
                const struct btrfs_ioctl_search_header *sh;
                unsigned i;

                args.key.nr_items = 256;
                if (ioctl(fd, BTRFS_IOC_TREE_SEARCH, &args) < 0) {
                        if (errno == ENOENT) /* quota tree missing: quota is disabled */
                                break;

                        return -errno;
                }

                if (args.key.nr_items <= 0)
                        break;

                FOREACH_BTRFS_IOCTL_SEARCH_HEADER(i, sh, args) {
                        void *p;

                        /* Make sure we start the next search at least from this entry */
                        btrfs_ioctl_search_args_set(&args, sh);

                        if (sh->type != BTRFS_QGROUP_RELATION_KEY)
                                continue;
                        if (sh->offset < sh->objectid)
                                continue;
                        if (sh->objectid != qgroupid)
                                continue;

                        p = reallocarray(items, n_items + 1, sizeof(*items));
                        if (!p)
                                return -ENOMEM;
                        items = p;

                        items[n_items++] = sh->offset;
                }

                /* Increase search key by one, to read the next item, if we can. */
                if (!btrfs_ioctl_search_args_inc(&args))
                        break;
        }

        if (n_items <= 0) {
                *ret = NULL;
                return 0;
        }

        *ret = TAKE_PTR(items);

        return (int) n_items;
}

static int qgroup_assign_or_unassign(int fd, bool b, uint64_t child, uint64_t parent) {
        struct btrfs_ioctl_qgroup_assign_args args = {
                .assign = b,
                .src = child,
                .dst = parent,
        };
        int r;

        r = is_fs_type_at(fd, NULL, BTRFS_SUPER_MAGIC);
        if (r < 0)
                return r;
        if (r == 0)
                return -ENOTTY;

        for (unsigned c = 0;; c++) {
                r = ioctl(fd, BTRFS_IOC_QGROUP_ASSIGN, &args);
                if (r < 0) {
                        if (errno == EBUSY && c < 10) {
                                (void) btrfs_quota_scan_wait(fd);
                                continue;
                        }

                        return -errno;
                }

                if (r == 0)
                        return 0;

                /* If the return value is > 0, we need to request a rescan */

                (void) btrfs_quota_scan_start(fd);
                return 1;
        }
}

static int btrfs_qgroup_destroy_recursive(int fd, uint64_t qgroupid) {
        _cleanup_free_ uint64_t *qgroups = NULL;
        uint64_t subvol_id;
        int n, r;

        /* Destroys the specified qgroup, but unassigns it from all
         * its parents first. Also, it recursively destroys all
         * qgroups it is assigned to that have the same id part of the
         * qgroupid as the specified group. */

        r = btrfs_qgroupid_split(qgroupid, NULL, &subvol_id);
        if (r < 0)
                return r;

        n = qgroup_find_parents(fd, qgroupid, &qgroups);
        if (n < 0)
                return n;

        for (int i = 0; i < n; i++) {
                uint64_t id;

                r = btrfs_qgroupid_split(qgroups[i], NULL, &id);
                if (r < 0)
                        return r;

                r = qgroup_assign_or_unassign(fd, false, qgroupid, qgroups[i]);
                if (r < 0)
                        return r;

                if (id != subvol_id)
                        continue;

                /* The parent qgroupid shares the same id part with
                 * us? If so, destroy it too. */

                (void) btrfs_qgroup_destroy_recursive(fd, qgroups[i]);
        }

        return qgroup_create_or_destroy(fd, false, qgroupid);
}

static int subvol_remove_children(int fd, const char *subvolume, uint64_t subvol_id) {
        struct btrfs_ioctl_search_args args = {
                .key.tree_id = BTRFS_ROOT_TREE_OBJECTID,

                .key.min_objectid = BTRFS_FIRST_FREE_OBJECTID,
                .key.max_objectid = BTRFS_LAST_FREE_OBJECTID,

                .key.min_type = BTRFS_ROOT_BACKREF_KEY,
                .key.max_type = BTRFS_ROOT_BACKREF_KEY,

                .key.min_transid = 0,
                .key.max_transid = UINT64_MAX,
        };

        struct btrfs_ioctl_vol_args vol_args = {};
        _cleanup_close_ int subvol_fd = -EBADF;
        struct stat st;
        bool made_writable = false;
        int r;

        assert(fd >= 0);
        assert(subvolume);

        if (fstat(fd, &st) < 0)
                return -errno;

        if (!S_ISDIR(st.st_mode))
                return -EINVAL;

        subvol_fd = openat(fd, subvolume, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
        if (subvol_fd < 0)
                return -errno;

        /* Let's check if this is actually a subvolume. Note that this is mostly redundant, as BTRFS_IOC_SNAP_DESTROY
         * would fail anyway if it is not. However, it's a good thing to check this ahead of time so that we can return
         * ENOTTY unconditionally in this case. This is different from the ioctl() which will return EPERM/EACCES if we
         * don't have the privileges to remove subvolumes, regardless if the specified directory is actually a
         * subvolume or not. In order to make it easy for callers to cover the "this is not a btrfs subvolume" case
         * let's prefer ENOTTY over EPERM/EACCES though. */
        r = btrfs_is_subvol_at(subvol_fd, NULL);
        if (r < 0)
                return r;
        if (r == 0) /* Not a btrfs subvolume */
                return -ENOTTY;

        if (subvol_id == 0) {
                r = btrfs_subvol_get_id_fd(subvol_fd, &subvol_id);
                if (r < 0)
                        return r;
        }

        /* First, try to remove the subvolume. If it happens to be
         * already empty, this will just work. */
        strncpy(vol_args.name, subvolume, sizeof(vol_args.name)-1);
        if (ioctl(fd, BTRFS_IOC_SNAP_DESTROY, &vol_args) >= 0) {
                (void) btrfs_qgroup_destroy_recursive(fd, subvol_id); /* for the leaf subvolumes, the qgroup id is identical to the subvol id */
                return 0;
        }
        if (errno != ENOTEMPTY)
                return -errno;

        /* OK, the subvolume is not empty, let's look for child
         * subvolumes, and remove them, first */

        args.key.min_offset = args.key.max_offset = subvol_id;

        while (btrfs_ioctl_search_args_compare(&args) <= 0) {
                const struct btrfs_ioctl_search_header *sh;
                unsigned i;

                args.key.nr_items = 256;
                if (ioctl(fd, BTRFS_IOC_TREE_SEARCH, &args) < 0)
                        return -errno;

                if (args.key.nr_items <= 0)
                        break;

                FOREACH_BTRFS_IOCTL_SEARCH_HEADER(i, sh, args) {
                        _cleanup_free_ char *p = NULL;
                        const struct btrfs_root_ref *ref;

                        btrfs_ioctl_search_args_set(&args, sh);

                        if (sh->type != BTRFS_ROOT_BACKREF_KEY)
                                continue;
                        if (sh->offset != subvol_id)
                                continue;

                        ref = BTRFS_IOCTL_SEARCH_HEADER_BODY(sh);

                        p = strndup((char*) ref + sizeof(struct btrfs_root_ref), le64toh(ref->name_len));
                        if (!p)
                                return -ENOMEM;

                        struct btrfs_ioctl_ino_lookup_args ino_args = {
                                .treeid = subvol_id,
                                .objectid = htole64(ref->dirid),
                        };

                        if (ioctl(fd, BTRFS_IOC_INO_LOOKUP, &ino_args) < 0)
                                return -errno;

                        if (!made_writable) {
                                r = btrfs_subvol_set_read_only_at(subvol_fd, NULL, false);
                                if (r < 0)
                                        return r;

                                made_writable = true;
                        }

                        if (isempty(ino_args.name))
                                /* Subvolume is in the top-level
                                 * directory of the subvolume. */
                                r = subvol_remove_children(subvol_fd, p, sh->objectid);
                        else {
                                _cleanup_close_ int child_fd = -EBADF;

                                /* Subvolume is somewhere further down,
                                 * hence we need to open the
                                 * containing directory first */

                                child_fd = openat(subvol_fd, ino_args.name, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
                                if (child_fd < 0)
                                        return -errno;

                                r = subvol_remove_children(child_fd, p, sh->objectid);
                        }
                        if (r < 0)
                                return r;
                }

                /* Increase search key by one, to read the next item, if we can. */
                if (!btrfs_ioctl_search_args_inc(&args))
                        break;
        }

        /* OK, the child subvolumes should all be gone now, let's try
         * again to remove the subvolume */
        if (ioctl(fd, BTRFS_IOC_SNAP_DESTROY, &vol_args) < 0)
                return -errno;

        (void) btrfs_qgroup_destroy_recursive(fd, subvol_id);
        return 0;
}

int btrfs_subvol_remove_at(int dir_fd, const char *path) {
        _cleanup_free_ char *subvolume = NULL;
        _cleanup_close_ int path_fd = -EBADF;
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(path);

        r = chaseat(dir_fd, path, CHASE_PARENT|CHASE_EXTRACT_FILENAME, &subvolume, &path_fd);
        if (r < 0)
                return r;

        fd = xopenat(path_fd, "", O_CLOEXEC|O_NOFOLLOW, 0, 0644);
        if (fd < 0)
                return fd;

        r = btrfs_validate_subvolume_name(subvolume);
        if (r < 0)
                return r;

        return subvol_remove_children(fd, subvolume, 0);
}

static int subvol_get_parent(int fd, uint64_t subvol_id, uint64_t *ret) {

        struct btrfs_ioctl_search_args args = {
                /* Tree of tree roots */
                .key.tree_id = BTRFS_ROOT_TREE_OBJECTID,

                /* Look precisely for the subvolume items */
                .key.min_type = BTRFS_ROOT_BACKREF_KEY,
                .key.max_type = BTRFS_ROOT_BACKREF_KEY,

                /* No restrictions on the other components */
                .key.min_offset = 0,
                .key.max_offset = UINT64_MAX,

                .key.min_transid = 0,
                .key.max_transid = UINT64_MAX,
        };
        int r;

        assert(fd >= 0);
        assert(ret);

        if (subvol_id == 0) {
                r = btrfs_subvol_get_id_fd(fd, &subvol_id);
                if (r < 0)
                        return r;
        } else {
                r = is_fs_type_at(fd, NULL, BTRFS_SUPER_MAGIC);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ENOTTY;
        }

        args.key.min_objectid = args.key.max_objectid = subvol_id;

        while (btrfs_ioctl_search_args_compare(&args) <= 0) {
                const struct btrfs_ioctl_search_header *sh;
                unsigned i;

                args.key.nr_items = 256;
                if (ioctl(fd, BTRFS_IOC_TREE_SEARCH, &args) < 0)
                        return negative_errno();

                if (args.key.nr_items <= 0)
                        break;

                FOREACH_BTRFS_IOCTL_SEARCH_HEADER(i, sh, args) {

                        if (sh->type != BTRFS_ROOT_BACKREF_KEY)
                                continue;
                        if (sh->objectid != subvol_id)
                                continue;

                        *ret = sh->offset;
                        return 0;
                }
        }

        return -ENXIO;
}

int btrfs_subvol_auto_qgroup_fd(int fd, uint64_t subvol_id, bool insert_intermediary_qgroup) {
        _cleanup_free_ uint64_t *qgroups = NULL;
        _cleanup_close_ int real_fd = -EBADF;
        uint64_t parent_subvol;
        bool changed = false;
        int n = 0, r;

        assert(fd >= 0);

        /*
         * Sets up the specified subvolume's qgroup automatically in
         * one of two ways:
         *
         * If insert_intermediary_qgroup is false, the subvolume's
         * leaf qgroup will be assigned to the same parent qgroups as
         * the subvolume's parent subvolume.
         *
         * If insert_intermediary_qgroup is true a new intermediary
         * higher-level qgroup is created, with a higher level number,
         * but reusing the id of the subvolume. The level number is
         * picked as one smaller than the lowest level qgroup the
         * parent subvolume is a member of. If the parent subvolume's
         * leaf qgroup is assigned to no higher-level qgroup a new
         * qgroup of level 255 is created instead. Either way, the new
         * qgroup is then assigned to the parent's higher-level
         * qgroup, and the subvolume itself is assigned to it.
         *
         * If the subvolume is already assigned to a higher level
         * qgroup, no operation is executed.
         *
         * Effectively this means: regardless if
         * insert_intermediary_qgroup is true or not, after this
         * function is invoked the subvolume will be accounted within
         * the same qgroups as the parent. However, if it is true, it
         * will also get its own higher-level qgroup, which may in
         * turn be used by subvolumes created beneath this subvolume
         * later on.
         *
         * This hence defines a simple default qgroup setup for
         * subvolumes, as long as this function is invoked on each
         * created subvolume: each subvolume is always accounting
         * together with its immediate parents. Optionally, if
         * insert_intermediary_qgroup is true, it will also get a
         * qgroup that then includes all its own child subvolumes.
         */

        /* Turn this into a proper fd, if it is currently O_PATH */
        fd = fd_reopen_condition(fd, O_RDONLY|O_CLOEXEC, O_PATH, &real_fd);
        if (fd < 0)
                return fd;

        if (subvol_id == 0) {
                r = btrfs_is_subvol_at(fd, NULL);
                if (r < 0)
                        return r;
                if (!r)
                        return -ENOTTY;

                r = btrfs_subvol_get_id_fd(fd, &subvol_id);
                if (r < 0)
                        return r;
        }

        n = qgroup_find_parents(fd, subvol_id, &qgroups);
        if (n < 0)
                return n;
        if (n > 0) /* already parent qgroups set up, let's bail */
                return 0;

        qgroups = mfree(qgroups);

        r = subvol_get_parent(fd, subvol_id, &parent_subvol);
        if (r == -ENXIO)
                /* No parent, hence no qgroup memberships */
                n = 0;
        else if (r < 0)
                return r;
        else {
                n = qgroup_find_parents(fd, parent_subvol, &qgroups);
                if (n < 0)
                        return n;
        }

        if (insert_intermediary_qgroup) {
                uint64_t lowest = 256, new_qgroupid;
                bool created = false;

                /* Determine the lowest qgroup that the parent
                 * subvolume is assigned to. */

                for (int i = 0; i < n; i++) {
                        uint64_t level;

                        r = btrfs_qgroupid_split(qgroups[i], &level, NULL);
                        if (r < 0)
                                return r;

                        if (level < lowest)
                                lowest = level;
                }

                if (lowest <= 1) /* There are no levels left we could use insert an intermediary qgroup at */
                        return -EBUSY;

                r = btrfs_qgroupid_make(lowest - 1, subvol_id, &new_qgroupid);
                if (r < 0)
                        return r;

                /* Create the new intermediary group, unless it already exists */
                r = qgroup_create_or_destroy(fd, true, new_qgroupid);
                if (r < 0 && r != -EEXIST)
                        return r;
                if (r >= 0)
                        changed = created = true;

                for (int i = 0; i < n; i++) {
                        r = qgroup_assign_or_unassign(fd, true, new_qgroupid, qgroups[i]);
                        if (r < 0 && r != -EEXIST) {
                                if (created)
                                        (void) btrfs_qgroup_destroy_recursive(fd, new_qgroupid);

                                return r;
                        }
                        if (r >= 0)
                                changed = true;
                }

                r = qgroup_assign_or_unassign(fd, true, subvol_id, new_qgroupid);
                if (r < 0 && r != -EEXIST) {
                        if (created)
                                (void) btrfs_qgroup_destroy_recursive(fd, new_qgroupid);
                        return r;
                }
                if (r >= 0)
                        changed = true;

        } else {
                int i;

                /* Assign our subvolume to all the same qgroups as the parent */

                for (i = 0; i < n; i++) {
                        r = qgroup_assign_or_unassign(fd, true, subvol_id, qgroups[i]);
                        if (r < 0 && r != -EEXIST)
                                return r;
                        if (r >= 0)
                                changed = true;
                }
        }

        return changed;
}
