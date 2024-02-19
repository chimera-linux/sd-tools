/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

int path_get_mnt_id_at_fallback(int dir_fd, const char *path, int *ret);
int fd_is_mount_point(int fd, char *filename, int flags);
