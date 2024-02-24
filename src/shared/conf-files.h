/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"

int conf_files_list_with_replacement(
                const char *root,
                char **config_dirs,
                const char *replacement,
                char ***files,
                char **replace_file);

typedef enum CatFlags {
        CAT_CONFIG_OFF          = 0,
        CAT_CONFIG_ON           = 1 << 0,
        CAT_FORMAT_HAS_SECTIONS = 1 << 1,  /* Sections are meaningful for this file format */
        CAT_TLDR                = 1 << 2,  /* Only print comments and relevant section headers */
} CatFlags;

int cat_files(const char *file, char **dropins, CatFlags flags);

typedef int parse_line_t(
                const char *fname,
                unsigned line,
                const char *buffer,
                bool *invalid_config,
                void *userdata);

int conf_file_read(
                const char *root,
                const char **config_dirs,
                const char *fn,
                parse_line_t parse_line,
                void *userdata,
                bool ignore_enoent,
                bool *invalid_config);
