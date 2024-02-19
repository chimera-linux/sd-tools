/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef int (*SpecifierCallback)(char specifier, const void *data, const char *root, const void *userdata, char **ret);

typedef struct Specifier {
        const char specifier;
        const SpecifierCallback lookup;
        const void *data;
} Specifier;

int specifier_printf(const char *text, size_t max_length, const Specifier table[], const char *root, const void *userdata, char **ret);

int specifier_machine_id(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_boot_id(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_hostname(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_short_hostname(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_kernel_release(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_architecture(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_os_id(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_os_version_id(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_os_build_id(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_os_variant_id(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_os_image_id(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_os_image_version(char specifier, const void *data, const char *root, const void *userdata, char **ret);

int specifier_tmp_dir(char specifier, const void *data, const char *root, const void *userdata, char **ret);
int specifier_var_tmp_dir(char specifier, const void *data, const char *root, const void *userdata, char **ret);
