/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2013 Intel Corporation

  Author: Auke Kok <auke-jan.h.kok@intel.com>
***/

#include <stdbool.h>
#include <sys/types.h>

#include "label-util.h"

bool mac_smack_use(void);
int mac_smack_init(void);

int mac_smack_fix(int atfd, const char *inode_path, const char *label_path);
int rename_and_apply_smack_floor_label(const char *from, const char *to);
