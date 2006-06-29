/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1996-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stddef.h>
#include <stdlib.h>
#include <sys/param.h>
#include <config_admin.h>
#include <memory.h>
#include "mema_test.h"

extern mtest_func_t memory_test_normal;
extern mtest_func_t memory_test_quick;
extern mtest_func_t memory_test_extended;

/*
 * Default test is first entry in the table (MTEST_DEFAULT_TEST).
 */
struct mtest_table_ent mtest_table[] = {
	{"normal",	memory_test_normal},
	{"quick",	memory_test_quick},
	{"extended",	memory_test_extended},
};

static char **opt_array;

char **
mtest_build_opts(int *maxerr_idx)
{
	if (opt_array == NULL) {
		int nopts;
		/*
		 * Test "type" options here, max_errors should be the
		 * last one.
		 */
		nopts = sizeof (mtest_table) / sizeof (mtest_table[0]);
		*maxerr_idx = nopts;

		/*
		 * One extra option for "max_errors"
		 */
		opt_array = (char **)malloc((nopts + 2) * sizeof (*opt_array));
		if (opt_array != NULL) {
			int i;

			for (i = 0; i < nopts; i++)
				opt_array[i] = (char *)mtest_table[i].test_name;

			opt_array[nopts] = "max_errors";
			opt_array[nopts + 1] = NULL;
		}
	}
	*maxerr_idx = sizeof (mtest_table) / sizeof (mtest_table[0]);
	return (opt_array);
}
