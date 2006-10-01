/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Check permissions on NIS+ tables for security
 *
 * Usage: /usr/lib/nscd_nischeck <table>
 *
 * Emit 1 if table isn't readable by "nobody" eg everybody.
 */

#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>
#include <unistd.h>

void
leave(int n);

int
check_col(struct nis_object *table, int col)
{
	struct table_col *c;
	c = table->zo_data.objdata_u.ta_data.ta_cols.ta_cols_val + col;
	return (NIS_NOBODY(c->tc_rights, NIS_READ_ACC));
}

int
main(int argc, char **argv)
{
	nis_result *tab;
	nis_object *obj;
	char namebuf[64];

	if (argc != 2) {
		(void) fprintf(stderr, "usage: %s cache_name\n", argv[0]);
		leave(1);
	}

	(void) snprintf(namebuf, sizeof (namebuf), "%s.org_dir", argv[1]);
	tab = nis_lookup(namebuf, EXPAND_NAME);
	if (tab->status != NIS_SUCCESS) {
		nis_perror(tab->status, namebuf);
		leave(2);
	}

	obj = tab->objects.objects_val;
	if (NIS_NOBODY(obj->zo_access, NIS_READ_ACC))
		leave(0);

	/*
	 *	Currently only makes sense for passwd
	 */

	if (strcmp(argv[1], "passwd") == 0) {
		leave(1);
	}

	leave(0);
	return (0);
}

void
leave(int n)
{
	if (getenv("NSCD_DEBUG"))
	    (void) fprintf(stderr, "nscd_nischeck: exit(%d)\n", n);
	exit(n);
}
