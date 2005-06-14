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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mdinclude.h"

/*
 * Function: findset
 * Purpose:  Return the setno of a set given the name of the set.
 * Returns:
 *		setno - the number of the set
 *		-1    - could not find the named set
 */
int
findset(char *setn)
{
	int i;
	char	setname[1024];

	if (setn == NULL) {
		return (-1);
	}

	for (i = 0; i < md_nsets; i++) {
		if (set_dbs[i].s_setname == 0) {
			continue;
		}
		if (mdb_vread(&setname, 1024,
		    (uintptr_t)set_dbs[i].s_setname) == -1) {
			mdb_warn("failed to read setname at %s\n",
			    set_dbs[i].s_setname);
		}
		if (strcmp(setname, setn) == 0) {
			return (i);
		}
	}
	return (-1);
}
