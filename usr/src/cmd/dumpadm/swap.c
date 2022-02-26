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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <sys/param.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "utils.h"
#include "swap.h"

swaptbl_t *
swap_list(void)
{
	swaptbl_t *swt;

	int n, i;
	char *p;

	if ((n = swapctl(SC_GETNSWP, NULL)) == -1) {
		warn(gettext("failed to get swap table size"));
		return (NULL);
	}

	swt = malloc(sizeof (int) + n * sizeof (swapent_t) + n * MAXPATHLEN);

	if (swt == NULL) {
		warn(gettext("failed to allocate swap table"));
		return (NULL);
	}

	swt->swt_n = n;
	p = (char *)swt + (sizeof (int) + n * sizeof (swapent_t));

	for (i = 0; i < n; i++) {
		swt->swt_ent[i].ste_path = p;
		p += MAXPATHLEN;
	}

	if ((n = swapctl(SC_LIST, swt)) == -1) {
		warn(gettext("failed to get swap table"));
		free(swt);
		return (NULL);
	}

	swt->swt_n = n;	/* Number of entries filled in */
	n = 0;		/* Number of valid entries */

	/*
	 * Shrink the array of swapent_t structures by stripping out
	 * all those which are ST_INDEL or ST_DOINGDEL.
	 */
	for (i = 0; i < swt->swt_n; i++) {
		if (!(swt->swt_ent[i].ste_flags & (ST_INDEL | ST_DOINGDEL))) {
			/*
			 * If i is ahead of the valid count (n), copy the
			 * ith entry back to the nth entry so valid entries
			 * fill the initial part of swt_ent[].
			 */
			if (i > n) {
				(void) memcpy(&swt->swt_ent[n],
				    &swt->swt_ent[i], sizeof (swapent_t));
			}

			/*
			 * If the pathname isn't absolute, assume it begins
			 * with /dev as swap(8) does.
			 */
			if (swt->swt_ent[n].ste_path[0] != '/') {
				char buf[MAXPATHLEN];

				(void) snprintf(buf, sizeof (buf), "/dev/%s",
				    swt->swt_ent[n].ste_path);
				(void) strcpy(swt->swt_ent[n].ste_path, buf);
			}

			n++;
		}
	}

	swt->swt_n = n;	/* Update swt_n with number of valid entries */
	return (swt);
}
