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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <grp.h>
#include <stdlib.h>
#include <errno.h>
#include "getent.h"


static int
putgrent(const struct group *grp, FILE *fp)
{
	char **mem;
	int rc = 0;

	if (grp == NULL) {
		return (1);
	}

	if (fprintf(fp, "%s:%s:%u:",
	    grp->gr_name != NULL ? grp->gr_name : "",
	    grp->gr_passwd != NULL ? grp->gr_passwd : "",
	    grp->gr_gid) == EOF)
		rc = 1;

	mem = grp ->gr_mem;

	if (mem != NULL) {
		if (*mem != NULL)
			if (fputs(*mem++, fp) == EOF)
				rc = 1;

		while (*mem != NULL)
			if (fprintf(fp, ",%s", *mem++) == EOF)
				rc = 1;
	}
	if (putc('\n', fp) == EOF)
		rc = 1;
	return (rc);
}

int
dogetgr(const char **list)
{
	struct group *grp;
	int rc = EXC_SUCCESS;
	char *ptr;
	gid_t gid;

	if (list == NULL || *list == NULL) {
		while ((grp = getgrent()) != NULL)
			(void) putgrent(grp, stdout);
	} else {
		for (; *list != NULL; list++) {
			errno = 0;

			/*
			 * Here we assume that the argument passed is
			 * a gid, if it can be completely transformed
			 * to a long integer. So we check for gid in
			 * the database and if we fail then we check
			 * for the group name.
			 * If the argument passed is not numeric, then
			 * we take it as the group name and proceed.
			 */
			gid = strtoul(*list, &ptr, 10);
			if (!(*ptr == '\0' && errno == 0) ||
			    ((grp = getgrgid(gid)) == NULL)) {
				grp = getgrnam(*list);
			}
			if (grp == NULL)
				rc = EXC_NAME_NOT_FOUND;
			else
				(void) putgrent(grp, stdout);
		}
	}

	return (rc);
}
