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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <grp.h>
#include <stdlib.h>
#include <project.h>
#include "getent.h"

static int
putprojent(const struct project *proj, FILE *fp)
{
	char **names;

	if (proj == NULL)
		return (1);

	if (fprintf(fp, "%s:%ld:%s:",
	    proj->pj_name != NULL ? proj->pj_name : "",
	    proj->pj_projid,
	    proj->pj_comment != NULL ? proj->pj_comment : "") == EOF)
		return (1);
	names = proj->pj_users;
	if (names != NULL) {
		if (*names != NULL)
			if (fputs(*names++, fp) == EOF)
				return (1);
		while (*names != NULL)
			if (fprintf(fp, ",%s", *names++) == EOF)
				return (1);
	}
	if (putc(':', fp) == EOF)
		return (1);
	names = proj->pj_groups;
	if (names != NULL) {
		if (*names != NULL)
			if (fputs(*names++, fp) == EOF)
				return (1);
		while (*names != NULL)
			if (fprintf(fp, ",%s", *names++) == EOF)
				return (1);
	}
	if (putc(':', fp) == EOF)
		return (1);
	if (fprintf(fp, "%s\n",
	    proj->pj_attr != NULL ? proj->pj_attr : "") == EOF)
		return (1);
	return (0);
}

int
dogetproject(const char **list)
{
	struct project proj;
	struct project *pproj;
	projid_t projid;
	void *buf[PROJECT_BUFSZ];
	int rc = EXC_SUCCESS;
	char *ptr;

	if (list == NULL || *list == NULL) {
		setprojent();
		while ((pproj = getprojent(&proj, buf, PROJECT_BUFSZ)) != NULL)
			(void) putprojent(pproj, stdout);
		endprojent();
	} else {
		for (; *list != NULL; list++) {
			projid = strtol(*list, &ptr, 10);
			if (ptr == *list)
				pproj = getprojbyname(*list, &proj,
				    buf, PROJECT_BUFSZ);
			else
				pproj = getprojbyid(projid, &proj,
				    buf, PROJECT_BUFSZ);
			if (pproj == NULL)
				rc = EXC_NAME_NOT_FOUND;
			else
				(void) putprojent(pproj, stdout);
		}
	}

	return (rc);
}
