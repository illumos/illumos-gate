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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*LINTLIBRARY*/

#include	<sys/types.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<ctype.h>
#include	<project.h>
#include	<users.h>
#include	<userdefs.h>

extern int
valid_projid(projid_t, struct project *, void *, size_t);

/*
 *	validate a project name or number and return the appropriate
 *	project structure for it.
 */
int
valid_project(char *project, struct project *pptr, void *buf, size_t len,
    int *warning)
{
	projid_t projid;
	char *ptr;

	*warning = 0;
	if (isdigit(*project)) {
		projid = (projid_t)strtol(project, &ptr, (int)10);
		if (! *ptr)
			return (valid_projid(projid, pptr, buf, len));
	}
	for (ptr = project; *ptr != '\0'; ptr++) {
		if (!isprint(*ptr) || (*ptr == ':') || (*ptr == '\n'))
			return (INVALID);
	}

	/* length checking and other warnings are done in valid_projname() */
	return (valid_projname(project, pptr, buf, len, warning));
}
