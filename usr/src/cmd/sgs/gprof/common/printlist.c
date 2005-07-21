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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "gprof.h"

/*
 *	these are the lists of names:
 *	there is the list head and then the listname
 *	is a pointer to the list head
 *	(for ease of passing to stringlist functions).
 */
struct stringlist	fhead = { 0, 0 };
struct stringlist	*flist = &fhead;
struct stringlist	Fhead = { 0, 0 };
struct stringlist	*Flist = &Fhead;
struct stringlist	ehead = { 0, 0 };
struct stringlist	*elist = &ehead;
struct stringlist	Ehead = { 0, 0 };
struct stringlist	*Elist = &Ehead;

void
addlist(struct stringlist *listp, char *funcname)
{
	struct stringlist	*slp;

	slp = malloc(sizeof (struct stringlist));

	if (slp == NULL) {
		(void) fprintf(stderr, "gprof: ran out room for printlist\n");
		exit(1);
	}

	slp->next = listp->next;
	slp->string = funcname;
	listp->next = slp;
}

bool
onlist(struct stringlist *listp, char *funcname)
{
	struct stringlist	*slp;

	for (slp = listp->next; slp; slp = slp->next) {
		if (strcmp(slp->string, funcname) == 0)
			return (TRUE);

		if (funcname[0] == '_' &&
		    strcmp(slp->string, &funcname[1]) == 0)
			return (TRUE);
	}
	return (FALSE);
}
