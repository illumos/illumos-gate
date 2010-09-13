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
#ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 1994, by Sun Microsystems, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "getent.h"

static int
putprotoent(const struct protoent *pp, FILE *fp)
{
	char **p;
	int rc = 0;

	if (pp == NULL) {
		return (1);
	}

	if (fprintf(fp, "%-20s %d",
		    pp->p_name, pp->p_proto) == EOF)
		rc = 1;
	for (p = pp->p_aliases; *p != 0; p++) {
		if (fprintf(fp, " %s", *p) == EOF)
			rc = 1;
	}
	if (putc('\n', fp) == EOF)
		rc = 1;
	return (rc);
}

/*
 * getprotobyname/addr - get entries from protocols database
 */
int
dogetproto(const char **list)
{
	struct protoent *pp;
	int rc = EXC_SUCCESS;

	if (list == NULL || *list == NULL) {
		while ((pp = getprotoent()) != NULL)
			(void) putprotoent(pp, stdout);
	} else {
		for (; *list != NULL; list++) {
			int protocol = atoi(*list);
			if (protocol != 0)
				pp = getprotobynumber(protocol);
			else
				pp = getprotobyname(*list);
			if (pp == NULL)
				rc = EXC_NAME_NOT_FOUND;
			else
				(void) putprotoent(pp, stdout);
		}
	}

	return (rc);
}
