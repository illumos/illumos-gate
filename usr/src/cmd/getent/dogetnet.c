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
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "getent.h"

/*
 * Print a network number such as 129.144
 */
char *
inet_nettoa(struct in_addr in)
{
	u_long addr = htonl(in.s_addr);
	u_char *up = (u_char *)&addr;
	static char result[256];

	/* Omit leading zeros */
	if (up[0]) {
		(void) sprintf(result, "%d.%d.%d.%d",
		    up[0], up[1], up[2], up[3]);
	} else if (up[1]) {
		(void) sprintf(result, "%d.%d.%d", up[1], up[2], up[3]);
	} else if (up[2]) {
		(void) sprintf(result, "%d.%d", up[2], up[3]);
	} else {
		(void) sprintf(result, "%d", up[3]);
	}
	return (result);
}

static int
putnetent(const struct netent *np, FILE *fp)
{
	char **p;
	int rc = 0;
	struct in_addr in;

	if (np == NULL) {
		return (1);
	}

	in.s_addr = np->n_net;
	if (fprintf(fp, "%-20s %s",
		    np->n_name, inet_nettoa(in)) == EOF)
		rc = 1;
	for (p = np->n_aliases; *p != 0; p++) {
		if (fprintf(fp, " %s", *p) == EOF)
			rc = 1;
	}
	if (putc('\n', fp) == EOF)
		rc = 1;
	return (rc);
}

/*
 * getnetbyname/addr - get entries from network database
 */
int
dogetnet(const char **list)
{
	struct netent *np;
	int rc = EXC_SUCCESS;

	if (list == NULL || *list == NULL) {
		while ((np = getnetent()) != NULL)
			(void) putnetent(np, stdout);
	} else {
		for (; *list != NULL; list++) {
			long addr = inet_network(*list);
			if (addr != -1)
				np = getnetbyaddr(addr, AF_INET);
			else
				np = getnetbyname(*list);
			if (np == NULL)
				rc = EXC_NAME_NOT_FOUND;
			else
				(void) putnetent(np, stdout);
		}
	}

	return (rc);
}
