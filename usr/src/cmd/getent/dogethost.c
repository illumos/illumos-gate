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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 1994-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <netdb.h>
#include "getent.h"

static int
puthostent(const struct hostent *hp, FILE *fp)
{
	char **p;
	int rc = 0;

	if (hp == NULL) {
		return (1);
	}

	for (p = hp->h_addr_list; *p != 0; p++) {
		struct in_addr in;
		char **q;

		(void) memcpy((char *)&in.s_addr, *p, sizeof (in));
		if (fprintf(fp, "%s\t%s",
			inet_ntoa(in), hp->h_name) == EOF)
			rc = 1;
		for (q = hp->h_aliases; *q != 0; q++) {
			if (fprintf(fp, " %s", *q) == EOF)
				rc = 1;
		}
		if (putc('\n', fp) == EOF)
			rc = 1;
	}
	return (rc);
}

/*
 * gethostbyname/addr - get entries from hosts database
 */
int
dogethost(const char **list)
{
	struct hostent *hp;
	int rc = EXC_SUCCESS;

	if (list == NULL || *list == NULL) {
		while ((hp = gethostent()) != NULL)
			(void) puthostent(hp, stdout);
	} else {
		for (; *list != NULL; list++) {
			struct in_addr addr;
			addr.s_addr = inet_addr(*list);
			if (addr.s_addr != (in_addr_t)-1)
				hp = gethostbyaddr((char *)&addr,
					sizeof (addr), AF_INET);
			else
				hp = gethostbyname(*list);
			if (hp == NULL)
				rc = EXC_NAME_NOT_FOUND;
			else
				(void) puthostent(hp, stdout);
		}
	}

	return (rc);
}
