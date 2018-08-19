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
 * Copyright (c) 2018 Peter Tribble.
 * Copyright (c) 1994-1999, by Sun Microsystems, Inc.
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
	char obuf[INET6_ADDRSTRLEN];

	if (hp == NULL) {
		return (1);
	}

	for (p = hp->h_addr_list; *p != 0; p++) {
		void		*addr;
		struct in_addr	in4;
		int		af;
		const char	*res;
		char **q;

		if (hp->h_addrtype == AF_INET6) {
			if (IN6_IS_ADDR_V4MAPPED((struct in6_addr *)*p)) {
				IN6_V4MAPPED_TO_INADDR((struct in6_addr *)*p,
				    &in4);
				af = AF_INET;
				addr = &in4;
			} else {
				af = AF_INET6;
				addr = *p;
			}
		} else {
			af = AF_INET;
			addr = *p;
		}
		res = inet_ntop(af, addr, obuf, sizeof (obuf));
		if (res == 0) {
			rc = 1;
			continue;
		}
		if (fprintf(fp, "%s\t%s", res, hp->h_name) == EOF)
			rc = 1;
		for (q = hp->h_aliases; q && *q; q++) {
			if (fprintf(fp, " %s", *q) == EOF)
				rc = 1;
		}
		if (putc('\n', fp) == EOF)
			rc = 1;
	}
	return (rc);
}

/*
 * getipnodebyname/addr - get entries from ipnodes database
 */
int
dogetipnodes(const char **list)
{
	struct hostent *hp;
	int rc = EXC_SUCCESS;
	struct in6_addr in6;
	struct in_addr	in4;
	int		af, len;
	void		*addr;
	int err_ret;

	if (list == NULL || *list == NULL) {
		rc = EXC_ENUM_NOT_SUPPORTED;
	} else {
		for (; *list != NULL; list++) {
			if (strchr(*list, ':') != 0) {
				af = AF_INET6;
				len = sizeof (in6);
				addr = &in6;
			} else {
				af = AF_INET;
				len = sizeof (in4);
				addr = &in4;
			}
			if (inet_pton(af, *list, addr) == 1)
				hp = getipnodebyaddr(addr, len, af, &err_ret);
			else
				hp = getipnodebyname(*list, AF_INET6,
				    AI_V4MAPPED|AI_ALL, &err_ret);
			if (hp == NULL)
				rc = EXC_NAME_NOT_FOUND;
			else
				(void) puthostent(hp, stdout);
		}
	}

	return (rc);
}
