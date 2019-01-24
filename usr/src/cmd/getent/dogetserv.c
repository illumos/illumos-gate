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
 * Copyright (c) 1994, by Sun Microsystems, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

#include <netdb.h>
#include "getent.h"

static int
putservent(const struct servent *sp, FILE *fp)
{
	char **p;
	int rc = 0;

	if (sp == NULL) {
		return (1);
	}

	if (fprintf(fp, "%-20s %d/%s",
	    sp->s_name, ntohs(sp->s_port), sp->s_proto) == EOF)
		rc = 1;
	for (p = sp->s_aliases; *p != 0; p++) {
		if (fprintf(fp, " %s", *p) == EOF)
			rc = 1;
	}
	if (putc('\n', fp) == EOF)
		rc = 1;
	return (rc);
}

/*
 * getservbyname/addr - get entries from service database
 * Accepts arguments as:
 *	port/protocol
 *	port
 *	name/protocol
 *	name
 */
int
dogetserv(const char **list)
{
	struct servent *sp;
	int rc = EXC_SUCCESS;

	if (list == NULL || *list == NULL) {
		while ((sp = getservent()) != NULL)
			(void) putservent(sp, stdout);
	} else {
		for (; *list != NULL; list++) {
			int port;
			char key[BUFSIZ];
			const char *protocol = NULL;
			char *cp;

			/* Copy string to avoiding modifying the argument */
			(void) strncpy(key, *list, sizeof (key));
			key[sizeof (key) - 1] = '\0';
			/* Split at a '/' to extract protocol number */
			if ((cp = strchr(key, '/')) != NULL) {
				*cp = '\0';
				protocol = cp + 1;
			}
			port = htons(atoi(key));
			if (port != 0)
				sp = getservbyport(port, protocol);
			else
				sp = getservbyname(key, protocol);
			if (sp == NULL)
				rc = EXC_NAME_NOT_FOUND;
			else
				(void) putservent(sp, stdout);
		}
	}

	return (rc);
}
