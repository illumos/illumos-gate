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
 * Copyright 1994,2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include "getent.h"

static int
putethers(const char *hostname, const struct ether_addr *e, FILE *fp)
{
	if (hostname == NULL || e == NULL)
		return (EXC_SYNTAX);

	if (fprintf(fp, "%-20s %s\n", hostname, ether_ntoa(e)) == EOF)
		return (EXC_SYNTAX); /* for lack of a better error code */
	return (EXC_SUCCESS);
}

/*
 * ether_ntohost/hostton - get entries from ethers database
 */
int
dogetethers(const char **list)
{
	int rc = EXC_SUCCESS;

	if (list == NULL || *list == NULL) {
		rc = EXC_ENUM_NOT_SUPPORTED;
	} else {
		for (; *list != NULL; list++) {
			struct ether_addr ea;
			struct ether_addr *e;
			char hostname[MAXHOSTNAMELEN + 1];
			char *hp;
			int	retval;

			if ((e = ether_aton(*list)) != NULL) {
				hp = hostname;
				retval = ether_ntohost(hp, e);
			} else {
				hp = (char *)*list;
				e = &ea;
				retval = ether_hostton(hp, e);
			}
			if (retval != 0)
				rc = EXC_NAME_NOT_FOUND;
			else
				rc = putethers(hp, e, stdout);
		}
	}

	return (rc);
}
