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
 * Copyright (c) 1994-1996, by Sun Microsystems, Inc.
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
#include <libsocket_priv.h>
#include "getent.h"

extern char *inet_nettoa(struct in_addr in);

static int
putnetmask(const struct in_addr key, const struct in_addr netmask, FILE *fp)
{
	int rc = 0;
	struct in_addr net;

	net.s_addr = ntohl(key.s_addr);
	if (fprintf(fp, "%-20s", inet_nettoa(net)) == EOF)
		rc = 1;
	if (fprintf(fp, " %s", inet_ntoa(netmask)) == EOF)
		rc = 1;
	if (putc('\n', fp) == EOF)
		rc = 1;
	return (rc);
}

/*
 * getnetmaskbyaddr - get entries from network database
 */
int
dogetnetmask(const char **list)
{
	int rc = EXC_SUCCESS;
	struct in_addr addr, netmask;

	if (list == NULL || *list == NULL)
		return (EXC_ENUM_NOT_SUPPORTED);

	for (; *list != NULL; list++) {
		addr.s_addr = htonl(inet_network(*list));
		if (addr.s_addr != -1) {
			if (getnetmaskbyaddr(addr, &netmask) == 0) {
				(void) putnetmask(addr, netmask, stdout);
			} else {
				rc = EXC_NAME_NOT_FOUND;
			}
		} else {
			rc = EXC_NAME_NOT_FOUND;
		}
	}

	return (rc);
}
