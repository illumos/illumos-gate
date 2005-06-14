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
 * Copyright (c) 1991 by Sun Microsystems, Inc.
 */

#include <rpc/rpc.h>
#include <netdb.h>
#include <sys/socket.h>
#include <stdio.h>

extern u_short pmap_getport(struct sockaddr_in *, rpcprog_t,
			rpcvers_t, rpcprot_t);

u_short
getrpcport(char *host, rpcprog_t prognum, rpcvers_t versnum, rpcprot_t proto)
{
	struct sockaddr_in addr;
	struct hostent *hp;

	if ((hp = gethostbyname(host)) == NULL)
		return (0);
	memcpy((char *) &addr.sin_addr, hp->h_addr, hp->h_length);
	addr.sin_family = AF_INET;
	addr.sin_port =  0;
	return (pmap_getport(&addr, prognum, versnum, proto));
}
