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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Ye olde non-reentrant interface (MT-unsafe, caveat utor)
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include <rpc/rpcent.h>
#include <nss_dbdefs.h>

#ifdef	NSS_INCLUDE_UNSAFE

/*
 * Don't free this, even on an endrpcent(), because bitter experience shows
 * that there's production code that does getXXXbyYYY(), then endXXXent(),
 * and then continues to use the pointer it got back.
 */
static nss_XbyY_buf_t *buffer;
#define	GETBUF()	\
	NSS_XbyY_ALLOC(&buffer, sizeof (struct rpcent), NSS_BUFLEN_RPC)
	/* === ?? set ENOMEM on failure?  */

struct rpcent *
getrpcbyname(const char *nam)
{
	nss_XbyY_buf_t	*b;

	if ((b = GETBUF()) == 0)
		return (NULL);
	return (getrpcbyname_r(nam, b->result, b->buffer, b->buflen));
}

struct rpcent *
getrpcbynumber(const int num)
{
	nss_XbyY_buf_t	*b;

	if ((b = GETBUF()) == 0)
		return (NULL);
	return (getrpcbynumber_r(num, b->result, b->buffer, b->buflen));
}

struct rpcent *
getrpcent(void)
{
	nss_XbyY_buf_t	*b;

	if ((b = GETBUF()) == 0)
		return (NULL);
	return (getrpcent_r(b->result, b->buffer, b->buflen));
}
#endif	/* NSS_INCLUDE_UNSAFE */
