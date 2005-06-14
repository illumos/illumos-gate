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
 * Copyright (c) 1986-1994,2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Ye olde non-reentrant interface (MT-unsafe, caveat utor)
 *
 * lib/libsocket/inet/getservent.c
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <netdb.h>
#include <nss_dbdefs.h>

#ifdef	NSS_INCLUDE_UNSAFE

/*
 * Don't free this, even on an endservent(), because bitter experience shows
 * that there's production code that does getXXXbyYYY(), then endXXXent(),
 * and then continues to use the pointer it got back.
 */
static nss_XbyY_buf_t *buffer;
#define	GETBUF()						\
NSS_XbyY_ALLOC(&buffer, (int)sizeof (struct servent), NSS_BUFLEN_SERVICES)
	/* === ?? set ENOMEM on failure?  */

struct servent *
getservbyname(const char *nam, const char *proto)
{
	nss_XbyY_buf_t	*b;
	struct servent	*res = 0;

	if ((b = GETBUF()) != 0) {
		res = getservbyname_r(nam, proto,
					b->result, b->buffer, b->buflen);
	}
	return (res);
}

struct servent *
getservbyport(int port, const char *proto)
{
	nss_XbyY_buf_t	*b;
	struct servent	*res = 0;

	if ((b = GETBUF()) != 0) {
		res = getservbyport_r(port, proto,
					b->result, b->buffer, b->buflen);
	}
	return (res);
}

struct servent *
getservent(void)
{
	nss_XbyY_buf_t	*b;
	struct servent	*res = 0;

	if ((b = GETBUF()) != 0) {
		res = getservent_r(b->result, b->buffer, b->buflen);
	}
	return (res);
}

#endif	/* NSS_INCLUDE_UNSAFE */
