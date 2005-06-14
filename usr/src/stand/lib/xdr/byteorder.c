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
 * Copyright 1991-2000, 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <netinet/in.h>

#ifdef	_LITTLE_ENDIAN
uint32_t
htonl(uint32_t in)
{
	uint32_t	i;

	i = (uint32_t)((in & (uint32_t)0xff000000) >> 24) +
	    (uint32_t)((in & (uint32_t)0x00ff0000) >> 8) +
	    (uint32_t)((in & (uint32_t)0x0000ff00) << 8) +
	    (uint32_t)((in & (uint32_t)0x000000ff) << 24);
	return (i);
}

uint32_t
ntohl(uint32_t in)
{
	return (htonl(in));
}

uint16_t
htons(uint16_t in)
{
	register int arg = (int)in;
	uint16_t i;

	i = (uint16_t)(((arg & 0xff00) >> 8) & 0xff);
	i |= (uint16_t)((arg & 0xff) << 8);
	return ((uint16_t)i);
}

uint16_t
ntohs(uint16_t in)
{
	return (htons(in));
}

#else	/* _LITTLE_ENDIAN */

#if defined(lint)

uint32_t
htonl(uint32_t in)
{
	return (in);
}

uint32_t
ntohl(uint32_t in)
{
	return (in);
}

uint16_t
htons(uint16_t in)
{
	return (in);
}

uint16_t
ntohs(uint16_t in)
{
	return (in);
}

#endif	/* lint */
#endif	/* _LITTLE_ENDIAN */
