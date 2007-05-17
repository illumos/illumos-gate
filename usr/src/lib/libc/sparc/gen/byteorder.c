/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/isa_defs.h>
#include <sys/types.h>


#if defined(_LITTLE_ENDIAN) && !defined(__lint)

#error	Use ISA-specific byteorder.s on a little-endian machine.

#else	/* !_LITTLE_ENDIAN */

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

#endif	/* _LITTLE_ENDIAN */
