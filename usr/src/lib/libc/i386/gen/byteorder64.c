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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2015, Joyent, Inc.
 */

#include <sys/isa_defs.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>

#if (defined(_BIG_ENDIAN) || defined(_LP64)) && !defined(__lint)

#error	Use ISA-dependent byteorder64.c only on a 32-bit little-endian machine.

#else

uint64_t
htonll(uint64_t in)
{
	return (htonl(in >> 32) | ((uint64_t)htonl(in) << 32));
}

uint64_t
ntohll(uint64_t in)
{
	return (ntohl(in >> 32) | (uint64_t)ntohl(in) << 32);
}

uint64_t
htobe64(uint64_t in)
{
	return (htonl(in >> 32) | ((uint64_t)htonl(in) << 32));
}

uint64_t
htole64(uint64_t in)
{
	return (in);
}

uint64_t
betoh64(uint64_t in)
{
	return (ntohl(in >> 32) | (uint64_t)ntohl(in) << 32);
}

uint64_t
letoh64(uint64_t in)
{
	return (in);
}

uint64_t
be64toh(uint64_t in)
{
	return (ntohl(in >> 32) | (uint64_t)ntohl(in) << 32);
}

uint64_t
le64toh(uint64_t in)
{
	return (in);
}

#endif	/* (_BIG_ENDIAN) || _LP64) && !__lint */
