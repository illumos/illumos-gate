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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ASM_BYTEORDER_H
#define	_ASM_BYTEORDER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(__lint) && defined(__GNUC__)

#if defined(__i386) || defined(__amd64)

extern __inline__ uint32_t htonl(uint32_t value)
{
	__asm__("bswap %0" : "+r" (value));
	return (value);
}

extern __inline__ uint32_t ntohl(uint32_t value)
{
	__asm__("bswap %0" : "+r" (value));
	return (value);
}

extern __inline__ uint16_t htons(uint16_t value)
{
#if defined(__amd64)
	__asm__("xchgb %h0, %b0" : "+Q" (value));
#elif defined(__i386)
	__asm__("xchgb %h0, %b0" : "+q" (value));
#endif
	return (value);
}

extern __inline__ uint16_t ntohs(uint16_t value)
{
#if defined(__amd64)
	__asm__("xchgb %h0, %b0" : "+Q" (value));
#elif defined(__i386)
	__asm__("xchgb %h0, %b0" : "+q" (value));
#endif
	return (value);
}

#endif	/* __i386 || __amd64 */

#endif	/* !__lint && __GNUC__ */

#ifdef	__cplusplus
}
#endif

#endif	/* _ASM_BYTEORDER_H */
