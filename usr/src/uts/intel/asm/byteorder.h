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
 */

#ifndef _ASM_BYTEORDER_H
#define	_ASM_BYTEORDER_H

#include <sys/ccompile.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(__lint) && defined(__GNUC__)

/*
 * htonll(), ntohll(), htonl(), ntohl(), htons(), ntohs()
 * These functions reverse the byte order of the input parameter and returns
 * the result.  This is to convert the byte order from host byte order
 * (little endian) to network byte order (big endian), or vice versa.
 */


#if defined(__i386) || defined(__amd64)

extern __GNU_INLINE uint16_t
htons(uint16_t value)
{
#if defined(__amd64)
	__asm__("xchgb %h0, %b0" : "+Q" (value));
#elif defined(__i386)
	__asm__("xchgb %h0, %b0" : "+q" (value));
#endif
	return (value);
}

extern __GNU_INLINE uint16_t
ntohs(uint16_t value)
{
#if defined(__amd64)
	__asm__("xchgb %h0, %b0" : "+Q" (value));
#elif defined(__i386)
	__asm__("xchgb %h0, %b0" : "+q" (value));
#endif
	return (value);
}

extern __GNU_INLINE uint32_t
htonl(uint32_t value)
{
	__asm__("bswap %0" : "+r" (value));
	return (value);
}

extern __GNU_INLINE uint32_t
ntohl(uint32_t value)
{
	__asm__("bswap %0" : "+r" (value));
	return (value);
}

#if defined(__amd64)
extern __GNU_INLINE uint64_t
htonll(uint64_t value)
{
	__asm__("bswapq %0" : "+r" (value));
	return (value);
}

extern __GNU_INLINE uint64_t
ntohll(uint64_t value)
{
	__asm__("bswapq %0" : "+r" (value));
	return (value);
}

#elif defined(__i386)
/* Use the htonl() and ntohl() inline functions defined above */
extern __GNU_INLINE uint64_t
htonll(uint64_t value)
{
	return (htonl(value >> 32) | ((uint64_t)htonl(value) << 32));
}

extern __GNU_INLINE uint64_t
ntohll(uint64_t value)
{
	return (ntohl(value >> 32) | (uint64_t)ntohl(value) << 32);
}
#endif	/* __amd64 */

#endif	/* __i386 || __amd64 */

#endif	/* !__lint && __GNUC__ */

#ifdef	__cplusplus
}
#endif

#endif	/* _ASM_BYTEORDER_H */
