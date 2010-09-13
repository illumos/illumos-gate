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

#ifndef _MACHLIBTNF_H
#define	_MACHLIBTNF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/isa_defs.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_BIG_ENDIAN) || defined(__sparc)

tnf_uint32_t	_tnf_swap32(tnf_uint32_t);
tnf_uint16_t	_tnf_swap16(tnf_uint16_t);

#elif defined(_LITTLE_ENDIAN) || defined(__i386) || defined(__amd64)

#include <sys/byteorder.h>

#define	_tnf_swap32(x)	ntohl(x)
#define	_tnf_swap16(x)	ntohs(x)

#else

#error Unknown endian

#endif

#ifdef __cplusplus
}
#endif

#endif /* _MACHLIBTNF_H */
