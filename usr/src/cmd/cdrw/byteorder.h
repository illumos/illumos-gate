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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_BYTEORDER_H
#define	_BYTEORDER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define	swap32(x) \
((uint32_t)((((uint32_t)(x) & 0x000000ff) << 24) | \
(((uint32_t)(x) & 0x0000ff00) << 8) | \
(((uint32_t)(x) & 0x00ff0000) >> 8) | \
(((uint32_t)(x) & 0xff000000) >> 24)))

#define	swap16(x) \
((uint16_t)((((uint16_t)(x) & 0x00ff) << 8) | \
(((uint16_t)(x) & 0xff00) >> 8)))

/*
 * endianess issues
 */
#if defined(_BIG_ENDIAN)
#define	CPU_TO_LE32(x)	swap32(x)
#define	CPU_TO_LE16(x)	swap16(x)
#define	CPU_TO_BE32(x)	(x)
#define	CPU_TO_BE16(x)	(x)
#else
#define	CPU_TO_LE32(x)	(x)
#define	CPU_TO_LE16(x)	(x)
#define	CPU_TO_BE32(x)	swap32(x)
#define	CPU_TO_BE16(x)	swap16(x)
#endif

#define	LE32_TO_CPU(x)	CPU_TO_LE32(x)
#define	LE16_TO_CPU(x)	CPU_TO_LE16(x)
#define	BE32_TO_CPU(x)	CPU_TO_BE32(x)
#define	BE16_TO_CPU(x)	CPU_TO_BE16(x)

#ifdef	__cplusplus
}
#endif

#endif /* _BYTEORDER_H */
