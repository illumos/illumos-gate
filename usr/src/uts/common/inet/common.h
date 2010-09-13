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
/* Copyright (c) 1990 Mentat Inc. */

#ifndef	_INET_COMMON_H
#define	_INET_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * WARNING: This file contains implementation-specific constants, typedefs
 *	    and macros which may change from release to release.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/inttypes.h>
#include <sys/sysmacros.h>
#include <sys/mkdev.h>

#define	A_CNT(arr)	(sizeof (arr) / sizeof (arr[0]))
#define	A_END(arr)	(&arr[A_CNT(arr)])
#define	A_LAST(arr)	(&arr[A_CNT(arr) - 1])

#define	nilp(t)		((t *)0)
#define	nil(t)		((t)0)
#define	noop

typedef	int	(*pfi_t)();
typedef	void	(*pfv_t)();

#define	BE32_EQL(a, b)	(((uint8_t *)a)[0] == ((uint8_t *)b)[0] && \
	((uint8_t *)a)[1] == ((uint8_t *)b)[1] && \
	((uint8_t *)a)[2] == ((uint8_t *)b)[2] && \
	((uint8_t *)a)[3] == ((uint8_t *)b)[3])
#define	BE16_EQL(a, b)	(((uint8_t *)a)[0] == ((uint8_t *)b)[0] && \
	((uint8_t *)a)[1] == ((uint8_t *)b)[1])
#define	BE16_TO_U16(a)	((((uint16_t)((uint8_t *)a)[0] << 8) | \
	((uint16_t)((uint8_t *)a)[1])) & 0xFFFF)
#define	BE32_TO_U32(a)	((((uint32_t)((uint8_t *)a)[0]) << 24) | \
	(((uint32_t)((uint8_t *)a)[1]) << 16) | \
	(((uint32_t)((uint8_t *)a)[2]) << 8)  | \
	((uint32_t)((uint8_t *)a)[3]))
#define	U16_TO_BE16(u, a) ((((uint8_t *)a)[0] = (uint8_t)((u) >> 8)), \
	(((uint8_t *)a)[1] = (uint8_t)(u)))
#define	U32_TO_BE32(u, a) ((((uint8_t *)a)[0] = (uint8_t)((u) >> 24)), \
	(((uint8_t *)a)[1] = (uint8_t)((u) >> 16)), \
	(((uint8_t *)a)[2] = (uint8_t)((u) >> 8)), \
	(((uint8_t *)a)[3] = (uint8_t)(u)))

/*
 * Local Environment Definition, this may and should override the
 * the default definitions above where the local environment differs.
 */
#include <inet/led.h>
#include <sys/isa_defs.h>

#ifdef	_BIG_ENDIAN
#define	ABE32_TO_U32(p)		(*((uint32_t *)p))
#define	ABE16_TO_U16(p)		(*((uint16_t *)p))
#define	U16_TO_ABE16(u, p)	(*((uint16_t *)p) = (u))
#define	U32_TO_ABE16(u, p)	U16_TO_ABE16(u, p)
#define	U32_TO_ABE32(u, p)	(*((uint32_t *)p) = (u))
#else
#define	ABE16_TO_U16(p)		BE16_TO_U16(p)
#define	ABE32_TO_U32(p)		BE32_TO_U32(p)
#define	U16_TO_ABE16(u, p)	U16_TO_BE16(u, p)
#define	U32_TO_ABE16(u, p)	U16_TO_ABE16(u, p)
#define	U32_TO_ABE32(u, p)	U32_TO_BE32(u, p)
#endif

#define	INET_MIN_DEV		2	/* minimum minor device number */

#ifdef _KERNEL
#include <sys/stream.h>

extern void *inet_minor_create(char *, dev_t, dev_t, int);
extern void inet_minor_destroy(void *);
extern dev_t inet_minor_alloc(void *);
extern void inet_minor_free(void *, dev_t);
extern void inet_freemsg(mblk_t *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_COMMON_H */
