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
 * Copyright (c) 1993, 1996, by Sun Microsystems Inc.
 * All rights reserved.
 */

#ifndef	_SYS_PROM_DEBUG_H
#define	_SYS_PROM_DEBUG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(DEBUG) && !defined(lint)

extern int	prom_debug;

#define	HERE	if (prom_debug)						\
	prom_printf("%s:%d: HERE\n", __FILE__, __LINE__)

#define	PRM_DEBUG(q)	if (prom_debug) {				\
	prom_printf("%s:%d: '%s' is ", __FILE__, __LINE__, #q);		\
	if (sizeof (q) <= sizeof (int))					\
		prom_printf("0x%x\n", (int)q);				\
	else								\
		prom_printf("0x%llx\n",	q);				\
}

#define	PRM_INFO(l)	if (prom_debug)					\
	(prom_printf("%s:%d: ", __FILE__, __LINE__), 			\
	prom_printf(l), prom_printf("\n"))

#define	PRM_INFO1(str, a)	if (prom_debug)				\
	(prom_printf("%s:%d: ", __FILE__, __LINE__), 			\
	prom_printf((str), (a)))

#define	PRM_INFO2(str, a, b)	if (prom_debug)				\
	(prom_printf("%s:%d: ", __FILE__, __LINE__), 			\
	prom_printf((str), (a), (b)))

#define	STUB(n)		if (prom_debug)					\
	(prom_printf("%s:%d: ", __FILE__, __LINE__), 			\
	prom_printf("STUB: %s", #n))

#else

#define	HERE

#define	PRM_DEBUG(q)

#define	PRM_INFO(l)

#define	PRM_INFO1(str, a)

#define	PRM_INFO2(str, a, b)

#define	STUB(n)

#endif /* DEBUG && !lint */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PROM_DEBUG_H */
