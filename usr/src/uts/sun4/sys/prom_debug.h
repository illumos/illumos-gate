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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
	prom_printf("%s:%d: '%s' is 0x%lx\n", __FILE__, __LINE__, #q,	\
	    (long)q);							\
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
