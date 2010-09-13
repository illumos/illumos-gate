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
 * Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#ifndef _DBG_H
#define	_DBG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Header file for debugging output.  This is compiled in only if the
 * code is compiled with -DDEBUG.  There are two kinds of debugging output.
 * The first is DBG, which is used to print output directly.  The second is
 * debug probes which can be controlled at run time via prex.
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef DEBUG
#include <stdio.h>

#define	DBG(x)		(x)
#else
#define	DBG(x)
#endif	/* DEBUG */

#ifdef DEBUG
#include <tnf/probe.h>

#define	DBG_TNF_PROBE_0(a, b, c)	\
	TNF_PROBE_0(a, b, c)
#define	DBG_TNF_PROBE_1(a, b, c, t1, n1, v1)	\
	TNF_PROBE_1(a, b, c, t1, n1, v1)
#define	DBG_TNF_PROBE_2(a, b, c, t1, n1, v1, t2, n2, v2)	\
	TNF_PROBE_2(a, b, c, t1, n1, v1, t2, n2, v2)
#define	DBG_TNF_PROBE_3(a, b, c, t1, n1, v1, t2, n2, v2, t3, n3, v3)	\
	TNF_PROBE_3(a, b, c, t1, n1, v1, t2, n2, v2, t3, n3, v3)
/* CSTYLED */
#define	DBG_TNF_PROBE_4(a, b, c, t1, n1, v1, t2, n2, v2, t3, n3, v3, t4, n4, v4)	\
	TNF_PROBE_4(a, b, c, t1, n1, v1, t2, n2, v2, t3, n3, v3, t4, n4, v4)

#else

#define	DBG_TNF_PROBE_0(a, b, c)	\
	((void)0)
#define	DBG_TNF_PROBE_1(a, b, c, t1, n1, v1)	\
	((void)0)
#define	DBG_TNF_PROBE_2(a, b, c, t1, n1, v1, t2, n2, v2)	\
	((void)0)
#define	DBG_TNF_PROBE_3(a, b, c, t1, n1, v1, t2, n2, v2, t3, n3, v3)	\
	((void)0)
/* CSTYLED */
#define	DBG_TNF_PROBE_4(a, b, c, t1, n1, v1, t2, n2, v2, t3, n3, v3, t4, n4, v4)	\
	((void)0)

#endif	/* DEBUG */

#ifdef __cplusplus
}
#endif

#endif	/* _DBG_H */
