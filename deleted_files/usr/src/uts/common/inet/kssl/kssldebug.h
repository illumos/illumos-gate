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

#ifndef	_INET_KSSL_KSSLDEBUG_H
#define	_INET_KSSL_KSSLDEBUG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* BEGIN CSTYLED */
#ifdef DEBUG
extern int kssl_debug;

#define	KSSL_DEBUG1(a1)			cmn_err(CE_CONT, (a1))
#define	KSSL_DEBUG2(a1,a2)		cmn_err(CE_CONT, (a1),(a2))
#define	KSSL_DEBUG3(a1,a2,a3)		cmn_err(CE_CONT, (a1),(a2),(a3))
#define	KSSL_DEBUG4(a1,a2,a3,a4)		cmn_err(CE_CONT, (a1),(a2),(a3),(a4))
#define	KSSL_DEBUG5(a1,a2,a3,a4,a5)		\
    cmn_err(CE_CONT,(a1),(a2),(a3),(a4),(a5))
#define	KSSL_DEBUG6(a1,a2,a3,a4,a5,a6)		\
    cmn_err(CE_CONT,(a1),(a2),(a3),(a4),(a5),(a6))
#define	KSSL_DEBUG7(a1,a2,a3,a4,a5,a6,a7)	\
    cmn_err(CE_CONT,(a1),(a2),(a3),(a4),(a5),(a6),(a7))
#define	KSSL_DEBUG8(a1,a2,a3,a4,a5,a6,a7,a8)	\
    cmn_err(CE_CONT,(a1),(a2),(a3),(a4),(a5),(a6),(a7),(a8))
#define	KSSL_DEBUG9(a1,a2,a3,a4,a5,a6,a7,a8,a9)	\
    cmn_err(CE_CONT,(a1),(a2),(a3),(a4),(a5),(a6),(a7),(a8),(a9))

#define	KSSL_DEBUG12(a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12) \
    cmn_err(CE_CONT,(a1),(a2),(a3),(a4),(a5),(a6),(a7),(a8),(a9),(a10),(a11), \
	(a12))
#define	KSSL_DEBUG14(a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14) \
    cmn_err(CE_CONT,(a1),(a2),(a3),(a4),(a5),(a6),(a7),(a8),(a9),(a10),(a11), \
	(a12),(a13),(a14))
#define	KSSL_DEBUG15(a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15) \
    cmn_err(CE_CONT,(a1),(a2),(a3),(a4),(a5),(a6),(a7),(a8),(a9),(a10),(a11), \
	(a12),(a13),(a14),(a15))

#define	KSSL_DEBUG1_IF(c,a1)			\
	{ if (c) KSSL_DEBUG1((a1)); }
#define	KSSL_DEBUG2_IF(c,a1,a2)			\
	{ if (c) KSSL_DEBUG2((a1),(a2)); }
#define	KSSL_DEBUG3_IF(c,a1,a2,a3)		\
	{ if (c) KSSL_DEBUG3((a1),(a2),(a3)); }
#define	KSSL_DEBUG4_IF(c,a1,a2,a3,a4)		\
	{ if (c) KSSL_DEBUG4((a1),(a2),(a3),(a4)); }
#define	KSSL_DEBUG5_IF(c,a1,a2,a3,a4,a5)		\
	{ if (c) KSSL_DEBUG5((a1),(a2),(a3),(a4),(a5)); }
#define	KSSL_DEBUG6_IF(c,a1,a2,a3,a4,a5,a6)	\
	{ if (c) KSSL_DEBUG6((a1),(a2),(a3),(a4),(a5),(a6)); }
#define	KSSL_DEBUG7_IF(c,a1,a2,a3,a4,a5,a6,a7)	\
	{ if (c) KSSL_DEBUG7((a1),(a2),(a3),(a4),(a5),(a6),(a7)); }

#else	/* !DEBUG */

#define	KSSL_DEBUG1(a1)				/* empty */
#define	KSSL_DEBUG2(a1,a2)			/* empty */
#define	KSSL_DEBUG3(a1,a2,a3)			/* empty */
#define	KSSL_DEBUG4(a1,a2,a3,a4)			/* empty */
#define	KSSL_DEBUG5(a1,a2,a3,a4,a5)		/* empty */
#define	KSSL_DEBUG6(a1,a2,a3,a4,a5,a6)		/* empty */
#define	KSSL_DEBUG7(a1,a2,a3,a4,a5,a6,a7)	/* empty */
#define	KSSL_DEBUG8(a1,a2,a3,a4,a5,a6,a7,a8)	/* empty */
#define	KSSL_DEBUG9(a1,a2,a3,a4,a5,a6,a7,a8,a9)	/* empty */

#define	KSSL_DEBUG12(a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12)	/* empty */
#define	KSSL_DEBUG14(a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14)
#define	KSSL_DEBUG15(a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15)

#define	KSSL_DEBUG1_IF(c,a1)			/* empty */
#define	KSSL_DEBUG2_IF(c,a1,a2) 			/* empty */
#define	KSSL_DEBUG3_IF(c,a1,a2,a3)		/* empty */
#define	KSSL_DEBUG4_IF(c,a1,a2,a3,a4)		/* empty */
#define	KSSL_DEBUG5_IF(c,a1,a2,a3,a4,a5)		/* empty */
#define	KSSL_DEBUG6_IF(c,a1,a2,a3,a4,a5,a6)	/* empty */
#define	KSSL_DEBUG7_IF(c,a1,a2,a3,a4,a5,a6,a7)	/* empty */

#endif	/* DEBUG */
/* END CSTYLED */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_KSSL_KSSLDEBUG_H */
