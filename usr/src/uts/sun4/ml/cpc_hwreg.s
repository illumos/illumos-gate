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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Routines for manipulating the UltraSPARC performance
 * counter registers (%pcr and %pic)
 */

#include <sys/asm_linkage.h>

	ENTRY(ultra_setpcr)
	retl
	wr	%o0, %pcr
	SET_SIZE(ultra_setpcr)

	ENTRY(ultra_getpcr)
	retl
	rd	%pcr, %o0
	SET_SIZE(ultra_getpcr)

	ENTRY(ultra_setpic)
#if defined(BB_ERRATA_1)	/* Writes to %pic may fail */
	ba	1f
	nop
	.align	16
1:	wr	%o0, %pic
	rd	%pic, %g0
	retl
	nop
#else
	retl
	wr	%o0, %pic
#endif	/* BB_ERRATA_1 */
	SET_SIZE(ultra_setpic)

	ENTRY(ultra_getpic)
	retl
	rd	%pic, %o0
	SET_SIZE(ultra_getpic)

