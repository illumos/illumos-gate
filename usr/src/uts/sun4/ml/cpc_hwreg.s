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
 * Copyright 1999-2001,2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Routines for manipulating the UltraSPARC performance
 * counter registers (%pcr and %pic)
 */

#include <sys/asm_linkage.h>

#if defined(lint) || defined(__lint)

#include <sys/cpc_ultra.h>

/*ARGSUSED*/
void
ultra_setpcr(uint64_t pcr)
{}

/*ARGSUSED*/
uint64_t
ultra_getpcr(void)
{ return (0); }

/*ARGSUSED*/
void
ultra_setpic(uint64_t pic)
{}

uint64_t
ultra_getpic(void)
{ return (0); }

uint64_t
ultra_gettick(void)
{ return (0); }

#else	/* lint || __lint */

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

/*
 * This isn't the routine you're looking for.
 *
 * The routine simply returns the value of %tick on the *current* processor.
 * Most of the time, gettick() [which in turn maps to %stick on platforms
 * that have different CPU %tick rates] is what you want.
 */

	ENTRY(ultra_gettick)
	retl
	rdpr	%tick, %o0
	SET_SIZE(ultra_gettick)

#endif	/* lint || __lint */
