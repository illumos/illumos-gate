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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/asm_linkage.h>
#include <sys/regset.h>

#if defined(__lint)
#include <ucontext.h>
#endif

#include "kmdb_context_off.h"

#define	UC_GREG(name)	(UC_MCTX + MCTX_GREGS + (name * MCTX_GREGS_INCR))

#if defined(__lint)
/*ARGSUSED*/
int
kmdb_setcontext(ucontext_t *ucp)
{
	return (0);
}
#else

	ENTRY(kmdb_setcontext)
	flushw

	mov	%o0, %g7

	ldx	[%g7 + UC_GREG(REG_O0)], %o0
	ldx	[%g7 + UC_GREG(REG_O1)], %o1
	ldx	[%g7 + UC_GREG(REG_O2)], %o2
	ldx	[%g7 + UC_GREG(REG_O3)], %o3
	ldx	[%g7 + UC_GREG(REG_O4)], %o4
	ldx	[%g7 + UC_GREG(REG_O5)], %o5
	ldx	[%g7 + UC_GREG(REG_O6)], %o6
	ldx	[%g7 + UC_GREG(REG_O7)], %o7

	ldx	[%g7 + UC_GREG(REG_G1)], %g1
	ldx	[%g7 + UC_GREG(REG_G2)], %g2
	ldx	[%g7 + UC_GREG(REG_G3)], %g3
	ldx	[%g7 + UC_GREG(REG_G4)], %g4
	ldx	[%g7 + UC_GREG(REG_G5)], %g5
	ldx	[%g7 + UC_GREG(REG_G6)], %g6

	/* ick */
	ldx	[%g7 + UC_GREG(REG_PC)], %l0
	jmp	%l0
	ldx	[%g7 + UC_GREG(REG_G7)], %g7

	SET_SIZE(kmdb_setcontext)

#endif
