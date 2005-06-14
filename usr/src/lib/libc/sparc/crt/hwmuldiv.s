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
 * Copyright (c) 1994-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

	.file	"%M%"

#include <sys/asm_linkage.h>

/*
 * Versions of .mul .umul .div .udiv .rem .urem written using
 * appropriate SPARC V8 instructions.
 */

	ENTRY(.mul)
	smul	%o0, %o1, %o0
	rd	%y, %o1
	sra	%o0, 31, %o2
	retl
	cmp	%o1, %o2	! return with Z set if %y == (%o0 >> 31)
	SET_SIZE(.mul)

	ENTRY(.umul)
	umul	%o0, %o1, %o0
	rd	%y, %o1
	retl
	tst	%o1		! return with Z set if high order bits are zero
	SET_SIZE(.umul)

	ENTRY(.div)
	sra	%o0, 31, %o2
	wr	%g0, %o2, %y
	nop
	nop
	nop
	sdivcc	%o0, %o1, %o0
	bvs,a	1f
	xnor	%o0, %g0, %o0	! Corbett Correction Factor
1:	retl
	nop
	SET_SIZE(.div)

	ENTRY(.udiv)
	wr	%g0, %g0, %y
	nop
	nop
	retl
	udiv	%o0, %o1, %o0
	SET_SIZE(.udiv)

	ENTRY(.rem)
	sra	%o0, 31, %o4
	wr	%o4, %g0, %y
	nop
	nop
	nop
	sdivcc	%o0, %o1, %o2
	bvs,a	1f
	xnor	%o2, %g0, %o2	! Corbett Correction Factor
1:	smul	%o2, %o1, %o2
	retl
	sub	%o0, %o2, %o0
	SET_SIZE(.rem)

	ENTRY(.urem)
	wr	%g0, %g0, %y
	nop
	nop
	nop
	udiv	%o0, %o1, %o2
	umul	%o2, %o1, %o2
	retl
	sub	%o0, %o2, %o0
	SET_SIZE(.urem)
