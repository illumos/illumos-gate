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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

	.inline	_curthread, 0
	.register %g7, #scratch
	mov	%g7, %o0
	.end

	.inline	__curthread, 0
	.register %g7, #scratch
	ldx	[%g7 + 80], %o0		! ul_self
	.end

	.inline	stkptr, 0
	mov	%sp, %o0
	.end

	.inline	gethrtime, 0
	.volatile
	ta	0x24
	sllx	%o0, 32, %o0
	or	%o1, %o0, %o0
	.nonvolatile
	.end

	.inline	set_lock_byte, 0
	ldstub	[%o0], %o0
	membar	#LoadLoad
	.end

	.inline	atomic_cas_32, 0
	cas	[%o0], %o1, %o2
	mov	%o2, %o0
	.end

	.inline	atomic_swap_32, 0
	ld	[%o0], %o2
1:
	mov	%o1, %o3
	cas	[%o0], %o2, %o3
	cmp	%o2, %o3
	bne,a,pn %icc, 1b
	  mov	%o3, %o2
	mov	%o3, %o0
	.end

	.inline	atomic_inc_32, 0
	ld	[%o0], %o2
1:
	add	%o2, 1, %o3
	cas	[%o0], %o2, %o3
	cmp	%o2, %o3
	bne,a,pn %icc, 1b
	  mov	%o3, %o2
	.end

	.inline	atomic_dec_32, 0
	ld	[%o0], %o2
1:
	sub	%o2, 1, %o3
	cas	[%o0], %o2, %o3
	cmp	%o2, %o3
	bne,a,pn %icc, 1b
	  mov	%o3, %o2
	.end

	.inline	atomic_and_32, 0
	ld	[%o0], %o2
1:
	and	%o2, %o1, %o3
	cas	[%o0], %o2, %o3
	cmp	%o2, %o3
	bne,a,pn %icc, 1b
	  mov	%o3, %o2
	.end

	.inline	atomic_or_32, 0
	ld	[%o0], %o2
1:
	or	%o2, %o1, %o3
	cas	[%o0], %o2, %o3
	cmp	%o2, %o3
	bne,a,pn %icc, 1b
	  mov	%o3, %o2
	.end

	.inline	caller, 0
	mov	%i7, %o0
	.end

	.inline	getfp, 0
	mov	%fp, %o0
	.end
