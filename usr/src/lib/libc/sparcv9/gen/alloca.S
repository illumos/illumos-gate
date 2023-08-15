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
 * Copyright (c) 1998, by Sun Microsystems, Inc.
 * All rights reserved.
 */

	.file	"alloca.s"

#include <sys/asm_linkage.h>
#include <sys/stack.h>

	!
	! o0: # bytes of space to allocate, already rounded to 0 mod 8
	! o1: %sp-relative offset of tmp area
	! o2: %sp-relative offset of end of tmp area
	!
	! we want to bump %sp by the requested size
	! then copy the tmp area to its new home
	! this is necessary as we could theoretically
	! be in the middle of a complicated expression.
	!
	ENTRY(__builtin_alloca)
	add	%sp, STACK_BIAS, %g1	! save current sp + STACK_BIAS
	sub	%sp, %o0, %sp		! bump to new value
	add	%sp, STACK_BIAS, %g5
	! copy loop: should do nothing gracefully
	b	2f
	subcc	%o2, %o1, %o5		! number of bytes to move
1:
	ldx	[%g1 + %o1], %o4	! load from old temp area
	stx	%o4, [%g5 + %o1]	! store to new temp area
	add	%o1, 8, %o1
2:	bg,pt	%xcc, 1b
	subcc	%o5, 8, %o5
	! now return new %sp + end-of-temp
	add	%sp, %o2, %o0
	retl
	add	%o0, STACK_BIAS, %o0
	SET_SIZE(__builtin_alloca)
