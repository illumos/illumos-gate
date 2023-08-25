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
 * Copyright (c) 1987 Sun Microsystems, Inc.
 */

#ident	"%Z%%M%	%I%	%E% SMI"

	.file	"alloca.s"

#include <sys/asm_linkage.h>

	!
	! o0: # bytes of space to allocate, already rounded to 0 mod 8
	! o1: %sp-relative offset of tmp area
	! o2: %sp-relative offset of end of tmp area
	!
	! we want to bump %sp by the requested size
	! then copy the tmp area to its new home
	! this is necessasy as we could theoretically
	! be in the middle of a compilicated expression.
	!
	ENTRY(__builtin_alloca)
	mov	%sp, %o3		! save current sp
	sub	%sp, %o0, %sp		! bump to new value
	! copy loop: should do nothing gracefully
	b	2f
	subcc	%o2, %o1, %o5		! number of bytes to move
1:
	ld	[%o3 + %o1], %o4	! load from old temp area
	st	%o4, [%sp + %o1]	! store to new temp area
	add	%o1, 4, %o1
2:	bg	1b
	subcc	%o5, 4, %o5
	! now return new %sp + end-of-temp
	retl
	add	%sp, %o2, %o0

	SET_SIZE(__builtin_alloca)
