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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"__align_cpy_8.s"

/* __align_cpy_8(s1, s2, n)
 *
 * Copy 8-byte aligned source to 8-byte aligned target in multiples of 8 bytes.
 *
 * Input:
 *	o0	address of target
 *	o1	address of source
 *	o2	number of bytes to copy (must be a multiple of 8)
 * Output:
 *	o0	address of target
 * Caller's registers that have been changed by this function:
 *	o1-o5
 *
 * Note:
 *	This helper routine will not be used by any 32-bit compilations. To do
 *	so would break binary compatibility with previous versions of Solaris.
 *
 * Assumptions:
 *	Source and target addresses are 8-byte aligned.
 *	Bytes to be copied are non-overlapping or _exactly_ overlapping.
 *	The number of bytes to be copied is a multiple of 8.
 *	Call will _usually_ be made with a byte count of more than 4*8 and
 *	less than a few hundred bytes.  Legal values are 0 to MAX_SIZE_T.
 *
 * Optimization attempt:
 *	Reasonable speed for a generic v9.  Going for 32 bytes at a time
 *	rather than 16 bytes at a time did not result in a time saving for
 *	the number of bytes expected to be copied.  No timing runs using other
 *	levels of optimization have been tried yet.
 *
 * Even when multiples of 16 bytes were used, the savings by going for 32 bytes
 * at a time were about 2%.  Thus, __align_cpy_16 is a second entry point to
 * the same code as __align_cpy_8.
 *
 * Register usage:
 *	o1	source address (updated for each read)
 *	o2	byte count remaining
 *	o3	contents being copied
 *	o4	more contents being copied
 *	o5	target address
 */

#include <sys/asm_linkage.h>

	ENTRY(__align_cpy_8)
	ENTRY(__align_cpy_16)
	cmp	%o0, %o1		! Identical--do nothing.
	be,pn	%xcc, .done
	subcc	%o2, 8, %o2
	bz,pn	%xcc, .wrdbl2		! Only 8 bytes need to be copied.
	mov	%o0, %o5		! Original target address is returned.
	bpos,a,pt %xcc, .wrdbl1		! Have at least 16 bytes to copy.
	ldx	[%o1], %o3
.done:
	retl				! No bytes to copy.
	nop

	.align	32
.wrdbl1:				! Copy 16 bytes at a time.
	subcc	%o2, 16, %o2
	ldx	[%o1+8], %o4
	add	%o1, 16, %o1
	stx	%o3, [%o5]
	stx	%o4, [%o5+8]
	add	%o5, 16, %o5
	bg,a,pt	%xcc, .wrdbl1		! Have at least 16 more bytes.
	ldx	[%o1], %o3

	bz,a,pt	%xcc, .wrdbl3		! Have 8 bytes remaining to copy.
	ldx	[%o1], %o3

	retl
	nop

.wrdbl2:
	ldx	[%o1], %o3		! Copy last 8 bytes.
.wrdbl3:
	stx	%o3, [%o5]
	retl
	nop

	SET_SIZE(__align_cpy_8)
	SET_SIZE(__align_cpy_16)
