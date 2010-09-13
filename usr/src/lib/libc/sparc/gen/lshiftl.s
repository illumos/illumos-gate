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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

	.file	"lshiftl.s"

/*
 * Shift a double long value. Ported from m32 version to sparc.
 *
 *	dl_t
 *	lshiftl (op, cnt)
 *		dl_t	op;
 *		int	cnt;
 */

#include "SYS.h"

	ENTRY(lshiftl)

	ld	[%o7+8],%o4		! Instruction at ret-addr should be a
	cmp     %o4,8			! 'unimp 8' indicating a valid call.
	be	1f			! if OK, go forward.
	nop				! delay instruction.
	jmp	%o7+8			! return
	nop				! delay instruction.

1:
	ld	[%o0+0],%o2		! fetch op.dl_hop
	ld	[%o0+4],%o3		! fetch op.dl_lop
	subcc	%g0,%o1,%o4		! test cnt < 0 and save reciprocol
	bz	.done
	ld	[%sp+(16*4)],%o0	! address to store result into
	bg	.right			!
	nop
					! Positive (or null) shift (left)
	and	%o1,0x3f,%o1		! Reduce range to 0..63
	subcc	%o1,32,%o5		! cnt - 32 (also test cnt >= 32)
	bneg,a	.leftsmall		!
	add	%o4,32,%o4		! 32 - cnt (actually ((-cnt) + 32)
	sll	%o3,%o5,%o2		! R.h = R.l << (cnt - 32)
	ba	.done			!
	or	%g0,%g0,%o3		! R.l = 0

.leftsmall:
	srl	%o3,%o4,%o5		! temp = R.l >> (31 - cnt)
	sll	%o3,%o1,%o3		! R.l = R.l << cnt
	sll	%o2,%o1,%o2		! R.h = R.h << cnt
	ba	.done			!
	or	%o2,%o5,%o2		! R.h = R.h | temp

.right:					! Negative shift (right)
	and	%o4,0x3f,%o4		! Reduce range to 0..63
	subcc	%o4,32,%o5		! cnt - 32 (also test cnt >= 32)
	bneg,a	.rightsmall		!
	add	%o1,32,%o1		! 32 - cnt (actually ((-cnt) + 32)
	srl	%o2,%o5,%o3		! R.l = R.h >> (cnt - 32)
	ba	.done			!
	or	%g0,%g0,%o2		! R.h = 0

.rightsmall:
	sll	%o2,%o1,%o5		! temp = R.h << (31 - cnt)
	srl	%o3,%o4,%o3		! R.l = R.l >> cnt
	srl	%o2,%o4,%o2		! R.h = R.h >> cnt
	ba	.done			!
	or	%o3,%o5,%o3		! R.l = R.l | temp

.done:
	st	%o2,[%o0+0]		! store result, dl_hop
	jmp	%o7+12			! return
	st	%o3,[%o0+4]		! store result, dl_lop

	SET_SIZE(lshiftl)
