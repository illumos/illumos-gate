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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

	.file	"%M%"

/*
 * Double long add routine.  Ported from pdp 11/70 version
 * with considerable effort.  All supplied comments were ported.
 *
 * Ported from m32 version to sparc. No comments about difficulty.
 *
 *	dl_t
 *	ladd (lop, rop)
 *		dl_t	lop;
 *		dl_t	rop;
 */

#include "SYS.h"

	ENTRY(ladd)

	ld	[%o7+8],%o4		! Instruction at ret-addr should be a
	cmp     %o4,8			! 'unimp 8' indicating a valid call.
	be	1f			! if OK, go forward.
	nop				! delay instruction.
	jmp	%o7+8			! return
	nop				! delay instruction.

1:
	ld	[%o0+0],%o2		! fetch lop.dl_hop
	ld	[%o0+4],%o3		! fetch lop.dl_lop
	ld	[%o1+0],%o4		! fetch rop.dl_hop
	ld	[%o1+4],%o5		! fetch rop.dl_lop
	addcc	%o3,%o5,%o3		! lop.dl_lop + rop.dl_lop (set carry)
	addxcc	%o2,%o4,%o2		! lop.dl_hop + rop.dl_hop + <carry>
	ld	[%sp+(16*4)],%o0	! address to store result into
	st	%o2,[%o0+0]		! store result, dl_hop
	jmp	%o7+12			! return
	st	%o3,[%o0+4]		! store result, dl_lop

	SET_SIZE(ladd)
